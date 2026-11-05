// Held-file dynamic-symbol reader reused from the maintained W owner.
use anyhow::{Error, anyhow};
use goblin::elf::Elf;
use std::fs;

/// Read the existing loader-visible symbol table from an already held inode.
pub(crate) fn defined_dynamic_symbols_in_file(
    file: &fs::File,
    path: &std::path::Path,
) -> Result<Vec<String>, Error> {
    use std::os::unix::fs::FileExt;

    use goblin::container::Ctx;
    use goblin::elf::dynamic::Dynamic;
    use goblin::elf::dynamic::DynamicInfo;
    use goblin::elf::program_header::PT_DYNAMIC;
    use goblin::elf::program_header::ProgramHeader;
    use goblin::elf::section_header::SHN_UNDEF;
    use goblin::elf::sym::Sym;
    use goblin::elf::sym::Symtab;
    use goblin::strtab::Strtab;

    let length = file
        .metadata()
        .map_err(|error| anyhow!("failed to stat {}: {error}", path.display()))?
        .len();
    let not_elf = |error: &dyn std::fmt::Display| anyhow!("{} is not ELF: {error}", path.display());
    let read = |offset: u64, size: usize| -> Result<Vec<u8>, Error> {
        if offset
            .checked_add(size as u64)
            .is_none_or(|end| end > length)
        {
            return Err(not_elf(&format_args!(
                "{size} bytes at {offset:#x} would end past its {length} bytes"
            )));
        }
        let mut bytes = vec![0; size];
        file.read_exact_at(&mut bytes, offset)
            .map_err(|error| anyhow!("failed to read {}: {error}", path.display()))?;
        Ok(bytes)
    };

    let header = Elf::parse_header(&read(0, goblin::elf64::header::SIZEOF_EHDR)?)
        .map_err(|error| not_elf(&error))?;
    let ctx = Ctx::new(
        header.container().map_err(|error| not_elf(&error))?,
        header.endianness().map_err(|error| not_elf(&error))?,
    );
    let count = usize::from(header.e_phnum);
    let program_headers = ProgramHeader::parse(
        &read(header.e_phoff, count * ProgramHeader::size(ctx))?,
        0,
        count,
        ctx,
    )
    .map_err(|error| not_elf(&error))?;
    // An image without a dynamic segment exports nothing.
    let Some(segment) = program_headers
        .iter()
        .find(|header| header.p_type == PT_DYNAMIC)
    else {
        return Ok(Vec::new());
    };
    // `Dynamic::parse` reads the segment from the bytes it is given at the
    // segment's file offset, so it is given the segment alone, at offset 0.
    // Its addresses are then mapped to file offsets with every header.
    let entries = read(
        segment.p_offset,
        usize::try_from(segment.p_filesz).map_err(|error| not_elf(&error))?,
    )?;
    let alone = ProgramHeader {
        p_offset: 0,
        ..segment.clone()
    };
    let Some(dynamic) = Dynamic::parse(&entries, &[alone], ctx).map_err(|error| not_elf(&error))?
    else {
        return Ok(Vec::new());
    };
    let info = DynamicInfo::new(&dynamic.dyns, &program_headers);
    let count = dynamic_symbol_count(&read, &info, ctx)?;
    if count == 0 || info.symtab == 0 || info.strtab == 0 {
        return Ok(Vec::new());
    }
    let symbols = read(
        info.symtab as u64,
        count.saturating_mul(Sym::size(ctx.container)),
    )?;
    let symbols = Symtab::parse(&symbols, 0, count, ctx).map_err(|error| not_elf(&error))?;
    let names = read(info.strtab as u64, info.strsz)?;
    let names = Strtab::parse(&names, 0, info.strsz, 0).map_err(|error| not_elf(&error))?;
    Ok(symbols
        .iter()
        .filter(|symbol| symbol.st_shndx != SHN_UNDEF as usize)
        .filter_map(|symbol| names.get_at(symbol.st_name).map(str::to_owned))
        .collect())
}

/// How many entries an ELF image's dynamic symbol table has, which only the
/// section headers record; without them it comes from the symbol hash table,
/// as goblin and readelf find it. A GNU hash table leaves out the first
/// `symoffset` symbols and chains every later one, so the count is one past
/// the end of the chain that starts last (a chain's final entry has its low
/// bit set); a SysV hash table's chain count is the symbol count.
fn dynamic_symbol_count(
    read: &dyn Fn(u64, usize) -> Result<Vec<u8>, Error>,
    info: &goblin::elf::dynamic::DynamicInfo,
    ctx: goblin::container::Ctx,
) -> Result<usize, Error> {
    let word = |bytes: &[u8], index: usize| {
        let bytes: [u8; 4] = bytes[4 * index..4 * index + 4]
            .try_into()
            .expect("four bytes");
        if ctx.is_little_endian() {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        }
    };
    if let Some(table) = info.gnu_hash {
        // nbuckets, symoffset, bloom_size and bloom_shift; then the bloom
        // filter's address-sized words, the buckets, and the chains.
        let header = read(table, 16)?;
        let buckets = word(&header, 0) as usize;
        let first = word(&header, 1) as usize;
        let starts_at = table + 16 + u64::from(word(&header, 2)) * ctx.size() as u64;
        let starts = read(starts_at, 4 * buckets)?;
        let Some(last) = (0..buckets)
            .map(|bucket| word(&starts, bucket) as usize)
            .max()
            .filter(|&last| last >= first)
        else {
            return Ok(first);
        };
        let chains_at = starts_at + 4 * buckets as u64;
        let mut symbol = last;
        while word(&read(chains_at + 4 * (symbol - first) as u64, 4)?, 0) & 1 == 0 {
            symbol += 1;
        }
        Ok(symbol + 1)
    } else if let Some(table) = info.hash {
        // nbucket, then nchain.
        Ok(word(&read(table, 8)?, 1) as usize)
    } else {
        Ok(0)
    }
}
