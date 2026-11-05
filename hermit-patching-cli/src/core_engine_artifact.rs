/* Copyright (c) Meta Platforms, Inc. and affiliates. */

//! The SaBRe C shim links the explicit, source-owned common core engine.
//!
//! This is artifact custody and a measured source-cohort check. It does not
//! grant private-image authority or qualify the native mechanism. In particular,
//! an engine which has not emitted the saved-frame entry set refuses.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const ENGINE: &str = "libhermit_inguest_engine.so";
const HEADER: &str = "hermit-engine-v1.h";
const NATIVE_HEADER: &str = "hermit-engine-native-v1.h";
const MAX_RECORD: u64 = 64 * 1024 * 1024;
const MAX_FILE: u64 = 2 * 1024 * 1024 * 1024;

// The saved-frame shim requires the actual ordinary header exports. The native
// header is also an exact required role of the SAME schema2 engine cohort.
const REQUIRED_ORDINARY_EXPORTS: &[&str] = &[
    "hermit_engine_preload_initialize_v1",
    "hermit_engine_loader_initialize_v1",
    "hermit_engine_saved_syscall_v1",
    "hermit_engine_install_loader_state_v1",
    "hermit_engine_raw_syscall_v1",
];

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    file: String,
    bytes: u64,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompiledUnit {
    package_id: String,
    target: String,
    crate_types: Vec<String>,
    features: Vec<String>,
    profile: serde_json::Value,
    fresh: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u32,
    kind: String,
    core_h_revision: String,
    core_h_tree: String,
    core_r_revision: String,
    artifacts: BTreeMap<String, Record>,
    profile: serde_json::Value,
    features: Vec<String>,
    cargo_package_id: String,
    source_records: BTreeMap<String, Record>,
    compiled_units: Vec<CompiledUnit>,
    qualification: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
    bytes: u64,
    mode: u32,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl From<Metadata> for Identity {
    fn from(info: Metadata) -> Self {
        Self {
            device: info.dev(),
            inode: info.ino(),
            bytes: info.size(),
            mode: info.mode(),
            mtime: (info.mtime(), info.mtime_nsec()),
            ctime: (info.ctime(), info.ctime_nsec()),
        }
    }
}

struct HeldFile {
    path: PathBuf,
    file: File,
    identity: Identity,
    sha256: String,
}

impl HeldFile {
    fn open(path: &Path, bound: u64, expected: Option<&Record>, executable: bool) -> Result<Self> {
        ensure!(
            path.is_absolute() && fs::canonicalize(path)? == path,
            "artifact path must be absolute and canonical: {}",
            path.display()
        );
        let before = fs::symlink_metadata(path)?;
        ensure!(
            before.is_file() && !before.file_type().is_symlink(),
            "artifact is not a real regular file: {}",
            path.display()
        );
        ensure!(
            0 < before.len() && before.len() <= bound,
            "artifact exceeds its length bound: {}",
            path.display()
        );
        ensure!(
            !executable || before.mode() & 0o111 != 0,
            "artifact is not executable: {}",
            path.display()
        );
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let identity = Identity::from(file.metadata()?);
        ensure!(
            identity == Identity::from(before),
            "artifact changed while opening"
        );
        let sha256 = {
            let mut hash = Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            let mut bounded = (&mut file).take(bound + 1);
            let mut total = 0_u64;
            loop {
                let count = bounded.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                total += count as u64;
                ensure!(
                    total <= identity.bytes && total <= bound,
                    "artifact grew while hashing: {}",
                    path.display()
                );
                hash.update(&buffer[..count]);
            }
            ensure!(
                total == identity.bytes,
                "artifact changed length while hashing"
            );
            format!("{:x}", hash.finalize())
        };
        if let Some(record) = expected {
            validate_record(record, bound)?;
            ensure!(
                path.file_name()
                    .is_some_and(|name| name == record.file.as_str())
                    && identity.bytes == record.bytes
                    && sha256 == record.sha256,
                "artifact length/name/SHA-256 differs from the producer: {}",
                path.display()
            );
        }
        let result = Self {
            path: path.to_owned(),
            file,
            identity,
            sha256,
        };
        result.recheck()?;
        Ok(result)
    }

    fn recheck(&self) -> Result<()> {
        let visible = fs::symlink_metadata(&self.path)?;
        ensure!(
            visible.is_file()
                && !visible.file_type().is_symlink()
                && Identity::from(visible) == self.identity
                && Identity::from(self.file.metadata()?) == self.identity
                && fs::canonicalize(&self.path)? == self.path,
            "held or visible artifact changed: {}",
            self.path.display()
        );
        Ok(())
    }

    fn bytes(&self, bound: u64) -> Result<Vec<u8>> {
        use std::os::unix::fs::FileExt;
        self.recheck()?;
        ensure!(self.identity.bytes <= bound, "artifact exceeds read bound");
        let mut bytes = vec![0; usize::try_from(self.identity.bytes)?];
        self.file.read_exact_at(&mut bytes, 0)?;
        ensure!(
            format!("{:x}", Sha256::digest(&bytes)) == self.sha256,
            "held artifact bytes changed: {}",
            self.path.display()
        );
        self.recheck()?;
        Ok(bytes)
    }
}

fn full_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_record(record: &Record, bound: u64) -> Result<()> {
    ensure!(
        !record.file.is_empty()
            && Path::new(&record.file).components().count() == 1
            && matches!(
                Path::new(&record.file).components().next(),
                Some(std::path::Component::Normal(_))
            )
            && record.bytes > 0
            && record.bytes <= bound
            && full_hex(&record.sha256, 64),
        "invalid producer file record"
    );
    Ok(())
}

fn validate_profile(profile: &serde_json::Value) -> Result<()> {
    let profile = profile
        .as_object()
        .context("engine profile is not an object")?;
    for field in [
        "opt_level",
        "debuginfo",
        "debug_assertions",
        "overflow_checks",
        "test",
    ] {
        ensure!(profile.contains_key(field), "engine profile omits {field}");
    }
    ensure!(
        profile.get("test") == Some(&serde_json::Value::Bool(false)),
        "a test artifact is not the core engine"
    );
    Ok(())
}

fn validate_roles(roles: &BTreeMap<String, Record>) -> Result<()> {
    ensure!(
        roles.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == BTreeSet::from(["engine", "header", "native_header"]),
        "engine requires precisely the engine and both header roles"
    );
    Ok(())
}

fn require_ordinary_exports(engine: &HeldFile) -> Result<()> {
    engine.recheck()?;
    use std::os::unix::fs::FileExt;
    let mut header = [0_u8; goblin::elf64::header::SIZEOF_EHDR];
    engine.file.read_exact_at(&mut header, 0)?;
    let header = goblin::elf::Elf::parse_header(&header)?;
    ensure!(
        header.e_machine == goblin::elf::header::EM_X86_64
            && header.e_type == goblin::elf::header::ET_DYN,
        "core engine is not an x86-64 shared ELF"
    );
    let actual = crate::artifact_elf::defined_dynamic_symbols_in_file(&engine.file, &engine.path)?;
    for required in REQUIRED_ORDINARY_EXPORTS {
        ensure!(
            actual.iter().any(|name| name == required),
            "core engine {} has not emitted required ordinary entry {required}; no legacy runtime is selected",
            engine.path.display()
        );
    }
    engine.recheck()?;
    Ok(())
}

pub(crate) struct CoreEngineArtifact {
    manifest: HeldFile,
    engine: HeldFile,
    header: HeldFile,
    native_header: HeldFile,
    records: BTreeMap<String, Record>,
    source: (String, String, String),
}

impl CoreEngineArtifact {
    pub(crate) fn open(input: &Path, file: &str, bytes: u64, sha256: &str) -> Result<Self> {
        ensure!(
            file == "engine-artifact.json",
            "wrong required engine manifest role"
        );
        let expected = Record {
            file: file.to_owned(),
            bytes,
            sha256: sha256.to_owned(),
        };
        let manifest = HeldFile::open(input, MAX_RECORD, Some(&expected), false)?;
        let record: Manifest = serde_json::from_slice(&manifest.bytes(MAX_RECORD)?)?;
        ensure!(
            record.schema == 2 && record.kind == "hermit-inguest-engine",
            "unsupported core engine artifact schema; schema 2 and both exact headers are required"
        );
        ensure!(
            full_hex(&record.core_h_revision, 40)
                && full_hex(&record.core_h_tree, 40)
                && full_hex(&record.core_r_revision, 40),
            "engine source identity is incomplete"
        );
        // current() refuses dirty/unknown/native/export producers. A path or
        // environment variable cannot supply or replace this measured identity.
        let current = serde_json::to_value(hermit::compatibility::current()?)?;
        ensure!(
            current["source"]["commit"].as_str() == Some(record.core_h_revision.as_str())
                && current["source"]["tree"].as_str() == Some(record.core_h_tree.as_str())
                && current["reverie"]["commit"].as_str() == Some(record.core_r_revision.as_str()),
            "core engine and the executable have different measured H/tree/R source cohorts"
        );
        validate_profile(&record.profile)?;
        ensure!(
            record
                .features
                .iter()
                .all(|name| matches!(name.as_str(), "default" | "dispatch-observer"))
                && record.features.iter().collect::<BTreeSet<_>>().len() == record.features.len(),
            "unexpected or duplicate engine features"
        );
        ensure!(
            !record.cargo_package_id.is_empty() && !record.compiled_units.is_empty(),
            "engine Cargo unit provenance is missing"
        );
        let mut units = BTreeSet::new();
        let mut emitted_engine = 0;
        for unit in &record.compiled_units {
            ensure!(
                !unit.package_id.is_empty()
                    && !unit.target.is_empty()
                    && !unit.crate_types.is_empty(),
                "incomplete compiled engine dependency unit"
            );
            // Profile.test is true only for actual test units; the producer is
            // a completed ordinary cdylib build and does not accept them.
            validate_profile(&unit.profile)?;
            let key = serde_json::to_string(&(
                &unit.package_id,
                &unit.target,
                &unit.crate_types,
                &unit.features,
                &unit.profile,
            ))?;
            ensure!(units.insert(key), "duplicate engine compiled unit");
            let _fresh = unit.fresh; // Cargo freshness is recorded, never inferred as new compilation.
            if unit.package_id == record.cargo_package_id
                && unit.target == "hermit_inguest_engine"
                && unit.crate_types == ["cdylib"]
            {
                ensure!(
                    unit.features == record.features && unit.profile == record.profile,
                    "engine artifact differs from its actual Cargo unit"
                );
                emitted_engine += 1;
            }
        }
        ensure!(
            emitted_engine == 1,
            "engine requires exactly one actual cdylib unit"
        );
        ensure!(
            record
                .source_records
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == BTreeSet::from([
                    "cargo_events",
                    "cargo_metadata",
                    "cargo_lock",
                    "package_manifest",
                    "installer"
                ]),
            "engine source record set is incomplete"
        );
        for row in record.source_records.values() {
            validate_record(row, MAX_RECORD)?;
        }
        ensure!(
            record.qualification
                == "artifact installation only; no loader/runtime/private qualification",
            "unsupported engine qualification declaration"
        );
        validate_roles(&record.artifacts)?;
        let directory = input.parent().context("engine manifest has no directory")?;
        let engine = HeldFile::open(
            &directory.join(ENGINE),
            MAX_FILE,
            Some(&record.artifacts["engine"]),
            true,
        )?;
        let header = HeldFile::open(
            &directory.join(HEADER),
            MAX_FILE,
            Some(&record.artifacts["header"]),
            false,
        )?;
        let native_header = HeldFile::open(
            &directory.join(NATIVE_HEADER),
            MAX_FILE,
            Some(&record.artifacts["native_header"]),
            false,
        )?;
        require_ordinary_exports(&engine)?;
        engine.recheck()?;

        let result = Self {
            manifest,
            engine,
            header,
            native_header,
            records: record.artifacts,
            source: (
                record.core_h_revision,
                record.core_h_tree,
                record.core_r_revision,
            ),
        };
        result.recheck()?;
        Ok(result)
    }
    pub(crate) fn require_source(&self, h: &str, tree: &str, r: &str) -> Result<()> {
        ensure!(
            self.source == (h.to_owned(), tree.to_owned(), r.to_owned()),
            "SaBRe envelope differs from the exact core H/tree/R engine source"
        );
        Ok(())
    }
    pub(crate) fn require_record(
        &self,
        role: &str,
        file: &str,
        bytes: u64,
        hash: &str,
    ) -> Result<()> {
        let row = self
            .records
            .get(role)
            .context("missing required core artifact role")?;
        ensure!(
            row.file == file && row.bytes == bytes && row.sha256 == hash,
            "SaBRe envelope differs from the core engine artifact role {role}"
        );
        Ok(())
    }
    pub(crate) fn engine_path(&self) -> &Path {
        &self.engine.path
    }
    pub(crate) fn mapping_identity(&self) -> Result<(u64, PathBuf)> {
        self.engine.recheck()?;
        ensure!(
            self.engine.identity.inode != 0,
            "engine has no mapped inode"
        );
        Ok((self.engine.identity.inode, self.engine.path.clone()))
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        for row in [
            &self.manifest,
            &self.engine,
            &self.header,
            &self.native_header,
        ] {
            row.recheck()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn held_headers_refuse_changed_bytes_replaced_inode_and_symlink() {
        let directory = tempfile::tempdir().unwrap();
        let path = fs::canonicalize(directory.path())
            .unwrap()
            .join(NATIVE_HEADER);
        fs::write(&path, b"actual header input").unwrap();
        let original = HeldFile::open(&path, MAX_RECORD, None, false).unwrap();
        assert_eq!(original.bytes(MAX_RECORD).unwrap(), b"actual header input");
        fs::write(&path, b"changed header input").unwrap();
        assert!(original.recheck().is_err());
        fs::write(&path, b"actual header input").unwrap();
        let original = HeldFile::open(&path, MAX_RECORD, None, false).unwrap();
        let replacement = path.with_extension("replacement");
        fs::write(&replacement, b"actual header input").unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert!(original.recheck().is_err());
        let link = path.with_extension("link");
        symlink(&path, &link).unwrap();
        assert!(HeldFile::open(&link, MAX_RECORD, None, false).is_err());
    }

    #[test]
    fn real_nonengine_elf_cannot_supply_the_saved_frame_entry_contract() {
        let path = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let file = HeldFile::open(&path, MAX_FILE, None, true).unwrap();
        assert!(require_ordinary_exports(&file).is_err());
    }

    #[test]
    fn schema2_roles_refuse_missing_native_header_and_unrelated_extra_role() {
        let mut roles = BTreeMap::new();
        for (role, file) in [
            ("engine", ENGINE),
            ("header", HEADER),
            ("native_header", NATIVE_HEADER),
        ] {
            roles.insert(
                role.to_owned(),
                Record {
                    file: file.to_owned(),
                    bytes: 1,
                    sha256: "0".repeat(64),
                },
            );
        }
        assert!(validate_roles(&roles).is_ok());
        let native = roles.remove("native_header").unwrap();
        assert!(validate_roles(&roles).is_err());
        roles.insert("native_header".to_owned(), native.clone());
        roles.insert("legacy_runtime".to_owned(), native);
        assert!(validate_roles(&roles).is_err());
    }
}
