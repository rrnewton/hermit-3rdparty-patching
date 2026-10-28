/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Required producer input, not basename or ABI-version discovery.
//!
//! The schema2 envelope binds the exact core engine manifest and both headers,
//! thin shim and pinned loader. Source identity and held inode checks do not
//! substitute for actual producer/ELF/loader qualification.

use std::ffi::OsStr;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Error, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::core_engine_artifact::CoreEngineArtifact;

pub const COHORT_ENV: &str = "HERMIT_SABRE_COHORT";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u32,
    core_h_revision: String,
    core_h_tree: String,
    core_r_revision: String,
    engine_artifact: ArtifactRecord,
    header: ArtifactRecord,
    native_header: ArtifactRecord,
    engine: ArtifactRecord,
    shim: ArtifactRecord,
    loader: ArtifactRecord,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactRecord {
    file: String,
    bytes: u64,
    sha256: String,
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

struct HeldArtifact {
    path: PathBuf,
    file: File,
    identity: Identity,
    sha256: String,
}

impl HeldArtifact {
    fn open(directory: &Path, name: &str, record: ArtifactRecord) -> Result<Self, Error> {
        Self::open_checked(directory, name, record, true)
    }

    fn open_checked(
        directory: &Path,
        name: &str,
        record: ArtifactRecord,
        executable: bool,
    ) -> Result<Self, Error> {
        ensure!(
            record.bytes <= 2 * 1024 * 1024 * 1024,
            "cohort role exceeds its length bound"
        );
        ensure!(
            record.file == name,
            "unexpected SaBRe cohort role/path for {name}"
        );
        ensure!(
            record.sha256.len() == 64
                && record
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "invalid SaBRe cohort SHA-256 for {name}"
        );
        let path = directory.join(name);
        let info = fs::symlink_metadata(&path)?;
        ensure!(
            info.is_file() && !info.file_type().is_symlink(),
            "cohort role is not a real file: {}",
            path.display()
        );
        ensure!(
            !executable || info.mode() & 0o111 != 0,
            "cohort role is not executable: {}",
            path.display()
        );
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        let identity = Identity::from(file.metadata()?);
        ensure!(
            identity == Identity::from(info),
            "cohort file changed while opening: {}",
            path.display()
        );
        ensure!(
            identity.bytes == record.bytes && record.bytes != 0,
            "cohort file size mismatch: {}",
            path.display()
        );
        let mut digest = Sha256::new();
        let mut block = [0_u8; 64 * 1024];
        let mut total = 0_u64;
        loop {
            let count = file.read(&mut block)?;
            if count == 0 {
                break;
            }
            total += count as u64;
            ensure!(
                total <= identity.bytes,
                "cohort artifact grew while hashing"
            );
            digest.update(&block[..count]);
        }
        ensure!(
            total == identity.bytes,
            "cohort artifact length changed while hashing"
        );
        ensure!(
            format!("{:x}", digest.finalize()) == record.sha256,
            "cohort artifact SHA-256 mismatch: {}",
            path.display()
        );
        let artifact = Self {
            path,
            file,
            identity,
            sha256: record.sha256,
        };
        artifact.recheck()?;
        Ok(artifact)
    }

    fn recheck(&self) -> Result<(), Error> {
        let visible = fs::symlink_metadata(&self.path)?;
        ensure!(
            visible.is_file() && !visible.file_type().is_symlink(),
            "cohort artifact is no longer a real visible file: {}",
            self.path.display()
        );
        ensure!(
            Identity::from(self.file.metadata()?) == self.identity
                && Identity::from(visible) == self.identity,
            "held or visible cohort artifact identity changed: {}",
            self.path.display()
        );
        Ok(())
    }

    fn mapping_identity(&self) -> Result<(u64, PathBuf), Error> {
        self.recheck()?;
        let path = fs::canonicalize(&self.path)?;
        ensure!(
            path == self.path,
            "cohort artifact canonical path changed: {}",
            self.path.display()
        );
        ensure!(
            self.identity.inode != 0,
            "cohort artifact has no file-backed mapping identity"
        );
        // The inode comes from the retained, hashed FD. recheck() also binds
        // the currently visible path to that exact held object; a replacement
        // cannot supply a new infrastructure identity.
        Ok((self.identity.inode, path))
    }
}

pub struct SabreArtifacts {
    cohort: HeldArtifact,
    engine: CoreEngineArtifact,
    shim: HeldArtifact,
    loader: HeldArtifact,
}

fn require_loader_selection(
    loader: &HeldArtifact,
    override_path: Option<&OsStr>,
    executable: &Path,
    path_env: &OsStr,
) -> Result<(), Error> {
    let selected = crate::sabre_loader::resolve_sabre_binary_from(
        override_path,
        Some(&loader.path),
        executable,
        path_env,
    )?;
    ensure!(
        Identity::from(fs::metadata(&selected)?) == loader.identity,
        "{}={} does not name the exact held producer loader {}",
        crate::sabre_loader::SABRE_BINARY_ENV,
        selected.display(),
        loader.path.display(),
    );
    loader.recheck()
}

impl SabreArtifacts {
    pub fn from_required_producer_input() -> Result<Self, Error> {
        let input = std::env::var_os(COHORT_ENV)
            .ok_or_else(|| anyhow::anyhow!("{COHORT_ENV} must name the exact core-engine/shim/loader producer cohort; no current producer is inferred"))?;
        let input = PathBuf::from(input);
        ensure!(
            input.is_absolute() && fs::canonicalize(&input)? == input,
            "{COHORT_ENV} must be an absolute canonical path"
        );
        ensure!(
            input.file_name().is_some_and(|name| name == "cohort.json"),
            "explicit SaBRe input must be cohort.json"
        );
        let info = fs::symlink_metadata(&input)?;
        ensure!(
            info.is_file() && !info.file_type().is_symlink() && info.len() <= 64 * 1024,
            "invalid SaBRe cohort manifest"
        );
        let bytes = fs::read(&input)?;
        ensure!(
            bytes.len() <= 64 * 1024,
            "SaBRe cohort manifest exceeded its byte bound"
        );
        let manifest: Manifest =
            serde_json::from_slice(&bytes).context("decoding the exact SaBRe producer cohort")?;
        ensure!(
            manifest.schema == 2,
            "unsupported SaBRe cohort schema; schema1 cannot select the common engine"
        );
        ensure!(
            manifest.core_h_revision == env!("HERMIT_PATCHING_CORE_H_REV"),
            "SaBRe cohort/core Hermit revision mismatch"
        );
        ensure!(
            manifest.core_r_revision == env!("HERMIT_PATCHING_CORE_R_REV"),
            "SaBRe cohort/core Reverie revision mismatch"
        );
        let directory = fs::canonicalize(
            input
                .parent()
                .ok_or_else(|| anyhow::anyhow!("cohort has no parent directory"))?,
        )?;
        let cohort = HeldArtifact::open_checked(
            &directory,
            "cohort.json",
            ArtifactRecord {
                file: "cohort.json".to_owned(),
                bytes: bytes.len() as u64,
                sha256: format!("{:x}", Sha256::digest(&bytes)),
            },
            false,
        )?;
        let engine = CoreEngineArtifact::open(
            &directory.join("engine-artifact.json"),
            &manifest.engine_artifact.file,
            manifest.engine_artifact.bytes,
            &manifest.engine_artifact.sha256,
        )?;
        engine.require_source(
            &manifest.core_h_revision,
            &manifest.core_h_tree,
            &manifest.core_r_revision,
        )?;
        for (role, row) in [
            ("engine", &manifest.engine),
            ("header", &manifest.header),
            ("native_header", &manifest.native_header),
        ] {
            engine.require_record(role, &row.file, row.bytes, &row.sha256)?;
        }
        let shim = HeldArtifact::open(&directory, "libhermit_engine_sabre.so", manifest.shim)?;
        let loader = HeldArtifact::open(&directory, "sabre", manifest.loader)?;
        // Retain the maintained loader preference/override semantics, then
        // bind the result to the already-admitted producer object. Discovery
        // cannot replace the mandatory engine/shim/loader source cohort.
        let override_path = std::env::var_os(crate::sabre_loader::SABRE_BINARY_ENV);
        let executable = std::env::current_exe()?;
        let path_env = std::env::var_os("PATH").unwrap_or_default();
        require_loader_selection(&loader, override_path.as_deref(), &executable, &path_env)?;
        // The exact absolute DT_NEEDED path prevents LD_LIBRARY_PATH or a
        // sibling basename from selecting another Detcore image.
        use std::os::unix::fs::FileExt;
        ensure!(
            shim.identity.bytes <= 64 * 1024 * 1024,
            "SaBRe shim ELF exceeds its bound"
        );
        let mut image = vec![0; usize::try_from(shim.identity.bytes)?];
        shim.file.read_exact_at(&mut image, 0)?;
        ensure!(
            format!("{:x}", Sha256::digest(&image)) == shim.sha256,
            "shim changed while inspecting ELF"
        );
        let elf = goblin::elf::Elf::parse(&image)?;
        ensure!(
            elf.header.e_machine == goblin::elf::header::EM_X86_64
                && elf.header.e_type == goblin::elf::header::ET_DYN,
            "SaBRe shim is not x86-64 shared ELF"
        );
        let expected = engine
            .engine_path()
            .to_str()
            .context("engine path is not UTF-8")?;
        ensure!(
            elf.libraries
                .iter()
                .filter(|name| **name == expected)
                .count()
                == 1,
            "SaBRe shim does not DT_NEEDED the exact held core engine"
        );
        ensure!(
            !elf.libraries
                .iter()
                .any(|name| name.contains("libdetcore_sabre") || name.contains("libreverie_sabre")),
            "SaBRe shim links a legacy Rust runtime"
        );
        let result = Self {
            cohort,
            engine,
            shim,
            loader,
        };
        result.recheck()?;
        Ok(result)
    }

    /// Held FDs remain alive across launch and teardown. Namespace-visible
    /// files must still be precisely those hashed files; hidden/replaced
    /// inputs refuse rather than falling back to a basename or another DSO.
    pub fn recheck(&self) -> Result<(), Error> {
        self.cohort.recheck()?;
        self.engine.recheck()?;
        self.shim.mapping_identity()?;
        self.loader.mapping_identity()?;
        Ok(())
    }

    pub fn shim(&self) -> &Path {
        &self.shim.path
    }
    pub fn loader(&self) -> &Path {
        &self.loader.path
    }

    pub(super) fn engine_mapping_identity(&self) -> Result<(u64, PathBuf), Error> {
        self.engine.mapping_identity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn mapping_identity_remains_bound_to_the_hashed_held_file() {
        let directory = tempfile::tempdir().expect("cohort directory");
        let name = "libhermit_inguest_engine.so";
        let directory_path =
            fs::canonicalize(directory.path()).expect("canonical cohort directory");
        let path = directory_path.join(name);
        let bytes = b"exact engine fixture";
        fs::write(&path, bytes).expect("engine fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("engine executable mode");
        let artifact = HeldArtifact::open(
            &directory_path,
            name,
            ArtifactRecord {
                file: name.to_owned(),
                bytes: bytes.len() as u64,
                sha256: format!("{:x}", Sha256::digest(bytes)),
            },
        )
        .expect("hash-bound engine");
        let held_inode = artifact.file.metadata().expect("held metadata").ino();
        assert_eq!(
            artifact.mapping_identity().expect("original identity"),
            (
                held_inode,
                fs::canonicalize(&path).expect("canonical fixture")
            ),
        );

        let executable = directory_path.join("hermit-sabre");
        require_loader_selection(&artifact, None, &executable, OsStr::new(""))
            .expect("the actual held producer loader remains selected");
        require_loader_selection(
            &artifact,
            Some(path.as_os_str()),
            &executable,
            OsStr::new(""),
        )
        .expect("a valid override names the same held producer loader");
        let other = directory_path.join("other-sabre");
        fs::write(&other, bytes).expect("byte-identical different loader");
        fs::set_permissions(&other, fs::Permissions::from_mode(0o700))
            .expect("other executable mode");
        assert!(
            require_loader_selection(
                &artifact,
                Some(other.as_os_str()),
                &executable,
                OsStr::new("")
            )
            .unwrap_err()
            .to_string()
            .contains("does not name the exact held producer loader"),
            "an executable override cannot select a different producer object",
        );

        // Preserve the original open FD while replacing its visible name.
        // Even byte-identical content is not the admitted held object.
        let replacement = directory_path.join("replacement.so");
        fs::write(&replacement, bytes).expect("replacement fixture");
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700))
            .expect("replacement executable mode");
        fs::rename(&replacement, &path).expect("replace visible name");
        assert_eq!(
            artifact.file.metadata().expect("original held FD").ino(),
            held_inode
        );
        assert!(
            artifact.mapping_identity().is_err(),
            "a replaced name must not gain infrastructure identity"
        );
    }
}
