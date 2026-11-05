/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Maintained SaBRe loader preference and executable validation.
//!
//! The live consumer supplies its exact already-held producer loader as the
//! packaged candidate. Its separate held-file check requires this selection,
//! including HERMIT_SABRE_BINARY when set, to name the admitted cohort's loader.
//! No discovery fallback can supply a different engine/shim/loader cohort.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::anyhow;
use hermit::Error;

pub(super) const SABRE_BINARY_ENV: &str = "HERMIT_SABRE_BINARY";

fn is_executable_file(path: &Path) -> bool {
    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

pub(super) fn resolve_sabre_binary_from(
    override_path: Option<&OsStr>,
    packaged_path: Option<&Path>,
    executable: &Path,
    path_env: &OsStr,
) -> Result<PathBuf, Error> {
    if let Some(requested) = override_path {
        if requested.is_empty() {
            return Err(anyhow!("{SABRE_BINARY_ENV} is empty"));
        }
        let path = PathBuf::from(requested);
        return is_executable_file(&path)
            .then_some(path.clone())
            .ok_or_else(|| {
                anyhow!(
                    "{SABRE_BINARY_ENV}={} is not an executable file",
                    path.display()
                )
            });
    }

    if let Some(path) = packaged_path
        && is_executable_file(path)
    {
        return Ok(path.to_path_buf());
    }

    let directory = executable
        .parent()
        .ok_or_else(|| anyhow!("Hermit executable has no parent directory"))?;
    let sibling = directory.join("sabre");
    let target_build = directory.parent().map(|target| target.join("sabre/sabre"));

    if is_executable_file(&sibling) {
        return Ok(sibling);
    }
    if let Some(candidate) = &target_build
        && is_executable_file(candidate)
    {
        return Ok(candidate.clone());
    }
    if !path_env.is_empty()
        && let Some(candidate) = std::env::split_paths(path_env)
            .map(|directory| directory.join("sabre"))
            .find(|candidate| is_executable_file(candidate))
    {
        return Ok(candidate);
    }

    Err(anyhow!(
        "SaBRe executable was not found in the Hermit installation, beside {}, or in PATH; set {} or {SABRE_BINARY_ENV}",
        executable.display(),
        hermit_resources::INSTALL_DIR_ENV
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_test_executable(path: &std::path::Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"test loader").unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[test]
    fn sabre_binary_resolver_finds_cargo_target_build() {
        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("target/release/hermit");
        let loader = temp.path().join("target/sabre/sabre");
        write_test_executable(&loader);

        assert_eq!(
            resolve_sabre_binary_from(None, None, &executable, OsStr::new("")).unwrap(),
            loader
        );
    }

    #[test]
    fn sabre_binary_resolver_uses_packaged_loader() {
        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("target/release/hermit");
        let packaged = temp.path().join("install_pkg/rsrcs/sabre");
        write_test_executable(&packaged);

        assert_eq!(
            resolve_sabre_binary_from(None, Some(&packaged), &executable, OsStr::new("")).unwrap(),
            packaged
        );
    }

    #[test]
    fn sabre_binary_resolver_prefers_and_validates_override() {
        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("target/release/hermit");
        let discovered = temp.path().join("target/sabre/sabre");
        let requested = temp.path().join("requested-sabre");
        write_test_executable(&discovered);
        write_test_executable(&requested);

        assert_eq!(
            resolve_sabre_binary_from(
                Some(requested.as_os_str()),
                Some(&discovered),
                &executable,
                OsStr::new(""),
            )
            .unwrap(),
            requested
        );

        let mut permissions = fs::metadata(&requested).unwrap().permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&requested, permissions).unwrap();
        let error = resolve_sabre_binary_from(
            Some(requested.as_os_str()),
            Some(&discovered),
            &executable,
            OsStr::new(""),
        )
        .unwrap_err();
        assert!(error.to_string().contains("is not an executable file"));
    }
}
