/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The maintained bare Reverie SaBRe strace launcher.
//!
//! This diagnostic uses the existing strace Tool artifacts. Detcore execution
//! uses the separate producer-bound shared-engine cohort in sabre_physical.
//! The core command owns global logging and output-cap admission before this
//! physical launcher resolves any environment-named artifact.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command as StdCommand;

use hermit::{Error, ExitStatus};
use tracing::metadata::LevelFilter;

fn sabre_artifact(variable: &str, description: &str, executable: bool) -> Result<OsString, Error> {
    let value = std::env::var_os(variable).ok_or_else(|| {
        Error::msg(format!(
            "the sabre backend needs {variable}=<path-to-{description}>"
        ))
    })?;
    validate_sabre_artifact(Path::new(&value), variable, executable)
}

fn validate_sabre_artifact(
    requested_path: &Path,
    variable: &str,
    executable: bool,
) -> Result<OsString, Error> {
    let path = fs::canonicalize(requested_path).map_err(|error| {
        Error::msg(format!(
            "the sabre backend cannot access {variable}={}: {error}",
            requested_path.display()
        ))
    })?;
    let metadata = fs::metadata(&path).map_err(|error| {
        Error::msg(format!(
            "the sabre backend cannot inspect {variable}={}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(Error::msg(format!(
            "the sabre backend needs {variable}={} to be a regular file",
            path.display()
        )));
    }
    if executable && metadata.permissions().mode() & 0o111 == 0 {
        return Err(Error::msg(format!(
            "the sabre backend needs {variable}={} to be executable",
            path.display()
        )));
    }
    Ok(path.into_os_string())
}

const SABRE_QUIET_ENV: &str = "REVERIE_SABRE_STRACE_QUIET";

fn sabre_command(
    runner: &OsString,
    sabre: &OsString,
    plugin: &OsString,
    program: &Path,
    args: &[String],
    quiet: bool,
    log: Option<LevelFilter>,
) -> StdCommand {
    let mut command = StdCommand::new(runner);
    command
        .arg("--sabre")
        .arg(sabre)
        .arg("--plugin")
        .arg(plugin)
        .arg("--")
        .arg(program)
        .args(args);
    if quiet {
        command.env(SABRE_QUIET_ENV, "1");
    }
    if let Some(level) = log {
        command.env("HERMIT_LOG", level.to_string());
    }
    command
}

fn sabre_artifacts() -> Result<(OsString, OsString, OsString), Error> {
    Ok((
        sabre_artifact("HERMIT_SABRE_RUNNER", "reverie-sabre-strace", true)?,
        sabre_artifact("HERMIT_SABRE_BINARY", "sabre", true)?,
        sabre_artifact(
            "HERMIT_SABRE_PLUGIN",
            "libreverie_sabre_strace_plugin.so",
            false,
        )?,
    ))
}

/// Runs program through the shared Reverie strace tool over SaBRe.
///
/// The SaBRe host and plugin live in the coordinated Reverie checkout, so
/// Hermit uses explicit artifact paths rather than taking an unreleased Cargo
/// dependency:
///
/// * HERMIT_SABRE_RUNNER: reverie-sabre-strace executable.
/// * HERMIT_SABRE_BINARY: pinned SaBRe executable.
/// * HERMIT_SABRE_PLUGIN: libreverie_sabre_strace_plugin.so.
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW: Review the transferred SaBRe CLI backend dispatch.
pub fn run_sabre_strace(program: &Path, args: &[String]) -> Result<ExitStatus, Error> {
    let (runner, sabre, plugin) = sabre_artifacts()?;

    eprintln!("hermit: [sabre backend] tracing {program:?} with the shared Reverie tool");

    let status = sabre_command(&runner, &sabre, &plugin, program, args, false, None)
        .status()
        .map_err(|error| {
            Error::msg(format!(
                "failed to launch the SaBRe runner {}: {error}",
                Path::new(&runner).display()
            ))
        })?;

    Ok(status.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sabre_artifact_returns_the_validated_absolute_path() {
        let file = tempfile::NamedTempFile::new_in(".").unwrap();
        let relative_path = file.path().file_name().unwrap();

        let resolved = validate_sabre_artifact(Path::new(relative_path), "test-artifact", false)
            .map(std::path::PathBuf::from)
            .unwrap();

        assert!(resolved.is_absolute());
        assert_eq!(resolved, fs::canonicalize(file.path()).unwrap());
    }
}
