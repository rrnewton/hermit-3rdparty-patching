/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Extension-owned physical launchers for SaBRe and e9patch.
//!
//! Generic Tool implementations and native/report algorithms stay in core.
//! The exact core API commit must replace the baseline manifest pin before build.

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use reverie::GlobalTool;
use reverie::Tool;
use reverie_examples::host::{Run, RunError, exit_code};
use reverie_util::CommonToolArguments;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum BackendKind {
    E9patch,
    Sabre,
}

/// The tool to run, as the example preload names it, and that preload.
pub struct Preload<'a> {
    /// The name the preload's selector knows the tool by.
    pub tool: &'a str,
    /// The example preload, `libreverie_patching_examples.so`.
    pub path: &'a Path,
}

/// Name the e9tool and e9patch binaries reverie-e9patch built from its
/// vendored source, unless the environment already names them, so that the
/// e9patch backend can rewrite the program.
///
/// # Safety
///
/// This sets environment variables, so no other thread may run.
pub unsafe fn use_bundled_e9patch() {
    for (name, path) in [
        (
            reverie_e9patch::E9TOOL_ENV,
            reverie_e9patch::bundled_e9tool_path(),
        ),
        (
            reverie_e9patch::E9PATCH_BACKEND_ENV,
            reverie_e9patch::bundled_e9patch_path(),
        ),
    ] {
        if std::env::var_os(name).is_none() {
            // SAFETY: the caller runs no other thread.
            unsafe { std::env::set_var(name, path) };
        }
    }
}

/// The example preload beside `executable`, as cargo lays out its binaries.
pub fn default_preload_path(executable: &Path) -> Option<std::path::PathBuf> {
    let parent = executable.parent()?;
    [
        parent.join("libreverie_patching_examples.so"),
        parent.join("deps/libreverie_patching_examples.so"),
        parent
            .parent()
            .unwrap_or(parent)
            .join("libreverie_patching_examples.so"),
    ]
    .into_iter()
    .find(|path| path.is_file())
}

pub async fn run<T>(
    backend: BackendKind,
    args: &CommonToolArguments,
    config: <T::GlobalState as GlobalTool>::Config,
    preload: Option<Preload<'_>>,
) -> Result<Run<T::GlobalState>, RunError>
where
    T: Tool + 'static,
    T::ThreadState: 'static,
    T::GlobalState: 'static,
    <T::GlobalState as GlobalTool>::Config: 'static,
{
    match backend {
        BackendKind::E9patch => {
            let preload = preload.ok_or_else(|| {
                RunError::Refused(format!(
                    "the {backend:?} backend hosts a tool only through a preload that compiles \
                     it in, and none was found (libreverie_patching_examples.so)"
                ))
            })?;
            run_e9patch::<T>(args, config, preload).await
        }
        BackendKind::Sabre => {
            let preload = preload.ok_or_else(|| {
                RunError::Refused("the SaBRe backend hosts a tool only by name".to_owned())
            })?;
            run_sabre::<T>(args, config, preload.tool).await
        }
    }
}

/// What a tool's launcher does with [`run`]: point e9patch at its bundled
/// tools (before any thread starts), find the example preload (`preload`, or
/// `libreverie_patching_examples.so` beside this binary), run the program under `T` on
/// `backend` in a new runtime, and pass on the output the backend captured.
/// `tool` is the name the example preload knows `T` by.
pub fn run_blocking<T>(
    backend: BackendKind,
    args: &CommonToolArguments,
    config: <T::GlobalState as GlobalTool>::Config,
    tool: &str,
    preload: Option<PathBuf>,
) -> anyhow::Result<Run<T::GlobalState>>
where
    T: Tool + 'static,
    T::ThreadState: 'static,
    T::GlobalState: 'static,
    <T::GlobalState as GlobalTool>::Config: 'static,
{
    if backend == BackendKind::E9patch {
        // SAFETY: no other thread runs yet; the runtime starts below.
        unsafe { use_bundled_e9patch() };
    }
    let preload = preload.or_else(|| {
        std::env::current_exe()
            .ok()
            .and_then(|executable| default_preload_path(&executable))
    });
    let preload = preload.as_deref().map(|path| Preload { tool, path });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let run = runtime
        .block_on(run::<T>(backend, args, config, preload))
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    if let Some((stdout, stderr)) = &run.captured {
        use std::io::Write as _;
        std::io::stdout().write_all(stdout)?;
        std::io::stderr().write_all(stderr)?;
    }
    Ok(run)
}

async fn run_e9patch<T>(
    args: &CommonToolArguments,
    config: <T::GlobalState as GlobalTool>::Config,
    preload: Preload<'_>,
) -> Result<Run<T::GlobalState>, RunError>
where
    T: Tool + 'static,
{
    let tool = preload.tool.as_bytes().to_vec();
    let command: reverie::process::Command = args.clone().into();
    let (output, global_state) =
        reverie_e9patch::E9patchBackend::run_direct_with_output_and_preload_data::<T>(
            command,
            config,
            preload.path,
            tool,
        )
        .await?;
    Ok(Run {
        status: output.status,
        exit_code: exit_code(output.status),
        global_state,
        captured: Some((output.stdout, output.stderr)),
    })
}

const SABRE_TOOL_ENV: &str = "REVERIE_SABRE_TOOL";

fn named_or_beside(variable: &str, name: &str) -> Option<PathBuf> {
    let path = match std::env::var_os(variable) {
        Some(path) => PathBuf::from(path),
        None => std::env::current_exe().ok()?.parent()?.join(name),
    };
    path.is_file().then_some(path)
}

async fn run_sabre<T>(
    args: &CommonToolArguments,
    config: <T::GlobalState as GlobalTool>::Config,
    tool: &str,
) -> Result<Run<T::GlobalState>, RunError>
where
    T: Tool + 'static,
    T::GlobalState: 'static,
{
    let sabre = named_or_beside("SABRE_BINARY", "sabre").ok_or_else(|| {
        RunError::Refused(
            "the SaBRe loader was not found: set SABRE_BINARY, or put sabre beside this binary \
             (`reverie-sabre-strace --print-sabre` names the one reverie-sabre built)"
                .to_owned(),
        )
    })?;
    let plugin =
        named_or_beside("SABRE_PLUGIN", "libreverie_sabre_strace_plugin.so").ok_or_else(|| {
            RunError::Refused(
                "the SaBRe example-tool plugin was not found: set SABRE_PLUGIN, or build \
                 reverie-sabre-strace beside this binary"
                    .to_owned(),
            )
        })?;
    let mut command: reverie::process::Command = args.clone().into();
    command.env(SABRE_TOOL_ENV, tool);
    let global = Arc::new(<T::GlobalState as GlobalTool>::init_global_state(&config).await);
    let status = reverie_host::run_with_global_state(
        command,
        Some(sabre),
        Some(plugin),
        global.clone(),
        config,
    )
    .await?;
    let global_state = Arc::try_unwrap(global).map_err(|_| {
        anyhow::anyhow!("a SaBRe guest process still holds the tool's global state")
    })?;
    Ok(Run {
        status,
        exit_code: exit_code(status),
        global_state,
        captured: None,
    })
}
