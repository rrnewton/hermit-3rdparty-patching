/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! SaBRe/e9patch recorder frontend; generic native observation and report
//! algorithms remain in the core example library.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::Parser;
use reverie_examples::host::run_native;
use reverie_examples::tools::recorder_tool::{self, Recorder, report, reverie_events};

use backend::BackendKind;
use reverie_patching_examples::backend;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum Target {
    Native,
    E9patch,
    Sabre,
}

/// Run PROGRAM under the pass-through recorder on BACKEND and write its
/// syscalls and their results to OUTPUT.
#[derive(Debug, Parser)]
struct Opts {
    #[clap(long, value_enum)]
    backend: Target,
    /// Where to write the record (stdout is the program's).
    #[clap(long)]
    output: PathBuf,
    /// The example preload the in-guest backends host the recorder in;
    /// by default `libreverie_patching_examples.so` beside this binary.
    #[clap(long)]
    preload: Option<PathBuf>,
    #[clap(value_name = "PROGRAM")]
    program: PathBuf,
    #[clap(
        value_name = "ARGS",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    args: Vec<OsString>,
}

fn utf8(value: &std::ffi::OsStr) -> anyhow::Result<String> {
    value
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 program or argument {value:?}"))
}

fn reverie_backend(target: Target) -> BackendKind {
    match target {
        Target::Native => unreachable!("native runs without Reverie"),
        Target::E9patch => BackendKind::E9patch,
        Target::Sabre => BackendKind::Sabre,
    }
}

fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    let report = if opts.backend == Target::Native {
        run_native(&opts.program, &opts.args)?
    } else {
        if opts.backend == Target::E9patch {
            // SAFETY: no other thread runs yet; the runtime starts below.
            unsafe { backend::use_bundled_e9patch() };
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let preload_path = opts.preload.clone().or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|executable| backend::default_preload_path(&executable))
        });
        let preload = preload_path.as_deref().map(|path| backend::Preload {
            tool: recorder_tool::NAME,
            path,
        });
        // The host's environment, as for a native run.
        let common = reverie_util::CommonToolArguments {
            log_file: None,
            no_host_envs: false,
            envs: Vec::new(),
            trace_syscalls: false,
            program: utf8(opts.program.as_os_str())?,
            program_args: opts
                .args
                .iter()
                .map(|arg| utf8(arg))
                .collect::<anyhow::Result<_>>()?,
        };
        let run = runtime.block_on(backend::run::<Recorder>(
            reverie_backend(opts.backend),
            &common,
            (),
            preload,
        ));
        match run {
            Ok(run) => {
                // The program's output, where the backend captured it, goes
                // where it would have gone.
                if let Some((stdout, stderr)) = &run.captured {
                    use std::io::Write as _;
                    std::io::stdout().write_all(stdout)?;
                    std::io::stderr().write_all(stderr)?;
                }
                let events = run.global_state.events.into_inner().unwrap();
                report(run.exit_code, reverie_events(events))
            }
            Err(error) => anyhow::bail!("{error}"),
        }
    };
    std::fs::write(&opts.output, report.text())?;
    Ok(())
}
