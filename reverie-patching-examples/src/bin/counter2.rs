/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Thin SaBRe/e9patch launcher for the single core-owned counter2 Tool.

use clap::Parser;
use reverie_examples::tools::counter2::CounterLocal;
use reverie_patching_examples::backend;
use reverie_util::CommonToolArguments;

/// Run PROGRAM under the existing counter2 Tool on a patching backend.
#[derive(Debug, Parser)]
struct Args {
    #[clap(long, value_enum)]
    backend: backend::BackendKind,
    /// The actual example preload that contains the same core Tool.
    #[clap(long)]
    preload: std::path::PathBuf,
    #[clap(flatten)]
    common: CommonToolArguments,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let log_guard = args.common.init_tracing();
    // SaBRe's historical "counter2" is its distinct process-local adaptation.
    // The exact selector embeds the same CounterLocal type as this coordinator.
    let tool = match args.backend {
        backend::BackendKind::Sabre => "counter2-exact",
        backend::BackendKind::E9patch => "counter2",
    };
    let run = backend::run_blocking::<CounterLocal>(
        args.backend,
        &args.common,
        (),
        tool,
        Some(args.preload),
    )?;
    let (total, processes, threads) = run.global_state.totals();
    eprintln!(
        " [counter tool] Total system calls in process tree: {}, from {} processes, {} thread(s).",
        total, processes, threads
    );
    drop(log_guard);
    run.status.raise_or_exit()
}
