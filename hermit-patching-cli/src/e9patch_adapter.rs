/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! e9patch remains preprocessing followed by the real core ptrace runtime.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Context;
use detcore_model::backend_engagement::{BackendEngagement, BackendEngagementReport};
use detcore_model::summary::RunSummary;
use hermit::Error;
use hermit::app::backend_hook::{
    BackendAdapter, CapturedOutput, ContainerScope, CoordinatorTracing, EvidenceRequirement,
    ExecutableOverlay, Execute, Execution, Mode, Observation, PairEvidence, Prepare,
    VerificationLogTransport,
};
use reverie::SiteCounters;
use reverie::process::Command;

use crate::e9patch;

pub struct E9patchAdapter;

pub struct Session {
    mode: Mode,
    saved_executed: bool,
    overlay: ExecutableOverlay,
    source: Option<PathBuf>,
    sites: SiteCounters,
    engagement: BackendEngagement,
    ordinary: Option<Ordinary>,
}

struct Ordinary {
    command: Option<Command>,
    container: ContainerScope,
    tracing: CoordinatorTracing,
    print_summary: bool,
    summary_json: Option<PathBuf>,
    engagement_path: Option<PathBuf>,
    _stdin: Option<File>,
}

impl BackendAdapter for E9patchAdapter {
    const NAME: &'static str = "e9patch";
    const PREPARES_RECORD: bool = true;
    const EVIDENCE: EvidenceRequirement = EvidenceRequirement::Common;
    const CAPABILITIES: reverie::BackendCapabilities = reverie::BackendCapabilities::PTRACE;
    const LOG_TRANSPORT: VerificationLogTransport = VerificationLogTransport::CoordinatorTracing;

    type Options = ();
    type Session = Session;
    type Pending = ();
    type Facts = ();

    // Transferred from the maintained record preparation body. Core supplies
    // the canonical target and retains ptrace admission and readonly mounts.
    fn prepare_record_program(&self, target: &Path) -> Result<Option<PathBuf>, Error> {
        if !is_elf_file(target)? {
            eprintln!(
                ":: Backend: e9patch preprocessing + ptrace record runtime; mapped_sites=0; \
                 main_executable=non-ELF; preprocessing=not-applicable"
            );
            return Ok(None);
        }
        if let Some(reason) = e9patch::unavailable_reason() {
            anyhow::bail!("backend `e9patch` is unavailable: {reason}");
        }

        let prepared = e9patch::prepare(target)?;
        let rewrite_cache = if prepared.patched_sites == 0 {
            "not-applicable"
        } else if prepared.rewrite_cache_hit {
            "hit"
        } else {
            "miss"
        };
        eprintln!(
            ":: Backend: e9patch preprocessing + ptrace record runtime; candidate_sites={}; \
             mapped_sites={}; b0_sites={}; instruction_map_cache={:?}; rewrite_cache={}; \
             artifact_sha256={}",
            prepared.candidate_sites,
            prepared.patched_sites,
            prepared.b0_sites,
            prepared.instruction_map_cache_status,
            rewrite_cache,
            prepared.artifact_sha256.as_deref().unwrap_or("none"),
        );

        Ok((prepared.patched_sites != 0).then_some(prepared.binary))
    }

    fn validate_mode(&self, mode: Mode) -> Result<(), Error> {
        // Saved uses the same real capture as a live pair; the core
        // retains the saved writer, evidence policy and comparison.
        match mode {
            Mode::Ordinary | Mode::VerificationPair | Mode::SavedVerification => Ok(()),
        }
    }

    fn parse(&self, _: &clap::ArgMatches) -> Result<(), clap::Error> {
        Ok(())
    }

    fn prepare(&self, (): (), mut request: Prepare<'_>) -> Result<Session, Error> {
        anyhow::ensure!(
            request.container().uses_namespace(),
            "e9patch requires mount namespaces to overlay the rewritten ELF at its original guest path"
        );
        hermit::validate_tracing_environment(hermit::NamespaceUse::Creates)?;
        // Resolution is common-owned and uses the real admitted command,
        // guest PATH/cwd, private /tmp and custom mounts/symlinks.
        let overlay = request.executable_overlay_plan()?;
        let (source, sites, engagement) = prepare_program(overlay.host_program())?;
        let ordinary = if matches!(
            request.mode(),
            Mode::VerificationPair | Mode::SavedVerification
        ) {
            hermit::reserve_output_stdin_snapshot(request.take_stdin())?;
            None
        } else {
            // Common code revalidates the exact semantic triple and all
            // original readonly/source-visibility policy when applying it.
            let (command, container) =
                request.command_with_executable_overlay(&overlay, source.as_deref())?;
            Some(Ordinary {
                command: Some(command),
                container,
                tracing: request.coordinator_tracing(),
                print_summary: request.summary_requested(),
                summary_json: request.summary_json().map(PathBuf::from),
                engagement_path: request.engagement_path().map(PathBuf::from),
                _stdin: request.take_stdin(),
            })
        };
        Ok(Session {
            mode: request.mode(),
            saved_executed: false,
            overlay,
            source,
            sites,
            engagement,
            ordinary,
        })
    }

    fn execute(&self, session: &mut Session, request: Execute<'_>) -> Result<Execution<()>, Error> {
        anyhow::ensure!(
            session.mode == request.mode(),
            "e9patch operation mode changed"
        );
        let sites = session.sites;
        if matches!(
            session.mode,
            Mode::VerificationPair | Mode::SavedVerification
        ) {
            if session.mode == Mode::SavedVerification {
                anyhow::ensure!(
                    !session.saved_executed,
                    "e9patch's single saved operation was already consumed"
                );
                session.saved_executed = true;
            }
            let capture = request.into_verification()?;
            let (physical, ()) = capture.run_in_container_with_executable_overlay(
                &session.overlay,
                session.source.as_deref(),
                (),
                "e9patch's preprocessed executable and ptrace coordinator",
                move |(), inputs| {
                    let (output, skid_overshoots) =
                        hermit::run_with_output_backend_timeout_and_skid_overshoots(
                            inputs.command,
                            inputs.config,
                            inputs.print_summary,
                            &inputs.summary_json,
                            hermit::Backend::Ptrace,
                            None,
                        )?;
                    relabel_dispatch_stats(&inputs.summary_json, sites)?;
                    Ok(CapturedOutput {
                        output,
                        skid_overshoots,
                        pending: (),
                    })
                },
            )?;
            return Ok(Execution::Verification(physical));
        }

        let ordinary = session.ordinary.take().ok_or_else(|| {
            Error::msg("e9patch's single ordinary operation was already consumed")
        })?;
        let container = ordinary.container.clone();
        let tracing = ordinary.tracing.clone();
        let (status, guards) = container.run_with_tracing(
            ordinary,
            "e9patch's preprocessed executable and ptrace coordinator",
            tracing,
            move |ordinary, config| {
                let command = ordinary
                    .command
                    .take()
                    .ok_or_else(|| Error::msg("e9patch's admitted command was already consumed"))?;
                let status = hermit::run_with_backend_timeout(
                    command,
                    config,
                    ordinary.print_summary,
                    &ordinary.summary_json,
                    hermit::Backend::Ptrace,
                    None,
                )?;
                relabel_dispatch_stats(&ordinary.summary_json, sites)?;
                Ok(status)
            },
        )?;
        // As in the maintained ordinary path, publish preparation facts only
        // after the physical run returns. This record is not a verify verdict.
        if let Some(path) = guards.engagement_path.as_deref() {
            write_engagement(path, session.engagement.clone())?;
        }
        Ok(Execution::Finished(status))
    }

    fn finish(&self, (): (), _: Observation<'_>) -> Result<(), Error> {
        Ok(())
    }

    fn pair_evidence(&self, _: &(), _: &()) -> Result<PairEvidence, Error> {
        Ok(PairEvidence::Common)
    }
}

fn prepare_program(
    host: &Path,
) -> Result<(Option<PathBuf>, SiteCounters, BackendEngagement), Error> {
    if !is_elf_file(host)? {
        hermit::app::backend_hook::controller_diagnostic(format_args!(
            ":: Backend: e9patch preprocessing + ptrace runtime; mapped_sites=0; \
             main_executable=non-ELF; preprocessing=not-applicable"
        ));
        return Ok((
            None,
            SiteCounters::default(),
            BackendEngagement::E9patch {
                candidate_sites: 0,
                mapped_sites: 0,
                b0_sites: 0,
            },
        ));
    }
    if let Some(reason) = e9patch::unavailable_reason() {
        anyhow::bail!("backend `e9patch` is unavailable: {reason}");
    }
    let prepared = e9patch::prepare(host)?;
    let engagement = BackendEngagement::E9patch {
        candidate_sites: u64::try_from(prepared.candidate_sites)
            .map_err(|_| Error::msg("e9patch candidate-site count does not fit u64"))?,
        mapped_sites: u64::try_from(prepared.patched_sites)
            .map_err(|_| Error::msg("e9patch mapped-site count does not fit u64"))?,
        b0_sites: u64::try_from(prepared.b0_sites)
            .map_err(|_| Error::msg("e9patch B0-site count does not fit u64"))?,
    };
    let sites = SiteCounters::from_rewrite(
        prepared.candidate_sites as u64,
        prepared.patched_sites as u64,
    );
    let rewrite_cache = if prepared.patched_sites == 0 {
        "not-applicable"
    } else if prepared.rewrite_cache_hit {
        "hit"
    } else {
        "miss"
    };
    hermit::app::backend_hook::controller_diagnostic(format_args!(
        ":: Backend: e9patch preprocessing + ptrace runtime; candidate_sites={}; \
         mapped_sites={}; b0_sites={}; instruction_map_cache={:?}; rewrite_cache={}; \
         artifact_sha256={}; preprocess_us={}",
        prepared.candidate_sites,
        prepared.patched_sites,
        prepared.b0_sites,
        prepared.instruction_map_cache_status,
        rewrite_cache,
        prepared.artifact_sha256.as_deref().unwrap_or("none"),
        prepared.preprocess_micros,
    ));
    let source = (prepared.patched_sites != 0).then_some(prepared.binary);
    Ok((source, sites, engagement))
}

fn is_elf_file(path: &Path) -> Result<bool, Error> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open executable {}", path.display()))?;
    let mut magic = [0_u8; 4];
    match file.read_exact(&mut magic) {
        Ok(()) => Ok(magic == *b"\x7fELF"),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect executable format for {}", path.display())),
    }
}

/// Attribute only the backend spelling and measured rewrite sites. Actual
/// ptrace stops and every other summary field stay the runtime's own values.
fn relabel_dispatch_stats(
    summary_json: &Option<PathBuf>,
    sites: SiteCounters,
) -> Result<(), Error> {
    let Some(path) = summary_json else {
        return Ok(());
    };
    let mut summary: RunSummary = serde_json::from_slice(
        &fs::read(path)
            .with_context(|| format!("reading the e9patch run summary {}", path.display()))?,
    )
    .with_context(|| format!("parsing the e9patch run summary {}", path.display()))?;
    let Some(record) = summary.dispatch_stats.as_mut() else {
        return Ok(());
    };
    record.backend = "e9patch".to_owned();
    record.sites = sites;
    fs::write(path, serde_json::to_string_pretty(&summary)? + "\n")
        .with_context(|| format!("writing the e9patch run summary {}", path.display()))
}

fn write_engagement(path: &Path, engagement: BackendEngagement) -> Result<(), Error> {
    let report = BackendEngagementReport::new(engagement);
    report.validate().map_err(Error::msg)?;
    let mut bytes = serde_json::to_vec(&report)?;
    bytes.push(b'\n');
    fs::write(path, bytes)
        .with_context(|| format!("writing backend engagement record {}", path.display()))
}
