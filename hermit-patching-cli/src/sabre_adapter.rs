/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! SaBRe supplies physical work to the single core CLI and capture owner.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hermit::Error;
use hermit::app::backend_hook::{
    BackendAdapter, CapturedOutput, ContainerScope, CoordinatorTracing, EvidenceRequirement,
    Execute, Execution, Mode, Observation, PairEvidence, Prepare, VerificationLogTransport,
};
use reverie::process::Command;

use crate::sabre_artifacts::SabreArtifacts;
use crate::{sabre_physical, sabre_ptrace};

pub struct SabreAdapter;

pub struct Session {
    mode: Mode,
    saved_executed: bool,
    artifacts: Arc<SabreArtifacts>,
    ordinary: Option<Ordinary>,
}

struct Ordinary {
    command: Option<Command>,
    container: ContainerScope,
    tracing: CoordinatorTracing,
    print_summary: bool,
    summary_json: Option<PathBuf>,
    // Retain any captured startup descriptor; the ordinary command keeps its
    // maintained stdin policy. Verification uses core's rewindable snapshot.
    _stdin: Option<File>,
}

impl BackendAdapter for SabreAdapter {
    const NAME: &'static str = "sabre";
    const SUPPORTS_STRACE: bool = true;
    const EVIDENCE: EvidenceRequirement = EvidenceRequirement::Common;
    const CAPABILITIES: reverie::BackendCapabilities = reverie::BackendCapabilities::SABRE;
    const LOG_TRANSPORT: VerificationLogTransport = VerificationLogTransport::InGuestSocket;

    type Options = ();
    type Session = Session;
    type Pending = sabre_ptrace::PathEvidence;
    type Facts = sabre_ptrace::PathEvidence;

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

    fn strace(&self, program: &Path, args: &[String]) -> Result<hermit::ExitStatus, Error> {
        crate::sabre_strace::run_sabre_strace(program, args)
    }

    fn prepare(&self, (): (), mut request: Prepare<'_>) -> Result<Session, Error> {
        anyhow::ensure!(
            request.engagement_path().is_none(),
            "--backend-engagement-json is not available for SaBRe; use HERMIT_SABRE_PATH_EVIDENCE"
        );
        let container = request.container();
        hermit::validate_tracing_environment(if container.uses_namespace() {
            hermit::NamespaceUse::Creates
        } else {
            hermit::NamespaceUse::None
        })?;
        let artifacts = Arc::new(SabreArtifacts::from_required_producer_input()?);
        let ordinary = if matches!(
            request.mode(),
            Mode::VerificationPair | Mode::SavedVerification
        ) {
            // Both verification modes retain the actual admitted stdin.
            // The core snapshot supplies the one saved run or both live runs.
            hermit::reserve_output_stdin_snapshot(request.take_stdin())?;
            None
        } else {
            Some(Ordinary {
                command: Some(request.command()?),
                container,
                tracing: request.coordinator_tracing(),
                print_summary: request.summary_requested(),
                summary_json: request.summary_json().map(PathBuf::from),
                _stdin: request.take_stdin(),
            })
        };
        Ok(Session {
            mode: request.mode(),
            saved_executed: false,
            artifacts,
            ordinary,
        })
    }

    fn execute(
        &self,
        session: &mut Session,
        request: Execute<'_>,
    ) -> Result<Execution<Self::Pending>, Error> {
        anyhow::ensure!(
            session.mode == request.mode(),
            "SaBRe operation mode changed"
        );
        if matches!(
            session.mode,
            Mode::VerificationPair | Mode::SavedVerification
        ) {
            if session.mode == Mode::SavedVerification {
                anyhow::ensure!(
                    !session.saved_executed,
                    "SaBRe's single saved operation was already consumed"
                );
                session.saved_executed = true;
            }
            let capture = request.into_verification()?;
            let artifacts = session.artifacts.clone();
            let (physical, _artifacts) = capture.run_in_container(
                artifacts,
                "the SaBRe coordinator and exact common-engine cohort",
                |artifacts, mut inputs| {
                    inputs.command.stdin(hermit::output_backend_stdin()?);
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    let completed = runtime.block_on(Box::pin(sabre_physical::run(
                        inputs.command,
                        inputs.config,
                        inputs.print_summary,
                        &inputs.summary_json,
                        true,
                        artifacts,
                    )))?;
                    // run() already closed its local inherited sender after
                    // real supervisor/RPC/GlobalState teardown. These returned
                    // facts and guards contain no DETLOG sender.
                    Ok(CapturedOutput {
                        output: completed.output,
                        skid_overshoots: 0,
                        pending: completed.path_evidence,
                    })
                },
            )?;
            return Ok(Execution::Verification(physical));
        }

        let ordinary = session
            .ordinary
            .take()
            .ok_or_else(|| Error::msg("SaBRe's single ordinary operation was already consumed"))?;
        let container = ordinary.container.clone();
        let tracing = ordinary.tracing.clone();
        let artifacts = session.artifacts.clone();
        let (completed, _guards) = container.run_with_tracing(
            (ordinary, artifacts),
            "the SaBRe coordinator and exact common-engine cohort",
            tracing,
            |(ordinary, artifacts), config| {
                let command = ordinary
                    .command
                    .take()
                    .ok_or_else(|| Error::msg("SaBRe's admitted command was already consumed"))?;
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                runtime.block_on(Box::pin(sabre_physical::run(
                    command,
                    config,
                    ordinary.print_summary,
                    &ordinary.summary_json,
                    false,
                    artifacts,
                )))
            },
        )?;
        Ok(Execution::Finished(completed.output.status))
    }

    fn finish(&self, pending: Self::Pending, _: Observation<'_>) -> Result<Self::Facts, Error> {
        // The physical owner already refuses a run that never reached its
        // real Detcore RPC endpoint. Preserve every path-evidence field.
        Ok(pending)
    }

    fn pair_evidence(&self, _: &Self::Facts, _: &Self::Facts) -> Result<PairEvidence, Error> {
        Ok(PairEvidence::Common)
    }
}
