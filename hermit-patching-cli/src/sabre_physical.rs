/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Maintained SaBRe physical work; common capture and verdict stay in core.
//! Source transfer: H bc5c6a9131ed233eae1f07f5159a3b5e2a40933e.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::anyhow;
use detcore::Config as DetConfig;
use hermit::{Error, ExitStatus};
use reverie::GlobalTool as _;
use reverie::process::{Command, Output};
use serde::{Deserialize, Serialize};

use crate::sabre_artifacts::SabreArtifacts;
use crate::{sabre_bootstrap, sabre_ptrace};

const SABRE_PATH_EVIDENCE_ENV: &str = "HERMIT_SABRE_PATH_EVIDENCE";
const SABRE_STAGING_DIRECTORY: &str = "/dev/shm";
const SABRE_RPC_DISCONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const SABRE_RPC_SOCKET_ENV: &str = "REVERIE_SABRE_HERMIT_RPC_SOCKET";
const SABRE_DETLOG_FORWARD_ENV: &str = "REVERIE_SABRE_HERMIT_FORWARD_DETLOG";
const SABRE_TOOL_OUTPUT_ENV: &str = "REVERIE_SABRE_TOOL_OUTPUT_FD";
const ENGINE_COORDINATOR: &str = "HERMIT_ENGINE_COORDINATOR";
const ENGINE_FINGERPRINT: &str = "HERMIT_ENGINE_CONFIG_FINGERPRINT";
const ENGINE_FORWARD: &str = "HERMIT_ENGINE_FORWARD_DETLOG";
const ENGINE_FORWARD_POLICY: &str = "HERMIT_ENGINE_FORWARD_DETLOG_POLICY";

#[derive(Serialize, Deserialize)]
pub struct Completion {
    pub output: Output,
    pub path_evidence: sabre_ptrace::PathEvidence,
}

/// The forwarding duplicate belongs only to this physical operation. Even an
/// error returns through this scope after the supervisor/RPC cleanup path;
/// no duplicate is retained in a returned capture guard or pending fact.
pub async fn run(
    command: Command,
    mut config: DetConfig,
    print_summary: bool,
    summary_json: &Option<PathBuf>,
    capture_output: bool,
    artifacts: &SabreArtifacts,
) -> Result<Completion, Error> {
    hermit::cpu_profile_admission::refuse_unadmitted_launch(&config, false)?;
    hermit::preemption_admission::refuse_unqualified_annotated_launch(&config)?;
    artifacts.recheck()?;
    config.launch_image = hermit::launched_image(&command);
    // This is the maintained SaBRe decision, not the InGuestTrap promise.
    // In particular, no prototype no-sequentialize/no-deterministic-io flags
    // replace the real admitted Detcore policy here.
    config.in_guest_site_patching_off = false;
    let policy = hermit::in_guest_detlog_forward_policy();
    let detlog_descriptor = if policy.forwards_any() {
        hermit::inheritable_in_guest_detlog_socket()?
    } else {
        None
    };
    let result = run_with_sender(
        command,
        config,
        print_summary,
        summary_json,
        capture_output,
        artifacts,
        &policy,
        detlog_descriptor.as_ref(),
    )
    .await;
    let identity = artifacts.recheck();
    // All guest/kernel waits, RPC stop/disconnect, and GlobalState finalization
    // precede this close. Core can now clear its sender and drain synchronously.
    drop(detlog_descriptor);
    match (result, identity) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(identity)) => {
            Err(error.context(format!("cohort recheck also failed: {identity:#}")))
        }
    }
}

struct StagedSabreProgram {
    path: PathBuf,
}

impl Drop for StagedSabreProgram {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn sabre_program_needs_neutral_name(program: &Path) -> bool {
    program
        .file_name()
        .is_some_and(|name| name.as_bytes().starts_with(b"ld"))
}

// TODO-HUMAN-REVIEW(PR-845): Review the neutral-name workaround for SaBRe's
// dynamic-loader prefix collision.
fn stage_sabre_program_in(
    program: &Path,
    staging_directory: &Path,
) -> Result<Option<StagedSabreProgram>, Error> {
    if !sabre_program_needs_neutral_name(program) {
        return Ok(None);
    }

    let path = staging_directory.join(format!("hermit-sabre-program-{}", std::process::id()));
    let mut source = fs::File::open(program).map_err(|error| {
        anyhow!(
            "failed to open SaBRe guest executable {} for neutral-name staging: {error}",
            program.display()
        )
    })?;
    let mut staged = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(&path)
        .map_err(|error| {
            anyhow!(
                "failed to stage SaBRe guest executable {} as {}: {error}",
                program.display(),
                path.display()
            )
        })?;
    if let Err(error) = io::copy(&mut source, &mut staged) {
        let _ = fs::remove_file(&path);
        return Err(anyhow!(
            "failed to stage SaBRe guest executable {} as {}: {error}",
            program.display(),
            path.display()
        ));
    }
    drop(staged);

    Ok(Some(StagedSabreProgram { path }))
}

async fn wait_for_sabre_rpc_disconnects<T>(
    global: &Arc<T>,
    timeout: Duration,
) -> Result<(), usize> {
    let disconnected = tokio::time::timeout(timeout, async {
        while Arc::strong_count(global) > 1 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await;

    if disconnected.is_ok() {
        return Ok(());
    }

    let live_references = Arc::strong_count(global).saturating_sub(1);
    if live_references == 0 {
        Ok(())
    } else {
        Err(live_references)
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-782): Review SaBRe RPC server shutdown errors.
async fn stop_sabre_rpc_server<E>(
    server_task: tokio::task::JoinHandle<Result<(), E>>,
) -> Result<(), Error>
where
    E: std::fmt::Display,
{
    server_task.abort();
    match server_task.await {
        Err(error) if error.is_cancelled() => Ok(()),
        Err(error) => Err(anyhow!("SaBRe coordinator task failed: {error}")),
        Ok(Err(error)) => Err(anyhow!("SaBRe coordinator server failed: {error}")),
        Ok(Ok(())) => Err(anyhow!("SaBRe coordinator server stopped unexpectedly")),
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-789): Review complete SaBRe RPC shutdown ordering.
async fn shutdown_sabre_rpc<T, E>(
    server_task: tokio::task::JoinHandle<Result<(), E>>,
    global: &Arc<T>,
    timeout: Duration,
) -> Result<(), Error>
where
    E: std::fmt::Display,
{
    let server_result = stop_sabre_rpc_server(server_task).await;
    let disconnect_result = wait_for_sabre_rpc_disconnects(global, timeout).await;

    server_result?;
    disconnect_result.map_err(|live_references| {
        anyhow!("SaBRe coordinator stopped with {live_references} live RPC reference(s)")
    })
}

async fn run_with_sender(
    mut command: Command,
    config: DetConfig,
    print_summary: bool,
    print_summary_to_json_file: &Option<PathBuf>,
    capture_output: bool,
    artifacts: &SabreArtifacts,
    detlog_policy: &detcore::detlog::ForwardPolicy,
    detlog_descriptor: Option<&OwnedFd>,
) -> Result<Completion, Error> {
    let path_evidence_file = std::env::var_os(SABRE_PATH_EVIDENCE_ENV).map(PathBuf::from);
    // Whether this run passes the plugin a DETLOG socket (below), in which case
    // every Tool image must forward on it; see
    // detcore::Config::in_guest_detlog_forward_policy.
    let mut config = config;
    config.in_guest_detlog_forward_policy =
        detlog_descriptor.is_some().then(|| detlog_policy.encode());
    // This is the producer-bound loader and C shim, not a second Rust Tool DSO.
    let sabre = artifacts.loader().to_path_buf();
    // The kernel execs SaBRe's loader, which loads the guest itself, so the
    // kernel's `exe` link names the loader (`detcore::LaunchImage::launcher`).
    // Declared even where the first image could not be resolved, so that a
    // link Detcore cannot answer is refused rather than named the loader.
    config
        .launch_image
        .get_or_insert(detcore::LaunchImage {
            exe: None,
            launcher: None,
        })
        .launcher = Some(PathBuf::from(&sabre));
    let plugin = artifacts.shim().to_path_buf();
    let program = command.find_program().map_err(|error| {
        anyhow!(
            "failed to resolve SaBRe guest executable {:?}: {error}",
            command.get_program()
        )
    })?;
    let staged_program = stage_sabre_program_in(&program, Path::new(SABRE_STAGING_DIRECTORY))?;
    let launch_program = staged_program
        .as_ref()
        .map_or(program.as_path(), |staged| staged.path.as_path());

    let bootstrap_launch =
        sabre_bootstrap::Launch::new(Path::new(&sabre), launch_program, &config)?;

    // This runs after Hermit enters the guest mount namespace, where `/tmp`
    // names the container-visible temporary filesystem. Do not inherit a
    // host-side nested TMPDIR: validation commonly sets TMPDIR=/tmp/<run>/tmp,
    // but that parent path is hidden once the private `/tmp` mount is active.
    // The SaBRe plugin and coordinator must name the socket through the same
    // namespace-visible path.
    let socket_dir = tempfile::Builder::new()
        .prefix("hermit-sabre-rpc-")
        .tempdir_in(Path::new("/tmp"))?;
    let socket_path = socket_dir.path().join("coordinator.sock");
    let fallback_ready = Arc::new(AtomicBool::new(false));
    let global = Arc::new(detcore::GlobalState::init_global_state(&config).await);
    let server = reverie_rpc_transport::RpcServer::bind_with_readiness(
        &socket_path,
        global.clone(),
        config.clone(),
        fallback_ready.clone(),
    )
    .map_err(|error| anyhow!("failed to start SaBRe coordinator RPC: {error}"))?;
    let server_task = tokio::spawn(async move { server.serve().await });

    let supervised_result = async {
        // SaBRe runs with the guest's own argv and environment, so the kernel
        // builds the guest's initial stack, /proc/self/cmdline and
        // /proc/self/environ from them, as for an exec of the guest itself. The
        // plugin and image paths and the plugin's settings go in a sealed launch
        // specification instead (reverie_sabre_stats::launch), which SaBRe's loader
        // reads and closes before the guest starts. A script runs as its
        // interpreter, with the argv the kernel would give it.
        let mut first_bytes = vec![0u8; 256];
        let read = std::fs::File::open(launch_program)
            .and_then(|mut file| std::io::Read::read(&mut file, &mut first_bytes))
            .map_err(|error| {
                anyhow!(
                    "failed to read SaBRe guest executable {}: {error}",
                    launch_program.display()
                )
            })?;
        first_bytes.truncate(read);
        let arg0 = command.get_arg0().to_owned();
        let client = match reverie_sabre_stats::launch::shebang(&first_bytes) {
            Some((interpreter, argument)) => {
                command.program(&sabre);
                command.arg0(OsStr::from_bytes(&interpreter));
                let mut words: Vec<&OsStr> = argument
                    .iter()
                    .map(|word| OsStr::from_bytes(word))
                    .collect();
                words.push(launch_program.as_os_str());
                command.prepend_args(words);
                PathBuf::from(OsStr::from_bytes(&interpreter))
            }
            None => {
                command.program(&sabre);
                command.arg0(&arg0);
                launch_program.to_path_buf()
            }
        };
        let mut launch_settings: Vec<Vec<u8>> = Vec::new();
        let mut setting = |name: &str, value: &OsStr| {
            let mut entry = name.as_bytes().to_vec();
            entry.push(b'=');
            entry.extend_from_slice(value.as_bytes());
            launch_settings.push(entry);
        };
        setting(ENGINE_COORDINATOR, socket_path.as_os_str());
        command.env_remove(SABRE_RPC_SOCKET_ENV);
        command.env_remove(sabre_bootstrap::ENVIRONMENT);
        if bootstrap_launch.initializes_random() {
            setting(sabre_bootstrap::ENVIRONMENT, OsStr::new("1"));
        }
        // Publish the configuration and clock RPC fingerprint for this coordinator.
        // The plugin is a separate artifact in the same target directory, so it can
        // be stale without looking it. Its check before connecting names the mismatch
        // instead of failing to decode Config or a later DetTime request field.
        // See detcore::config_wire_fingerprint.
        setting(
            ENGINE_FINGERPRINT,
            OsStr::new(&detcore::config_wire_fingerprint()),
        );
        command.env_remove(detcore::CONFIG_FINGERPRINT_ENV);
        command.env_remove(SABRE_PATH_EVIDENCE_ENV);
        command.env_remove(SABRE_DETLOG_FORWARD_ENV);
        // Per emitting module, as each in-process `detlog!` callsite asks tracing:
        // asking only about `detcore` dropped every record a target-scoped
        // RUST_LOG (warn,detcore::random=info) keeps under ptrace.
        command.env_remove(SABRE_TOOL_OUTPUT_ENV);
        if detlog_policy.forwards_any() {
            setting(ENGINE_FORWARD_POLICY, OsStr::new(&detlog_policy.encode()));
            if let Some(socket) = detlog_descriptor {
                setting(
                    ENGINE_FORWARD,
                    OsStr::new(&detcore::detlog::tool_output_env_value(socket.as_raw_fd())?),
                );
            }
        }
        for key in [
            ENGINE_COORDINATOR,
            ENGINE_FORWARD,
            ENGINE_FORWARD_POLICY,
            ENGINE_FINGERPRINT,
        ] {
            command.env_remove(key);
        }
        command.env_remove("SABRE_BINARY");
        command.env_remove("SABRE_PLUGIN");
        // Always collect: the statistics page is a descriptor the guest can see,
        // so creating it only when a summary or DEBUG log is requested would make
        // those flags change the guest's view. Its number travels in the launch
        // specification, and the descriptor sits above the plugin's fixed RPC
        // socket.
        let stats = reverie_sabre_stats::SabreStats::create(reverie::BackendStatsRequest::ENABLED)
            .map_err(|error| anyhow!("failed to create the SaBRe statistics page: {error}"))?
            .expect("an enabled request creates the statistics page");
        setting(
            reverie_sabre_stats::BACKEND_STATS_ENV,
            OsStr::new(&stats.raw_fd().to_string()),
        );
        command.env_remove(reverie_sabre_stats::BACKEND_STATS_ENV);
        let launch_settings: Vec<&[u8]> = launch_settings.iter().map(Vec::as_slice).collect();
        let launch_spec = reverie_sabre_stats::launch::spec_bytes(
            plugin.as_os_str().as_bytes(),
            client.as_os_str().as_bytes(),
            &launch_settings,
        )
        .ok_or_else(|| anyhow!("the SaBRe launch specification is malformed or too large"))?;
        // Kept open until the guest has started (it inherits its own copy, which
        // SaBRe's loader closes).
        let _launch_spec = reverie_sabre_stats::launch::spec_fd(&launch_spec)
            .map_err(|error| anyhow!("failed to create the SaBRe launch specification: {error}"))?;

        // THE SOCKET PATH IS DELIBERATELY RANDOM AND MUST NOT BE COMPARED.
        //
        // `tempfile` appends a random 6-character suffix to the directory above, so
        // the absolute path differs on every launch by design -- that is what keeps
        // concurrent hermit invocations on a shared host from binding the same
        // coordinator socket. Emitting it at INFO put per-launch randomness into the
        // INFO stream, which `--verify-strict` compares:
        //
        //   Mismatch at log messages 2 (run 1) and 2 (run 2):
        //   < socket=/tmp/hermit-sabre-rpc-Gw6tUi/coordinator.sock
        //   > socket=/tmp/hermit-sabre-rpc-7SZ94p/coordinator.sock
        //
        // That fails EVERY SaBRe verify cell before the guest executes an
        // instruction, for a host-side value with no guest-visible content. The
        // defect was in the oracle, not the backend.
        //
        // WHY THE VALUE IS DROPPED FROM INFO RATHER THAN MADE DETERMINISTIC: the two
        // `--verify` runs execute in SEPARATE CHILD PROCESSES, so any path stable
        // across both would have to be derived from state shared between them. That
        // trades `tempfile`'s guaranteed-fresh directory for a reused one, and a
        // run1 that dies holding the socket would then make run2 fail to bind -- a
        // real new failure mode in exchange for a cosmetic field. The path keeps its
        // randomness; only the compared stream stops carrying it.
        //
        // This is NOT a comparator relaxation. No normalization envelope is widened,
        // so any future randomness leaking into this banner still fails the
        // comparison. The full path remains available one level down.
        tracing::debug!(
            target: "hermit::sabre",
            socket = %socket_path.display(),
            "SaBRe coordinator RPC socket (per-launch temp path, deliberately not at INFO)",
        );
        tracing::info!(
            target: "hermit::sabre",
            guest = %program.display(),
            plugin = %plugin.display(),
            "launching Detcore guest through SaBRe with coordinator RPC",
        );

        sabre_ptrace::run(
            command.into_std_lossy(),
            artifacts,
            fallback_ready,
            global.clone(),
            bootstrap_launch,
            stats.clone(),
            capture_output,
        )
        .await
    }
    .await;
    let supervised = match supervised_result {
        Ok(supervised) => supervised,
        Err(error) => {
            global.release_all_physical_process_exits();
            global.force_shutdown_with_error();
            let _ = shutdown_sabre_rpc(server_task, &global, SABRE_RPC_DISCONNECT_TIMEOUT).await;
            return Err(error);
        }
    };
    // The supervisor returns only after every tracee reached a final kernel wait status. Release
    // the root process's barrier (and any intentionally unreaped child barriers) before scheduler
    // shutdown; no guest thread remains that could race timer fast-forward here.
    global.release_all_physical_process_exits();
    // A SaBRe execution in which no guest thread ever reached the coordinator
    // is an execution in which Detcore was never loaded as a Reverie tool: the
    // guest ran on bare Linux. Treat it exactly like a failed run so the
    // scheduler is torn down here instead of blocking forever in `clean_up`
    // below, waiting for a guest thread that will never register.
    let detcore_never_engaged = !supervised.path_evidence.guest_rpc_observed;
    let requires_forced_shutdown = !supervised.status.success() || detcore_never_engaged;
    if requires_forced_shutdown {
        global.force_shutdown_with_error();
    }
    // Emit one unconditional, machine-readable per-run fact instead of a
    // free-form warning. SaBRe loads the guest interpreter before the Detcore
    // plugin, so pre-plugin loader syscalls are structurally absent from its
    // observation envelope. Versioning that fact lets scorecard consumers
    // reject old or incomplete records rather than infer coverage from silence.
    //
    // Keep this in the controller-diagnostic stream rather than writing
    // directly to the process stderr that also carries captured guest stderr.
    // WARN is Hermit's default tracing level, and `--log-file` can therefore
    // separate the unconditional controller fact from guest output without a
    // comparator exception. A missing record remains distinct from a record
    // whose counters are zero.
    let backend_evidence = sabre_backend_evidence_line(&supervised.path_evidence);
    tracing::warn!(target: "hermit::sabre", "{backend_evidence}");
    let path_evidence_result = (|| -> Result<(), Error> {
        if let Some(path) = path_evidence_file {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&path)
                .map_err(|error| {
                    anyhow!(
                        "failed to open SaBRe path evidence {}: {error}",
                        path.display()
                    )
                })?;
            serde_json::to_writer(&mut file, &supervised.path_evidence)?;
            writeln!(file)?;
        }
        Ok(())
    })();
    let output = Output {
        status: supervised.status.into(),
        stdout: supervised.stdout,
        stderr: supervised.stderr,
    };

    shutdown_sabre_rpc(server_task, &global, SABRE_RPC_DISCONNECT_TIMEOUT).await?;
    let mut global = Arc::try_unwrap(global).map_err(|global| {
        anyhow!(
            "SaBRe coordinator stopped with {} live RPC reference(s)",
            Arc::strong_count(&global) - 1
        )
    })?;
    if requires_forced_shutdown {
        global.cancel_internal_scheduler().await;
    }
    let dispatch_stats = hermit::backend_stats::report_with_names(
        "sabre",
        "sabre",
        hermit::backend_stats::request(print_summary_to_json_file),
        &stats,
    );
    // SaBRe's plugin starts after the guest's dynamic loader, whose syscalls
    // the histogram therefore misses.
    global.note_syscall_observation_gap(detcore::SyscallObservationGap::InProcessRuntimeStart);
    let finalized = global
        .clean_up_with_dispatch_stats(print_summary, print_summary_to_json_file, dispatch_stats)
        .await;
    tracing::info!(
        target: "hermit::sabre::fallback",
        ptrace_fallback_sites = supervised.path_evidence.ptrace_fallback_sites,
        trusted_shared_object_sites = supervised.path_evidence.trusted_shared_object_sites,
        guest_rpc_observed = supervised.path_evidence.guest_rpc_observed,
        "SaBRe ptrace fallback completed",
    );
    if detcore_never_engaged {
        return detcore::combine_finalization(
            Err(Error::new(hermit::BackendRunFailure)
                .context(sabre_uninstrumented_guest_message(&output.status))),
            finalized,
        );
    }
    let output = detcore::combine_finalization(Ok(output), finalized)?;
    path_evidence_result?;
    Ok(Completion {
        output,
        path_evidence: supervised.path_evidence,
    })
}

fn sabre_reach_state(guest_rpc_observed: bool, ptrace_fallback_sites: usize) -> &'static str {
    match (guest_rpc_observed, ptrace_fallback_sites) {
        (false, _) => "no-detcore-reached",
        (true, 1..) => "degraded-ptrace-fallback",
        (true, 0) => "sabre-exercised",
    }
}

/// Produce the versioned SaBRe backend fact consumed by compatibility reports.
///
/// `preplugin_coverage=absent` is a property of SaBRe's launch order: the guest
/// interpreter runs before the Detcore plugin is loaded. It is recorded rather
/// than inferred from counters because the ptrace fallback cannot observe that
/// interval either.
///
/// Preserve the originating https://github.com/rrnewton/hermit/issues/1725 measurement as provenance for that field:
/// on its measurement host, `/bin/true` produced 3 COMMITs under SaBRe versus
/// 14 under ptrace; the 11 absent records were the loader's libc.so.6 path
/// resolution. The launch-order fact, not that host-specific count, is the
/// runtime contract.
fn sabre_backend_evidence_line(evidence: &sabre_ptrace::PathEvidence) -> String {
    format!(
        ":: Backend: sabre static rewriting + ptrace runtime; run_mode=run; \
         evidence_schema={}; preplugin_coverage=absent; ptrace_fallback_sites={}; \
         trusted_shared_object_sites={}; guest_rpc_observed={}; reach_state={}",
        evidence.schema,
        evidence.ptrace_fallback_sites,
        evidence.trusted_shared_object_sites,
        evidence.guest_rpc_observed,
        sabre_reach_state(evidence.guest_rpc_observed, evidence.ptrace_fallback_sites),
    )
}

/// Explain a SaBRe run whose guest never reached the Detcore coordinator.
///
/// `guest_rpc_observed` is set by the coordinator RPC listener the first time a
/// SaBRe-loaded guest connects. When it stays false the guest completed without
/// Detcore intercepting anything, so the run carries no determinism guarantee
/// whatsoever -- its timing, scheduling, PIDs, and clock reads all came from the
/// host. Reporting that as a successful `hermit run` would be a fail-open
/// determinism hole, so the caller turns it into a hard error and this function
/// supplies the diagnosis.
///
/// The dominant cause is a guest whose syscall sites SaBRe never rewrote. A
/// statically linked ELF is the sharp edge: it has no dynamic loader and no
/// shared library through which SaBRe could regain control, so an unrewritten
/// static client runs entirely on bare Linux with no second chance.
fn sabre_uninstrumented_guest_message(status: &ExitStatus) -> String {
    format!(
        "the SaBRe backend finished ({status:?}) without the guest ever reaching the Detcore \
         coordinator: no syscall was intercepted, so this run applied no determinization at all \
         and its result is not a Hermit guarantee. This means SaBRe rewrote no syscall site in \
         the guest -- most often a statically linked ELF, whose syscall sites SaBRe must patch \
         in the client image itself because there is no dynamic loader to intercept."
    )
}

#[cfg(test)]
mod tests;
