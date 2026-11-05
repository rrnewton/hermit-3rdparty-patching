/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Exact maintained SaBRe helper controls transferred from H bc5c6a91.
//! No runtime or loader qualification is implied by source ownership.

use super::*;

#[test]
fn uninstrumented_sabre_guest_is_reported_as_no_determinization() {
    let message = sabre_uninstrumented_guest_message(&ExitStatus::Exited(0));
    assert!(
        message.contains("no determinization at all"),
        "must not present an uninstrumented run as a weaker guarantee: {message}"
    );
    assert!(
        message.contains("Detcore coordinator"),
        "must name the authority that was never reached: {message}"
    );
    assert!(
        message.contains("statically linked ELF"),
        "must name the dominant cause so the reader can act: {message}"
    );
    // The exit status is carried because a successful-looking status is
    // exactly what makes this failure mode dangerous.
    assert!(
        message.contains("Exited(0)"),
        "must carry the observed status: {message}"
    );
    assert!(
        sabre_uninstrumented_guest_message(&ExitStatus::Exited(139)).contains("Exited(139)"),
        "must carry a failing status too"
    );
}

#[test]
fn sabre_reach_states_are_pairwise_distinct() {
    let no_detcore = sabre_reach_state(false, 0);
    let degraded = sabre_reach_state(true, 1);
    let exercised = sabre_reach_state(true, 0);

    assert_eq!(no_detcore, "no-detcore-reached");
    assert_eq!(degraded, "degraded-ptrace-fallback");
    assert_eq!(exercised, "sabre-exercised");
    assert_ne!(no_detcore, degraded);
    assert_ne!(no_detcore, exercised);
    assert_ne!(degraded, exercised);
    assert_eq!(
        sabre_reach_state(false, 9),
        "no-detcore-reached",
        "absence of a guest RPC must dominate any fallback count"
    );
}

#[test]
fn sabre_backend_fact_is_versioned_and_names_preplugin_coverage() {
    let exercised = super::sabre_ptrace::PathEvidence {
        schema: 1,
        guest_rpc_observed: true,
        ptrace_fallback_sites: 0,
        trusted_shared_object_sites: 2,
        trusted_shared_objects: vec!["/usr/lib/libc.so.6".to_owned()],
    };
    assert_eq!(
        sabre_backend_evidence_line(&exercised),
        ":: Backend: sabre static rewriting + ptrace runtime; run_mode=run; \
             evidence_schema=1; preplugin_coverage=absent; ptrace_fallback_sites=0; \
             trusted_shared_object_sites=2; guest_rpc_observed=true; \
             reach_state=sabre-exercised"
    );

    let unengaged = super::sabre_ptrace::PathEvidence {
        guest_rpc_observed: false,
        ..exercised
    };
    let fact = sabre_backend_evidence_line(&unengaged);
    assert!(fact.contains("preplugin_coverage=absent"));
    assert!(fact.contains("reach_state=no-detcore-reached"));
    assert!(!fact.contains("reach_state=sabre-exercised"));
}

#[test]
fn sabre_rpc_socket_uses_private_exec_environment() {
    assert!(SABRE_RPC_SOCKET_ENV.starts_with("REVERIE_SABRE_"));
}

#[test]
fn sabre_stages_program_names_that_collide_with_loader_prefix() {
    assert!(sabre_program_needs_neutral_name(
        PathBuf::from("/usr/bin/ld").as_path()
    ));
    assert!(sabre_program_needs_neutral_name(
        PathBuf::from("/usr/bin/ld.bfd").as_path()
    ));
    assert!(!sabre_program_needs_neutral_name(
        PathBuf::from("/usr/bin/gold").as_path()
    ));
}

#[test]
fn sabre_neutral_name_staging_preserves_program_bytes_and_cleans_up() {
    let temp = tempfile::tempdir().unwrap();
    let program = temp.path().join("ld.test");
    fs::write(&program, b"linker image").unwrap();

    let staged = stage_sabre_program_in(&program, temp.path())
        .unwrap()
        .expect("ld-prefixed program should be staged");
    let staged_path = staged.path.clone();
    assert_eq!(fs::read(&staged_path).unwrap(), b"linker image");
    assert!(
        staged_path
            .file_name()
            .unwrap()
            .as_encoded_bytes()
            .starts_with(b"hermit-sabre-program-")
    );

    drop(staged);
    assert!(!staged_path.exists());
}

#[tokio::test(start_paused = true)]
async fn sabre_rpc_disconnect_wait_observes_delayed_release() {
    let global = Arc::new(());
    let connection = global.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        drop(connection);
    });

    assert_eq!(
        wait_for_sabre_rpc_disconnects(&global, Duration::from_millis(50)).await,
        Ok(())
    );
}

#[tokio::test(start_paused = true)]
async fn sabre_rpc_disconnect_wait_reports_stuck_connection() {
    let global = Arc::new(());
    let _connection = global.clone();

    assert_eq!(
        wait_for_sabre_rpc_disconnects(&global, Duration::from_millis(10)).await,
        Err(1)
    );
}

#[tokio::test]
async fn sabre_rpc_server_intentional_abort_is_clean() {
    let server_task = tokio::spawn(std::future::pending::<Result<(), &'static str>>());

    assert!(stop_sabre_rpc_server(server_task).await.is_ok());
}

#[tokio::test]
async fn sabre_rpc_server_failure_is_reported() {
    let server_task = tokio::spawn(async { Err::<(), _>("accept failed") });
    while !server_task.is_finished() {
        tokio::task::yield_now().await;
    }

    let error = stop_sabre_rpc_server(server_task).await.unwrap_err();
    assert!(error.to_string().contains("accept failed"));
}

#[tokio::test(start_paused = true)]
async fn sabre_rpc_shutdown_drains_connections_after_server_failure() {
    let global = Arc::new(());
    let connection = global.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        drop(connection);
    });
    let server_task = tokio::spawn(async { Err::<(), _>("accept failed") });
    while !server_task.is_finished() {
        tokio::task::yield_now().await;
    }

    let error = shutdown_sabre_rpc(server_task, &global, Duration::from_millis(50))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("accept failed"));
    assert_eq!(Arc::strong_count(&global), 1);
}
