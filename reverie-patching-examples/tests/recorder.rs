/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The unchanged SaBRe recorder controls now target its extension frontend.

use std::path::Path;
use std::process::Command;

/// Every run gets the sanitizer settings reverie-ptrace adds to its guest's
/// environment (tracer.rs), so that ptrace's guest has the native one: the
/// number of variables decides when `sh -c` grows its heap.
fn record(backend: &str, program: &[&str], output: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_patching-recorder"))
        .env("ASAN_OPTIONS", "detect_leaks=0")
        .env("LSAN_OPTIONS", "detect_leaks=0")
        .args(["--backend", backend, "--output"])
        .arg(output)
        .args(program)
        .output()
        .expect("run the recorder")
}

#[test]
fn sabre_without_its_loader_refuses_by_name() {
    let directory = tempfile::tempdir().unwrap();
    let output_path = directory.path().join("record");
    let output = Command::new(env!("CARGO_BIN_EXE_patching-recorder"))
        .env("SABRE_BINARY", directory.path().join("no-such-loader"))
        .args(["--backend", "sabre", "--output"])
        .arg(&output_path)
        .arg("/bin/true")
        .output()
        .expect("run the recorder");
    assert!(!output.status.success(), "sabre ran");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("REFUSED: the SaBRe loader was not found"),
        "sabre: {stderr}"
    );
    assert!(!output_path.exists(), "sabre wrote a record");
}

/// SaBRe hosts the recorder in experimental/reverie-sabre-strace's plugin, its
/// GlobalState served from the recorder: the tool sees the program's calls
/// from when SaBRe's loader has loaded it, and the exit code. (Which calls,
/// and their results, are the cross-backend check's ledger rows,
/// reverie-examples/e2e/.) It needs reverie-sabre-strace built beside the
/// recorder (`cargo build -p reverie-sabre-strace`), for the plugin and for
/// the loader it names (`--print-sabre`).
#[test]
#[ignore = "requires `cargo build -p reverie-sabre-strace`; run with --ignored"]
fn sabre_hosts_the_recorder_in_its_example_tool_plugin() {
    let binaries = Path::new(env!("CARGO_BIN_EXE_patching-recorder"))
        .parent()
        .unwrap();
    let loader = Command::new(binaries.join("reverie-sabre-strace"))
        .arg("--print-sabre")
        .output()
        .expect("run reverie-sabre-strace --print-sabre");
    assert!(loader.status.success(), "{loader:?}");
    let loader = String::from_utf8(loader.stdout).unwrap();
    let directory = tempfile::tempdir().unwrap();
    for program in [&["/bin/true"][..], &["/bin/false"]] {
        let native = directory.path().join("native");
        let output = record("native", program, &native);
        assert!(output.status.success(), "native {program:?}");
        let native = std::fs::read_to_string(&native).unwrap();
        let path = directory.path().join("sabre");
        let output = Command::new(env!("CARGO_BIN_EXE_patching-recorder"))
            .env("SABRE_BINARY", loader.trim_end())
            .args(["--backend", "sabre", "--output"])
            .arg(&path)
            .args(program)
            .output()
            .expect("run the recorder");
        assert!(
            output.status.success(),
            "sabre {program:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let got = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            got.lines().next(),
            native.lines().next(),
            "sabre {program:?}"
        );
        assert!(
            got.ends_with("\nexit_group=?\n") && got.lines().count() > 3,
            "sabre {program:?}:\n{got}"
        );
    }
}
