#!/usr/bin/env python3
"""Build the C-only shim and install its exact schema2 engine/headers/loader cohort.

Invoke only inside the allocated normal build wrapper. Cargo's loader build
and metadata are explicit inputs, never PATH/basename availability discovery.
This producer does not execute the loader or qualify runtime behavior.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib

from portable_preload import PreloadPolicyError, require_portable_cohort


def load_core(root: Path):
    source = root / "inguest-engine/artifact.py"
    spec = importlib.util.spec_from_file_location("core_engine_artifact", source)
    if spec is None or spec.loader is None:
        raise ValueError("the explicit core artifact producer cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("core-source", "engine-artifact", "patching-revision",
                 "cargo-metadata", "loader-events", "target-dir",
                 "native-output", "destination"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    native = Path(__file__).resolve().parent
    root = native.parent.parent
    core_root = Path(args.core_source).resolve(strict=True)
    core = load_core(core_root)
    expected_w = core.revision(args.patching_revision)
    patching_tree = core.committed_source(root, expected_w)
    core.git(root, "cat-file", "-e", "HEAD:hermit-patching-cli/native/produce.py")
    core.require(not core.git(root, "ls-files", "--others", "--exclude-standard", "--",
                              "hermit-patching-cli", "experimental/reverie-sabre"),
                 "uncommitted native/loader sources cannot be labelled with HEAD")
    engine_manifest = Path(args.engine_artifact).resolve(strict=True)
    engine_manifest_record = core.digest(engine_manifest)
    core.require(engine_manifest.name == "engine-artifact.json", "explicit core engine manifest name mismatch")
    engine = core.check(engine_manifest)
    h, r = engine["core_h_revision"], engine["core_r_revision"]
    core_tree = core.committed_source(core_root, h)
    core.require(core_tree == engine["core_h_tree"], "engine/core source tree mismatch")
    core.require(core.digest(core_root / "inguest-engine/artifact.py")
                 == engine["source_records"]["installer"],
                 "engine artifact producer differs from the exact core source")
    frontend = tomllib.loads((native.parent / "Cargo.toml").read_text())
    for name in ("hermit", "detcore", "detcore-model", "hermit-resources"):
        core.require(frontend["dependencies"][name]["rev"] == h,
                     f"frontend/core Hermit pin mismatch: {name}")
    for name in ("reverie", "reverie-rpc-transport"):
        core.require(frontend["dependencies"][name]["rev"] == r,
                     f"frontend/core Reverie pin mismatch: {name}")

    metadata_path = Path(args.cargo_metadata).resolve(strict=True)
    events_path = Path(args.loader_events).resolve(strict=True)
    metadata_bytes = core.read_record(metadata_path)
    event_bytes = core.read_record(events_path)
    metadata = json.loads(metadata_bytes)
    records = core.parse_cargo_events(event_bytes)
    core.require(Path(metadata["workspace_root"]).resolve() == root,
                 "loader metadata belongs to another workspace")
    target = Path(args.target_dir).resolve(strict=True)
    core.require(Path(metadata["target_directory"]).resolve() == target,
                 "loader metadata and requested target differ")
    package_root = root / "experimental/reverie-sabre"
    package = core.one([p for p in metadata["packages"]
                        if p["name"] == "reverie-sabre"
                        and Path(p["manifest_path"]).resolve() == package_root / "Cargo.toml"],
                       "metadata does not identify the maintained local SaBRe producer")
    producer = core.one([row for row in records
                         if row.get("reason") == "build-script-executed"
                         and row.get("package_id") == package["id"]],
                        "one actual SaBRe build-script output is required")
    core.one([row for row in records if row.get("reason") == "compiler-artifact"
              and row.get("package_id") == package["id"]
              and "lib" in row.get("target", {}).get("kind", [])],
             "the successful loader-producing Cargo invocation is missing its package unit")
    pairs = producer["env"]
    core.require(len(pairs) == len({pair[0] for pair in pairs}),
                 "duplicate SaBRe build-script environment key")
    environment = dict(pairs)
    out_dir = Path(producer["out_dir"]).resolve(strict=True)
    loader = Path(environment["REVERIE_SABRE_LOADER"])
    core.require(out_dir.is_relative_to(target), "loader OUT_DIR is outside the declared target")
    core.require(loader == out_dir / "sabre-build-v4/sabre",
                 "loader is not the maintained build.rs emitted artifact")
    core.require(Path(environment["REVERIE_SABRE_SOURCE"]).resolve()
                 == package_root / "vendor/sabre", "loader was built from another source")
    core.elf(loader, shared=False)
    loader_record = core.digest(loader)

    # One fresh native output makes this an actual link, not a cached-file
    # availability claim. The enclosing normal runner owns its budget/group.
    output = Path(args.native_output).absolute()
    destination = Path(args.destination).absolute()
    core.require(output != destination, "native output and installed cohort must differ")
    core.require(output.resolve().is_relative_to(target),
                 "fresh native output must use the same declared target tree")
    os.mkdir(output, 0o700)
    engine_directory = engine_manifest.parent
    os.mkdir(destination, 0o700)
    destination = destination.resolve(strict=True)
    roles = {
        "engine": core.copy_exclusive(engine_directory / core.ENGINE, destination / core.ENGINE, 0o755),
        "header": core.copy_exclusive(engine_directory / core.HEADER, destination / core.HEADER, 0o644),
        "native_header": core.copy_exclusive(engine_directory / core.NATIVE_HEADER,
                                             destination / core.NATIVE_HEADER, 0o644),
    }
    for role in ("engine", "header", "native_header"):
        core.require(roles[role] == engine["artifacts"][role], f"installed core role differs: {role}")
    installed_manifest = core.copy_exclusive(engine_manifest, destination / "engine-artifact.json", 0o644)
    core.require(installed_manifest == engine_manifest_record, "installed core manifest changed")
    core.check(destination / "engine-artifact.json")
    command = ["make", "--no-print-directory", "-C", str(native),
               f"ENGINE_DIR={destination}", f"ENGINE_INCLUDE_DIR={destination}",
               f"OUT={output}"]
    subprocess.run(command, check=True)
    shim = output / "libhermit_engine_sabre.so"
    core.elf(shim, shared=True)
    shim_record = core.digest(shim)
    core.require(core.digest(engine_manifest) == engine_manifest_record,
                 "neutral engine manifest changed during native link")
    core.check(engine_manifest)
    core.require(core.digest(loader) == loader_record, "loader changed during native link")
    core.require(core.committed_source(root, expected_w) == patching_tree
                 and core.committed_source(core_root, h) == core_tree,
                 "source changed during native link")

    # No replacing/repairing a partial destination. All required roles are
    # copied from held, rechecked inputs; the runtime commit record is last.
    roles["shim"] = core.copy_exclusive(shim, destination / shim.name, 0o755)
    roles["loader"] = core.copy_exclusive(loader, destination / "sabre", 0o755)
    core.require(roles["engine"] == engine["artifacts"]["engine"],
                 "installed engine differs from the neutral producer artifact")
    core.require(roles["shim"] == shim_record, "installed shim differs from actual linked output")
    core.require(roles["loader"] == {**loader_record, "file": "sabre"},
                 "installed loader differs from its actual producer output")
    core.check(destination / "engine-artifact.json")
    metadata_record = {"file": metadata_path.name, "bytes": len(metadata_bytes),
                       "sha256": hashlib.sha256(metadata_bytes).hexdigest()}
    event_record = {"file": events_path.name, "bytes": len(event_bytes),
                    "sha256": hashlib.sha256(event_bytes).hexdigest()}
    core.require(core.digest(metadata_path) == metadata_record
                 and core.digest(events_path) == event_record,
                 "loader Cargo evidence changed during installation")
    portable = require_portable_cohort(destination / core.ENGINE, roles["engine"],
                                       destination / shim.name, roles["shim"])
    provenance = {
        "schema": 2, "patching_revision": expected_w, "patching_tree": patching_tree,
        "core_h_revision": h, "core_h_tree": core_tree, "core_r_revision": r,
        "neutral_engine_manifest": engine_manifest_record,
        "header": roles["header"], "native_header": roles["native_header"], "actual_shim_build_command": command,
        "loader_package_id": package["id"], "loader_out_dir": str(out_dir),
        "cargo_metadata": metadata_record, "loader_events": event_record,
        "portable_preload": portable,
        "source_records": {name: core.digest(path) for name, path in (
            ("producer", Path(__file__).resolve()),
            ("preload_gate", native / "portable_preload.py"),
            ("native_makefile", native / "Makefile"),
            ("shim", native / "sabre-shim.c"),
            ("loader_build", package_root / "build.rs"),
            ("workspace_lock", root / "Cargo.lock"))},
        "qualification": "installed artifact cohort only; ELF/constructor/loader/Tool/phase qualification remains separate",
    }
    core.write_new(destination / "build-provenance.json", provenance)
    core.write_new(destination / "cohort.json", {
        "schema": 2, "core_h_revision": h, "core_h_tree": core_tree, "core_r_revision": r,
        "engine_artifact": installed_manifest, **roles,
    })


if __name__ == "__main__":
    try:
        main()
    except PreloadPolicyError as error:
        print(f"produce.py: {error}", file=sys.stderr)
        sys.exit(2)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"patching native artifact refused: {error}", file=sys.stderr)
        sys.exit(1)
