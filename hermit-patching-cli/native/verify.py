#!/usr/bin/env python3
"""Verify an installed SaBRe engine/shim/loader cohort and its exact sources."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tomllib

from portable_preload import require_portable_cohort
from produce import load_core


def verify(core_source: Path, cohort: Path) -> dict:
    native = Path(__file__).resolve().parent
    root = native.parent.parent
    if not core_source.is_absolute() or core_source.resolve(strict=True) != core_source:
        raise ValueError("explicit core source must be absolute and canonical")
    core = load_core(core_source)
    core.require(cohort.is_absolute() and cohort.resolve(strict=True) == cohort
                 and cohort.name == "cohort.json", "explicit cohort must be canonical cohort.json")
    directory = cohort.parent
    manifest_file, before = core.open_regular(cohort)
    with manifest_file:
        core.require(before.st_size <= 64 * 1024, "SaBRe cohort manifest exceeds its byte bound")
        raw = manifest_file.read(64 * 1024 + 1)
        core.require(len(raw) == before.st_size, "SaBRe cohort manifest changed length")
        manifest = json.loads(raw)
        core.require(set(manifest) == {"schema", "core_h_revision", "core_h_tree", "core_r_revision",
                                      "engine_artifact", "engine", "header", "native_header", "shim", "loader"}
                     and manifest["schema"] == 2, "unknown or incomplete SaBRe cohort schema")
        engine_path = directory / "engine-artifact.json"
        core.require(core.digest(engine_path) == manifest["engine_artifact"],
                     "installed engine manifest differs from the cohort")
        engine = core.check(engine_path)
        for key in ("core_h_revision", "core_h_tree", "core_r_revision"):
            core.require(manifest[key] == engine[key], "cohort and engine source identities differ")
        h, r = manifest["core_h_revision"], manifest["core_r_revision"]
        core.require(core.committed_source(core_source, h) == manifest["core_h_tree"],
                     "core source differs from installed engine")
        core.require(core.digest(core_source / "inguest-engine/artifact.py") == engine["source_records"]["installer"],
                     "core artifact verifier is not the engine's source owner")
        frontend = tomllib.loads((native.parent / "Cargo.toml").read_text())
        for name in ("hermit", "detcore", "detcore-model", "hermit-resources"):
            core.require(frontend["dependencies"][name]["rev"] == h,
                         f"frontend/core Hermit pin mismatch: {name}")
        for name in ("reverie", "reverie-rpc-transport"):
            core.require(frontend["dependencies"][name]["rev"] == r,
                         f"frontend/core Reverie pin mismatch: {name}")

        # Inspect the actual preload contract before manifest hash comparisons,
        # preserving the existing publisher/verifier RUNPATH rejection order.
        portable = require_portable_cohort(directory / core.ENGINE, manifest["engine"],
                                           directory / "libhermit_engine_sabre.so", manifest["shim"])
        for role, name in (("engine", core.ENGINE), ("header", core.HEADER),
                           ("native_header", core.NATIVE_HEADER),
                           ("shim", "libhermit_engine_sabre.so"), ("loader", "sabre")):
            core.require(core.digest(directory / name) == manifest[role],
                         f"installed cohort role differs: {role}")
            if role in engine["artifacts"]:
                core.require(manifest[role] == engine["artifacts"][role],
                             f"cohort role is not the exact core engine role: {role}")
        core.elf(directory / "sabre", shared=False)

        provenance = json.loads(core.read_record(directory / "build-provenance.json"))
        current = core.git(root, "rev-parse", "HEAD")
        tree = core.committed_source(root, current)
        core.git(root, "cat-file", "-e", "HEAD:hermit-patching-cli/native/verify.py")
        core.require(not core.git(root, "ls-files", "--others", "--exclude-standard", "--",
                                  "hermit-patching-cli/native"),
                     "uncommitted cohort verification sources cannot be labelled with HEAD")
        core.require(provenance["schema"] == 2
                     and provenance["patching_revision"] == current
                     and provenance["patching_tree"] == tree,
                     "installed cohort belongs to another patching source")
        for key in ("core_h_revision", "core_h_tree", "core_r_revision"):
            core.require(provenance[key] == manifest[key], "build provenance source differs")
        source_paths = {
            "producer": native / "produce.py",
            "preload_gate": native / "portable_preload.py",
            "native_makefile": native / "Makefile",
            "shim": native / "sabre-shim.c",
            "loader_build": root / "experimental/reverie-sabre/build.rs",
            "workspace_lock": root / "Cargo.lock",
        }
        core.require(set(provenance["source_records"]) == set(source_paths),
                     "cohort build provenance is missing source inputs")
        for name, source in source_paths.items():
            core.git(root, "cat-file", "-e", "HEAD:" + str(source.relative_to(root)))
            core.require(core.digest(source) == provenance["source_records"][name],
                         f"cohort build source changed: {name}")
        core.require(provenance["portable_preload"] == portable,
                     "actual portable preload result differs from the producer")
        core.check(engine_path)
        core.require(core.committed_source(root, current) == tree
                     and core.committed_source(core_source, h) == manifest["core_h_tree"],
                     "source changed during cohort verification")
        core.recheck(cohort, manifest_file, before)
        return {"schema": 2, "patching_revision": current, "core_h_revision": h,
                "core_r_revision": r, "cohort": str(cohort), "portable_preload": portable}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-source", required=True, type=Path)
    parser.add_argument("--cohort", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.core_source, args.cohort), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"verify.py: {error}", file=sys.stderr)
        sys.exit(2)
