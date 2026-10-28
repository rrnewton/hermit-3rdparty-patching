#!/usr/bin/env python3
"""Transferred SaBRe publisher/verifier RUNPATH controls using real call sites.

The tiny C ELFs and Cargo records are declared fixtures, not a Rust build or
runtime qualification. Neither producer, verifier, core checker nor portable
preload gate is replaced. The maintained Makefile performs the actual shim link.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

NATIVE = Path(__file__).resolve().parent


def record(path: Path) -> dict:
    data = path.read_bytes()
    return {"file": path.name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


class GuestPreloadPublicationTest(unittest.TestCase):
    def setUp(self) -> None:
        for tool in ("cc", "make", "git", "readelf"):
            self.assertIsNotNone(shutil.which(tool), f"required fixture tool: {tool}")
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.base = Path(self.scratch.name).resolve()
        self.env = dict(os.environ)
        self.env.update(PYTHONDONTWRITEBYTECODE="1", NIX_DONT_SET_RPATH="1",
                        NIX_DONT_SET_RPATH_FOR_TARGET="1",
                        NIX_DONT_SET_RPATH_x86_64_unknown_linux_gnu="1",
                        GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_AUTHOR_NAME="Publication fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
                        GIT_COMMITTER_NAME="Publication fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid")
        self.core = self.base / "core"
        self.patching = self.base / "patching"
        self.target = self.base / "target"
        self.target.mkdir()
        self.installed = self.base / "engine-installed"
        self.installed.mkdir()
        self.native = self.patching / "hermit-patching-cli/native"
        self.native.mkdir(parents=True)
        # The core source is an explicit input, matching the production verifier.
        source = os.environ.get("HERMIT_CORE_SOURCE")
        self.assertIsNotNone(source, "HERMIT_CORE_SOURCE must name the actual core source")
        source = Path(source)
        self.assertTrue(source.is_absolute() and source.resolve(strict=True) == source)
        for name in ("produce.py", "verify.py", "portable_preload.py", "Makefile"):
            shutil.copy2(NATIVE / name, self.native / name)
        engine = self.core / "inguest-engine"
        (engine / "include").mkdir(parents=True)
        shutil.copy2(source / "inguest-engine/artifact.py", engine / "artifact.py")
        for name in ("hermit-engine-v1.h", "hermit-engine-native-v1.h"):
            shutil.copy2(source / "inguest-engine/include" / name, engine / "include" / name)
        self.write(self.core / "Cargo.toml", '[workspace]\nmembers = ["inguest-engine"]\n')
        self.write(self.core / "Cargo.lock", "version = 3\n")
        self.write(engine / "Cargo.toml", '[package]\nname = "hermit-inguest-engine"\nversion = "0.0.0"\n')
        reverie = self.core / "reverie"
        reverie.mkdir()
        self.write(reverie / "fixture", "Real fixture Git dependency identity; no build claim.\n")
        self.r = self.commit(reverie)
        self.h = self.commit(self.core)
        self.tree = self.git(self.core, "rev-parse", "HEAD^{tree}")
        self.cc(self.installed / "libhermit_inguest_engine.so",
                "int fixture_engine(void) { return 7; }\n", shared=True)
        for name in ("hermit-engine-v1.h", "hermit-engine-native-v1.h"):
            shutil.copy2(engine / "include" / name, self.installed / name)
        # These evidence files describe fixture inputs; check() is the real
        # schema2 checker, and every source record hashes its actual file.
        metadata = self.base / "core-metadata.json"
        events = self.base / "core-events.jsonl"
        package_id = f"path+file://{engine}#hermit-inguest-engine@0.0.0"
        profile = {"test": False}
        unit = {"reason": "compiler-artifact", "package_id": package_id,
                "target": {"name": "hermit_inguest_engine", "crate_types": ["cdylib"]},
                "features": [], "profile": profile, "fresh": False,
                "filenames": [str(self.installed / "libhermit_inguest_engine.so")]}
        self.json(metadata, {"workspace_root": str(self.core), "target_directory": str(self.target),
                             "packages": [{"id": package_id, "name": "hermit-inguest-engine",
                                           "manifest_path": str(engine / "Cargo.toml")}]})
        self.write(events, json.dumps(unit) + '\n{"reason":"build-finished","success":true}\n')
        self.json(self.installed / "engine-artifact.json", {
            "schema": 2, "kind": "hermit-inguest-engine", "core_h_revision": self.h,
            "core_h_tree": self.tree, "core_r_revision": self.r,
            "artifacts": {role: record(self.installed / name) for role, name in (
                ("engine", "libhermit_inguest_engine.so"), ("header", "hermit-engine-v1.h"),
                ("native_header", "hermit-engine-native-v1.h"))},
            "profile": profile, "features": [], "cargo_package_id": package_id,
            "source_records": {"cargo_events": record(events), "cargo_metadata": record(metadata),
                               "cargo_lock": record(self.core / "Cargo.lock"),
                               "package_manifest": record(engine / "Cargo.toml"),
                               "installer": record(engine / "artifact.py")},
            "compiled_units": [{key: unit[key] for key in ("package_id", "features", "profile", "fresh")}
                               | {"target": "hermit_inguest_engine", "crate_types": ["cdylib"]}],
            "qualification": "tiny C ELF and record fixtures only; no Rust build/runtime qualification",
        })
        dependencies = "[dependencies]\n" + "".join(
            f'{name} = {{ git = "https://example.invalid/core", rev = "{pin}" }}\n'
            for name, pin in [(name, self.h) for name in ("hermit", "detcore", "detcore-model", "hermit-resources")]
            + [(name, self.r) for name in ("reverie", "reverie-rpc-transport")])
        self.write(self.patching / "hermit-patching-cli/Cargo.toml", dependencies)
        self.write(self.patching / "Cargo.lock", "version = 3\n")
        self.write(self.native / "sabre-shim.c", "extern int fixture_engine(void);\nint fixture_plugin(void) { return fixture_engine(); }\n")
        package = self.patching / "experimental/reverie-sabre"
        self.write(package / "Cargo.toml", '[package]\nname = "reverie-sabre"\nversion = "0.0.0"\n')
        self.write(package / "build.rs", "fn main() {}\n")
        self.write(package / "src/ffi/recursion_protector.c", "int fixture_recursion(void) { return 0; }\n")
        for name in ("plugins/sbr_api_defs.h", "loader/backend_stats.h"):
            self.write(package / "vendor/sabre/includes" / name, "/* Explicit non-runtime fixture input. */\n")
        self.package_id = f"path+file://{package}#reverie-sabre@0.0.0"
        out = self.target / "loader-out"
        loader = out / "sabre-build-v4/sabre"
        self.cc(loader, "int main(void) { return 0; }\n", shared=False)
        self.metadata = self.base / "loader-metadata.json"
        self.events = self.base / "loader-events.jsonl"
        self.json(self.metadata, {"workspace_root": str(self.patching), "target_directory": str(self.target),
                                  "packages": [{"id": self.package_id, "name": "reverie-sabre",
                                                "manifest_path": str(package / "Cargo.toml")}]})
        self.write(self.events, "\n".join(json.dumps(row) for row in (
            {"reason": "build-script-executed", "package_id": self.package_id, "out_dir": str(out),
             "env": [["REVERIE_SABRE_LOADER", str(loader)], ["REVERIE_SABRE_SOURCE", str(package / "vendor/sabre")]]},
            {"reason": "compiler-artifact", "package_id": self.package_id, "target": {"kind": ["lib"]}},
            {"reason": "build-finished", "success": True})) + "\n")
        self.destination = self.base / "cohort"

    def write(self, path: Path, body: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)

    def json(self, path: Path, value: dict) -> None:
        self.write(path, json.dumps(value, sort_keys=True, indent=2) + "\n")

    def run_command(self, argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(argv, env=self.env, capture_output=True, text=True, check=check, timeout=30)

    def git(self, root: Path, *args: str) -> str:
        return self.run_command(["git", "-C", str(root), *args]).stdout.strip()

    def commit(self, root: Path) -> str:
        if not (root / ".git").exists():
            self.git(root, "init", "-q")
            self.git(root, "config", "commit.gpgsign", "false")
        self.git(root, "add", "--all")  # Isolated fixture only.
        self.git(root, "-c", "core.hooksPath=/dev/null", "commit", "-qm", "Publication fixture")
        return self.git(root, "rev-parse", "HEAD")

    def cc(self, output: Path, body: str, *, shared: bool, engine: Path | None = None, runpath: bool = False) -> None:
        output.parent.mkdir(parents=True, exist_ok=True)
        source = self.base / (output.name + ".c")
        source.write_text(body)
        command = ["cc", "-nostdlib"]
        command += ["-shared", "-fPIC"] if shared else ["-Wl,-e,main"]
        command += ["-o", str(output), str(source)]
        if engine is not None:
            command += [str(engine)]
        if runpath:
            command += ["-Wl,--enable-new-dtags", "-Wl,-rpath,/nix/store/fixture-glibc/lib"]
        self.run_command(command)

    def publish(self) -> subprocess.CompletedProcess[str]:
        revision = self.commit(self.patching)
        return self.run_command([sys.executable, "-B", str(self.native / "produce.py"),
            "--core-source", str(self.core), "--engine-artifact", str(self.installed / "engine-artifact.json"),
            "--patching-revision", revision, "--cargo-metadata", str(self.metadata),
            "--loader-events", str(self.events), "--target-dir", str(self.target),
            "--native-output", str(self.target / "native-output"), "--destination", str(self.destination)], check=False)

    def verify(self) -> subprocess.CompletedProcess[str]:
        return self.run_command([sys.executable, "-B", str(self.native / "verify.py"),
                                "--core-source", str(self.core), "--cohort", str(self.destination / "cohort.json")], check=False)

    def test_publish_refuses_each_guest_preload_with_a_runpath(self) -> None:
        makefile = self.native / "Makefile"
        makefile.write_text(makefile.read_text() + "\nLDFLAGS += -Wl,--enable-new-dtags -Wl,-rpath,/nix/store/fixture-glibc/lib\n")
        result = self.publish()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("produce.py: SaBRe plugin records a library search path", result.stderr)
        self.assertIn(str(self.destination / "libhermit_engine_sabre.so"), result.stderr)
        self.assertFalse((self.destination / "cohort.json").exists())

    def test_verify_refuses_each_guest_preload_with_a_runpath(self) -> None:
        published = self.publish()
        self.assertEqual(published.returncode, 0, published.stdout + published.stderr)
        clean = self.verify()
        self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)
        shim = self.destination / "libhermit_engine_sabre.so"
        original, mode = shim.read_bytes(), shim.stat().st_mode
        try:
            self.cc(shim, "extern int fixture_engine(void);\nint fixture_plugin(void) { return fixture_engine(); }\n",
                    shared=True, engine=self.destination / "libhermit_inguest_engine.so", runpath=True)
            self.assertIn("(RUNPATH)", self.run_command(["readelf", "-d", str(shim)]).stdout)
            refused = self.verify()
            self.assertEqual(refused.returncode, 2, refused.stdout + refused.stderr)
            self.assertIn("verify.py: SaBRe plugin records a library search path", refused.stderr)
            self.assertIn(str(shim), refused.stderr)
        finally:
            shim.write_bytes(original)
            shim.chmod(mode)
        restored = self.verify()
        self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)


if __name__ == "__main__":
    unittest.main()
