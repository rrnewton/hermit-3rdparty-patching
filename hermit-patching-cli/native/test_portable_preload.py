#!/usr/bin/env python3
"""Real-ELF preload policy controls, retained from core, plus the engine edge.

The seven existing ELF fixtures and rejection assertions are unchanged. They
exercise the external cohort checker's same glibc floor/search-path policy.
Production publisher/verifier call sites have separate full invocation tests.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import portable_preload

NATIVE = Path(__file__).resolve().parent
SCRIPTS = (NATIVE / "portable_preload.py",)
LABEL = "Fixture preload"


def floor_minor() -> int:
    return portable_preload.GUEST_PRELOAD_GLIBC_MINOR_FLOOR


def run_gate(script: Path, preload: Path) -> subprocess.CompletedProcess[str]:
    program = """import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from portable_preload import held_preload, inspect
try:
    with held_preload(Path(sys.argv[3])) as held:
        inspect(held, sys.argv[2])
except ValueError as error:
    print(f"gate: {error}", file=sys.stderr)
    raise SystemExit(2)
"""
    return subprocess.run(
        [sys.executable, "-B", "-c", program, str(script.parent), LABEL, str(preload)],
        capture_output=True, text=True, check=False,
    )


def readelf(*args: str) -> str:
    return subprocess.run(["readelf", *args], capture_output=True, text=True, check=True).stdout


def record(path: Path) -> dict:
    data = path.read_bytes()
    return {"file": path.name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


class GuestPreloadGateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        for tool in ("cc", "readelf", "bash"):
            if shutil.which(tool) is None:
                raise AssertionError(f"the guest-preload gate test needs {tool} on PATH")
        cls.floor = floor_minor()
        cls.scratch = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.scratch.name)
        # The Nix compiler wrapper of the pinned root records a RUNPATH for every
        # directory it links a library from. These names turn that off for the
        # wrapper's target; every other compiler ignores them.
        cls.env = dict(os.environ)
        cls.env["NIX_DONT_SET_RPATH"] = "1"
        cls.env["NIX_DONT_SET_RPATH_FOR_TARGET"] = "1"
        cls.env["NIX_DONT_SET_RPATH_x86_64_unknown_linux_gnu"] = "1"
        (cls.dir / "body.c").write_text("int fixture_preload(void) { return 0; }\n")
        (cls.dir / "caller.c").write_text(
            "extern int fixture_versioned(void);\n"
            "int fixture_preload(void) { return fixture_versioned(); }\n"
        )
        (cls.dir / "stub.c").write_text("int fixture_versioned(void) { return 0; }\n")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.scratch.cleanup()

    def cc(self, output: str, *args: str) -> Path:
        path = self.dir / output
        path.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["cc", "-shared", "-fPIC", "-nostdlib", "-o", str(path), *args],
            cwd=self.dir,
            env=self.env,
            check=True,
        )
        return path

    def stub(self, soname: str, version: str | None) -> Path:
        """A stub shared library named SONAME defining fixture_versioned at VERSION."""
        directory = self.dir / f"stub-{soname}-{version}"
        args = [f"-Wl,-soname,{soname}"]
        if version is not None:
            script = self.dir / f"{soname}-{version}.map"
            script.write_text(f"{version} {{ global: fixture_versioned; local: *; }};\n")
            args.append(f"-Wl,--version-script={script}")
        self.cc(str(directory.relative_to(self.dir) / soname), *args, "stub.c")
        return directory

    def linked_against(self, output: str, soname: str, version: str | None) -> Path:
        directory = self.stub(soname, version)
        return self.cc(output, "caller.c", f"-L{directory}", f"-l:{soname}")

    def assert_accepted(self, preload: Path) -> None:
        for script in SCRIPTS:
            result = run_gate(script, preload)
            self.assertEqual(
                result.returncode, 0, f"{script.name} refused {preload.name}: {result.stderr}"
            )

    def assert_refused(self, preload: Path, message: str) -> None:
        for script in SCRIPTS:
            result = run_gate(script, preload)
            self.assertEqual(
                result.returncode,
                2,
                f"{script.name} did not refuse {preload.name}: {result.stdout}{result.stderr}",
            )
            self.assertIn(f"gate: {LABEL} {message}", result.stderr, script.name)

    def test_a_clean_preload_is_accepted(self) -> None:
        preload = self.cc("clean.so", "body.c")
        dynamic = readelf("-d", str(preload))
        self.assertNotRegex(dynamic, r"\((RPATH|RUNPATH)\)")
        self.assertNotIn("(NEEDED)", dynamic)
        self.assert_accepted(preload)

    def test_a_runpath_is_refused(self) -> None:
        preload = self.cc(
            "runpath.so", "body.c", "-Wl,--enable-new-dtags", "-Wl,-rpath,/nix/store/fixture-glibc/lib"
        )
        self.assertIn("(RUNPATH)", readelf("-d", str(preload)))
        self.assert_refused(preload, "records a library search path")

    def test_an_rpath_is_refused(self) -> None:
        preload = self.cc(
            "rpath.so", "body.c", "-Wl,--disable-new-dtags", "-Wl,-rpath,/nix/store/fixture-glibc/lib"
        )
        dynamic = readelf("-d", str(preload))
        self.assertIn("(RPATH)", dynamic)
        self.assertNotIn("(RUNPATH)", dynamic)
        self.assert_refused(preload, "records a library search path")

    def test_a_library_outside_glibc_is_refused(self) -> None:
        preload = self.linked_against("gcc-s.so", "libgcc_s.so.1", None)
        dynamic = readelf("-d", str(preload))
        self.assertIn("Shared library: [libgcc_s.so.1]", dynamic)
        self.assertNotRegex(dynamic, r"\((RPATH|RUNPATH)\)")
        self.assert_refused(preload, "needs libgcc_s.so.1, which not every guest's glibc provides")

    def test_the_floor_version_is_accepted(self) -> None:
        version = f"GLIBC_2.{self.floor}"
        preload = self.linked_against("floor.so", "libc.so.6", version)
        needs = readelf("-V", "--wide", str(preload))
        self.assertIn(f"Name: {version} ", needs)
        self.assertNotRegex(readelf("-d", str(preload)), r"\((RPATH|RUNPATH)\)")
        self.assert_accepted(preload)

    def test_a_version_above_the_floor_is_refused(self) -> None:
        version = f"GLIBC_2.{self.floor + 1}"
        preload = self.linked_against("newer.so", "libc.so.6", version)
        needs = readelf("-V", "--wide", str(preload))
        self.assertIn(f"Name: {version} ", needs)
        self.assertNotRegex(readelf("-d", str(preload)), r"\((RPATH|RUNPATH)\)")
        self.assert_refused(preload, f"requires symbol version {version}")

    def test_a_version_name_outside_glibc_2_n_is_refused(self) -> None:
        # The exact need that broke libdetcore_liteinst.so for host guests
        # (https://github.com/rrnewton/hermit/issues/3967).
        version = "GLIBC_ABI_DT_RELR"
        preload = self.linked_against("relr.so", "libc.so.6", version)
        needs = readelf("-V", "--wide", str(preload))
        self.assertIn(f"Name: {version} ", needs)
        self.assertNotRegex(readelf("-d", str(preload)), r"\((RPATH|RUNPATH)\)")
        self.assert_refused(preload, f"requires symbol version {version}")


    def test_shim_needs_the_exact_held_engine(self) -> None:
        engine = self.cc("engine.so", "body.c")
        shim = self.cc("shim.so", "body.c", "-Wl,--no-as-needed", str(engine))
        self.assertIn(f"Shared library: [{engine}]", readelf("-d", str(shim)))
        accepted = portable_preload.require_portable_cohort(engine, record(engine), shim, record(shim))
        self.assertEqual(accepted["shim"]["needed"].count(str(engine)), 1)
        other = self.dir / "other-engine.so"
        shutil.copy2(engine, other)
        with self.assertRaisesRegex(ValueError, "exact held core engine once"):
            portable_preload.require_portable_cohort(other, record(other), shim, record(shim))

    def test_engine_dependencies_are_checked_beyond_the_shim_edge(self) -> None:
        engine = self.linked_against("engine-gcc.so", "libgcc_s.so.1", None)
        shim = self.cc("shim-gcc.so", "body.c", "-Wl,--no-as-needed", str(engine))
        self.assertIn("Shared library: [libgcc_s.so.1]", readelf("-d", str(engine)))
        self.assertIn(f"Shared library: [{engine}]", readelf("-d", str(shim)))
        with self.assertRaisesRegex(ValueError, "Shared Detcore engine needs libgcc_s.so.1"):
            portable_preload.require_portable_cohort(engine, record(engine), shim, record(shim))


if __name__ == "__main__":
    unittest.main()
