#!/usr/bin/env python3
"""Patching physical adapters for the single core counter2 benchmark driver."""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import sys


BACKENDS = ("sabre", "e9patch")


class HeldFile:
    """Keep the named input's inode open and reject changed path/file metadata."""

    def __init__(self, supplied: Path, *, executable: bool = False):
        if not supplied.is_absolute():
            raise ValueError(f"physical/source input must be absolute: {supplied}")
        self.path = supplied.resolve(strict=True)
        fd = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        self.stream = os.fdopen(fd, "rb")
        self.before = os.fstat(fd)
        try:
            if not stat.S_ISREG(self.before.st_mode):
                raise ValueError(f"not a regular input: {self.path}")
            if executable and not os.access(self.path, os.X_OK):
                raise ValueError(f"input is not executable: {self.path}")
            value = hashlib.sha256()
            for block in iter(lambda: self.stream.read(1024 * 1024), b""):
                value.update(block)
            self.sha256 = value.hexdigest()
            self.recheck()
        except BaseException:
            self.stream.close()
            raise

    @staticmethod
    def identity(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
                value.st_mtime_ns, value.st_ctime_ns)

    def recheck(self):
        if self.identity(os.fstat(self.stream.fileno())) != self.identity(self.before):
            raise ValueError(f"held input changed: {self.path}")
        if self.identity(self.path.lstat()) != self.identity(self.before):
            raise ValueError(f"input path changed: {self.path}")

    def record(self):
        self.recheck()
        return {"path": str(self.path), "sha256": self.sha256,
                "bytes": self.before.st_size, "device": self.before.st_dev,
                "inode": self.before.st_ino,
                "mode": oct(stat.S_IMODE(self.before.st_mode))}

    def close(self):
        self.stream.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="Other arguments go unchanged to the core counter2 driver.",
    )
    parser.add_argument("--core-driver", type=Path, required=True)
    parser.add_argument("--core-driver-sha256", required=True)
    parser.add_argument("--counter2-bin", type=Path, required=True)
    parser.add_argument("--preload", type=Path, required=True)
    parser.add_argument("--sabre-loader", type=Path)
    parser.add_argument("--sabre-plugin", type=Path)
    parser.add_argument("--e9tool", type=Path)
    parser.add_argument("--e9patch-backend", type=Path)
    args, benchmark_args = parser.parse_known_args()
    if not re.fullmatch(r"[a-f0-9]{64}", args.core_driver_sha256):
        parser.error("--core-driver-sha256 must be a complete lowercase SHA256")

    with ExitStack() as ownership:
        held = {}

        def bind(role, path, *, executable=False):
            if path is None:
                parser.error(f"missing explicit {role} input for the selected backend")
            value = HeldFile(path, executable=executable)
            ownership.callback(value.close)
            held[role] = value
            return value

        core = bind("core_driver", args.core_driver)
        if core.sha256 != args.core_driver_sha256:
            parser.error("core driver bytes differ from --core-driver-sha256")
        frontend = bind("counter2_bin", args.counter2_bin, executable=True)
        preload = bind("preload", args.preload)
        here = bind("physical_adapter_source", Path(__file__).resolve())

        # Import only the explicitly hash-bound driver. No copied comparison,
        # calibration, workload, sampling, or reporting implementation lives here.
        spec = importlib.util.spec_from_file_location("reverie_counter2_driver", core.path)
        if spec is None or spec.loader is None:
            raise ValueError("cannot load the explicit core driver")
        driver = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = driver
        sys.dont_write_bytecode = True
        spec.loader.exec_module(driver)
        core.recheck()
        if getattr(driver, "EXTERNAL_BACKEND_API", None) != 1:
            raise ValueError("core driver does not implement the physical adapter API1")
        parsed = driver.parse_args(benchmark_args, BACKENDS)
        selected = [item.strip() for item in parsed.backends.split(",") if item.strip()]
        if "sabre" in selected:
            bind("sabre_loader", args.sabre_loader, executable=True)
            bind("sabre_plugin", args.sabre_plugin)
        if "e9patch" in selected:
            bind("e9tool", args.e9tool, executable=True)
            bind("e9patch_backend", args.e9patch_backend, executable=True)

        def recheck_all():
            for value in held.values():
                value.recheck()

        def command(backend, artifact, arguments, _root, _target):
            if backend not in BACKENDS:
                raise RuntimeError(f"unknown patching backend {backend}")
            recheck_all()
            return [str(frontend.path), "--backend", backend,
                    "--preload", str(preload.path), "--", str(artifact), *arguments]

        def environment(backend, inherited, _root, _target):
            recheck_all()
            result = inherited.copy()
            if backend == "sabre":
                result["REVERIE_SABRE_STRACE_QUIET"] = "1"
                result["SABRE_BINARY"] = str(held["sabre_loader"].path)
                result["SABRE_PLUGIN"] = str(held["sabre_plugin"].path)
            elif backend == "e9patch":
                result["REVERIE_E9TOOL"] = str(held["e9tool"].path)
                result["REVERIE_E9PATCH_BACKEND"] = str(held["e9patch_backend"].path)
            elif backend != "native":
                raise RuntimeError(f"unknown patching backend {backend}")
            return result

        inputs = {role: value.record() for role, value in held.items()}
        try:
            driver.main(
                argv=benchmark_args,
                backend_names=BACKENDS,
                command_factory=command,
                environment_factory=environment,
                adapter_identity={"name": "hermit-3rdparty-patching-counter2",
                                  "api": 1, "inputs": inputs},
            )
        finally:
            recheck_all()


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        raise SystemExit(f"patching-counter2-shootout: {error}") from error
