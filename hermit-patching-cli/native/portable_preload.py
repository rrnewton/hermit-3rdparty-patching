#!/usr/bin/env python3
"""Check the guest loader contract of an exact engine and thin SaBRe shim.

The existing preload policy admits glibc through 2.34, with no library search
path and no dependency on another system runtime. The shim adds exactly one
dependency: the absolute pathname of its held, independently checked engine.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import subprocess

GUEST_PRELOAD_GLIBC_MINOR_FLOOR = 34
GLIBC_LIBRARIES = frozenset({
    "ld-linux-x86-64.so.2", "libc.so.6", "libm.so.6", "libdl.so.2",
    "libpthread.so.0", "librt.so.1", "libutil.so.1",
})
MAX_FILE = 2 * 1024 * 1024 * 1024
MAX_READELF_OUTPUT = 4 * 1024 * 1024


class PreloadPolicyError(ValueError):
    """The actual engine/shim loader contract or its producer binding refused."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreloadPolicyError(message)


def identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode,
            info.st_mtime_ns, info.st_ctime_ns)


class HeldPreload:
    def __init__(self, path: Path, descriptor: int, before: os.stat_result):
        self.path = path
        self.descriptor = descriptor
        self.before = before
        checksum = hashlib.sha256()
        offset = 0
        while block := os.pread(descriptor, 65536, offset):
            offset += len(block)
            require(offset <= before.st_size, f"preload grew while hashing: {path}")
            checksum.update(block)
        require(offset == before.st_size, f"preload changed length: {path}")
        self.record = {"file": path.name, "bytes": offset, "sha256": checksum.hexdigest()}
        self.recheck()

    def recheck(self) -> None:
        require(identity(os.fstat(self.descriptor)) == identity(self.before)
                and identity(self.path.lstat()) == identity(self.before)
                and self.path.resolve(strict=True) == self.path,
                f"held or visible preload changed: {self.path}")

    def readelf(self, *arguments: str) -> str:
        self.recheck()
        # Inspect the held object. A replaced pathname cannot select another
        # file between hashing and readelf; recheck also keeps the visible name.
        result = subprocess.run(
            ["readelf", *arguments, f"/proc/self/fd/{self.descriptor}"],
            pass_fds=(self.descriptor,), capture_output=True, check=False,
            timeout=30, env={**os.environ, "LC_ALL": "C"},
        )
        require(result.returncode == 0,
                f"cannot inspect preload ELF: {self.path}: {result.stderr[:1024]!r}")
        require(len(result.stdout) <= MAX_READELF_OUTPUT
                and len(result.stderr) <= MAX_READELF_OUTPUT,
                f"preload ELF inspection exceeds its byte bound: {self.path}")
        self.recheck()
        return result.stdout.decode("utf-8")


@contextmanager
def held_preload(path: Path):
    require(path.is_absolute() and path.resolve(strict=True) == path,
            f"preload must have an absolute canonical path: {path}")
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_FILE,
            f"preload is not a bounded regular file: {path}")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        require(identity(os.fstat(descriptor)) == identity(before),
                f"preload changed while opening: {path}")
        yield HeldPreload(path, descriptor, before)
    finally:
        os.close(descriptor)


def check_record(actual: dict, expected: dict) -> None:
    require(set(expected) == {"file", "bytes", "sha256"}
            and type(expected["bytes"]) is int and 0 < expected["bytes"] <= MAX_FILE
            and isinstance(expected["sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", expected["sha256"]) is not None,
            "invalid preload producer record")
    require(actual == expected, f"preload differs from its producer record: {expected['file']}")


def inspect(preload: HeldPreload, label: str, *, engine: Path | None = None) -> dict:
    header = os.pread(preload.descriptor, 64, 0)
    require(len(header) == 64 and header[:7] == b"\x7fELF\x02\x01\x01"
            and struct.unpack_from("<HH", header, 16) == (3, 62),
            f"{label} is not an x86-64 shared ELF: {preload.path}")
    dynamic = preload.readelf("--dynamic", "--wide")
    require(re.search(r"\((?:RPATH|RUNPATH)\)", dynamic) is None,
            f"{label} records a library search path, so a guest would load the build root's libraries: {preload.path}")
    needed = re.findall(r"\(NEEDED\).*Shared library: \[([^\]\r\n]+)\]", dynamic)
    require(len(needed) == len(re.findall(r"\(NEEDED\)", dynamic)),
            f"cannot decode every {label} dependency: {preload.path}")
    if engine is not None:
        require(needed.count(str(engine)) == 1,
                f"{label} must DT_NEEDED the exact held core engine once: {preload.path}")
    for library in needed:
        if engine is not None and library == str(engine):
            continue
        require(library in GLIBC_LIBRARIES,
                f"{label} needs {library}, which not every guest's glibc provides: {preload.path}")
    versions = re.findall(r"Name: ([^ ]+) *Flags:", preload.readelf("--version-info", "--wide"))
    for version in versions:
        match = re.fullmatch(r"GLIBC_2\.([0-9]+)(?:\.[0-9]+)?", version)
        require(match is not None and int(match[1]) <= GUEST_PRELOAD_GLIBC_MINOR_FLOOR,
                f"{label} requires symbol version {version}; only glibc's up to GLIBC_2.{GUEST_PRELOAD_GLIBC_MINOR_FLOOR} load in every guest: {preload.path}")
    preload.recheck()
    return {"path": str(preload.path), **preload.record, "needed": needed,
            "symbol_versions": sorted(set(versions))}


def require_portable_cohort(engine: Path, engine_record: dict,
                            shim: Path, shim_record: dict) -> dict:
    with held_preload(engine) as held_engine, held_preload(shim) as held_shim:
        engine_result = inspect(held_engine, "Shared Detcore engine")
        shim_result = inspect(held_shim, "SaBRe plugin", engine=held_engine.path)
        # Keep the old verifier's order: inspect the actual loader contract
        # before the manifest comparison, then require BOTH predicates.
        check_record(held_engine.record, engine_record)
        check_record(held_shim.record, shim_record)
        held_engine.recheck()
        held_shim.recheck()
        return {"glibc_minor_floor": GUEST_PRELOAD_GLIBC_MINOR_FLOOR,
                "engine": engine_result, "shim": shim_result}
