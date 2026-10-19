"""Prepare a verified, isolated wheel runtime on the WSL Linux filesystem.

This changes code placement only. Native ABI/source checks still execute for
every operation. No private state or globally installed package is copied.
"""

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
import zipfile


def wheel_manifest(wheel):
    """Read exact packaged bytes; reject paths outside a pure Python wheel."""
    entries = {}
    with zipfile.ZipFile(wheel) as archive:
        for info in archive.infolist():
            name = PurePosixPath(info.filename)
            if (name.is_absolute() or ".." in name.parts or "\\" in info.filename
                    or info.filename in entries or not name.parts):
                raise ValueError("invalid/duplicate wheel member")
            if info.is_dir():
                continue
            if name.parts[0] not in ("ibme", "experiments") and not name.parts[0].endswith(".dist-info"):
                raise ValueError("expected a pure IB-ME wheel")
            entries[info.filename] = hashlib.sha256(archive.read(info)).hexdigest()
    if "ibme/__init__.py" not in entries:
        raise ValueError("wheel does not contain IB-ME")
    # pip updates RECORD when adding its own installation metadata.
    return {name: digest for name, digest in entries.items() if not name.endswith(".dist-info/RECORD")}


def verify_runtime(root, expected):
    """Check all packaged files, including native source and static demo assets."""
    root = root.resolve()
    for name, digest in expected.items():
        target = root / name
        if (not target.resolve().is_relative_to(root) or target.is_symlink()
                or not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != digest):
            raise ValueError("installed runtime differs from the supplied wheel: " + name)
    # A stale additional Python module must not become an unrecorded provider.
    for package in ("ibme", "experiments"):
        for target in (root / package).rglob("*"):
            if target.is_file() and "__pycache__" not in target.parts:
                name = target.relative_to(root).as_posix()
                if name not in expected:
                    raise ValueError("unexpected runtime file: " + name)


@contextmanager
def _locked(path):
    import fcntl
    with path.open("a+b") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def prepare(wheel, cache_root=None):
    if sys.platform != "linux":
        raise RuntimeError("run this helper in the prescribed WSL Sage environment")
    wheel = wheel.resolve(strict=True)
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    expected = wheel_manifest(wheel)
    cache = (Path.home() / ".cache/ibme-wheel-runtimes" if cache_root is None else Path(cache_root)).resolve()
    if cache == Path("/mnt") or Path("/mnt") in cache.parents:
        raise ValueError("choose a runtime cache on the WSL Linux filesystem")
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = cache / digest
    with _locked(cache / (digest + ".lock")):
        if not destination.exists():
            staging = Path(tempfile.mkdtemp(prefix=digest + ".pending-", dir=cache))
            # Keep an interrupted/failed installation for inspection; never
            # overwrite a previous runtime or mutate this Python environment.
            subprocess.run([sys.executable, "-m", "pip", "install", "--no-deps", "--no-index",
                            "--no-compile", "--target", str(staging), str(wheel)],
                           stdout=sys.stderr, stderr=sys.stderr, check=True)
            verify_runtime(staging, expected)
            staging.rename(destination)
        verify_runtime(destination, expected)
    return dict(runtime_root=str(destination), wheel_sha256=digest, verified_files=len(expected),
                global_environment_modified=False, native_source_checks="unchanged")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--cache-root", type=Path)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--module", choices=("ibme.webui", "ibme.cli"), default="ibme.webui")
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    receipt = prepare(args.wheel, args.cache_root)
    if args.prepare_only:
        print(json.dumps(receipt, sort_keys=True))
        return
    print(json.dumps(receipt, sort_keys=True), file=sys.stderr, flush=True)
    environment = dict(os.environ, PYTHONPATH=receipt["runtime_root"])
    os.chdir(receipt["runtime_root"])
    forwarded = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
    os.execve(sys.executable, [sys.executable, "-m", args.module, *forwarded], environment)


if __name__ == "__main__":
    main()
