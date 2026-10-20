"""Read only: bind published package source hashes to their declared Git blobs."""
from pathlib import Path, PurePosixPath
import hashlib
import io
import json
import re
import subprocess


def verify():
    root = Path(__file__).resolve().parents[3]
    folder = root / "docs/research/2026-10-20-multi-backend-optimization"
    manifest = json.loads((folder / "source-manifest.json").read_bytes())
    commit = manifest["source_commit"]
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError("invalid source commit")
    mapped = []
    for name, digest in manifest["files"].items():
        path = PurePosixPath(name)
        if (path.is_absolute() or ".." in path.parts or str(path) != name
                or "\n" in name or "\r" in name):
            raise ValueError("noncanonical package source")
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("invalid source digest")
        if name.startswith("ibme/"):
            source = "src/" + name
        elif name.startswith("experiments/"):
            source = name
        else:
            raise ValueError("unmapped installed source: " + name)
        mapped.append((source, digest))
    requests = "".join(commit + ":" + name + "\n" for name, _ in mapped).encode()
    payload = subprocess.check_output(["git", "cat-file", "--batch"], input=requests, cwd=root)
    stream = io.BytesIO(payload)
    for source, expected in mapped:
        _oid, kind, size = stream.readline().decode().split()
        if kind != "blob":
            raise ValueError("source is not a blob: " + source)
        blob = stream.read(int(size))
        if stream.read(1) != b"\n" or hashlib.sha256(blob).hexdigest() != expected:
            raise ValueError("source digest mismatch: " + source)
    return dict(status="passed", source_commit=commit, python_source_bindings=len(mapped),
                private_state_opened=False, native_binaries_authenticated=False,
                cryptographic_experiment_rerun=False)


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2, sort_keys=True))
