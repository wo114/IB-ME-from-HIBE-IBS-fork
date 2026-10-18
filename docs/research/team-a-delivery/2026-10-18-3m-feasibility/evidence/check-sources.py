"""Verify PUBLIC receipt provider hashes against their recorded Git commits.

Run with Windows Python when Git is not installed in WSL. Does not open any
private experiment directory. Paths in receipts are mapped only to tracked
src/ibme or experiments/research files and read through git show.
"""

import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[5]
HERE = Path(__file__).resolve().parent
COMMON = ROOT/"docs/research/2026-10-18-full-system-baseline/evidence/latte-mldsa44.json"
CACHE = {}


def blob_hash(revision, relative):
    if not re.fullmatch(r"[0-9a-f]{7,40}", revision): raise ValueError("bounded Git commit required")
    if not relative.endswith(".py") or ".." in Path(relative).parts:
        raise ValueError("bounded tracked Python provider required")
    key = revision, relative
    if key not in CACHE:
        raw = subprocess.run(["git", "show", revision+":"+relative], cwd=ROOT,
            capture_output=True, check=True).stdout
        CACHE[key] = hashlib.sha256(raw).hexdigest()
    return CACHE[key]


def relative_provider(raw):
    path = raw.replace("\\", "/")
    for anchor in ("/src/ibme/", "/experiments/research/"):
        if anchor in path:
            return path[path.index(anchor)+1:]
    raise ValueError("provider is outside the two tracked Python source roots")


def check_record(value, inherited=None):
    count = 0
    if isinstance(value, dict):
        revision = value.get("source_commit", inherited)
        if "source_providers" in value:
            for provider in value["source_providers"].values():
                relative = relative_provider(provider["path"])
                if blob_hash(revision, relative) != provider["sha256"]:
                    raise ValueError("provider hash differs from recorded Git source: "+relative)
                count += 1
        for key, child in value.items():
            if key != "source_providers": count += check_record(child, revision)
    elif isinstance(value, list):
        count += sum(check_record(child, inherited) for child in value)
    return count


def main():
    records = []
    for path in [HERE/name for name in ("n2-q40.json", "n2-q80.json", "n4-q80.json", "n8-q80.json", "reference-restored.json")]+[COMMON]:
        record = json.loads(path.read_bytes())
        if record.get("status") != "passed": raise ValueError("successful receipt required")
        count = check_record(record)
        if not count: raise ValueError("receipt has no captured providers")
        records.append(dict(file=str(path.relative_to(ROOT)), provider_occurrences=count))
    strict = json.loads((HERE/"strict-sage.json").read_bytes())
    for relative, expected in strict["source_sha256"].items():
        # CI captures test/catalog sources, including JSON; all are already
        # whitelisted by ci/run.py. No private state path is accepted here.
        if not relative.startswith(("tests/", "ci/", "src/ibme/")) or ".." in Path(relative).parts:
            raise ValueError("unexpected CI fingerprint root")
        raw = subprocess.run(["git", "show", "11483c2:"+relative], cwd=ROOT, capture_output=True, check=True).stdout
        if hashlib.sha256(raw).hexdigest() != expected: raise ValueError("CI source fingerprint mismatch")
    print(json.dumps(dict(status="passed", receipts=records,
        provider_occurrences=sum(row["provider_occurrences"] for row in records),
        distinct_commit_file_pairs=len(CACHE), strict_CI_source_files=len(strict["source_sha256"]),
        strict_CI_fixed_source="11483c2", private_state_files_opened=0,
        reference_original_failure_has_no_provider_capture=True), indent=2))


if __name__ == "__main__": main()
