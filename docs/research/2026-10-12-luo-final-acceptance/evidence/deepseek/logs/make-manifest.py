"""Generate MANIFEST.json for the step-24 deliverable directory.

Run from anywhere: the workspace root is the parent of this script's logs/
directory, so the manifest always lands beside the deliverables rather than
inside logs/. Self-non-hashing: MANIFEST.json itself is excluded. The
sandbox-blocked .tmp-pytest subtree (see findings.json ENV2) is skipped and
recorded, never claimed as a deliverable.
"""
import hashlib
import json
from pathlib import Path

SCRIPT = Path(__file__).resolve()
LOGS = SCRIPT.parent
WS = LOGS.parent
EXCLUDED_NAMES = {"MANIFEST.json"}
EXCLUDED_PREFIXES = (".tmp-pytest",)


def iter_files():
    for path in sorted(WS.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(WS).as_posix()
        if path.name in EXCLUDED_NAMES:
            continue
        if any(rel == p or rel.startswith(p + "/") for p in EXCLUDED_PREFIXES):
            continue
        yield rel, path


def main():
    files = {}
    skipped = []
    for rel, path in iter_files():
        try:
            files[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            skipped.append(dict(path=rel, error=type(exc).__name__))
    payload = dict(
        schema="IBME/DEEPSEEK-STEP24-DELIVERABLE/1",
        date="2026-10-12",
        subject_commit="e5e0b97752f9291ce7621dd830d665baff86aef8",
        self_non_hashing=True,
        excluded_from_manifest=sorted(EXCLUDED_NAMES),
        skipped_unreadable=skipped,
        skipped_reason=("sandbox-blocked .tmp-pytest subtree from an aborted pytest run; "
                        "see findings.json environment_limitations ENV2"),
        files=files,
    )
    (WS / "MANIFEST.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(dict(manifest_files=len(files), skipped=skipped), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
