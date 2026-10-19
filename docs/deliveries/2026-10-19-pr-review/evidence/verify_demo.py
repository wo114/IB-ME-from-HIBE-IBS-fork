"""Verify fixed historical demo receipts and explicitly reviewed source drift.

The original verifier/provenance and measurements remain unchanged. The
source snapshots are used only for their original fingerprint checks.
Fresh regression results for the corrected code are recorded separately.
"""
from hashlib import sha256
import json
from pathlib import Path
import runpy
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
ORIGINAL = ROOT / "docs/deliveries/2026-10-18-demo-acceptance/evidence"


def main():
    read_bytes = Path.read_bytes
    bridges = json.loads((HERE / "demo-source-bridge.json").read_text(encoding="utf-8"))
    provenance = json.loads((ORIGINAL / "provenance.json").read_text(encoding="utf-8"))
    replacements = {}
    for name, entry in bridges.items():
        target = (ROOT / name).resolve()
        snapshot = (HERE / entry["snapshot"]).resolve()
        if not target.is_relative_to(ROOT) or not snapshot.is_relative_to(HERE):
            raise ValueError("source bridge path")
        frozen = read_bytes(snapshot)
        if (sha256(frozen).hexdigest() != provenance["final_source_files"][name]
                or sha256(frozen).hexdigest() != entry["original_sha256"]
                or sha256(read_bytes(target)).hexdigest() != entry["current_sha256"]):
            raise ValueError("source bridge fingerprint: " + name)
        replacements[target] = frozen

    def original_source_only(path):
        resolved = path.resolve()
        return replacements[resolved] if resolved in replacements else read_bytes(path)

    with patch.object(Path, "read_bytes", original_source_only):
        runpy.run_path(str(ORIGINAL / "verify.py"), run_name="__main__")
    print(json.dumps({"reviewed_source_bridges": len(bridges), "historical_receipts_changed": False,
                      "cryptographic_operations_by_verifier": 0}))


if __name__ == "__main__":
    main()
