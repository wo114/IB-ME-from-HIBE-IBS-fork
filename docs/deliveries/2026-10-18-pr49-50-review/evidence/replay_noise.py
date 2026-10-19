"""Replay public geometry/CDF and reclassify the original finite estimates.

The lattice estimator is deliberately not rerun. Its original fields and
elapsed times remain historical inputs, rather than new measurements.
"""

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import time

from experiments.research.abb_rom.noise_tradeoff_probe import (
    build_tradeoff_report,
    finalize_comparison,
)


ROOT = Path(__file__).resolve().parents[4]
SOURCE = ROOT / "docs/research/team-a-delivery/2026-10-18-abb-noise-tradeoff/parameter-card.json"


def mathematical_payload(report):
    payload = deepcopy(report)
    for key in ("environment", "source_sha256", "measurements"):
        payload.pop(key)
    payload["finite_noise"].pop("build_seconds")
    return payload


def replay():
    started = time.monotonic()
    raw = SOURCE.read_bytes()
    original = json.loads(raw)
    current = build_tradeoff_report(tuple(row["n"] for row in original["rows"]), build_cdf=True)
    current["estimator"] = deepcopy(original["estimator"])
    for row, frozen in zip(current["rows"], original["rows"], strict=True):
        row["estimator_results"] = deepcopy(frozen["estimator_results"])
    finalize_comparison(current)
    if mathematical_payload(current) != mathematical_payload(original):
        raise ValueError("current geometry, CDF, or comparison decisions differ from the original card")
    current["measurements"]["total_seconds"] = time.monotonic() - started
    current["review_replay"] = {
        "original_head": "fcc79e4de670102c6ac39df01c7f231ff8d0468b",
        "source_card": str(SOURCE.relative_to(ROOT)).replace("\\", "/"),
        "source_card_sha256": hashlib.sha256(raw).hexdigest(),
        "geometry_and_finite_cdf_recomputed": True,
        "mathematical_payload_matches_original": True,
        "estimator_rerun": False,
        "estimator_results_and_timings_reused_from_original": True,
        "current_rop_validation": "exact int/float, finite, conversion-safe; summaries reset on each call",
    }
    return current


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = replay()
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
    print("4 public rows and finite CDF replayed; original estimates reused; mathematical payload unchanged")


if __name__ == "__main__":
    main()
