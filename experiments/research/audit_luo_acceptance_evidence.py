"""Recompute the selected historical Step17 ledger; no experiment is rerun.

The exported JSON is a descriptive audit, not a probability or security proof.
Raw CSVs are archived under docs/research/2026-10-11-luo-acceptance/evidence.
"""
from collections import Counter, defaultdict
import csv
import json
from pathlib import Path
import statistics

ROOT = Path(__file__).resolve().parents[2]
DEFAULT = ROOT / "docs/research/2026-10-11-luo-acceptance/evidence/historical"


def csv_rows(path):
    with path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    if any(None in row or None in row.values() for row in rows):
        raise ValueError("ragged CSV")
    return rows


def audit(directory=DEFAULT):
    if not __debug__:
        raise RuntimeError("audit requires Python assertions enabled; do not use -O")
    events = csv_rows(directory / "B-attempt-events.csv")
    calls = csv_rows(directory / "B-call-summary.csv")
    summary = json.loads((directory / "B-summary-v2.json").read_text(encoding="utf-8"))
    by_call = defaultdict(list)
    for event in events:
        by_call[event["call_id"]].append(event)
    assert len({row["call_id"] for row in calls}) == len(calls) == 111
    assert set(by_call) == {row["call_id"] for row in calls}
    natural_calls = [row for row in calls if row["call_id"].startswith("nat-")]
    natural = [row for row in events if row["call_id"].startswith("nat-")]
    for call in natural_calls:
        rows = by_call[call["call_id"]]
        assert [int(row["attempt"]) for row in rows] == list(range(1, int(call["attempts"]) + 1))
        assert not call["category"] and call["aligned"] == "True"
        assert int(call["accepted_attempt"]) == len(rows)
        assert [row["accepted"] for row in rows] == ["False"] * (len(rows) - 1) + ["True"]
        for field in ("ez", "elow", "ew0c"):
            assert all(row[field] in ("0", "1") for row in rows)
            assert sum(int(row[field]) for row in rows) == int(call[field])
        assert sum(int(row["ez"]) * int(row["elow"]) for row in rows) == int(call["ez_elow"])
        for row in rows:
            flags = [bool(int(row[f])) for f in ("ez", "elow", "ew0c")]
            assert (row["accepted"] == "True") == (not any(flags))
            assert row["combo"] == ("+".join(name for name, flag in zip(("z", "low", "w0c"), flags) if flag) or "accept")
    n = summary["natural"]
    assert len(natural_calls) == n["calls"] == 108
    assert len(natural) == n["attempts"] == 1000
    assert n["natural_aborts"] == sum(bool(row["category"]) for row in natural_calls) == 0
    totals = {field: sum(int(row[field]) for row in natural) for field in ("ez", "elow", "ew0c")}
    assert all(totals[field] == n[field] for field in totals)
    overlap = sum(int(row["ez"]) * int(row["elow"]) for row in natural)
    assert overlap == n["ez_elow"] == 363
    controls = [row for row in calls if not row["call_id"].startswith("nat-")]
    categories = dict(Counter(row["category"] for row in controls))
    assert len(controls) == summary["negative_controls"]["calls"] == 3
    assert categories == summary["negative_controls"]["categories"]
    for call in controls:
        rows = by_call[call["call_id"]]
        assert len(rows) == int(call["attempts"]) == 1
        assert rows[0]["category"] == call["category"] and rows[0]["accepted"] == "False"

    timings = csv_rows(directory / "D-raw-v2.csv")
    expected = {(fmt, length, rep) for fmt in ("reference", "compact") for length in (0, 256, 3924) for rep in range(5)}
    keys = [(row["format"], int(row["msg_bytes"]), int(row["rep"])) for row in timings]
    assert len(set(keys)) == len(keys) == 30 and set(keys) == expected
    assert all(not row["failure"] and row["rng_type"] == "deterministic" for row in timings)
    pairs = defaultdict(dict)
    for row in timings:
        pairs[int(row["msg_bytes"]), int(row["rep"])][row["format"]] = row
    differing_attempts = sum(pair["reference"]["sign_attempts"] != pair["compact"]["sign_attempts"] for pair in pairs.values())
    stats = {}
    for length in (0, 256, 3924):
        stats[str(length)] = {}
        for fmt in ("reference", "compact"):
            selected = [r for r in timings if int(r["msg_bytes"]) == length and r["format"] == fmt]
            stats[str(length)][fmt] = {
                "n": len(selected),
                **{field: statistics.median(float(row[field]) for row in selected)
                   for field in ("encrypt_seconds", "decrypt_seconds")},
                "ciphertext_bytes": sorted({int(row["ciphertext_bytes"]) for row in selected}),
            }
    deltas = {int(pair["reference"]["ciphertext_bytes"]) - int(pair["compact"]["ciphertext_bytes"]) for pair in pairs.values()}
    assert deltas == {13392}
    return {
        "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False,
        "provenance": "DeepSeek Step17 historical CSV; independently recounted, not rerun",
        "B": {"natural_calls": len(natural_calls), "natural_attempts": len(natural),
              "natural_aborts": n["natural_aborts"], **totals, "ez_elow": overlap,
              "negative_controls": categories, "rates_are_not_theoretical_probabilities": True},
        "D": {"rows": len(timings), "workload_pairs": len(pairs),
              "pairs_with_different_sign_attempts": differing_attempts,
              "median_seconds_by_application_bytes": stats,
              "ciphertext_reduction_bytes": 13392, "causal_speed_claim": False,
              "note": "format-specific random streams; same workload is not same randomness; old Setup/codec labels withdrawn"},
    }


if __name__ == "__main__":
    print(json.dumps(audit(), ensure_ascii=False, indent=2))
