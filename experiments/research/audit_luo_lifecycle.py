"""Independent Step20 CSV audit. Reads public evidence only, never key bytes.

Pass the directory containing the three CSVs and run-metadata-<run>.json.
This audits the specified 54-call matrix, not a security or probability claim.
"""

import argparse
import csv
import json
import math
from pathlib import Path
import statistics


LENGTHS = (1, 5, 64)
MESSAGES = (0, 256, 4096)
EXPECTED = {(s, i, m, r) for s in range(3) for i in LENGTHS
            for m in MESSAGES for r in range(2)}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def key(row):
    return tuple(int(row[field]) for field in
                 ("system", "identity_len", "message_len", "repetition"))


def seconds(row, field="seconds"):
    value = float(row[field])
    require(math.isfinite(value) and value >= 0, "invalid elapsed seconds")
    return value


def unique(rows, key_function):
    result = {}
    for row in rows:
        identity = key_function(row)
        require(identity not in result, f"duplicate evidence key: {identity}")
        result[identity] = row
    return result


def audit_rows(calls, events, metadata):
    require(metadata["completed"] is True, "run not completed")
    require(metadata["failure_type"] is None and not metadata["interrupted"], "failed run")
    require(metadata["security_claim"] == "none" and metadata["backend_admitted"] is False
            and metadata["parameters_are_formal"] is False, "invalid security labels")
    indexed = unique(calls, key)
    require(set(indexed) == EXPECTED, "missing or unexpected normal calls")
    for row in calls:
        require(row["status"] == "ok" and not row["failure_type"], "failed normal call")
        require(row["verify_reference"] == row["verify_compact"] == "True", "Verify=False")
        require(row["math_fields_equal"] == row["roundtrip_equal"] == "yes", "roundtrip mismatch")
        require(int(row["reference_bytes"]) == 29455 and int(row["compact_bytes"]) == 16063,
                "unexpected default signature size")
        require(1 <= int(row["sign_attempts"]) <= 1024, "invalid Sign attempts")
        seconds(row, "sign_seconds")
    for row in events:
        seconds(row)
        require(row["status"] == "ok" and not row["error_type"], "failed event")
    setups = unique([r for r in events if r["stage"] == "setup"], key)
    require(set(setups) == {(s, 0, 0, -1) for s in range(3)}, "incomplete Setup events")
    restores = unique([r for r in events if r["stage"] == "master_state_recover"], key)
    expected_restores = {(s, identity, 0, -1): count for s in range(3)
                         for count, identity in enumerate((0, 1, 5, 64))}
    require(set(restores) == set(expected_restores), "incomplete master restoration events")
    require(all(int(restores[k]["cache_entries"]) == count for k, count in expected_restores.items()),
            "master restoration depth mismatch")

    sign_rows = unique([r for r in events if r["stage"] == "sign"], key)
    require(set(sign_rows) == EXPECTED, "Sign events do not match call denominator")
    for identity, row in indexed.items():
        event = sign_rows[identity]
        require(int(event["sign_attempts"]) == int(row["sign_attempts"]), "attempt ledger mismatch")
        require(seconds(event) == seconds(row, "sign_seconds"), "Sign timer mismatch")

    for stage in ("encode", "decode", "verify"):
        selected = unique([r for r in events if r["stage"] == stage],
                          lambda row: (key(row), row["format"]))
        require(set(selected) == {(k, fmt) for k in EXPECTED for fmt in ("reference", "compact")},
                f"incomplete {stage} pairs")
        for row in selected.values():
            if stage in ("decode", "verify"):
                require(row["math_fields_equal"] == "yes", f"invalid {stage} result")

    for stage in ("extract_cold", "extract_cached", "signing_key_recover"):
        selected = unique([r for r in events if r["stage"] == stage],
                          lambda row: (int(row["system"]), int(row["identity_len"])))
        require(set(selected) == {(s, n) for s in range(3) for n in LENGTHS}, f"incomplete {stage}")
        if stage == "extract_cached":
            require(all(int(r["extract_attempts"]) == 0 for r in selected.values()), "cache resampled")
        if stage == "extract_cold":
            require(all(1 <= int(r["extract_attempts"]) <= 1024 for r in selected.values()), "bad Extract count")

    grouped = {}
    for row in events:
        # Do not pool identity/message lengths for performance claims.
        identity = (row["stage"], row["format"], int(row["identity_len"]), int(row["message_len"]))
        grouped.setdefault(identity, []).append(seconds(row))
    return {
        "normal_calls": len(indexed), "sign_attempts": sum(int(r["sign_attempts"]) for r in calls),
        "normal_failures": 0, "scope": "complete recorded matrix; NOT theoretical abort bound",
        "per_cell_timings": [dict(stage=k[0], format=k[1], identity_len=k[2], message_len=k[3],
                                  n=len(v), median_seconds=statistics.median(v),
                                  min_seconds=min(v), max_seconds=max(v))
                             for k, v in sorted(grouped.items())],
    }


def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def audit_sizes(rows):
    # Frozen profile wire sizes independently derived from its framing/layout.
    cells = {("public_key_wire", 0, 0): 248000,
             ("master_state_wire", 0, 0): 291072,
             ("master_state_wire", 0, 1): 356681,
             ("master_state_wire", 0, 3): 487966,
             ("identity_signing_key_wire", 1, 1): 313662,
             ("identity_signing_key_wire", 5, 2): 313666,
             ("identity_signing_key_wire", 64, 3): 313725}
    expected = {(s, *k): size for s in range(3) for k, size in cells.items()}
    indexed = unique(rows, lambda r: (int(r["system"]), r["component"],
                                     int(r["identity_len"]), int(r["cache_entries"])))
    require(set(indexed) == set(expected), "incomplete or unexpected size cells")
    for k, size in expected.items():
        require(int(indexed[k]["bytes"]) == size and str(indexed[k]["includes_public_key"]) == "True",
                "incorrect size or public-key inclusion")


def audit(directory, run_id):
    calls = read_csv(directory / f"luo-sign-calls-{run_id}.csv")
    events = read_csv(directory / f"luo-single-call-ledger-{run_id}.csv")
    metadata = json.loads((directory / f"run-metadata-{run_id}.json").read_text(encoding="utf-8-sig"))
    audit_sizes(read_csv(directory / f"primitive-sizes-{run_id}.csv"))
    return audit_rows(calls, events, metadata)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--run-id", default="main")
    arguments = parser.parse_args()
    print(json.dumps(audit(arguments.directory, arguments.run_id), ensure_ascii=False, indent=2))
