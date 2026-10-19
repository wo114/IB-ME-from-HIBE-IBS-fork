"""Zero-entropy SRGG representation accounting; no allocation or new benchmark.

Separate a hypothetical full shape matrix from current ring/low-rank execution
and from measured serialized objects. The 64-byte slot is a scenario, not a
bound on QQ/interval storage, peak RSS, or the size of a key.
"""
from __future__ import annotations

import argparse
from decimal import Decimal, localcontext
from hashlib import sha256
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
BASE = Path("docs/research/team-b-delivery")
OLD = BASE / "2026-10-16-srgg-qualification/formal-candidates.json"
FINAL = BASE / "2026-10-18-srgg-source-schur"
SOURCES = (
    "experiments/research/candidates/srgg/representation_audit.py",
    "experiments/research/candidates/srgg/formal_candidates.py",
    "experiments/research/candidates/srgg/structured_geometry.py",
    "experiments/research/candidates/srgg/structured_samplef.py",
    "experiments/research/candidates/srgg/paper_backend.py",
    "experiments/research/candidates/srgg/paper_samplef.py",
    "experiments/research/candidates/srgg/paper_schur_samplef.py",
    "experiments/research/candidates/srgg/paper_schur_fourier.py",
    "experiments/research/candidates/srgg/paper_objects.py",
)


def _positive(value):
    if type(value) is not int or not 1 <= value <= 2**16:
        raise ValueError("bounded positive integer required")
    return value


def units(size):
    if type(size) is not int or not 1 <= size <= 2**128:
        raise ValueError("bounded positive byte count required")
    with localcontext() as context:
        context.prec = 128
        return {name: format(Decimal(size) / divisor, "f") for name, divisor in
                (("MB", 10**6), ("MiB", 2**20), ("GB", 10**9), ("GiB", 2**30))}


def matrix_scenario(*, degree, module_rows, slot_bytes=64):
    """Count slots for the SAME square ring operator and its dense expansion."""
    n, rows, width = map(_positive, (degree, module_rows, slot_bytes))
    dense, coefficients = (rows*n)**2, rows*rows*n
    dense_bytes, ring_bytes = dense*width, coefficients*width
    return {"degree": n, "module_rows": rows, "coefficient_dimension": rows*n,
            "assumed_bytes_per_slot": width, "dense_slots": dense,
            "ring_coefficient_slots": coefficients, "slot_ratio": n,
            "dense_payload_bytes": dense_bytes, "dense_payload_units": units(dense_bytes),
            "ring_payload_bytes": ring_bytes, "ring_payload_units": units(ring_bytes),
            "actual_peak_rss_bytes": None}


def row_scenario(rank, digits):
    columns = (2+digits)*rank
    return {"rank": rank, "digits": digits,
            "master": matrix_scenario(degree=512, module_rows=columns),
            "signature": matrix_scenario(degree=512, module_rows=columns+1)}


def build_report(root=ROOT):
    root, inputs = Path(root), {}

    def read(relative):
        raw = (root / relative).read_bytes()
        inputs[relative.as_posix()] = sha256(raw).hexdigest()
        return json.loads(raw)

    old = read(OLD)
    historical = []
    for row in old["conditional_candidates"]:
        p = row["parameters"]
        if (p["degree"], p["digits"], p["rank"]) not in [(512, 8, d) for d in (2, 3, 4)]:
            raise ValueError("historical candidate scope changed")
        scenario = row_scenario(p["rank"], p["digits"])
        for phase in ("master", "signature"):
            saved = row["resources"][phase+"_geometry"]
            if (saved["single_dense_matrix_payload_scenarios_bytes"]["64"] !=
                    scenario[phase]["dense_payload_bytes"] or
                    saved["module_square_coefficient_count"] !=
                    scenario[phase]["ring_coefficient_slots"]):
                raise ValueError("historical matrix count mismatch")
        historical.append(scenario)
    if sorted(row["rank"] for row in historical) != [2, 3, 4]:
        raise ValueError("exactly three historical ranks required")
    objects = []
    for rank, label in enumerate(("i", "ii", "iii"), 2):
        relative = FINAL / f"param-{label}-bounded-final-lifecycle.json"
        receipt = read(relative)
        p = receipt["published_inputs"]
        if ((p["degree"], p["digits"], p["rank"], p["Q"]) != (512, 2, rank, 15744063)
                or receipt["status"] != "functional-pass"
                or receipt["backend_class"] !=
                "experiments.research.candidates.srgg.paper_schur_backend.SourceSchurBackend"
                or receipt["parameters_are_formal"] is not False
                or any(receipt[k].get("dense_coefficient_matrix_materialized") is not False
                       for k in ("master_sampler", "signature_sampler"))):
            raise ValueError("published execution scope changed")
        objects.append({"profile": p["name"], "receipt": relative.as_posix(),
                        "object_sizes_bytes": receipt["object_sizes_bytes"],
                        "identity_bytes": receipt["identity_bytes"],
                        "message_bytes": receipt["message_bytes"],
                        "randomness": receipt["randomness"],
                        "dense_coefficient_matrix_materialized": False,
                        "historical_single_lifecycle_only": True,
                        "peak_rss_bytes": None})
    return {"schema": "IBME/SRGG-REPRESENTATION-ACCOUNTING/1",
            "scope": "counts and existing public receipts; no entropy or new cryptographic execution",
            "base_commit": "fa912804749d64977078579e1691a2ed083171c2",
            "historical_w8_scenarios": sorted(historical, key=lambda x: x["rank"]),
            "published_w2_scenarios": [row_scenario(d, 2) for d in (2, 3, 4)],
            "published_w2_measured_json_objects": objects,
            "interpretation": {
                "64_bytes_is_assumed_not_measured_or_bounded": True,
                "512_slot_ratio_is_not_a_time_or_RSS_speedup": True,
                "full_ring_square_is_not_required_by_low_rank_backend": True,
                "object_wire_is_distinct_from_sampler_workspace": True,
                "current_backends_already_use_ring_structure": True,
                "frozen_receipts_and_sampler_sources_modified": False,
            },
            "input_sha256": inputs,
            "source_sha256": {p: sha256((root/p).read_bytes()).hexdigest() for p in SOURCES},
            "security_claim": "none", "backend_admitted": False,
            "parameters_are_formal": False, "nist_security_category": None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    raw = (json.dumps(build_report(), ensure_ascii=False, indent=2, sort_keys=True)+"\n").encode("utf-8")
    if args.check:
        if args.output.read_bytes() != raw:
            raise SystemExit("representation accounting differs from current inputs")
        print("representation accounting matches")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(raw)


if __name__ == "__main__":
    main()
