"""Fail-closed ABB full-basis representation and consumer feasibility probe.

The input is a public ABB noise-tradeoff parameter card.  This probe does not
construct a matrix, key, identity oracle, ciphertext, random tape, or sampler.
It accounts for the complete m-by-m basis required by ABB BasisDel/RandBasis
and for the access pattern of the current exact GPV consumer.  The result is a
current-implementation engineering gate, not an impossibility theorem and not
a security admission.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import sys
import time


SOURCE_SCHEMA = "A/ABB-NOISE-TRADEOFF/2"
SCHEMA = "A/ABB-BASIS-REPRESENTATION/2"
RUNTIME_SCHEMA = "A/ABB-BASIS-REPRESENTATION-RUNTIME/2"
PRIVATE_ENTRY_WIRE_FLOOR = 6
CURRENT_MAX_BLOB_BYTES = 128 * 2**20
PAYLOAD_SAMPLEPRE_CALLS = 256
BYTE_RATES = {
    "1_GiB_per_second": 2**30,
    "10_GiB_per_second": 10 * 2**30,
    "100_GiB_per_second": 100 * 2**30,
}
ENTRY_RATES = {
    "1e9_entries_per_second": 10**9,
    "1e12_entries_per_second": 10**12,
}


def _integer(value, name, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} requires an exact integer >= {minimum}")
    return value


def _ceil_div(numerator, denominator):
    return (numerator + denominator - 1) // denominator


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _relative_or_name(path, root):
    try:
        return str(path.resolve().relative_to(root))
    except ValueError:
        return path.name


def _validate_source(card):
    if not isinstance(card, dict) or card.get("schema") != SOURCE_SCHEMA:
        raise ValueError("ABB noise-tradeoff source schema required")
    if (card.get("security_claim") != "none" or
            card.get("backend_admitted") is not False or
            card.get("parameters_are_formal") is not False):
        raise ValueError("source card must retain none/false/false security metadata")
    for name in ("root_or_key_generations", "ciphertext_generations", "private_entropy_bytes"):
        if card.get(name) != 0:
            raise ValueError("public source card must contain zero private execution")
    fixed = card.get("fixed_inputs")
    if not isinstance(fixed, dict):
        raise ValueError("source fixed inputs required")
    q_text = fixed.get("q")
    if not isinstance(q_text, str) or not q_text.isascii() or not q_text.isdecimal():
        raise ValueError("source modulus must use canonical decimal text")
    q = int(q_text)
    q_bits = _integer(fixed.get("q_bits"), "q_bits", 1)
    if q <= 2 or q.bit_length() != q_bits:
        raise ValueError("source modulus metadata mismatch")
    calls = _integer(fixed.get("independently_encrypted_bits"), "encrypted bits", 1)
    if calls != PAYLOAD_SAMPLEPRE_CALLS or fixed.get("seed_bytes") != 32:
        raise ValueError("this probe requires the declared 32-byte ABB payload")
    rows = card.get("rows")
    if not isinstance(rows, list) or not rows:
        raise ValueError("nonempty ABB candidate rows required")
    identifiers = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("ABB candidate row must be an object")
        identifier = row.get("candidate_id")
        if not isinstance(identifier, str) or not identifier or identifier in identifiers:
            raise ValueError("unique ABB candidate identifiers required")
        identifiers.add(identifier)
        n = _integer(row.get("n"), "LWE dimension", 1)
        if row.get("q") != q or row.get("q_bits") != q_bits:
            raise ValueError("source row modulus metadata mismatch")
        dimension = _integer(row.get("root_dimension"), "ABB basis dimension", n)
        if (row.get("parent_dimension") != dimension or row.get("leaf_dimension") != dimension):
            raise ValueError("ABB fixed-dimension row required")
        lower = row.get("minimum_wire_bytes")
        if not isinstance(lower, dict):
            raise ValueError("ABB public size lower bounds required")
        basis_floor = PRIVATE_ENTRY_WIRE_FLOOR * dimension**2
        for name in ("root_full_basis", "parent_stored_full_basis", "leaf_material"):
            if lower.get(name) != basis_floor:
                raise ValueError("source complete-basis wire floor mismatch")
        residue_width = (q_bits + 7) // 8
        if lower.get("public_root_residues") != n * dimension * residue_width:
            raise ValueError("source public-matrix wire floor mismatch")
        if lower.get("capsule_coefficients") != calls * (dimension + 1) * residue_width:
            raise ValueError("source ciphertext wire floor mismatch")
        if row.get("runtime_admitted") is not False:
            raise ValueError("source must not pre-admit an ABB runtime candidate")
    candidate_fields = (
        "root_trapdoor_comparison_candidates",
        "ciphertext_comparison_candidates",
        "comparison_model_candidates",
        "complete_runtime_candidates",
    )
    classification = {}
    for name in candidate_fields:
        values = card.get(name)
        if (not isinstance(values, list) or any(not isinstance(value, str) for value in values) or
                len(values) != len(set(values)) or
                any(value not in identifiers for value in values)):
            raise ValueError("source candidate summary mismatch")
        classification[name] = list(values)
    root = set(classification["root_trapdoor_comparison_candidates"])
    ciphertext = set(classification["ciphertext_comparison_candidates"])
    joint = set(classification["comparison_model_candidates"])
    runtime = set(classification["complete_runtime_candidates"])
    if not joint <= root & ciphertext:
        raise ValueError("source joint candidate summary mismatch")
    for row in rows:
        identifier = row["candidate_id"]
        expected = (
            ("root_trapdoor_comparison_gate", identifier in root),
            ("ciphertext_comparison_gate", identifier in ciphertext),
            ("comparison_model_gate", identifier in joint),
            ("runtime_admitted", identifier in runtime),
        )
        if any(row.get(field) is not value for field, value in expected):
            raise ValueError("source row/candidate classification mismatch")
    return fixed, rows, classification


def _seconds_for_units(units, rates):
    return {name: _ceil_div(units, rate) for name, rate in rates.items()}


def _row_accounting(row):
    dimension = row["root_dimension"]
    entries = dimension**2
    basis_bytes = PRIVATE_ENTRY_WIRE_FLOOR * entries
    # A successful current GPV call visits m projection-weight rows and m
    # basis columns.  Counting only one m-entry read of each gives 2*m^2;
    # center/step updates, rational arithmetic, allocation and geometry are
    # deliberately omitted.  RandBasis needs at least m successful candidates.
    samplepre_touches = 2 * entries
    payload_touches = PAYLOAD_SAMPLEPRE_CALLS * samplepre_touches
    randbasis_touches = dimension * samplepre_touches
    read_write_bytes = 2 * basis_bytes
    lower = row["minimum_wire_bytes"]
    return {
        "candidate_id": row["candidate_id"],
        "n": row["n"],
        "q": row["q"],
        "q_bits": row["q_bits"],
        "basis_dimension": dimension,
        "complete_basis_entries": entries,
        "current_private_codec_minimum_bytes": basis_bytes,
        "public_matrix_minimum_bytes": lower["public_root_residues"],
        "raw_32_byte_ciphertext_minimum_bytes": lower["capsule_coefficients"],
        "fits_current_128_MiB_secret_blob": basis_bytes <= CURRENT_MAX_BLOB_BYTES,
        "ideal_external_one_basis_read_seconds": _seconds_for_units(basis_bytes, BYTE_RATES),
        "ideal_external_parent_read_plus_output_write_bytes": read_write_bytes,
        "ideal_external_parent_read_plus_output_write_seconds": _seconds_for_units(
            read_write_bytes, BYTE_RATES
        ),
        "current_one_SamplePre_coefficient_touch_floor": samplepre_touches,
        "current_256_SamplePre_coefficient_touch_floor": payload_touches,
        "current_successful_RandBasis_coefficient_touch_floor": randbasis_touches,
        "current_256_SamplePre_touch_floor_seconds": _seconds_for_units(
            payload_touches, ENTRY_RATES
        ),
        "current_RandBasis_touch_floor_seconds": _seconds_for_units(
            randbasis_touches, ENTRY_RATES
        ),
        "touch_floor_scope": (
            "current exact GPV coefficient reads only; excludes geometry, vector updates, "
            "rational arithmetic, rank tests, ToBasis, allocation and failures"
        ),
        "external_storage_only_runtime_candidate": False,
        "external_storage_only_blockers": [
            "entrywise externalization leaves the complete-basis entry count and current codec floor unchanged",
            "current KernelBasis and GPV consumers require resident finite sequences",
            "current GPV retains m-by-m rational projection weights",
            "current successful RandBasis invokes at least m complete GPV samples",
            "public matrix and ciphertext sizes are unaffected by private-basis storage",
        ],
    }


def _representation_options():
    return [
        {
            "id": "current-tuple-sage-full-basis",
            "preserves_current_ABB_semantics": True,
            "current_consumer_compatible": True,
            "reduces_complete_basis_entries": False,
            "runtime_candidate": False,
        },
        {
            "id": "resident-packed-matrix-v1",
            "implementation": "src/ibme/lattice/matrix_sampling/packed.py",
            "backing": "resident immutable bytes with a bounded native block cache; not external storage",
            "declared_limits": {
                "max_dimension": 2**20,
                "max_entries": 2**24,
                "max_payload_bytes": 512 * 2**20,
                "max_coordinate_bits": 256,
            },
            "preserves_entry_values_within_its_profile": True,
            "current_consumer_compatible": False,
            "incompatibilities": [
                "target dimension exceeds the packed profile dimension limit",
                "target entries exceed the packed profile entry and payload limits",
                "ABB private coordinates allow up to 4096 bits",
                "KernelBasis and MatrixFiniteGPV require tuple/list rows",
            ],
            "runtime_candidate": False,
        },
        {
            "id": "hypothetical-exact-external-chunks",
            "preserves_entrywise_full_basis": True,
            "current_consumer_compatible": False,
            "reduces_complete_basis_entries": False,
            "reduces_public_matrix_or_ciphertext": False,
            "required_rewrites": [
                "streaming complete-kernel validation without dense determinant/materialization",
                "out-of-core exact Gram-Schmidt/projection-weight provider",
                "streaming GPV residual updates",
                "out-of-core ToBasis/HNF and RandBasis independence/postprocessing",
            ],
            "unmet_security_obligation": (
                "show that rewritten BasisDel/RandBasis output and SamplePre retain the paper and "
                "finite-adaptation distributions"
            ),
            "runtime_candidate": False,
        },
        {
            "id": "seed-only-replay",
            "preserves_current_ABB_semantics": False,
            "reason": (
                "the RandBasis tape alone cannot reproduce samples without the complete input "
                "trapdoor; retaining an ancestor trapdoor in a delegated key breaks the key boundary, "
                "and replacing true coins by a PRG adds an unanalysed assumption"
            ),
            "runtime_candidate": False,
        },
        {
            "id": "MP12-or-gadget-trapdoor-substitution",
            "preserves_current_ABB_semantics": False,
            "changes_algorithm": True,
            "reason": "compact gadget trapdoors are a separately named implementation route, not ABB BasisDel",
            "runtime_candidate": False,
        },
    ]


def build_representation_report(source_card_path):
    """Read and account for public metadata only; fail on changed claims."""
    started = time.monotonic()
    source_card_path = Path(source_card_path)
    raw = source_card_path.read_bytes()
    try:
        card = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("valid UTF-8 JSON ABB parameter card required") from exc
    fixed, rows, classification = _validate_source(card)
    root = Path(__file__).resolve().parents[3]
    source_files = (
        "experiments/research/abb_rom/basis_representation_probe.py",
        "src/ibme/hibe/abb_rom/objects.py",
        "src/ibme/hibe/abb_rom/primitives.py",
        "src/ibme/lattice/chkp/basis.py",
        "src/ibme/lattice/matrix_sampling/basis.py",
        "src/ibme/lattice/matrix_sampling/gpv.py",
        "src/ibme/lattice/matrix_sampling/randbasis.py",
        "src/ibme/lattice/matrix_sampling/packed.py",
        "papers/2010_lattice_basis_delegation_agrawal.pdf",
    )
    report = {
        "schema": SCHEMA,
        "source": {
            "path": _relative_or_name(source_card_path, root),
            "schema": card["schema"],
            "sha256": hashlib.sha256(raw).hexdigest(),
            "fixed_inputs": fixed,
            "candidate_classification": classification,
        },
        "paper_contract": {
            "source": "Agrawal-Boneh-Boyen, CRYPTO 2010, fixed local PDF",
            "BasisDel_section_3_1": [
                "multiply every parent basis vector by R",
                "complete the resulting independent set to a full target-lattice basis",
                "apply RandBasis and output the resulting full basis",
            ],
            "ROM_HIBE_section_4_1": (
                "a delegated secret key is the full short basis and Decrypt calls SamplePre with it"
            ),
            "representation_change_is_not_automatically_a_distribution_proof": True,
        },
        "current_consumer_contract": {
            "KernelBasis": "validates finite m-by-m integer rows and materializes an exact Sage matrix",
            "BasisDel": "materializes R, parent basis, transformed basis, completion and randomized basis",
            "MatrixFiniteGPV": (
                "accepts tuple/list basis rows, materializes columns, and retains m-by-m exact "
                "projection weights"
            ),
            "MatrixFiniteRandBasis": (
                "retains candidate vectors and materializes the complete chosen matrix before ToBasis"
            ),
            "PackedMatrix": "resident bytes only and not accepted as a KernelBasis/GPV basis",
        },
        "accounting_constants": {
            "private_entry_wire_floor_bytes": PRIVATE_ENTRY_WIRE_FLOOR,
            "private_entry_wire_floor_reason": "sign byte + uint32 length + at least one magnitude byte",
            "current_secret_blob_limit_bytes": CURRENT_MAX_BLOB_BYTES,
            "payload_SamplePre_calls": PAYLOAD_SAMPLEPRE_CALLS,
            "illustrative_byte_rates": BYTE_RATES,
            "illustrative_entry_touch_rates": ENTRY_RATES,
            "rate_results_are_lower_bound_comparators_not_benchmarks": True,
        },
        "rows": [_row_accounting(row) for row in rows],
        "representation_options": _representation_options(),
        "complete_runtime_candidates": [],
        "decision": (
            "do not implement external backing alone: it cannot make any tested ABB row runnable "
            "under the current complete-basis consumers"
            + (
                "; the source also has no joint comparison candidate"
                if not classification["comparison_model_candidates"]
                else "; every source joint comparison candidate remains blocked by these consumers"
            )
        ),
        "next_required_breakthrough": (
            "a cited ABB-compatible algorithm that avoids expanding the randomized full basis in "
            "BasisDel and SamplePre, with a new distribution/security mapping; none exists in this repository"
        ),
        "not_an_impossibility_theorem": True,
        "root_or_key_generations": 0,
        "ciphertext_generations": 0,
        "private_entropy_bytes": 0,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "logical_cpus": os.cpu_count(),
        },
        "source_sha256": {name: _sha256(root / name) for name in source_files},
        "measurements": {
            "total_seconds": time.monotonic() - started,
            "process_max_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        },
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
    }
    return report


def runtime_summary(report):
    return {
        "schema": RUNTIME_SCHEMA,
        "source_schema": report["schema"],
        "measurements": report["measurements"],
        "environment": report["environment"],
        "row_count": len(report["rows"]),
        "repetitions": 1,
        "rng": "none; public JSON validation and exact integer accounting only",
        "root_or_key_generations": 0,
        "ciphertext_generations": 0,
        "private_entropy_bytes": 0,
        "complete_runtime_candidates": [],
        "source_root_trapdoor_comparison_candidate_count": len(
            report["source"]["candidate_classification"]["root_trapdoor_comparison_candidates"]
        ),
        "source_ciphertext_comparison_candidate_count": len(
            report["source"]["candidate_classification"]["ciphertext_comparison_candidates"]
        ),
        "source_joint_comparison_candidate_count": len(
            report["source"]["candidate_classification"]["comparison_model_candidates"]
        ),
        "decision": report["decision"],
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-card", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runtime-output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.resolve() == args.runtime_output.resolve():
        raise ValueError("distinct report and runtime output paths required")
    for path in (args.output, args.runtime_output):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as stream:
            stream.write('{"status":"public-probe-started"}\n')
    report = build_representation_report(args.source_card)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    args.runtime_output.write_text(
        json.dumps(runtime_summary(report), indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"{len(report['rows'])} ABB rows; zero keys; "
        "external-storage-only runtime candidates: 0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
