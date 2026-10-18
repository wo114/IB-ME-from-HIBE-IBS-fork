"""ABB-ROM q*alpha tradeoff with an actual finite noise table.

This public probe joins four facts for the *same* projected configuration:
the ABB q/5 correctness inequality, the current finite rounded-continuous
Gaussian support, separate root-trapdoor and ciphertext lattice-estimator
comparison models, and complete-basis/wire lower bounds.  It never constructs
a root, basis, key, identity oracle matrix, ciphertext, or private random tape.
Passing the comparison model is not a security admission and does not make a
configuration runnable.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import sys
import time
from fractions import Fraction
from math import isfinite, isqrt

from ibme.lattice.chkp.noise_budget import RoundedNoiseParams
from ibme.lattice.chkp.rounded_noise import build_rounded_noise

from .scaled_parameter_screen import abb_projection, run_estimators


Q208 = 411376139330301510538742295639337626245683966408394965837151957
TAIL_BITS = 128
MASS_BITS = 256
PRECISION_BITS = 320
MAX_RADIUS = 8192
ANCHOR_Q = 65537
COMPARISON_BITS = 128
DEFAULT_DIMENSIONS = (9472, 9600, 9728, 10240)
ROOT_REQUIRED_ESTIMATES = (
    "sis_lattice-classical",
    "sis_lattice-quantum",
)
CIPHERTEXT_REQUIRED_ESTIMATES = (
    "primal_usvp-classical",
    "dual-classical",
    "primal_usvp-quantum",
    "dual-quantum",
)


def maximum_finite_scaled_width(*, tail_bits=TAIL_BITS, max_radius=MAX_RADIUS):
    """Largest integer width whose certified cutoff fits max_radius."""
    if (type(tail_bits) is not int or not 8 <= tail_bits <= 256 or
            type(max_radius) is not int or not 1 <= max_radius <= 16384):
        raise ValueError("bounded finite-noise tail/radius required")
    width = isqrt(max_radius * max_radius // (tail_bits + 1))
    while (width + 1) ** 2 * (tail_bits + 1) <= max_radius**2:
        width += 1
    return width


FINITE_SCALED_WIDTH = maximum_finite_scaled_width()


def build_finite_noise_certificate():
    """Actually build the exact public CDF used for q*alpha=721."""
    started = time.monotonic()
    params = RoundedNoiseParams(
        ANCHOR_Q,
        Fraction(FINITE_SCALED_WIDTH, ANCHOR_Q),
        tail_bits=TAIL_BITS,
        mass_bits=MASS_BITS,
        precision_bits=PRECISION_BITS,
        max_radius=MAX_RADIUS,
    )
    table = build_rounded_noise(params)
    certificate = table.certificate()
    return {
        "built": True,
        "build_seconds": time.monotonic() - started,
        "anchor_modulus": ANCHOR_Q,
        "anchor_modulus_used_for_ciphertext": False,
        "scaled_width": FINITE_SCALED_WIDTH,
        "target": "round(continuous Gaussian of width q*alpha)",
        "radius": table.radius,
        "support_count": len(table.thresholds),
        "draw_bytes": table.draw_bytes,
        "certificate": certificate,
    }


def finite_noise_projection():
    """Metadata-only counterpart used by zero-private-work unit tests."""
    square = FINITE_SCALED_WIDTH**2 * (TAIL_BITS + 1)
    radius = isqrt(square) + int(isqrt(square) ** 2 < square)
    return {
        "built": False,
        "build_seconds": None,
        "anchor_modulus": ANCHOR_Q,
        "anchor_modulus_used_for_ciphertext": False,
        "scaled_width": FINITE_SCALED_WIDTH,
        "target": "round(continuous Gaussian of width q*alpha)",
        "radius": radius,
        "support_count": 2 * radius + 1,
        "draw_bytes": (MASS_BITS + 7) // 8,
        "certificate": None,
    }


def _phase_accounting(row):
    noise = row["noise"]
    continuous_squared = int(noise["continuous_squared_upper"])
    continuous = isqrt(continuous_squared)
    if continuous * continuous != continuous_squared:
        raise ArithmeticError("ABB public continuous bound must be an exact square")
    used = Fraction(noise["rounding_error_upper"]) + continuous
    radius = Fraction(noise["phase_radius"])
    return {
        "used_upper": str(used),
        "radius": str(radius),
        "strict_margin": str(radius - used),
        "used_fraction_of_radius": str(used / radius),
    }


def build_tradeoff_report(dimensions=DEFAULT_DIMENSIONS, *, build_cdf=True):
    """Build public same-group rows; no secret object or entropy is touched."""
    from sage.all import ZZ
    from sage.version import version as sage_version

    dimensions = tuple(dimensions)
    if (not dimensions or len(set(dimensions)) != len(dimensions) or
            any(type(n) is not int or not 2 <= n <= 16384 for n in dimensions)):
        raise ValueError("distinct ABB projection dimensions in 2..16384 required")
    if not ZZ(Q208).is_prime(proof=True):
        raise ValueError("fixed q208 candidate must be a proven prime")
    finite_noise = build_finite_noise_certificate() if build_cdf else finite_noise_projection()
    rows = []
    for n in dimensions:
        row = abb_projection(n, Q208, noise_width=FINITE_SCALED_WIDTH)
        row.update(
            candidate_id=f"abb-rom-n{n}-q208-chi{FINITE_SCALED_WIDTH}",
            projection_only=True,
            root_or_key_generated=False,
            ciphertext_generated=False,
            private_entropy_bytes=0,
            finite_noise_table_built=finite_noise["built"],
            phase_accounting=_phase_accounting(row),
            comparison_threshold_bits=COMPARISON_BITS,
            root_trapdoor_comparison_gate=False,
            root_trapdoor_comparison_minimum_log2_rop=None,
            ciphertext_comparison_gate=False,
            ciphertext_comparison_minimum_log2_rop=None,
            comparison_model_gate=False,
            comparison_minimum_log2_rop=None,
            estimator_results={},
            runtime_admitted=False,
            security_claim="none",
            backend_admitted=False,
            parameters_are_formal=False,
        )
        row["current_execution_gates"].update(
            finite_noise_scaled_width_within_current_cap=FINITE_SCALED_WIDTH <= 16384,
            finite_noise_radius_within_current_cap=finite_noise["radius"] <= MAX_RADIUS,
        )
        row["runtime_blockers"] = [
            name for name, passed in row["current_execution_gates"].items() if not passed
        ]
        rows.append(row)

    source_root = Path(__file__).resolve().parents[3]
    sources = (
        "experiments/research/abb_rom/noise_tradeoff_probe.py",
        "experiments/research/abb_rom/scaled_parameter_screen.py",
        "src/ibme/lattice/chkp/noise_budget.py",
        "src/ibme/lattice/chkp/rounded_noise.py",
    )
    return {
        "schema": "A/ABB-NOISE-TRADEOFF/2",
        "fixed_inputs": {
            "q": str(Q208),
            "q_bits": 208,
            "scaled_noise_width": FINITE_SCALED_WIDTH,
            "identity_bytes_per_level": 86,
            "seed_bytes": 32,
            "independently_encrypted_bits": 256,
            "encapsulations": 2**20,
            "correctness_error_bits": 128,
            "comparison_threshold_bits": COMPARISON_BITS,
        },
        "finite_noise": finite_noise,
        "rows": rows,
        "estimator": None,
        "root_trapdoor_comparison_candidates": [],
        "ciphertext_comparison_candidates": [],
        "comparison_model_candidates": [],
        "smallest_tested_ciphertext_comparison_candidate": None,
        "smallest_tested_comparison_candidate": None,
        "largest_tested_comparison_margin_candidate": None,
        "complete_runtime_candidates": [],
        "secure_candidate_selected": False,
        "root_or_key_generations": 0,
        "ciphertext_generations": 0,
        "private_entropy_bytes": 0,
        "environment": {
            "python": sys.version.split()[0],
            "sage": sage_version,
            "platform": platform.platform(),
            "logical_cpus": os.cpu_count(),
        },
        "source_sha256": {
            name: hashlib.sha256((source_root / name).read_bytes()).hexdigest()
            for name in sources
        },
        "measurements": {
            "finite_cdf_build_seconds": finite_noise["build_seconds"],
            "total_seconds": None,
            "process_max_rss_kib": None,
        },
        "unresolved": [
            "complete-basis representation is petabyte-scale for every tested row",
            "no AP09 root, BasisDel key, ciphertext, Hybrid, or IB-ME runtime was attempted",
            "root comparison is a conditional one-column SIS reduction, not exact planted-R or complete-basis recovery",
            "root shared-matrix multi-target amortization and ciphertext BDD/hybrid, BKW, algebraic, multi-target, query, and reduction losses are not estimated",
            "finite SampleR/BasisDel/SamplePre total TV, abort, and workspace remain unclosed",
            "ROM instantiation and formal HIBE/Wang mappings remain unclosed",
        ],
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
    }


def _finite_minimum(results, required):
    values = []
    for name in required:
        result = results.get(name)
        value = result.get("rop_log2") if isinstance(result, dict) else None
        if (not isinstance(result, dict) or result.get("status") != "finite_estimate" or
                type(value) not in (int, float) or not isfinite(value) or value < 0):
            return False, None
        values.append(float(value))
    return True, min(values)


def finalize_comparison(report):
    """Fail closed unless both root and ciphertext models have finite costs."""
    root_candidates = []
    ciphertext_candidates = []
    joint_candidates = []
    report["smallest_tested_ciphertext_comparison_candidate"] = None
    report["smallest_tested_comparison_candidate"] = None
    report["largest_tested_comparison_margin_candidate"] = None
    for row in report["rows"]:
        all_results = row.get("estimator_results", {})
        root_complete, root_minimum = _finite_minimum(
            all_results.get("root_trapdoor_recovery", {}), ROOT_REQUIRED_ESTIMATES
        )
        ciphertext_complete, ciphertext_minimum = _finite_minimum(
            all_results.get("ciphertext_lwe", {}), CIPHERTEXT_REQUIRED_ESTIMATES
        )
        root_gate = bool(root_complete and root_minimum >= COMPARISON_BITS)
        ciphertext_gate = bool(ciphertext_complete and ciphertext_minimum >= COMPARISON_BITS)
        complete = root_complete and ciphertext_complete
        minimum = min(root_minimum, ciphertext_minimum) if complete else None
        gate = bool(
            complete
            and minimum >= COMPARISON_BITS
            and row["noise"]["conditional_noise_sufficient"]
            and row["noise"]["strict_Regev_noise_prerequisite"]
            and row["finite_noise_table_built"]
        )
        row["root_trapdoor_comparison_estimates_complete"] = root_complete
        row["root_trapdoor_comparison_minimum_log2_rop"] = root_minimum
        row["root_trapdoor_comparison_gate"] = root_gate
        row["ciphertext_comparison_estimates_complete"] = ciphertext_complete
        row["ciphertext_comparison_minimum_log2_rop"] = ciphertext_minimum
        row["ciphertext_comparison_gate"] = ciphertext_gate
        row["comparison_estimates_complete"] = complete
        row["comparison_minimum_log2_rop"] = minimum
        row["comparison_model_gate"] = gate
        row["runtime_admitted"] = gate and not row["runtime_blockers"]
        if root_gate:
            root_candidates.append(row)
        if ciphertext_gate:
            ciphertext_candidates.append(row)
        if gate:
            joint_candidates.append(row)
    report["root_trapdoor_comparison_candidates"] = [row["candidate_id"] for row in root_candidates]
    report["ciphertext_comparison_candidates"] = [row["candidate_id"] for row in ciphertext_candidates]
    report["comparison_model_candidates"] = [row["candidate_id"] for row in joint_candidates]
    if ciphertext_candidates:
        report["smallest_tested_ciphertext_comparison_candidate"] = min(
            ciphertext_candidates, key=lambda row: row["n"]
        )["candidate_id"]
    if joint_candidates:
        report["smallest_tested_comparison_candidate"] = min(
            joint_candidates, key=lambda row: row["n"]
        )["candidate_id"]
        report["largest_tested_comparison_margin_candidate"] = max(
            joint_candidates, key=lambda row: row["comparison_minimum_log2_rop"]
        )["candidate_id"]
    report["complete_runtime_candidates"] = [
        row["candidate_id"] for row in joint_candidates if row["runtime_admitted"]
    ]
    # Comparison estimates and a CDF are not a complete security admission.
    report["secure_candidate_selected"] = False
    return report


def runtime_summary(report):
    return {
        "schema": "A/ABB-NOISE-TRADEOFF-RUNTIME/2",
        "source_schema": report["schema"],
        "measurements": report["measurements"],
        "environment": report["environment"],
        "parameters": report["fixed_inputs"],
        "row_count": len(report["rows"]),
        "repetitions": 1,
        "rng": "none; public arithmetic/CDF/estimator run",
        "actual_finite_cdf_built": report["finite_noise"]["built"],
        "root_or_key_generations": 0,
        "ciphertext_generations": 0,
        "private_entropy_bytes": 0,
        "root_trapdoor_comparison_candidates": report["root_trapdoor_comparison_candidates"],
        "ciphertext_comparison_candidates": report["ciphertext_comparison_candidates"],
        "comparison_model_candidates": report["comparison_model_candidates"],
        "complete_runtime_candidates": report["complete_runtime_candidates"],
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
        "limitations": report["unresolved"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runtime-output", type=Path, required=True)
    parser.add_argument("--estimator-path", type=Path, required=True)
    parser.add_argument("--dimensions", type=int, nargs="+", default=list(DEFAULT_DIMENSIONS))
    args = parser.parse_args(argv)
    for path in (args.output, args.runtime_output):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as stream:
            stream.write('{"status":"public-probe-started"}\n')
    started = time.monotonic()
    report = build_tradeoff_report(tuple(args.dimensions), build_cdf=True)

    def save_report():
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    save_report()
    run_estimators(report, args.estimator_path, checkpoint=save_report)
    finalize_comparison(report)
    report["measurements"]["total_seconds"] = time.monotonic() - started
    report["measurements"]["process_max_rss_kib"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    save_report()
    args.runtime_output.write_text(json.dumps(runtime_summary(report), indent=2) + "\n", encoding="utf-8")
    print(
        f"{len(report['rows'])} public rows; "
        f"{len(report['ciphertext_comparison_candidates'])} ciphertext candidates; "
        f"{len(report['comparison_model_candidates'])} joint candidates; "
        "zero keys; zero runtime admissions"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
