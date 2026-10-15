"""Numerical stability and HNF-key diagnostics for the SRGG research sampler.

The precision check couples two finite implementations to the same deterministic
byte stream and records only disagreement/abort counts.  The HNF check records
equation success and aggregate norm statistics, never a key or private shape.
Neither check is a total-variation proof, a key-distribution proof, or a
security admission.  Use the specified WSL Sage environment.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import platform
import sys

from sage.all import QQ, RealField
from sage.version import version as sage_version

from ibme.core.randomness import DeterministicRandom
from experiments.research.gaussian_reference import SamplingAbort, draw_uniform_integer
from .algebra import Params, build_public
from .audit import PAPER, PAPER_SHA, ROOT, require
from .full_sampling import FullSamplingOptions, prepare_f, prepare_p
from .geometry import Widths, master_geometry
from .perturbation import MasterPerturbation, extract_with_perturbation
from .runtime import sample_geometry
from .sampling import GadgetSampler, TableOptions


def _options(precision_bits):
    """Keep all finite-table resources fixed while changing real precision."""
    return FullSamplingOptions(
        precision_bits=precision_bits,
        ticket_bits=96,
        tail_bits=24,
        mass_bits=64,
        gaussian_abort_bits=24,
        max_uniform_trials=64,
    )


def _paired_precision(label, prepare, *, low, high, samples):
    low_plan = prepare(_options(low))
    high_plan = prepare(_options(high))
    disagreements = 0
    low_aborts = high_aborts = 0
    one_sided_aborts = 0
    paired_successes = 0
    max_linf = 0
    total_l1 = 0
    for index in range(samples):
        seed = b"srgg-numeric-coupling:" + label.encode() + index.to_bytes(4, "big")
        left = right = None
        try:
            left = low_plan.sample(rng=DeterministicRandom(seed))
        except SamplingAbort:
            low_aborts += 1
        try:
            right = high_plan.sample(rng=DeterministicRandom(seed))
        except SamplingAbort:
            high_aborts += 1
        if left is None or right is None:
            one_sided_aborts += int((left is None) != (right is None))
            continue
        paired_successes += 1
        distances = [abs(int(a) - int(b)) for a, b in zip(left, right)]
        max_linf = max(max_linf, max(distances, default=0))
        total_l1 += sum(distances)
        disagreements += int(left != right)
    rate = (QQ(disagreements) / paired_successes) if paired_successes else None
    mean_l1 = (QQ(total_l1) / paired_successes) if paired_successes else None
    return {
        "fixture": label,
        "low_precision_bits": low,
        "high_precision_bits": high,
        "samples": samples,
        "paired_successes": paired_successes,
        "low_aborts": low_aborts,
        "high_aborts": high_aborts,
        "one_sided_abort_pairs": one_sided_aborts,
        "coupled_disagreements": disagreements,
        "coupled_disagreement_rate": None if rate is None else str(rate),
        "max_linf_difference": max_linf,
        "mean_l1_difference": None if mean_l1 is None else str(mean_l1),
        "coupling": "same deterministic byte stream per pair; test-only reproducibility",
        "scope": "empirical finite-precision diagnostic; not a TV certificate",
    }


def precision_audit(*, samples):
    f_covariance = ((64, 24), (24, 64))
    p_covariance = ((64, 0, 24, 0), (0, 64, 0, 24),
                    (24, 0, 64, 0), (0, 24, 0, 64))
    return [
        _paired_precision(
            "sample-f-2d",
            lambda options: prepare_f(f_covariance, (QQ(1) / 3, -QQ(2) / 5), 4,
                                       options=options),
            low=128, high=192, samples=samples,
        ),
        _paired_precision(
            "sample-p-4d-block2",
            lambda options: prepare_p(p_covariance, (0, 0, 0, 0), 2, 4,
                                       options=options),
            low=128, high=192, samples=samples,
        ),
    ]


def _hnf_equation_audit(*, repetitions):
    """Run the small public perturbation fixture and export aggregates only."""
    params = Params(degree=2, rank=1, p=5, base=3, digits=1)
    widths = Widths(512, 128, 4)
    source = DeterministicRandom(b"srgg-hnf-key-aggregate-fixture")

    def uniform(bound):
        return draw_uniform_integer(source, bound)

    a_hat = tuple(tuple(tuple(uniform(params.modulus) for _ in range(params.degree))
                        for _ in range(params.rank)) for _ in range(params.rank))
    witness_values = []
    for _ in range(2 * params.rank * params.rank * params.digits * params.degree):
        witness_values.append((uniform(2) - uniform(2)))
    witness = tuple(tuple(tuple(witness_values[(i * params.rank * params.digits + j) * params.degree:
                                      (i * params.rank * params.digits + j + 1) * params.degree])
                         for j in range(params.rank * params.digits))
                    for i in range(2 * params.rank))
    public = build_public(params, a_hat, witness)
    perturbation = MasterPerturbation(params, witness, widths)
    gadget = GadgetSampler(
        params, params.base**2 * widths.r_squared,
        TableOptions(tail_bits=16, mass_bits=64, precision_bits=192, max_radius=128),
    )
    norms = []
    first_block_changed = 0
    aborts = 0
    for index in range(repetitions):
        target = tuple(tuple(uniform(params.modulus) for _ in range(params.degree))
                       for _ in range(params.rank))
        try:
            result = extract_with_perturbation(
                public, target, perturbation, gadget,
                perturbation_rng=source, gadget_rng=source,
            )
        except SamplingAbort:
            aborts += 1
            continue
        norms.append(sum(int(value) * int(value)
                         for polynomial in result.reconstructed for value in polynomial))
        first_block_changed += int(result.reconstructed[:params.rank] != result.raw.raw_vector[:params.rank])
    require(norms, "HNF aggregate fixture produced no successful samples")
    return {
        "parameters": {"degree": params.degree, "rank": params.rank,
                       "digits": params.digits, "p": params.p,
                       "b": params.base, "Q": params.modulus},
        "attempts": repetitions,
        "successful_reconstructions": len(norms),
        "observed_aborts": aborts,
        "first_block_changed": first_block_changed,
        "reconstructed_key_norm_squared": {
            "minimum": min(norms), "maximum": max(norms),
            "mean": str(QQ(sum(norms)) / len(norms)),
        },
        "equation_check": "reconstruct_vector and extract_with_perturbation completed without exception",
        "scope": "aggregate HNF diagnostic only; no key values, private shapes, or key-distribution claim",
    }


def _covariance_audit(*, samples):
    """Check all coefficient covariance entries of the Algorithm 3 fixture."""
    params = Params(degree=2, rank=1, p=5, base=3, digits=1)
    witness = (((1, -1),), ((1, 1),))
    geometry = master_geometry(params, witness, Widths(512, 128, 4))
    options = _options(192)
    source = DeterministicRandom(b"srgg-sample-geometry-moment-fixture")
    values = []
    for _ in range(samples):
        sampled = sample_geometry(geometry, params.degree, 4, source, options)
        values.append(tuple(int(coefficient) for polynomial in sampled for coefficient in polynomial))
    dimension = len(values[0])
    means = [QQ(sum(row[index] for row in values)) / samples for index in range(dimension)]
    empirical = [[QQ(sum((row[i] - means[i]) * (row[j] - means[j]) for row in values)) / samples
                  for j in range(dimension)] for i in range(dimension)]
    field = RealField(160)
    target = [[field(geometry.perturbation[i][j]) / (2 * field.pi())
               for j in range(dimension)] for i in range(dimension)]
    mean_linf = max((abs(field(value)) for value in means), default=field(0))
    errors = [[abs(field(empirical[i][j]) - target[i][j])
               for j in range(dimension)] for i in range(dimension)]
    diagonal_relative = [errors[i][i] / abs(target[i][i]) for i in range(dimension)]
    cross_errors = [errors[i][j] for i in range(dimension) for j in range(i)
                    if geometry.perturbation[i][j] != 0]
    return {
        "fixture": "master_geometry-nonzero-R-degree2",
        "samples": samples,
        "dimension": dimension,
        "target_convention": "geometry.perturbation/(2*pi)",
        "mean_linf": str(mean_linf),
        "max_absolute_covariance_error": str(max((value for row in errors for value in row), default=field(0))),
        "max_diagonal_relative_error": str(max(diagonal_relative, default=field(0))),
        "max_nonzero_cross_covariance_error": str(max(cross_errors, default=field(0))),
        "nonzero_cross_covariance_entries": len(cross_errors),
        "scope": "empirical full-matrix moment diagnostic; not a TV or key-distribution proof",
    }


def audit(*, precision_samples=64, hnf_repetitions=32, covariance_samples=4096):
    require(sha256((ROOT / PAPER).read_bytes()).hexdigest() == PAPER_SHA,
            "SRGG source PDF fingerprint differs")
    if type(precision_samples) is not int or not 1 <= precision_samples <= 4096:
        raise ValueError("precision_samples outside audit range")
    if type(hnf_repetitions) is not int or not 1 <= hnf_repetitions <= 4096:
        raise ValueError("hnf_repetitions outside audit range")
    if type(covariance_samples) is not int or not 128 <= covariance_samples <= 16384:
        raise ValueError("covariance_samples outside audit range")
    return {
        "schema": "IBME/SRGG-NUMERIC-STABILITY-AUDIT/1",
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
        "paper_source": PAPER,
        "paper_sha256": PAPER_SHA,
        "environment": {
            "python": sys.version,
            "sage": sage_version,
            "platform": platform.platform(),
            "processor": platform.processor(),
        },
        "precision_coupling": precision_audit(samples=precision_samples),
        "sample_geometry_covariance": _covariance_audit(samples=covariance_samples),
        "hnf_key_aggregate": _hnf_equation_audit(repetitions=hnf_repetitions),
        "limitations": [
            "Coupled disagreement counts are empirical finite-sample diagnostics, not a total-variation bound.",
            "The two precision runs share byte streams but may consume different finite-table budgets.",
            "HNF norm aggregates do not establish the reconstructed-key distribution or a Gaussian claim.",
            "The small HNF fixture is a research probe and is not a security parameter set.",
            "No formal parameter estimate, strong-unforgeability reduction, or HIBE composition is established.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--precision-samples", type=int, default=64)
    parser.add_argument("--hnf-repetitions", type=int, default=32)
    parser.add_argument("--covariance-samples", type=int, default=4096)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(precision_samples=args.precision_samples,
                   hnf_repetitions=args.hnf_repetitions,
                   covariance_samples=args.covariance_samples)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
