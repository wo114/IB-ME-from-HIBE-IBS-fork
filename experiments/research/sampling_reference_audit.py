"""Reproduce the fourth-round finite-error sampling reference experiments.

Use WSL conda ~/miniconda3/envs/sage/bin/python with PYTHONPATH=src. All saved
samples use labelled deterministic test entropy; no cryptographic keys/messages.
"""

from __future__ import annotations

import argparse
from collections import Counter
from itertools import product
import json
from pathlib import Path
import platform
import sys

from sage.all import QQ, RealIntervalField
from sage.version import version as sage_version

from ibme.core.randomness import DeterministicRandom
from .gaussian_reference import (PowerOfTwoGadgetSampler, build_gaussian_table,
    finite_gadget_distribution, interval_bounds, interval_record)


def scalar_statistics(table, *, samples, seed):
    rng = DeterministicRandom(seed.encode("ascii"))
    values = [table.sample(rng=rng) for _ in range(samples)]
    counts = Counter(values)
    mean = QQ(sum(values))/samples
    second = QQ(sum(x*x for x in values))/samples
    expected_mean = sum((QQ(x)*mass for x, mass in zip(table.support, table.masses)), QQ(0))/table.total_mass
    expected_second = sum((QQ(x*x)*mass for x, mass in zip(table.support, table.masses)), QQ(0))/table.total_mass
    far = [x for x in table.support if abs(QQ(x)-table.center) >= table.s]
    return {"samples": samples, "seed_ascii": seed,
            "random_source": "DeterministicRandom; test only",
            "observed_mean": float(mean), "observed_variance": float(second-mean**2),
            "cdf_expected_mean": float(expected_mean),
            "cdf_expected_variance": float(expected_second-expected_mean**2),
            "tail_definition": "abs(x-center) >= s",
            "tail_count": sum(counts[x] for x in far),
            "cdf_expected_tail_count": float(samples*sum((table.probability(x) for x in far), QQ(0))),
            "out_of_support": sum(x not in table.support for x in values),
            "wrong_residue": sum((x-table.residue)%table.step != 0 for x in values),
            "histogram": {str(x): counts[x] for x in table.support},
            "statistics_are_diagnostic_not_security_proof": True}


def finite_spherical_comparison(sampler, syndrome):
    """Certified TV enclosure against target Gaussian conditioned on finite box.

    Exact rational CDF probabilities are independently compared with interval
    exp(-pi*sum(x_i^2)/s^2) on the same small box and fixed syndrome. This
    finite-box distance is NOT an infinite-coset certificate.
    """
    law = finite_gadget_distribution(sampler, syndrome)
    field = RealIntervalField(192)
    support = sorted(set(sampler.tables[0].support) | set(sampler.tables[1].support))
    weights = {}
    for v in product(support, repeat=sampler.k):
        if sum((1 << i)*x for i, x in enumerate(v)) % sampler.q == syndrome:
            weights[v] = (-field.pi()*field(QQ(sum(x*x for x in v))/sampler.tables[0].s**2)).exp()
    total = sum(weights.values(), field(0))
    distance = sum((abs(field(law.get(v, QQ(0)))-w/total) for v, w in weights.items()), field(0))/2
    lower, upper = interval_bounds(distance)
    return {"q": sampler.q, "syndrome": syndrome, "s": str(sampler.tables[0].s),
            "box_states": len(support)**sampler.k,
            "coset_states": len(weights), "cdf_total_probability": str(sum(law.values(), QQ(0))),
            "finite_box_tv_interval": interval_record(distance),
            "finite_box_tv_approx": float((lower+upper)/2),
            "zero_vector_cdf_probability": str(law.get((0,)*sampler.k, QQ(0))),
            "zero_vector_spherical_probability": (interval_record(1/total) if syndrome==0 else None),
            "scope": "finite CDF recurrence versus spherical Gaussian conditioned on box; random-draw abort excluded"}


def audit_report(*, samples=8192):
    if not isinstance(samples, int) or isinstance(samples, bool) or samples < 1:
        raise ValueError("samples must be a positive integer")
    scalar_cases = [
        ("integer_center", dict(s=3)),
        ("fractional_center", dict(s=3, center="1/3")),
        ("half_integer_center", dict(s=1, center="1/2")),
        ("narrow_even_coset", dict(s="3/2", step=2, residue=0)),
        ("narrow_odd_coset", dict(s="3/2", step=2, residue=1)),
    ]
    scalars = {}
    for name, config in scalar_cases:
        table = build_gaussian_table(**config)
        scalars[name] = {"certificate": table.certificate(),
            "statistics": scalar_statistics(table, samples=samples, seed=f"ibme-round4:{name}")}

    narrow = PowerOfTwoGadgetSampler(8, "3/2", tail_bits=40, mass_bits=96, precision_bits=160)
    finite = [finite_spherical_comparison(narrow, u) for u in range(8)]
    wide = PowerOfTwoGadgetSampler(16, 12)
    syndrome = (0, 15)
    rng = DeterministicRandom(b"ibme-round4:wide-gadget")
    failures = 0
    first = []
    for i in range(samples):
        v = wide.sample(syndrome, rng=rng)
        if i < 4:
            first.append(list(v))
        actual = tuple(sum((1 << j)*v[block*wide.k+j] for j in range(wide.k)) % wide.q
                       for block in range(len(syndrome)))
        failures += actual != syndrome
    field = RealIntervalField(192)
    return {
        "schema_version": 1,
        "security_claim": "none",
        "source": {"paper": "MP12 ePrint 2011/501", "locations": ["section 2.3", "section 4.1, PDF 18-19"]},
        "environment": {"python": sys.version.split()[0], "sage": sage_version,
                        "platform": platform.platform(), "interval_precision_default_bits": 192},
        "method": "outward interval certificates, exact rational CDF laws, exhaustive small cosets and deterministic sampling diagnostics",
        "convention": {"weight": "exp(-pi*(x-c)^2/s^2)",
            "s_equals_sigma_times_sqrt_2pi": True,
            "discrete_variance_not_assumed_equal_to_s_squared_over_2pi": True,
            "continuous_sigma_at_s3": interval_record(field(3)/(2*field.pi()).sqrt())},
        "identities_and_messages": "none; no IBME/IBS keys, identities or messages",
        "scalar_cases": scalars,
        "narrow_gadget": {"certificate": narrow.certificate(), "finite_box_comparisons": finite,
            "note": "Small s is intentionally outside cryptographic smoothing claims; parity-normalizer bias is visible even with accurate scalar sampling"},
        "wide_gadget": {"certificate": wide.certificate(dimension=2),
            "scalar_certificates": [t.certificate() for t in wide.tables],
            "samples": samples, "syndrome": list(syndrome),
            "random_source": "DeterministicRandom; test only", "seed_ascii": "ibme-round4:wide-gadget",
            "modular_equation_failures": failures, "first_four_vectors": first},
        "limitations": ["No general-q gadget sampler, TrapGen, DelTrap, perturbation, SamplePre or backend integration",
            "Sampling is variable-time and may abort at bounded random rejection limit",
            "Certificates assume independent uniform bytes; saved deterministic diagnostics do not prove probabilistic security",
            "No formal lattice-security parameter set or SIS/LWE work-factor estimate"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=8192)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    serialized = json.dumps(audit_report(samples=args.samples), ensure_ascii=False, indent=2)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8", newline="\n")
    else:
        print(serialized, end="")


if __name__ == "__main__":
    main()
