"""Proved batch entropy caps for the unchanged finite scalar rejection law.

The only new runtime behavior is an explicit aggregate-budget abort. Original
Gaussian/uniform trial limits, weights and random-source choices are retained.
Certificates cover scalar kernels, not an n512 SRGG Gaussian factor or IBS law.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
from fractions import Fraction
import hashlib
import json
from pathlib import Path
from time import perf_counter

from sage.all import QQ

from ibme.core.randomness import DeterministicRandom, SecureRandom
from experiments.research.gaussian_reference import SamplingAbort, build_gaussian_table_squared
from .formal_candidates import conditional_candidate
from .sampling import TableOptions
from .wide_scalar import WideScalarGaussian, WideScalarOptions, conditional_widths


SCHEMA = "IBME/SRGG-AGGREGATE-BUDGET/1"
MAX_BYTES = 256*1024*1024
MAX_COUNT = 2**20


def _integer(value, name, low=1, high=MAX_COUNT):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded exact integer required: " + name)
    return value


def _fraction(value):
    # Fraction(SageRational) is incompatible with this Python 3.13 runtime.
    if callable(getattr(value, "numerator", None)):
        return Fraction(int(value.numerator()), int(value.denominator()))
    if isinstance(value, bool) or not isinstance(value, (int, str, Fraction)):
        raise ValueError("exact rational required")
    return Fraction(value)


def _ceil(value):
    value = _fraction(value)
    return -(-value.numerator//value.denominator)


def _dyadic_upper(exponent):
    return Fraction(1, 2**(-exponent)) if exponent < 0 else Fraction(2**exponent)


def success_count_bound(count, probability_lower, error_bits):
    """A conditional success probability suffices; independence is not needed.

    For S_t successes, E[2^-S_t] <= (1-p/2)^t <= exp(-pt/2)
    <= 2^-floor(pt/2). Markov gives P[S_t<count] <= 2^(count-1-floor(pt/2)).
    t=ceil(2*(count+K)/p) therefore gives at most 2^(-K-1).
    """
    _integer(count, "success count", high=2**48)
    _integer(error_bits, "error bits", low=8, high=512)
    p = _fraction(probability_lower)
    if not 0 < p <= 1:
        raise ValueError("conditional success probability must be in (0,1]")
    trials = _ceil(Fraction(2*(count+error_bits))/p)
    exponent = count-1-(p*trials/2).__floor__()
    return {"successes": count, "probability_lower": str(p), "trials": trials,
            "dyadic_exponent": exponent, "overflow_upper_exact": str(_dyadic_upper(exponent))}


def batch_certificate(sampler, count, *, error_bits=128, max_bytes=MAX_BYTES):
    """One width class and N admitted centers, possibly chosen adaptively."""
    if not isinstance(sampler, WideScalarGaussian):
        raise ValueError("validated WideScalarGaussian required")
    _integer(count, "scalar count")
    _integer(max_bytes, "aggregate byte limit", high=MAX_BYTES)
    gaussian = success_count_bound(count, sampler.acceptance_probability_lower, error_bits)
    # Support has M-1 points at integer centers and M at other centers.
    q = min(Fraction(n, 2**((n-1).bit_length()))
            for n in (sampler.max_support_count-1, sampler.max_support_count))
    uniform = success_count_bound(gaussian["trials"], q, error_bits)
    probabilistic_bytes = uniform["trials"]*sampler.candidate_bytes+gaussian["trials"]*sampler.bernoulli_bytes
    naive = count*sampler.random_tape_bytes
    budget = min(naive, probabilistic_bytes)
    extra = (_fraction(gaussian["overflow_upper_exact"])+_fraction(uniform["overflow_upper_exact"])) if budget < naive else Fraction(0)
    scalar_tv = count*_fraction(sampler.tv_upper)
    scalar_abort = count*_fraction(sampler.abort_upper)
    return {"schema": SCHEMA, "count": count, "squared_width_class": [str(sampler.v_min), str(sampler.v_max)],
            "gaussian_proposals": gaussian, "uniform_candidates": uniform,
            "candidate_bytes": sampler.candidate_bytes, "bernoulli_bytes": sampler.bernoulli_bytes,
            "naive_all_path_bytes": naive, "chernoff_cap_bytes": probabilistic_bytes,
            "selected_cap_bytes": budget, "public_max_bytes": max_bytes, "admitted": budget <= max_bytes,
            "uses_probabilistic_cap": budget < naive,
            "aggregate_budget_abort_upper_exact": str(extra),
            "existing_scalar_abort_union_upper_exact": str(min(Fraction(1), scalar_abort)),
            "abort_upper_including_aggregate_exact": str(min(Fraction(1), scalar_abort+extra)),
            "scalar_kernel_tv_union_upper_exact": str(min(Fraction(1), scalar_tv)),
            "scalar_kernel_tv_including_aggregate_exact": str(min(Fraction(1), scalar_tv+extra)),
            "reference": "sequential ideal D_Z scalar kernels at the same admitted exact adaptive centers",
            "full_continuous_or_IBS_tv_certified": False,
            "all_original_gaussian_and_uniform_limits_retained": True,
            "requires_independent_uniform_bytes": True,
            "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False}


class AggregateByteSource:
    """Hard cap, no entropy fallback and no partial batch return on overflow."""
    def __init__(self, source, maximum):
        _integer(maximum, "aggregate byte cap", high=MAX_BYTES)
        if not callable(getattr(source, "read", None)):
            raise ValueError("random source must implement read(n)->bytes")
        self.source, self.maximum, self.used = source, maximum, 0

    def read(self, size):
        if type(size) is not int or size < 0 or self.used+size > self.maximum:
            raise SamplingAbort("aggregate scalar entropy budget exhausted; no fallback")
        data = self.source.read(size)
        if not isinstance(data, (bytes, bytearray, memoryview)) or len(data) != size:
            raise ValueError("invalid aggregate entropy byte count or type")
        data = bytes(data)
        if len(data) != size:
            raise ValueError("aggregate bytes conversion changed byte count")
        self.used += size
        return data


def sample_batch(sampler, width_squared, centers, *, rng=None, error_bits=128, max_bytes=MAX_BYTES):
    """Opt-in fixed-center batch. Underlying scalar draw code is unmodified."""
    if not isinstance(centers, (list, tuple)):
        raise ValueError("bounded exact center tuple/list required")
    certificate = batch_certificate(sampler, len(centers), error_bits=error_bits, max_bytes=max_bytes)
    if not certificate["admitted"]:
        raise ValueError("aggregate scalar byte cap exceeds the public budget")
    # Invalid last centers are rejected before even the first scalar consumes bytes.
    for center in centers:
        sampler.checked_inputs(width_squared, center)
    source = AggregateByteSource(SecureRandom() if rng is None else rng, certificate["selected_cap_bytes"])
    return tuple(sampler.sample(width_squared, center, rng=source) for center in centers)


def gadget_certificate(candidate, count, *, error_bits=128):
    """Keep the old TableOptions and every exact integer CDF mass unchanged."""
    options = TableOptions()
    tables = tuple(build_gaussian_table_squared(candidate.base**2*candidate.r_squared,
        step=candidate.base, residue=a, **asdict(options)) for a in range(candidate.base))
    q = min(Fraction(table.total_mass, 2**((table.total_mass-1).bit_length())) for table in tables)
    byte_size = max(((table.total_mass-1).bit_length()+7)//8 for table in tables)
    bound = success_count_bound(count, q, error_bits)
    naive = count*options.max_trials*byte_size
    proposed = bound["trials"]*byte_size
    cap = min(naive, proposed)
    extra = _fraction(bound["overflow_upper_exact"]) if cap < naive else Fraction(0)
    tv = count*max(_fraction(table.tv_upper) for table in tables)
    abort = count*max(_fraction(table.abort_upper) for table in tables)
    return {"count": count, "original_table_options": asdict(options),
            "all_exact_CDF_laws_retained": True, "uniform_candidates": bound,
            "candidate_bytes": byte_size, "naive_all_path_bytes": naive, "selected_cap_bytes": cap,
            "aggregate_budget_abort_upper_exact": str(extra),
            "scalar_kernel_tv_including_aggregate_exact": str(min(Fraction(1), tv+extra)),
            "abort_upper_including_aggregate_exact": str(min(Fraction(1), abort+extra)),
            "reference": "original adaptive gadget scalar coset kernels, before fiber-normalizer comparison"}


def phase_certificate(candidate, *, phase, sign_attempts=1, error_bits=128):
    """Count every scalar and fixed continuous ticket; no factor/shape claim."""
    _integer(sign_attempts, "sign attempts", high=128)
    _integer(error_bits, "error bits", low=8, high=510)
    n, d, w = candidate.degree, candidate.rank, candidate.digits
    widths = conditional_widths(candidate)
    if phase == "master":
        counts = {"rounding_and_signing_u": 2*d*n, "master_lower": w*d*n}
        fixed = 2*d*n*16  # Existing 128-bit midpoint ticket profile; n is even.
    elif phase == "signature":
        counts = {"rounding_and_signing_u": (candidate.columns+1)*n*sign_attempts,
                  "signature_lower": n*sign_attempts}
        fixed = candidate.columns*n*16*sign_attempts
    else:
        raise ValueError("master or signature phase required")
    # At most 3 groups, each with <=2^-(K+2) additional abort.
    groups = {name: batch_certificate(WideScalarGaussian(widths[name], widths[name]), count,
        error_bits=error_bits+2) for name, count in counts.items()}
    if phase == "master":
        groups["gadget_CDF"] = gadget_certificate(candidate, w*d*n, error_bits=error_bits+2)
    total = fixed+sum(group["selected_cap_bytes"] for group in groups.values())
    naive = fixed+sum(group["naive_all_path_bytes"] for group in groups.values())
    extra = sum((_fraction(group["aggregate_budget_abort_upper_exact"]) for group in groups.values()), Fraction(0))
    tv = sum((_fraction(group["scalar_kernel_tv_including_aggregate_exact"]) for group in groups.values()), Fraction(0))
    abort = sum((_fraction(group["abort_upper_including_aggregate_exact"]) for group in groups.values()), Fraction(0))
    return {"candidate": candidate.name, "phase": phase, "sign_attempts": sign_attempts if phase == "signature" else None,
            "groups": groups, "fixed_continuous_ticket_bytes": fixed, "ticket_bits": 128,
            "selected_cap_bytes": total, "naive_all_path_bytes": naive,
            "admitted_under_256MiB": total <= MAX_BYTES,
            "aggregate_budget_abort_upper_exact": str(extra),
            "scalar_kernel_tv_including_aggregate_exact": str(min(Fraction(1), tv)),
            "abort_upper_including_aggregate_exact": str(min(Fraction(1), abort)),
            "scope": "entropy cap and sequential scalar kernel TV only; continuous numerical/smoothing/fiber/HNF/IBS errors excluded",
            "implemented_n512_phase": False}


def audit(*, draw=False):
    rows, phases = [], []
    for rank in (2, 3, 4):
        candidate = conditional_candidate(degree=512, rank=rank, digits=8)
        for name, width in conditional_widths(candidate).items():
            counts = {"rounding_and_signing_u": 2*rank*512+(candidate.columns+1)*512,
                      "master_lower": 8*rank*512, "signature_lower": 512}
            sampler = WideScalarGaussian(width, width)
            certificate = batch_certificate(sampler, counts[name])
            record = {"candidate": candidate.name, "stage": name, "certificate": certificate,
                      "draw_performed": draw}
            if draw:
                centers = tuple(QQ((i % 11)-5)/3 for i in range(counts[name]))
                seed = f"IBME/SRGG-aggregate/n512/d{rank}/{name}".encode()
                source = AggregateByteSource(DeterministicRandom(seed), MAX_BYTES)
                started = perf_counter()
                actual = sample_batch(sampler, width, centers, rng=source)
                seconds = perf_counter()-started
                replay_source = DeterministicRandom(seed)
                # Exact same finite sampler with no aggregate cap, same byte stream.
                replay = tuple(sampler.sample(width, center, rng=replay_source) for center in centers)
                record.update(draw_seconds=seconds, actual_bytes=source.used,
                    unmodified_scalar_replay_matches=actual == replay,
                    deterministic_seed_utf8=seed.decode(), center_pattern="((i%11)-5)/3",
                    output_sha256=hashlib.sha256(json.dumps(actual).encode()).hexdigest())
            rows.append(record)
        phases.extend((phase_certificate(candidate, phase="master"),
                       phase_certificate(candidate, phase="signature"),
                       phase_certificate(candidate, phase="signature", sign_attempts=16)))
    files = (Path(__file__), Path(__file__).with_name("wide_scalar.py"),
             Path(__file__).with_name("formal_candidates.py"))
    return {"schema": SCHEMA, "scalar_cases": rows, "phase_cases": phases,
            "source_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in files},
            "production_configuration_modified": False, "full_n512_sampler_implemented": False,
            "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--draw", action="store_true", help="real scalar batches at the full listed counts")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    payload = json.dumps(audit(draw=args.draw), indent=2)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload+"\n", encoding="utf-8")
    print(payload)


if __name__ == "__main__":
    main()
