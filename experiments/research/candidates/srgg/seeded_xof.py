"""Seeded SRGG matrix embedding in a pre-initialized ideal byte XOF.

Finite trajectory models and exact arithmetic only.  This is not a production
XOF/QRO, SHAKE programming, a cryptographic key sampler, or a security proof.
The frozen bridge/reduction implementation is read only for source hashes.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from fractions import Fraction
import hashlib
from itertools import product
import json
from pathlib import Path
import platform


SCHEMA = "IBME/SRGG-SEEDED-XOF-EMBEDDING/1"
DEFAULT_INPUT = Path("docs/research/team-b-delivery/2026-10-16-srgg-bridge/integrated-bridge.json")
MAX_ENUM_NODES = 8192
MAX_PREFIX_STATES = 4096


def _integer(value, name, low=0, high=2**128):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded exact integer required: " + name)
    return value


def rejection_layout(q, word_bits):
    q = _integer(q, "modulus", 2)
    bits = _integer(word_bits, "word bits", 1, 128)
    size = 2**bits
    if q > size:
        raise ValueError("word range must cover modulus")
    lifts = size//q
    limit = lifts*q
    return {"q": q, "word_bits": bits, "word_range_size": size,
        "accepted_lifts_per_residue": lifts, "limit": limit,
        "rejected_words": size-limit, "rho": str(Fraction(size-limit, size))}


@dataclass(frozen=True)
class Trace:
    words: tuple[int, ...]
    accepted: tuple[int, ...]
    success: bool


def _trajectory_law(*, q, word_bits, count, max_trials, targets):
    layout = rejection_layout(q, word_bits)
    size, limit = layout["word_range_size"], layout["limit"]
    _integer(word_bits, "finite-model word bits", 1, 8)
    count = _integer(count, "finite-model coefficient count", 1, 2)
    trials = _integer(max_trials, "finite-model trials", 1, 256)
    if targets is not None:
        if not isinstance(targets, (tuple, list)) or len(targets) != count:
            raise ValueError("one exact target per coefficient required")
        targets = tuple(_integer(a, "canonical target", 0, q-1) for a in targets)
    output, visited = {}, 0

    def walk(index, used, words, accepted, mass):
        nonlocal visited
        visited += 1
        if visited > MAX_ENUM_NODES:
            raise ValueError("finite trajectory enumeration resource limit exceeded")
        if index == count:
            trace = Trace(words, accepted, True)
            output[trace] = output.get(trace, Fraction(0))+mass
            return
        if used == trials:
            trace = Trace(words, accepted, False)
            output[trace] = output.get(trace, Fraction(0))+mass
            return
        for value in range(limit, size):
            walk(index, used+1, words+(value,), accepted, mass/size)
        if targets is None:
            accepted_values, weight = range(limit), Fraction(1, size)
        else:
            a = targets[index]
            accepted_values, weight = range(a, limit, q), Fraction(q, size)
        for value in accepted_values:
            walk(index+1, 0, words+(value,), accepted+(value % q,), mass*weight)

    walk(0, 0, (), (), Fraction(1))
    return output


def raw_trajectory_law(*, q, word_bits, count, max_trials):
    """Law of iid raw words parsed until success or the first trial-limit abort."""
    return _trajectory_law(q=q, word_bits=word_bits, count=count,
        max_trials=max_trials, targets=None)


def conditioned_target_trajectory_law(*, q, word_bits, targets, max_trials):
    """Fix target residues but retain the independent trial-limit abort.

    This is NOT the raw law conditioned on successful parsing of targets:
    failure is retained. Each rejected word has mass 1/M, and each accepted
    lift of the current target has mass q/M. Averaging uniform targets gives
    the entire raw trajectory law, including prefixes that later abort.
    """
    if not isinstance(targets, (tuple, list)):
        raise ValueError("explicit target sequence required")
    return _trajectory_law(q=q, word_bits=word_bits, count=len(targets),
        max_trials=max_trials, targets=targets)


def observed_prefix_law(law, *, word_bits, words):
    """Observe a fixed prefix; after stopping, continue with fresh iid words."""
    bits = _integer(word_bits, "finite-model word bits", 1, 8)
    observed = _integer(words, "observed words", 0, 12)
    size = 2**bits
    if size**observed > MAX_PREFIX_STATES:
        raise ValueError("observed prefix enumeration resource limit exceeded")
    if not isinstance(law, dict) or not law or sum(law.values()) != 1:
        raise ValueError("normalized finite trajectory law required")
    result = {}
    for trace, mass in law.items():
        if not isinstance(trace, Trace) or type(mass) not in (int, Fraction) or mass < 0:
            raise ValueError("exact finite trace probabilities required")
        if any(type(v) is not int or not 0 <= v < size for v in trace.words):
            raise ValueError("trace words outside the declared word range")
        if len(trace.words) >= observed:
            key = trace.words[:observed]
            result[key] = result.get(key, Fraction(0))+mass
        else:
            extra = observed-len(trace.words)
            for suffix in product(range(size), repeat=extra):
                key = trace.words+suffix
                result[key] = result.get(key, Fraction(0))+mass/size**extra
    return result


def _dyadic_upper(value):
    value = Fraction(value)
    if value == 0:
        return Fraction(0), None
    exponent = value.numerator.bit_length()-value.denominator.bit_length()
    covered = value.numerator <= value.denominator << exponent if exponent >= 0 else (
        value.numerator << -exponent <= value.denominator)
    exponent += not covered
    return (Fraction(2**exponent) if exponent >= 0 else Fraction(1, 2**(-exponent))), exponent


def expansion_certificate(*, q, count, max_trials=256, budget_per_coefficient=4096):
    q = _integer(q, "modulus", 2)
    count = _integer(count, "coefficient count", 1, 2**20)
    trials = _integer(max_trials, "maximum trials", 1, 4096)
    budget_factor = _integer(budget_per_coefficient, "per-coefficient budget", 1, 2**20)
    width = ((q-1).bit_length()+7)//8
    layout = rejection_layout(q, 8*width)
    rho = Fraction(layout["rho"])
    single = rho**trials
    # Keep the exact rational bound factored: decimal serialization of the
    # denominator 2^(56*256) would exceed Python's intentional digit limit.
    bound, exponent = _dyadic_upper(min(Fraction(1), count*single))
    max_reads = count*trials*width
    budget = count*budget_factor
    # read(width) grows the deterministic SHAKE prefix cache by doubling
    # from 4096, capped at the budget. These cached bytes are not new coins.
    wanted_cache = max(4096, min(max_reads, budget))
    cache_upper = min(budget, 2**((wanted_cache-1).bit_length()))
    return {**layout, "coefficient_count": count, "word_bytes": width,
        "max_trials_per_coefficient": trials, "raw_read_budget_bytes": budget,
        "maximum_consumed_bytes_before_success_or_abort": max_reads,
        "generated_prefix_cache_bytes_upper": cache_upper,
        "byte_budget_always_sufficient_under_trial_cap": max_reads <= budget,
        "extra_read_budget_failure_probability": "0" if max_reads <= budget else None,
        "exact_trial_failure_probability_expression": "1-(1-rho^max_trials)^coefficient_count",
        "exact_union_bound_factored": {"factor": count, "base": str(rho), "exponent": trials},
        "trial_failure_upper_dyadic_exact": str(bound),
        "trial_failure_upper_dyadic_exponent": exponent,
        "failure_retained_as_abort": True,
        "Public_recomputation_is_same_oracle_point_not_another_failure_trial": True,
        "XOFStream_buffer_is_a_prefix_cache_not_an_extra_independent_stream": True}


def classical_prequery_hit_upper(query_count, *, seed_bits=256):
    q = _integer(query_count, "classical prequery count", 0, 2**64)
    bits = _integer(seed_bits, "seed bits", 1, 512)
    return min(Fraction(1), Fraction(q, 2**bits))


def finite_model_report():
    q, bits, count, trials = 3, 2, 2, 2
    raw = raw_trajectory_law(q=q, word_bits=bits, count=count, max_trials=trials)
    mixed = {}
    for targets in product(range(q), repeat=count):
        conditional = conditioned_target_trajectory_law(q=q, word_bits=bits,
            targets=targets, max_trials=trials)
        for trace, mass in conditional.items():
            mixed[trace] = mixed.get(trace, Fraction(0))+mass/q**count
    tv = sum(abs(raw.get(t, 0)-mixed.get(t, 0)) for t in raw.keys() | mixed.keys())/2
    prefix = observed_prefix_law(mixed, word_bits=bits, words=5)
    prefix_tv = sum(abs(mass-Fraction(1, 4**5)) for mass in prefix.values())/2
    return {"q": q, "word_bits": bits, "count": count, "max_trials": trials,
        "raw_trajectory_count": len(raw), "uniform_target_mixture_count": len(mixed),
        "whole_trajectory_TV_exact": str(tv), "observed_prefix_words": 5,
        "prefix_to_iid_TV_exact": str(prefix_tv),
        "raw_abort_mass_exact": str(sum(p for t, p in raw.items() if not t.success)),
        "scope": "exhaustive finite law including abort and fresh continuation; no secret material"}


def build_report(input_path=DEFAULT_INPUT):
    path = Path(input_path)
    data = path.read_bytes()
    source = json.loads(data)
    if source.get("schema") != "IBME/SRGG-INTEGRATED-BRIDGE/1":
        raise ValueError("known integrated bridge schema required")
    params = source["profiles"][0]["parameters"]
    n, d = params["degree"], params["rank"]
    q = params["p"]*params["base"]**params["digits"]
    project = Path(__file__).resolve().parents[4]
    source_files = ("experiments/research/candidates/srgg/seeded_xof.py",
        "experiments/research/candidates/srgg/structured_execution.py",
        "experiments/research/candidates/wang_pw/hashing.py", "src/ibme/core/encoding.py")
    return {"schema": SCHEMA, "input_path": path.as_posix(),
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "source_sha256": {name: hashlib.sha256((project/name).read_bytes()).hexdigest()
                          for name in source_files},
        "parameters": params,
        "environment": {"python": platform.python_version(), "platform": platform.platform(),
                        "machine": platform.machine(), "processor": platform.processor()},
        "matrix_expansion": expansion_certificate(q=q, count=n*d*d),
        "identity_expansion": expansion_certificate(q=q, count=n*d),
        "classical_prequery_rows": [{"queries": k, "seed_hit_upper_exact": str(classical_prequery_hit_upper(k))}
                                    for k in (0, 2**20, 2**40)],
        "finite_model": finite_model_report(), "actual_entropy_bytes": 0,
        "experiment_kind": "deterministic exhaustive finite model and exact arithmetic; no random repetitions",
        "classical_ideal_XOF_initialization_lemma": "conditional proof in seeded-xof.md; retained failure",
        "QROM_initial_joint_law_scope": "only explicitly coherent ideal-byte oracle initialized before all queries",
        "quantum_prequery_bound_established": False, "QROM_IBS_security_proved": False,
        "production_SHAKE_or_QRO_programmed": False,
        "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False,
        "nist_security_category": None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = build_report(args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
