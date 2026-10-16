"""Exact finite issuance-law analysis and counterexamples, not a sampler.

Inputs to these helpers are explicit finite probability laws. They establish
general pushforward/conditioning facts and public synthetic counterexamples;
they do not supply the unknown law of SRGG's full real sampler or a PSF proof.
``None`` is the observable abort outcome and is never silently renormalized.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import json
from pathlib import Path

from .algebra import (
    Params, PublicRelation, add, constant, identity, matvec, matrix,
    reconstruct_vector, scale, trapdoor_relation, vector,
)


MAX_STATES = 4096


def _fraction(value):
    if isinstance(value, bool) or not isinstance(value, (int, Fraction)):
        raise ValueError("exact integer or Fraction mass required")
    result = Fraction(value)
    if result < 0 or max(result.numerator.bit_length(), result.denominator.bit_length()) > 16384:
        raise ValueError("bounded nonnegative exact mass required")
    return result


def _probability(value):
    result = _fraction(value)
    if result > 1:
        raise ValueError("probability exceeds one")
    return result


def _count(value, *, positive=False):
    if type(value) is not int or not int(positive) <= value <= 2**64:
        raise ValueError("bounded exact query count required")
    return value


def _law(values):
    if not isinstance(values, dict) or not 1 <= len(values) <= MAX_STATES:
        raise ValueError("explicit bounded finite law required")
    result = {key: _fraction(mass) for key, mass in values.items()}
    if sum(result.values()) != 1:
        raise ValueError("finite probability law must sum to one, including abort")
    return {key: mass for key, mass in result.items() if mass}


def _normalized(weights):
    total = sum(weights.values())
    if total <= 0:
        raise ValueError("positive total mass required")
    return _law({key: mass / total for key, mass in weights.items()})


def _bump(values, key, mass):
    if key not in values and len(values) >= MAX_STATES:
        raise ValueError("finite output support exceeds the analysis budget")
    values[key] = values.get(key, Fraction(0)) + mass


def total_variation(left, right):
    """Exact TV of two normalized finite laws, including any abort atoms."""
    left, right = _law(left), _law(right)
    return sum(abs(left.get(key, 0) - right.get(key, 0))
               for key in left.keys() | right.keys()) / 2


def condition_success(values):
    """Return (success probability, conditional law), refusing zero success."""
    values = _law(values)
    success = 1 - values.get(None, Fraction(0))
    if not success:
        raise ValueError("cannot condition on a zero-probability success")
    return success, {key: mass / success for key, mass in values.items() if key is not None}


def conditional_tv_upper(tv_before_filter, success_left, success_right):
    """Sharp general bound after the SAME success filter of two laws.

    For alpha<=beta, the conditional overlap is at least
    sum_A min(P(x),Q(x))/beta. Its deficit is <= TV(P,Q)/beta.
    The inputs must be a TV bound before that shared filter and its two
    success probabilities; arbitrary unrelated conditioning is not covered.
    """
    distance = _probability(tv_before_filter)
    alpha, beta = _probability(success_left), _probability(success_right)
    if not alpha or not beta:
        raise ValueError("both success probabilities must be positive")
    return min(Fraction(1), distance / max(alpha, beta))


def finite_raw_extraction_law(public, trapdoor, target, perturbation_law, gadget_kernel):
    """Compose explicit finite SampleP and conditional gadget laws exactly.

    This is Algorithm 2's raw law IF the supplied laws actually describe its
    samplers. A kernel row includes its own abort mass and must have support
    F*x=v-e mod Q for canonical e=v mod p. No Gaussian claim is inferred.
    """
    p = public.params
    trapdoor = matrix(p, trapdoor, 2*p.rank, p.rank*p.digits)
    if not trapdoor_relation(public, trapdoor):
        raise ValueError("master public/trapdoor relation required")
    target = vector(p, target, p.rank, p.modulus)
    if not callable(gadget_kernel):
        raise TypeError("explicit conditional gadget kernel required")
    stacked = trapdoor + identity(p, p.rank*p.digits)
    result = {}
    for perturbation, p_mass in _law(perturbation_law).items():
        if perturbation is None:
            _bump(result, None, p_mass)
            continue
        perturbation = vector(p, perturbation, p.columns)
        residual = tuple(add(h, scale(v, -1), p.modulus)
                         for h, v in zip(target, matvec(p, public.a, perturbation, p.modulus)))
        error = tuple(tuple(value % p.p for value in row) for row in residual)
        expected = tuple(add(h, scale(e, -1), p.modulus) for h, e in zip(target, error))
        for gadget, g_mass in _law(gadget_kernel(residual)).items():
            if gadget is None:
                _bump(result, None, p_mass*g_mass)
                continue
            gadget = vector(p, gadget, p.rank*p.digits)
            raw = tuple(add(u, v) for u, v in zip(perturbation, matvec(p, stacked, gadget)))
            if matvec(p, public.a, raw, p.modulus) != expected:
                raise ValueError("gadget kernel violates its approximate fiber")
            _bump(result, raw, p_mass*g_mass)
    return _law(result)


def tail_law(public, raw_law):
    """Marginalize only the first d blocks, retaining the abort outcome."""
    p, result = public.params, {}
    for raw, mass in _law(raw_law).items():
        tail = None if raw is None else vector(p, raw, p.columns)[p.rank:]
        _bump(result, tail, mass)
    return _law(result)


def issuance_law(public, target, raw_law, *, user_norm_squared=None):
    """Exact raw -> HNF -> optional norm admission law, preserving aborts."""
    p, result = public.params, {}
    target = vector(p, target, p.rank, p.modulus)
    if user_norm_squared is not None and (type(user_norm_squared) is not int or user_norm_squared < 0):
        raise ValueError("nonnegative exact squared-norm cutoff required")
    for raw, mass in _law(raw_law).items():
        if raw is None:
            _bump(result, None, mass)
            continue
        raw = vector(p, raw, p.columns)
        error = tuple(add(h, scale(v, -1), p.modulus)
                      for h, v in zip(target, matvec(p, public.a, raw, p.modulus)))
        if any(e >= p.p for row in error for e in row):
            raise ValueError("raw law lies outside canonical approximate fibers")
        restored = reconstruct_vector(public, target, raw[p.rank:])
        norm = sum(value*value for row in restored for value in row)
        output = None if user_norm_squared is not None and norm > user_norm_squared else restored
        _bump(result, output, mass)
    return _law(result)


def condition_domain_on_image(public, target, domain_law):
    """Finite PSF reference: condition a full-witness domain law on A*y=h.

    Returns (image probability, conditional full-witness law). This defines
    the reference exactly for the supplied finite domain, not an infinite
    Gaussian normalizer or a PSF property of SRGG's actual sampler.
    """
    p, selected = public.params, {}
    target = vector(p, target, p.rank, p.modulus)
    for raw, mass in _law(domain_law).items():
        if raw is None:
            raise ValueError("ideal domain reference must not contain abort")
        raw = vector(p, raw, p.columns)
        if matvec(p, public.a, raw, p.modulus) == target:
            _bump(selected, raw, mass)
    probability = sum(selected.values())
    return probability, _normalized(selected)


def reference_decoder_comparison(public, target, exact_reference_law):
    """Coupling bound between full exact witnesses and their HNF decoding.

    They agree whenever the original first block is already canonical.
    Thus TV <= the reference's head-wrap probability. A compressed key is
    not automatically the same mathematical witness as SampleDom returned.
    """
    p = public.params
    target = vector(p, target, p.rank, p.modulus)
    reference = _law(exact_reference_law)
    moved = Fraction(0)
    for raw, mass in reference.items():
        if raw is None or matvec(p, public.a, vector(p, raw, p.columns), p.modulus) != target:
            raise ValueError("full exact-preimage reference required")
        moved += mass * (raw != reconstruct_vector(public, target, raw[p.rank:]))
    decoded = issuance_law(public, target, reference)
    distance = total_variation(reference, decoded)
    return {"head_wrap_probability": moved, "full_reference_to_decoded_tv": distance,
            "coupling_bound_holds": distance <= moved}


def service_abort_upper(*, new_identities, signing_queries, issuance_abort,
                        signing_sampling_abort, signing_norm_reject, max_sign_attempts,
                        infrastructure_abort):
    """Union bound under explicitly supplied uniform conditional bounds.

    Each issuance is attempted once. Each signature retries only norm
    rejection; sampling failures abort immediately. No independence between
    queries is assumed. Infrastructure failure requires its own probability
    model; this function does not derive that probability from fsync/locks.
    """
    q_e, q_s = _count(new_identities), _count(signing_queries)
    attempts = _count(max_sign_attempts, positive=True)
    if attempts > 128:
        raise ValueError("attempt count exceeds the backend public maximum")
    extraction, sampling, rejection, infrastructure = map(_probability, (
        issuance_abort, signing_sampling_abort, signing_norm_reject, infrastructure_abort))
    signing = min(Fraction(1), attempts*sampling + rejection**attempts)
    return min(Fraction(1), q_e*extraction + q_s*signing + infrastructure)


def transcript_tv_upper(*, new_identities, signing_queries, issuance_tv_including_abort,
                        signing_tv_including_abort, infrastructure_divergence):
    """Sequential coupling bound, given uniform per-query complete-law TV.

    Cached extraction consumes no new sampler call. First-time signing
    identities must be counted in new_identities if the orchestration lazily
    issues them. Abort is already included in the per-query TV inputs.
    """
    q_e, q_s = _count(new_identities), _count(signing_queries)
    extraction, signing, infrastructure = map(_probability, (
        issuance_tv_including_abort, signing_tv_including_abort, infrastructure_divergence))
    return min(Fraction(1), q_e*extraction + q_s*signing + infrastructure)


def _fixture_public(a_hat):
    p = Params(degree=2, rank=1, p=5, base=3, digits=1)
    return PublicRelation(p, ((constant(p, a_hat),),), ((constant(p, p.p),),))


def finite_gaussian_hnf_counterexample():
    """A finite Gaussian on approximate fibers does not imply an exact law.

    The rational weight 2^(-||y||^2) is a Gaussian density with
    s^2=pi/log(2), restricted to the stated finite public support. This
    refutes an exact distribution identity in general, not SRGG security.
    """
    public = _fixture_public(1)
    p, weights, reference = public.params, {}, {}
    zero, target = constant(p, 0), (constant(p, 0),)
    for head in range(-5, 6):
        for tail in (0, 1):
            raw = (constant(p, head), constant(p, tail), zero)
            if (-head-tail) % p.modulus < p.p:
                weights[raw] = Fraction(1, 2**(head*head + tail*tail))
    for tail in (0, 1):
        full = reconstruct_vector(public, target, (constant(p, tail), zero))
        reference[full] = Fraction(1, 2**sum(x*x for row in full for x in row))
    raw_law, exact_law = _normalized(weights), _normalized(reference)
    decoded = issuance_law(public, target, raw_law)
    return {"params": {"degree": 2, "p": 5, "base": 3, "digits": 1},
            "raw_support": "head coefficient -5..5; first tail coefficient in {0,1}; others zero; canonical approximate fibers",
            "reference_support": "exact HNF witnesses with the same two tails",
            "gaussian_density": "2^(-squared_norm), finite conditioning",
            "raw_state_count": len(raw_law),
            "repaired_state_count": len(decoded),
            "repaired_to_finite_exact_gaussian_tv": total_variation(decoded, exact_law),
            "is_actual_srgg_sampler_law": False}


def rare_success_counterexample(epsilon=Fraction(1, 100)):
    """A shared norm filter can amplify TV epsilon to conditional TV one."""
    epsilon = _probability(epsilon)
    if not 0 < epsilon < 1:
        raise ValueError("strictly intermediate example probability required")
    public = _fixture_public(0)
    p, target = public.params, (constant(public.params, 0),)
    zero = constant(p, 0)
    atoms = [(zero, constant(p, value), zero) for value in (0, 1, 2)]
    left = {atoms[0]: epsilon, atoms[2]: 1-epsilon}
    right = {atoms[1]: epsilon, atoms[2]: 1-epsilon}
    left_out = issuance_law(public, target, left, user_norm_squared=1)
    right_out = issuance_law(public, target, right, user_norm_squared=1)
    alpha, left_cond = condition_success(left_out)
    beta, right_cond = condition_success(right_out)
    before = total_variation(left, right)
    return {"before_filter_tv": before,
            "including_abort_after_filter_tv": total_variation(left_out, right_out),
            "success_left": alpha, "success_right": beta,
            "conditioned_on_success_tv": total_variation(left_cond, right_cond),
            "conditional_tv_upper": conditional_tv_upper(before, alpha, beta),
            "is_actual_srgg_sampler_law": False}


def build_report():
    return {"schema": "IBME/SRGG-ISSUANCE-ANALYSIS/1",
            "scope": "general exact finite-law tools and synthetic counterexamples",
            "finite_gaussian_hnf": finite_gaussian_hnf_counterexample(),
            "rare_success": rare_success_counterexample(),
            "actual_raw_law_certified": False, "psf_distribution_bridge_closed": False,
            "security_claim": "none", "backend_admitted": False,
            "parameters_are_formal": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(build_report(), default=str, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8", newline="\n")
    print(encoded, end="")


if __name__ == "__main__":
    main()
