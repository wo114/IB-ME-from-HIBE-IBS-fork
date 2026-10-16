"""Exact SRGG quotient-coset and accepted-signature bijection evidence.

Finite algebra only: no Gaussian draw, oracle service or quantum security proof.
The finite-u hybrid cost is read from the unchanged frozen n512 receipt.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
from itertools import product
import json
from pathlib import Path
import platform


SCHEMA = "IBME/SRGG-QUOTIENT-CHALLENGE/1"
MAX_STATES = 4096
MAX_DEGREE = 32


def _int(value, name, low=0, high=2**64):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded exact integer required: " + name)
    return value


def _vector(value, *, binary=False):
    if not isinstance(value, tuple) or not 2 <= len(value) <= MAX_DEGREE:
        raise ValueError("bounded exact coefficient tuple required")
    n = len(value)
    if n & (n-1):
        raise ValueError("power-of-two degree required")
    for coefficient in value:
        _int(coefficient, "coefficient", 0 if binary else -2**64, 1 if binary else 2**64)
    return value


def zeta_action(value, *, adjoint=False):
    """Exact multiplication by 1+X^(n/2), or its 1-X^(n/2) adjoint."""
    value = _vector(value)
    half = len(value)//2
    a, b = value[:half], value[half:]
    if adjoint:
        return tuple(x+y for x, y in zip(a, b))+tuple(y-x for x, y in zip(a, b))
    return tuple(x-y for x, y in zip(a, b))+tuple(x+y for x, y in zip(a, b))


def coset_class(value):
    """Z^n / zeta Z^n -> {0,1}^(n/2), also for signed integer vectors."""
    value = _vector(value)
    half = len(value)//2
    return tuple((a+b) % 2 for a, b in zip(value[:half], value[half:]))


def split_challenge(challenge):
    challenge = _vector(challenge, binary=True)
    return coset_class(challenge), challenge[len(challenge)//2:]


def join_challenge(challenge_class, high):
    if not isinstance(challenge_class, tuple) or not isinstance(high, tuple) or len(challenge_class) != len(high):
        raise ValueError("matching binary half tuples required")
    challenge = tuple(a ^ b if type(a) is int and type(b) is int else -1
        for a, b in zip(challenge_class, high))+high
    _vector(challenge_class+high, binary=True)
    return _vector(challenge, binary=True)


def canonical_challenge(challenge_class):
    if not isinstance(challenge_class, tuple):
        raise ValueError("binary half tuple required")
    return join_challenge(challenge_class, (0,)*len(challenge_class))


def coset_inverse(value, challenge):
    """Return the unique integer u with zeta*u+challenge=value, or None."""
    value, challenge = _vector(value), _vector(challenge, binary=True)
    if len(value) != len(challenge):
        raise ValueError("matching coefficient dimensions required")
    delta = tuple(x-c for x, c in zip(value, challenge))
    twice_u = zeta_action(delta, adjoint=True)
    return None if any(x % 2 for x in twice_u) else tuple(x//2 for x in twice_u)


def centered_exponent_squared(u, challenge):
    u, challenge = _vector(u), _vector(challenge, binary=True)
    if len(u) != len(challenge):
        raise ValueError("matching coefficient dimensions required")
    adjoint = zeta_action(challenge, adjoint=True)
    return sum((Fraction(2*x+c, 2)**2 for x, c in zip(u, adjoint)), Fraction(0))


def _multiply(first, second, modulus):
    n = len(first)
    result = [0]*n
    for i, a in enumerate(first):
        for j, b in enumerate(second):
            k = i+j
            result[k % n] += a*b if k < n else -a*b
    return tuple(x % modulus for x in result)


def recover(a, target, response, challenge, modulus):
    """Toy exact ring relation [2A,Q*j-2h]z-Q*j*c mod 2Q."""
    q = _int(modulus, "odd modulus", 3, 2**32)
    if not q % 2:
        raise ValueError("odd modulus required")
    c = _vector(challenge, binary=True)
    n = len(c)
    if not isinstance(a, tuple) or not 1 <= len(a) <= 4 or not isinstance(target, tuple) or len(target) != len(a):
        raise ValueError("bounded matching public ring rows required")
    if not isinstance(a[0], tuple) or not 1 <= len(a[0]) <= 8:
        raise ValueError("bounded public columns required")
    columns = len(a[0])
    if not isinstance(response, tuple) or len(response) != columns+1:
        raise ValueError("response column count mismatch")
    polys = list(target)+list(response)
    for row in a:
        if not isinstance(row, tuple) or len(row) != columns:
            raise ValueError("rectangular public ring matrix required")
        polys.extend(row)
    if any(len(_vector(poly)) != n for poly in polys):
        raise ValueError("ring coefficient dimension mismatch")
    zero = (0,)*n
    zeta_adjoint = (1,)+(0,)*(n//2-1)+(-1,)+(0,)*(n//2-1)
    result = []
    for row_index, row in enumerate(a):
        coefficients = [2*sum(_multiply(poly, z, 2*q)[i]
            for poly, z in zip(row, response[:-1])) for i in range(n)]
        j = zeta_adjoint if row_index == 0 else zero
        last_column = tuple(q*x-2*h for x, h in zip(j, target[row_index]))
        last = _multiply(last_column, response[-1], 2*q)
        correction = _multiply(j, c, 2*q)
        result.append(tuple((x+y-q*t) % (2*q)
            for x, y, t in zip(coefficients, last, correction)))
    return tuple(result)


def accepted_signature_bijection(a, target, responses, oracle, *, modulus, norm_cap):
    """Enumerate accepted signatures for a fixed context and arbitrary hash table.

    oracle(commitment) returns the full binary challenge. The identity/message
    are fixed in this finite model, so its point is represented by commitment.
    """
    _int(norm_cap, "squared norm cap")
    if not isinstance(responses, tuple) or not 1 <= len(responses) <= MAX_STATES:
        raise ValueError("bounded response collection required")
    if not callable(oracle):
        raise ValueError("fixed oracle callable required")
    if not responses[0] or not isinstance(responses[0], tuple):
        raise ValueError("ring response tuple required")
    n = len(_vector(responses[0][0]))
    if len(responses)*(1 << n) > MAX_STATES:
        raise ValueError("accepted-signature enumeration resource limit")
    full, quotient = set(), set()
    # Keep the table fixed even if the supplied function attempts fresh draws.
    table = {}
    def at(commitment):
        if commitment not in table:
            value = _vector(oracle(commitment), binary=True)
            if len(value) != n:
                raise ValueError("oracle challenge dimension mismatch")
            table[commitment] = value
        return table[commitment]
    for z in responses:
        # Validate all responses before applying their norm gate.
        recover(a, target, z, (0,)*n, modulus)
        if sum(x*x for poly in z for x in poly) > norm_cap:
            continue
        for c in product(range(2), repeat=n):
            w = recover(a, target, z, c, modulus)
            if at(w) == c:
                full.add((z, c))
        for e in product(range(2), repeat=n//2):
            w = recover(a, target, z, canonical_challenge(e), modulus)
            if split_challenge(at(w))[0] == e:
                quotient.add((z, e))
    stripped = {(z, split_challenge(c)[0]) for z, c in full}
    lifted = set()
    for z, e in quotient:
        w = recover(a, target, z, canonical_challenge(e), modulus)
        lifted.add((z, join_challenge(e, split_challenge(at(w))[1])))
    if stripped != quotient or len(full) != len(stripped) or lifted != full:
        raise ArithmeticError("accepted full/quotient signature bijection failed")
    # An injective map preserves every exact returned-signature membership log.
    return {"degree": n, "response_candidates": len(responses),
        "full_accepted": len(full), "quotient_accepted": len(quotient),
        "oracle_points": len(table), "strip_and_lift_are_inverse_on_accepted_domain": True,
        "exact_signature_novelty_preserved": True,
        "all_accepted_logs_preserved_by_injectivity": True}


def _responses(degree, columns):
    flat = [(0,)*(degree*columns)]
    for i in range(degree*columns):
        for sign in (-1, 1):
            flat.append(tuple(sign if j == i else 0 for j in range(degree*columns)))
    # Deliberately include an invalid-norm candidate; the same gate removes it.
    flat.append((2,)+(0,)*(degree*columns-1))
    return tuple(tuple(value[i:i+degree] for i in range(0,len(value),degree)) for value in flat)


def _finite_cases():
    rows = []
    for n in (2, 4):
        one, two = (1,)+(0,)*(n-1), (2,)+(0,)*(n-1)
        a, h = ((one, two),), ((1,)*n,)
        for salt in range(4):
            def oracle(w):
                if salt < 2:
                    return (salt,)*n
                raw = hashlib.sha256(bytes([salt])+json.dumps(w).encode()).digest()
                return tuple((raw[0] >> i) & 1 for i in range(n))
            rows.append({"hash_fixture": salt, "Q": 5, "norm_cap": 1,
                **accepted_signature_bijection(a, h, _responses(n, 3), oracle, modulus=5, norm_cap=1)})
    return rows


def finite_u_cost(receipt_path, *, sign_queries=2**40):
    _int(sign_queries, "sign query upper bound")
    path = Path(receipt_path)
    if path.stat().st_size > 2*1024*1024:
        raise ValueError("frozen receipt resource limit")
    receipt = json.loads(path.read_text(encoding="utf-8"))
    if receipt.get("schema") != "IBME/SRGG-STRUCTURED-EXECUTION/1":
        raise ValueError("frozen structured-execution receipt required")
    params, batch = receipt["parameters"], receipt["u_batch"]
    degree = _int(params["degree"], "receipt degree", 2, 4096)
    attempts = _int(params["sign_max_attempts"], "sign norm retry cap", 1, 128)
    if (type(batch["count"]) is not int or batch["count"] != degree
            or batch["admitted"] is not True or receipt["numerical_profile"] != "query-bounded-deep"
            or batch["squared_width_class"] != [str(params["r_squared"])]*2):
        raise ValueError("matching deep finite-u receipt required")
    delta = Fraction(batch["scalar_kernel_tv_including_aggregate_exact"])
    if not 0 <= delta <= 1:
        raise ValueError("receipt finite-u probability outside [0,1]")
    byte_cap = _int(batch["selected_cap_bytes"], "u byte cap", 1, 256*1024*1024)
    cost = min(Fraction(1), sign_queries*attempts*delta)
    return {"input_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "degree": degree, "sign_queries": sign_queries, "max_norm_attempts": attempts,
        "squared_u_width": params["r_squared"], "numerical_profile": receipt["numerical_profile"],
        "u_batch_tv_including_bottom_exact": str(delta),
        "full_transcript_finite_u_replacement_upper_exact": str(cost),
        "below_2_minus_138_for_this_u_term_only": cost < Fraction(1, 2**138),
        "per_attempt_finite_u_hard_byte_cap": byte_cap,
        "scalar_kernel_uniform_in_admitted_adaptive_centers_required": True,
        "classical_sign_requests_with_quantum_reference_allowed": True,
        "P_sampler_replacement_required_for_quotient_equivalence": False,
        "ideal_P_entropy_automatically_inherited": False,
        "other_sampling_or_IBS_security_terms_included": False}


def build_report(receipt_path=None):
    root = Path(__file__).parents[4]
    path = root/"docs/research/team-b-delivery/2026-10-16-srgg-bridge/structured-execution-n512-d2w8.json" if receipt_path is None else Path(receipt_path)
    coset_cases = 0
    for n in (2, 4, 8):
        vectors = ((0,)*n, tuple((-1)**i for i in range(n)), tuple(i-2 for i in range(n)))
        for c in product(range(2), repeat=n):
            e, b = split_challenge(c)
            if join_challenge(e, b) != c:
                raise ArithmeticError("binary split/join failed")
            canonical = canonical_challenge(e)
            for u in vectors:
                v = tuple(x+y for x, y in zip(zeta_action(u), c))
                u0 = coset_inverse(v, canonical)
                if u0 is None or centered_exponent_squared(u, c) != Fraction(sum(x*x for x in v), 2) or centered_exponent_squared(u0, canonical) != centered_exponent_squared(u, c):
                    raise ArithmeticError("exact coset exponent identity failed")
                coset_cases += 1
    return {"schema": SCHEMA, "coset_exponent_cases": coset_cases,
        "finite_signature_cases": _finite_cases(), "finite_u_cost": finite_u_cost(path),
        "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "environment": {"platform": platform.platform(), "python": platform.python_version()},
        "actual_entropy_bytes": 0, "new_cryptographic_lifecycle": False,
        "scope": "exact finite algebra and conditional finite-u hybrid accounting; not quantum extraction or H1 embedding",
        "production_algorithm_or_hash_changed": False,
        "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False,
        "nist_security_category": None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    payload = json.dumps(build_report(args.input), indent=2)+"\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    print(payload, end="")


if __name__ == "__main__":
    main()
