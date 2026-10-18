"""Exact prime-square Hensel and polynomial CRT check for SRGG Table 4.

Only public ring algebra is handled. In particular, factor dimensions and CRT
idempotents do not estimate the cost of Ring-HNF, MSIS, or a subfield attack.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

from .paper_profiles import SOURCE_PDF, SOURCE_SHA256


SCHEMA = "IBME/SRGG-PAPER-RING-CRT-LIFT/1"


def _coefficients(poly, degree):
    return [int(poly[i]) for i in range(degree)]


def _digest(poly, degree):
    data = json.dumps(_coefficients(poly, degree), separators=(",", ":")).encode("ascii")
    return sha256(data).hexdigest()


def _require_inputs(prime, degree):
    from sage.all import ZZ

    if type(prime) is not int or not 3 <= prime <= 127 or not ZZ(prime).is_prime():
        raise ValueError("bounded exact odd prime required")
    if type(degree) is not int or not 4 <= degree <= 512 or degree & (degree - 1):
        raise ValueError("bounded power-of-two degree required")
    return prime, degree


def prime_square_crt(*, prime, degree):
    """Construct every monic factor and idempotent of Z/p²[X]/(X^n+1).

    A single Hensel step lifts each factor against its complement. The
    idempotent inverse is lifted separately from F_p, so polynomial Euclid
    over the non-field Z/p² is never assumed to work.
    """
    from sage.all import GF, PolynomialRing, ZZ, Zmod

    prime, degree = _require_inputs(prime, degree)
    integers = PolynomialRing(ZZ, "x")
    field = PolynomialRing(GF(prime), "x")
    quotient = PolynomialRing(Zmod(prime**2), "x")
    x = integers.gen()
    F = x**degree + 1
    Fp = field([int(c) % prime for c in F.list()])
    factors = tuple(f for f, multiplicity in Fp.factor() for _ in range(multiplicity))
    if len(factors) > 16 or Fp.gcd(Fp.derivative()) != 1:
        raise ValueError("factor count or squarefreeness gate failed")

    def over_z(poly):
        return integers([int(c) for c in poly.list()])

    def over_p(poly):
        return field([int(c) % prime for c in poly.list()])

    def over_p2(poly):
        return quotient([int(c) % (prime**2) for c in poly.list()])

    lifted = []
    for f in factors:
        g = Fp // f
        f0, g0 = over_z(f), over_z(g)
        difference = F - f0 * g0
        if any(int(c) % prime for c in difference.list()):
            raise AssertionError("initial factorization does not reduce to F")
        residual = over_p(integers([ZZ(c) // prime for c in difference.list()]))
        a = (residual * g.inverse_mod(f)) % f
        b, rem = (residual - a * g).quo_rem(f)
        if rem != 0:
            raise AssertionError("Hensel correction has nonzero remainder")
        high_f = f0 + prime * over_z(a)
        high_g = g0 + prime * over_z(b)
        if high_f.degree() != f.degree() or high_g.degree() != g.degree():
            raise AssertionError("Hensel correction changed monic degrees")
        if over_p2(high_f * high_g) != over_p2(F):
            raise AssertionError("prime-square pair product failed")
        lifted.append(over_p2(high_f))

    F2 = over_p2(F)
    product = quotient.one()
    for f in lifted:
        product *= f
    if product != F2:
        raise AssertionError("all lifted factors do not multiply to F")

    idempotents = []
    for f, fp in zip(lifted, factors):
        complement = F2 // f  # Monic division is valid over Z/p².
        if complement * f != F2:
            raise AssertionError("nonexact complementary factor division")
        u0 = over_p(complement).inverse_mod(fp)
        u0_high = over_p2(u0)
        residual = (quotient.one() - complement * u0_high) % f
        if any(int(c) % prime for c in residual.list()):
            raise AssertionError("idempotent inverse residual not divisible by p")
        correction = over_p(integers([int(c) // prime for c in residual.list()]))
        u1 = (correction * u0) % fp
        inverse = (u0_high + prime * over_p2(u1)) % f
        if (complement * inverse) % f != 1:
            raise AssertionError("lifted inverse check failed")
        idempotents.append((complement * inverse) % F2)

    if sum(idempotents, quotient.zero()) % F2 != 1:
        raise AssertionError("CRT idempotents do not sum to one")
    for i, e in enumerate(idempotents):
        for j, f in enumerate(lifted):
            if e % f != int(i == j):
                raise AssertionError("CRT idempotent projection failed")

    probe = over_p2(integers([3, -7, 0, 5, 11, -2]))
    reconstructed = sum((e * (probe % f) for e, f in zip(idempotents, lifted)), quotient.zero()) % F2
    if reconstructed != probe % F2:
        raise AssertionError("CRT polynomial reconstruction failed")

    modulus = prime**2
    records = []
    for f, e in zip(lifted, idempotents):
        centered = [((int(e[i]) + modulus // 2) % modulus) - modulus // 2
                    for i in range(degree)]
        records.append({"factor_degree": int(f.degree()),
                        "factor_coefficients_sha256": _digest(f, int(f.degree()) + 1),
                        "idempotent_coefficients_sha256": _digest(e, degree),
                        "centered_idempotent_norm_squared": sum(c*c for c in centered),
                        "centered_idempotent_l1": sum(abs(c) for c in centered)})
    return {"schema": SCHEMA, "prime": prime, "exponent": 2,
            "degree": degree, "modulus": modulus, "factor_count": len(records),
            "factors": records, "all_lifted_factors_product_equals_Xn_plus_1": True,
            "idempotents_pairwise_project_and_sum_to_one": True,
            "public_polynomial_crt_reconstruction": True,
            "centered_idempotent_norms_are_not_attack_costs": True,
            "unreduced_lift_l2_multiplier_upper": "centered idempotent l1 by signed-shift triangle inequality",
            "quotient_representative_norm_or_attack_cost_inferred": False,
            "actual_attack_cost": None, "CBD1_projection_law": None,
            "actual_entropy_bytes": 0, "sampler_draws": 0,
            "security_claim": "none", "backend_admitted": False,
            "parameters_are_formal": False, "nist_security_category": None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("--output already exists")
    root = Path(__file__).resolve().parents[4]
    if sha256((root / SOURCE_PDF).read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("frozen paper checksum differs")
    report = prime_square_crt(prime=31, degree=512)
    report["paper"] = {"path": SOURCE_PDF, "sha256": SOURCE_SHA256}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"factor_count": report["factor_count"],
                      "security_claim": report["security_claim"]}))


if __name__ == "__main__":
    main()
