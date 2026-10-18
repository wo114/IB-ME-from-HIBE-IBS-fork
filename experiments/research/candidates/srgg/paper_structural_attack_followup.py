"""Bounded original-Table-4 structural attack follow-up.

The exact result is a universal final-column kernel of the published 2Q
verification matrix, not a Ring-HNF, CRT, subfield, or fresh-message attack.
All other actual attack costs remain unknown. No secret or estimator is used.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path
import platform

from .paper_profiles import SOURCE_PDF, SOURCE_SHA256, profiles


SCHEMA = "IBME/SRGG-PAPER-STRUCTURAL-ATTACK-FOLLOWUP/1"
ROOT = Path(__file__).resolve().parents[4]
SOURCE_FILES = (
    "experiments/research/candidates/srgg/paper_structural_attack_followup.py",
    "experiments/research/candidates/srgg/paper_profiles.py",
    "experiments/research/candidates/srgg/paper_parameters.py",
    "experiments/research/candidates/srgg/paper_algebra.py",
    "experiments/research/candidates/srgg/paper_backend.py",
    "experiments/research/candidates/srgg/paper_schur_backend.py",
    "experiments/research/candidates/srgg/paper_objects.py",
    "experiments/research/candidates/srgg/structured_execution.py",
)


def _inputs(degree: int, modulus: int) -> tuple[int, int]:
    if (type(degree) is not int or degree < 2 or degree > 512
            or degree & (degree - 1)):
        raise ValueError("bounded even power-of-two degree required")
    if type(modulus) is not int or not 3 <= modulus <= 2**32 or modulus % 2 != 1:
        raise ValueError("bounded odd Q required")
    return degree, modulus


def final_column_shift(degree: int, modulus: int, *, index: int = 0,
                       direction: int = 1) -> tuple[int, ...]:
    """Q X^index (1-X^(n/2)), using 0<=index<n/2."""
    degree, modulus = _inputs(degree, modulus)
    if type(index) is not int or not 0 <= index < degree // 2:
        raise ValueError("index in the first half required")
    if type(direction) is not int or direction not in (-1, 1):
        raise ValueError("direction must be -1 or +1")
    result = [0] * degree
    result[index] = direction * modulus
    result[index + degree // 2] = -direction * modulus
    return tuple(result)


def kernel_certificate(degree: int, modulus: int, gamma: Fraction) -> dict:
    """Exact universal kernel and restricted shortest-norm argument.

    For delta=Q*t in the final column, the -2h term always vanishes modulo
    2Q. Because Q is odd, the remaining condition is zeta_star*t=0 mod 2.
    In F2[X]/(X^n+1), multiplication by zeta_star=1-X^(n/2) sends the two
    coefficient halves (a,b) to (a+b,a+b). Thus its annihilator has a=b.
    A nonzero odd-parity t needs at least two unit-magnitude coefficients;
    all-even nonzero t has a coefficient of magnitude >=2. The minimum
    squared norm in this restricted Q-multiple family is exactly 2Q^2.
    """
    degree, modulus = _inputs(degree, modulus)
    if type(gamma) is not Fraction or gamma <= 0:
        raise ValueError("positive exact gamma required")
    minimum = 2 * modulus**2
    cap_fraction = gamma**2
    cap = cap_fraction.numerator // cap_fraction.denominator
    return {
        "n": degree, "Q": modulus, "verification_modulus": 2 * modulus,
        "zeta_star": "1-X^(n/2)",
        "witness": "Q*(1-X^(n/2)) in the final response column",
        "identity": "(1-X^(n/2))^2=-2*X^(n/2) in Z[X]/(X^n+1)",
        "universal_for_every_public_A_and_identity_h": True,
        "restricted_family": "nonzero Q*t in final column only, with integer t and zero 2Q commitment",
        "restricted_minimum_norm_squared": minimum,
        "restricted_minimum_attained": True,
        "restricted_minimum_argument": "mod2 t has equal halves; nonzero odd parity has >=2 unit coefficients, all-even nonzero t has one coefficient magnitude >=2",
        "explicit_construction_nonzero_coefficients": 2,
        "explicit_construction_BKZ_calls": 0,
        "published_gamma": str(gamma),
        "published_norm_squared_cap": cap,
        "witness_inside_single_signature_radius": minimum <= cap,
        "public_last_column_algebra_only": True,
        "fresh_message_forgery_from_kernel_alone": False,
        "full_ring_HNF_MSIS_attack_cost": None,
        "CRT_subfield_attack_cost": None,
        "successful_replacement_probability": None,
    }


def crt_component_lift_floors(modulus: int) -> list[dict]:
    """Necessary coefficient magnitudes for a single coefficient CRT factor.

    If a centered integer coefficient vanishes in every component except m,
    it is divisible by Q/m. This is sharp for the coefficient component,
    but polynomial-factor constraints may demand much larger vectors.
    """
    _inputs(2, modulus)
    from .paper_hardness_preflight import coefficient_crt

    return [{
        "prime": item["prime"], "prime_power": item["prime_power"],
        "other_components_product": item["cofactor"],
        "nonzero_centered_coefficient_abs_lower": item["cofactor"],
        "whole_prime_power_component_floor_is_sharp": True,
        "single_polynomial_factor_floor_is_sharp": None,
        "global_short_solution_or_attack_cost_inferred": False,
    } for item in coefficient_crt(modulus)]


def public_replacement_probe(public, identity: bytes, message: bytes, signature) -> dict:
    """Check the best +/-Q*zeta_star last-column shift on one valid answer.

    The input signature is verified first. No signing/key source is accepted
    here, and the output contains aggregate public diagnostics only.
    """
    from .paper_algebra import PaperRing, identity_target
    from .paper_backend import Backend
    from .paper_objects import PublicKey, Signature

    if type(public) is not PublicKey or type(signature) is not Signature:
        raise TypeError("paper public key and signature required")
    class NoRead:
        def read(self, count):
            raise AssertionError("public replacement must not draw entropy")
    backend = Backend(rng=NoRead())
    if not backend.verify(public, identity, message, signature):
        raise ValueError("valid published verifier answer required")
    params = public.params
    n, q = params.degree, params.modulus
    ring = PaperRing(params)
    target = identity_target(public, identity)
    matrix = ring.signing_matrix(public, target)
    zeta_star = ring.zeta(True)
    expected_last = tuple(ring.add(
        ring.scale(zeta_star, q), ring.scale(target[row], -2), 2*q)
        if row == 0 else ring.scale(target[row], -2, 2*q)
        for row in range(params.rank))
    if tuple(row[-1] for row in matrix) != expected_last:
        raise AssertionError("published final verification column changed")
    delta = final_column_shift(n, q)
    zero = tuple(0 for _ in range(n))
    if any(ring.multiply(row[-1], delta, 2*q) != zero for row in matrix):
        raise AssertionError("claimed final-column kernel is not exact")
    old_norm = sum(x*x for poly in signature.response for x in poly)
    last = signature.response[-1]
    choices = []
    for i in range(n // 2):
        difference = last[i] - last[i+n//2]
        direction = -1 if difference >= 0 else 1
        new_norm = old_norm + 2*q*q - 2*q*abs(difference)
        choices.append((new_norm, i, direction))
    best_norm, best_index, best_direction = min(choices)
    shifted = final_column_shift(n, q, index=best_index, direction=best_direction)
    response = signature.response[:-1] + (tuple(a+b for a,b in zip(last, shifted)),)
    replacement = replace(signature, response=response)
    canonical = Signature.from_bytes(replacement.to_bytes()).to_bytes() == replacement.to_bytes()
    commitment_equal = (
        ring.recover(public, target, signature.response, signature.challenge)
        == ring.recover(public, target, replacement.response, replacement.challenge)
    )
    actual_norm = sum(x*x for poly in response for x in poly)
    accepted = backend.verify(public, identity, message, replacement)
    if not (canonical and commitment_equal and actual_norm == best_norm):
        raise AssertionError("public last-column shift correspondence failed")
    if accepted != (best_norm <= params.signature_norm_cap):
        raise AssertionError("published verifier norm gate correspondence failed")
    return {
        "valid_original_required_and_checked": True,
        "published_last_column_checked": True,
        "all_rows_kernel_checked": True,
        "canonical_alternative_object": canonical,
        "recovered_commitment_equal": commitment_equal,
        "distinct_canonical_signature": replacement.to_bytes() != signature.to_bytes(),
        "original_norm_squared": old_norm,
        "best_shift_norm_squared": best_norm,
        "signature_norm_squared_cap": params.signature_norm_cap,
        "tested_pair_positions": n//2,
        "eligible_pair_positions": sum(x[0] <= params.signature_norm_cap for x in choices),
        "best_pair_index": best_index,
        "best_direction": best_direction,
        "best_replacement_accepted": accepted,
        "same_message_identity_challenge": True,
        "fresh_under_exact_signature_strong_game": accepted,
        "fresh_under_paper_new_message_G0": False,
        "success_probability": None,
        "private_material_exported": False,
    }


def replay_default_param_i() -> dict:
    """One frozen test-only source signature; export public aggregates only."""
    from ibme.core.randomness import DeterministicRandom
    from .paper_parameters import PaperParams
    from .paper_schur_backend import SourceSchurBackend

    name, interpretation = "PARAM-I", "table-standard-deviation"
    seed = ("paper-baseline-" + name + "-" + interpretation).encode("ascii")
    backend = SourceSchurBackend(rng=DeterministicRandom(seed))
    params = PaperParams(name, interpretation)
    public, master = backend.setup(params)
    key = backend.key_extract(master, b"Alice")
    signature = backend.sign(key, b"SRGG paper baseline: 32 bytes!!!")
    return {
        "profile": name, "interpretation": interpretation,
        "randomness": "DeterministicRandom TEST ONLY",
        "signature_queries": 1,
        "public_key_sha256": sha256(public.to_bytes()).hexdigest(),
        "probe": public_replacement_probe(
            public, b"Alice", b"SRGG paper baseline: 32 bytes!!!", signature),
    }


def build_report() -> dict:
    from sage.version import version as sage_version

    if sha256((ROOT / SOURCE_PDF).read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("frozen original paper checksum differs")
    rows = []
    for source in profiles:
        row = kernel_certificate(source.degree, source.Q, Fraction(source.gamma))
        row.update(profile=source.name, d=source.rank, w=source.digits,
                   CRT_component_lift_floors=crt_component_lift_floors(source.Q),
                   security_claim="none", backend_admitted=False,
                   parameters_are_formal=False, nist_security_category=None)
        rows.append(row)
    return {
        "schema": SCHEMA,
        "paper": {"path": SOURCE_PDF, "sha256": SOURCE_SHA256,
                  "locations": "Table 4; Algorithms 7-8; Section 5.2 and Table 5"},
        "source_sha256": {name: sha256((ROOT / name).read_bytes()).hexdigest()
                          for name in SOURCE_FILES},
        "environment": {"python": platform.python_version(), "sage": sage_version,
                        "platform": platform.platform()},
        "routes": [
            {"route": "direct ring-HNF/CRT/subfield attack-cost transfer",
             "result": "unclosed: actual accepted seeded public-root law, local short-solution law, and global norm lift are absent",
             "actual_attack_cost": None},
            {"route": "coefficient CRT-only lift floor",
             "result": "exact necessary magnitude Q/m; does not determine polynomial-factor lifting or attack success",
             "actual_attack_cost": None},
            {"route": "universal final-column verification kernel",
             "result": "exact zero-BKZ public restricted-kernel witness; not a fresh-message forgery or complete structural estimate",
             "actual_attack_cost": None},
        ],
        "rows": rows,
        "one_actual_signature_probe": replay_default_param_i(),
        "full_ring_HNF_MSIS_attack_cost": None,
        "CRT_subfield_attack_cost": None,
        "accepted_setup_root_structural_attack_cost": None,
        "published_Table5_costs_reproduced": False,
        "private_material_exported": False,
        "HIBE_involved": False,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8", newline="\n")
    print(json.dumps({"output": str(args.output), "rows": len(report["rows"]),
                      "replacement_accepted": report["one_actual_signature_probe"]["probe"]["best_replacement_accepted"],
                      "security_claim": "none"}, sort_keys=True))


if __name__ == "__main__":
    main()
