"""Public same-message SRGG replacement under the published verifier.

This is an exact algebraic/finite-execution audit, not a universal forgery
probability or a proof about the paper's EUF (fresh-message) game.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import platform

from sage.version import version as sage_version

from ibme.core.randomness import DeterministicRandom

from .paper_algebra import PaperRing, identity_target
from .paper_objects import PublicKey, Signature
from .paper_parameters import PaperParams
from .paper_schur_backend import SourceSchurBackend


ROOT = Path(__file__).resolve().parents[4]
PAPER = "papers/2025_efficient_ibs_jia.pdf"
IDENTITY = b"Alice"
MESSAGE = b"SRGG paper baseline: 32 bytes!!!"
SOURCE_FILES = (
    "experiments/research/candidates/srgg/paper_strong_game.py",
    "experiments/research/candidates/srgg/paper_schur_backend.py",
    "experiments/research/candidates/srgg/paper_backend.py",
    "experiments/research/candidates/srgg/paper_validation.py",
    "experiments/research/candidates/srgg/paper_objects.py",
    "experiments/research/candidates/srgg/paper_algebra.py",
    "experiments/research/candidates/srgg/paper_parameters.py",
    "experiments/research/candidates/srgg/paper_profiles.py",
)


class NoRead:
    def read(self, count):
        raise AssertionError("public replacement must not consume entropy")


def squared_norm(response):
    return sum(value * value for poly in response for value in poly)


def q_shift_replacement(public, identity, message, signature):
    """Return one strict, publicly computable replacement or None.

    The search covers the +/-Q unit shifts in the first rank identity-block
    polynomials. It does not search all same-message forgeries. Among both
    signs, moving a coefficient toward zero minimizes the squared norm.
    """
    if type(public) is not PublicKey or type(signature) is not Signature:
        raise TypeError("paper public key and signature required")
    backend = SourceSchurBackend(rng=NoRead())
    if not backend.verify(public, identity, message, signature):
        raise ValueError("a valid public signing-oracle answer is required")

    params, q = public.params, public.params.modulus
    cap, old_norm = params.signature_norm_cap, squared_norm(signature.response)
    ring = PaperRing(params)
    target = identity_target(public, identity)
    matrix = ring.signing_matrix(public, target)
    choices = []
    for row in range(params.rank):
        # This explicitly checks the paper's [2I_d | ...] block; a changed
        # protocol must not inherit the Q-shift conclusion by accident.
        if any(matrix[i][row] != ring.constant(2 if i == row else 0)
               for i in range(params.rank)):
            raise ValueError("published 2I identity block absent")
        for column, value in enumerate(signature.response[row]):
            delta = -q if value >= 0 else q
            new_norm = old_norm + q * q + 2 * value * delta
            choices.append((new_norm, row, column, delta, value))
    best = min(choices)
    eligible = sum(item[0] <= cap for item in choices)
    result = {
        "original_valid": True,
        "identity_block_2I_checked": True,
        "modulus_Q": q,
        "original_norm_squared": old_norm,
        "signature_norm_cap_squared": cap,
        "best_shift_norm_squared": best[0],
        "best_shift_excess_over_cap": max(0, best[0] - cap),
        "tested_basis_positions": len(choices),
        "eligible_basis_positions": eligible,
        "single_basis_replacement_found": eligible > 0,
        "same_identity": True,
        "same_message": True,
        "same_challenge": True,
        "fresh_under_exact_signature_sEUF_game": False,
        "fresh_under_paper_G0_fresh_message_game": False,
        "private_material_exported": False,
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
        "nist_security_category": None,
    }
    if not eligible:
        result.update({"replacement": None, "replacement_valid": None,
                       "canonical_signature_distinct": None,
                       "recovered_commitment_equal": None})
        return None, result

    new_norm, row, column, delta, value = best
    updated = [list(poly) for poly in signature.response]
    updated[row][column] = value + delta
    replacement = replace(signature, response=updated)
    old_bytes, new_bytes = signature.to_bytes(), replacement.to_bytes()
    roundtrip = Signature.from_bytes(new_bytes).to_bytes() == new_bytes
    loaded = backend.load_signature(public, new_bytes).to_bytes() == new_bytes
    equal_commitment = (
        ring.recover(public, target, signature.response, signature.challenge)
        == ring.recover(public, target, replacement.response, replacement.challenge)
    )
    valid = backend.verify(public, identity, message, replacement)
    distinct = old_bytes != new_bytes
    if not (new_norm <= cap and squared_norm(replacement.response) == new_norm
            and equal_commitment and valid and distinct and roundtrip and loaded):
        raise AssertionError("claimed public strong replacement failed")
    result.update({
        "replacement": {"row": row, "coefficient_index": column,
                        "original_coefficient": value, "delta": delta,
                        "changed_coefficient": value + delta,
                        "norm_squared": new_norm,
                        "original_signature_sha256": sha256(old_bytes).hexdigest(),
                        "replacement_signature_sha256": sha256(new_bytes).hexdigest()},
        "replacement_valid": valid,
        "canonical_signature_distinct": distinct and roundtrip and loaded,
        "recovered_commitment_equal": equal_commitment,
        "fresh_under_exact_signature_sEUF_game": True,
    })
    return replacement, result


def replay_original_row(profile_name, interpretation):
    """Use the frozen audit's test-only tape; export public diagnostics only."""
    params = PaperParams(profile_name, interpretation)
    paper_hash = sha256((ROOT / PAPER).read_bytes()).hexdigest()
    if paper_hash != params.source.source_sha256:
        raise ValueError("frozen paper hash mismatch")
    seed = ("paper-baseline-" + profile_name + "-" + interpretation).encode("ascii")
    backend = SourceSchurBackend(rng=DeterministicRandom(seed))
    public, master = backend.setup(params)
    key = backend.key_extract(master, IDENTITY)
    signature = backend.sign(key, MESSAGE)
    _, evidence = q_shift_replacement(public, IDENTITY, MESSAGE, signature)
    return {
        "profile": profile_name,
        "interpretation": interpretation,
        "test_only_random_seed_utf8": seed.decode("ascii"),
        "identity_bytes": len(IDENTITY),
        "message_bytes": len(MESSAGE),
        "signature_queries": 1,
        "setup_attempts": backend.setup_attempts,
        "extraction_calls": backend.extract_calls,
        "sign_attempts": backend.sign_attempts,
        "public_key_sha256": sha256(public.to_bytes()).hexdigest(),
        "published_gamma": str(params.source.gamma),
        "probe": evidence,
    }


def build_report(rows):
    if not rows:
        raise ValueError("at least one original row required")
    return {
        "schema": "IBME/SRGG-PAPER-STRONG-GAME/1",
        "paper": {"path": PAPER,
                  "sha256": sha256((ROOT / PAPER).read_bytes()).hexdigest(),
                  "locations": "PDF p.4 Definition 3; p.8 Algorithms 7-8, Theorem 2 and G0"},
        "source_sha256": {name: sha256((ROOT / name).read_bytes()).hexdigest()
                          for name in SOURCE_FILES},
        "environment": {"python": platform.python_version(), "sage": sage_version,
                        "platform": platform.platform(), "machine": platform.machine()},
        "randomness": "DeterministicRandom TEST ONLY",
        "hash_model": "SHAKE implementation; no ROM or QROM security proof",
        "game_freshness": {
            "paper_Definition_3_and_G0": "fresh (identity,message)",
            "native_strong_target": "fresh exact canonical (identity,message,signature) triple",
            "same_message_replacement_wins_paper_G0": False,
        },
        "rows": rows,
        "scope": "one authentic source-Schur signature per row; public single-basis Q shift only",
        "private_material_exported": False,
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
        "nist_security_category": None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile", choices=("PARAM-I", "PARAM-II", "PARAM-III"))
    parser.add_argument("--interpretation", choices=("table-standard-deviation",
                                                        "literal-density-width"))
    args = parser.parse_args()
    if args.profile is None and args.interpretation is not None:
        parser.error("--interpretation needs --profile")
    if args.profile is not None:
        interpretations = (args.interpretation or "table-standard-deviation",)
        profiles = (args.profile,)
    else:
        interpretations = ("table-standard-deviation", "literal-density-width")
        profiles = ("PARAM-I", "PARAM-II", "PARAM-III")
    rows = [replay_original_row(name, interpretation)
            for interpretation in interpretations for name in profiles]
    result = build_report(rows)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8", newline="\n")
    print(json.dumps({"output": str(args.output), "rows": len(rows),
                      "replacements": sum(bool(row["probe"]["replacement_valid"])
                                          for row in rows),
                      "security_claim": "none"}, sort_keys=True))


if __name__ == "__main__":
    main()
