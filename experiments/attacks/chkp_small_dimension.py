"""Bounded public seed recovery for weak n <= 2 CHKP research parameters.

Enumerate the finite errors at an invertible public preamble minor, solve for
the encryption vector, then check every remaining public equation. No private
key, trapdoor, expected seed, or encryption vector is an input. The result
contains only candidate seed hashes and public diagnostics. This is a negative
control for deliberately small parameters, not an attack on general CHKP/LWE.

CLI: python -m experiments.attacks.chkp_small_dimension public-fixture.json
The fixture contains schema, oracle_hex, capsule_hex, receiver_hex, sender_hex,
noise_radius, and optionally max_candidates. The runner prints JSON to stdout;
it does not load or write any key/state file and imports no Sage module.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
from itertools import combinations, product
import json
from math import gcd
from pathlib import Path
import sys

SCHEMA = "IBME:CHKP:PUBLIC-SMALL-DIMENSION-ATTACK:v1"
DEFAULT_MAX_CANDIDATES = 10_000
MAX_CANDIDATES = 1_000_000
MAX_PIVOT_CHECKS = 100_000
MAX_FIXTURE_BYTES = 40 * 2**20


class AttackInputError(ValueError):
    """The supplied public objects do not satisfy this diagnostic's contract."""


class AttackBudgetExceeded(ValueError):
    """An explicit finite diagnostic budget would be exceeded; nothing is hidden."""


def _integer(value, name, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise AttackInputError(f"{name} must be an integer in {minimum}..{maximum}")
    return value


def _inverse_minor(rows, q):
    """Return n public columns and their inverse, with bounded minor search."""
    n, width = len(rows), len(rows[0])
    for tries, positions in enumerate(combinations(range(width), n), 1):
        if tries > MAX_PIVOT_CHECKS:
            raise AttackBudgetExceeded("public invertible-minor search budget exceeded")
        if n == 1:
            a = rows[0][positions[0]]
            if gcd(a, q) == 1:
                return positions, ((pow(a, -1, q),),), tries
        else:
            i, j = positions
            # The selected equations are A[:, position]^T * r = b - e.
            a, b, c, d = rows[0][i], rows[1][i], rows[0][j], rows[1][j]
            determinant = (a * d - b * c) % q
            if gcd(determinant, q) == 1:
                scale = pow(determinant, -1, q)
                return positions, ((d * scale % q, -b * scale % q),
                                   (-c * scale % q, a * scale % q)), tries
    raise AttackInputError("public preamble has no invertible minor for this diagnostic")


def _center(value, q):
    value %= q
    return value if value <= q // 2 else value - q


def _bit(phase, q):
    """Original nearest-center rule: ties decode to one, including odd q."""
    phase %= q
    return int(abs(_center(phase, q)) >= abs(_center(phase - q // 2, q)))


def recover_seed_hashes(oracle, receiver, sender, capsule, radius, *,
                        max_candidates=DEFAULT_MAX_CANDIDATES):
    """Recover hashes of all public-consistent seeds within the declared support.

    radius is the actual public finite rounded-noise support, not alpha or a
    Gaussian standard deviation. Completeness is conditional on all errors
    lying in [-radius, radius]; no probability/security bound is inferred.
    Even a unique hash is a candidate until the experiment compares its digest
    with the original seed outside this attacker. No secret value is returned.
    """
    from ibme.lattice.chkp.identity import ROHIBEContext
    from ibme.lattice.chkp.seed_kem import SeedCapsule
    from ibme.core.errors import IBMEError

    if type(oracle) is not ROHIBEContext or type(capsule) is not SeedCapsule:
        raise AttackInputError("canonical public ROHIBEContext and SeedCapsule required")
    _integer(oracle.n, "dimension", 1, 2)
    _integer(oracle.q, "q", 5, 2**61 - 1)
    _integer(radius, "noise radius", 0, 2**60)
    _integer(max_candidates, "max_candidates", 1, MAX_CANDIDATES)
    if 2 * radius >= oracle.q // 2:
        raise AttackInputError("noise support must be strictly inside a unique bit decoding interval")
    total = (2 * radius + 1) ** oracle.n
    if total > max_candidates:
        raise AttackBudgetExceeded(f"error enumeration needs {total} candidates, cap is {max_candidates}")
    # Frozen dataclasses are not an authenticity boundary. Reparse their public
    # wire to recheck dimensions/residues and recompute the context digest.
    try:
        canonical = ROHIBEContext.from_bytes(oracle.to_bytes())
        parsed = SeedCapsule.from_bytes(capsule.to_bytes())
        if canonical != oracle or canonical.context != oracle.context or parsed != capsule:
            raise AttackInputError("noncanonical public object")
        oracle.path_bytes((receiver, sender))
    except (IBMEError, ValueError, TypeError, OverflowError, AttributeError) as exc:
        raise AttackInputError("invalid canonical public input") from exc
    if (capsule.context != oracle.context or capsule.q != oracle.q
            or len(capsule.preamble) != oracle.leaf_dimension):
        raise AttackInputError("public context/modulus/preamble shape mismatch")
    rows = oracle.leaf_rows(receiver, sender)
    positions, inverse, pivot_checks = _inverse_minor(rows, oracle.q)
    targets = oracle.targets(receiver, sender)
    columns = tuple(zip(*rows))
    q, hashes, preamble_candidates, surviving = oracle.q, set(), 0, 0
    for errors in product(range(-radius, radius + 1), repeat=oracle.n):
        residual = tuple((capsule.preamble[i] - e) % q for i, e in zip(positions, errors))
        encryption_vector = tuple(sum(a * b for a, b in zip(row, residual)) % q for row in inverse)
        if not all(abs(_center(value - sum(a * r for a, r in zip(column, encryption_vector)), q)) <= radius
                   for column, value in zip(columns, capsule.preamble)):
            continue
        preamble_candidates += 1
        bits = []
        for target, value in zip(targets, capsule.terminals):
            phase = (value - sum(a * r for a, r in zip(target, encryption_vector))) % q
            bit = _bit(phase, q)
            if abs(_center(phase - bit * (q // 2), q)) > radius:
                break
            bits.append(bit)
        if len(bits) != 256:
            continue
        recovered = bytes(sum(bits[8 * i + j] << (7 - j) for j in range(8)) for i in range(32))
        hashes.add(sha256(recovered).hexdigest())
        surviving += 1
    return dict(schema=SCHEMA, status="candidate_found" if hashes else "no_candidate_in_support",
                n=oracle.n, q=q, preamble_coordinates=len(columns), seed_bits=256,
                finite_noise_radius=radius, max_candidates=max_candidates,
                enumerated_error_tuples=total, pivot_checks=pivot_checks,
                selected_public_positions=list(positions), preamble_candidates=preamble_candidates,
                surviving_candidates=surviving, distinct_seed_candidates=len(hashes),
                recovered_seed_sha256=sorted(hashes), unique_seed_candidate=len(hashes) == 1,
                public_context_sha256=sha256(oracle.to_bytes()).hexdigest(),
                capsule_sha256=sha256(capsule.to_bytes()).hexdigest(),
                private_state_loaded=False, private_seed_input=False, randomness_used=False,
                limitation="Weak n<=2 research-profile diagnostic; finite support is an explicit assumption, not a general LWE break.",
                security_claim="none", backend_admitted=False, parameters_are_formal=False)


def attack_fixture(fixture):
    """Strict public-only JSON object; no paths or private material are accepted."""
    from ibme.lattice.chkp.identity import ROHIBEContext
    from ibme.lattice.chkp.seed_kem import SeedCapsule

    required = {"schema", "oracle_hex", "capsule_hex", "receiver_hex", "sender_hex", "noise_radius"}
    if (type(fixture) is not dict or not required <= set(fixture)
            or set(fixture) - required - {"max_candidates"} or fixture.get("schema") != SCHEMA):
        raise AttackInputError("unsupported public fixture schema/fields")
    raw = {}
    for name in ("oracle_hex", "capsule_hex", "receiver_hex", "sender_hex"):
        value = fixture[name]
        if (type(value) is not str or not value or len(value) % 2
                or any(c not in "0123456789abcdef" for c in value)):
            raise AttackInputError("public fixture requires nonempty canonical lowercase hex")
        raw[name] = bytes.fromhex(value)
    return recover_seed_hashes(ROHIBEContext.from_bytes(raw["oracle_hex"]), raw["receiver_hex"],
                               raw["sender_hex"], SeedCapsule.from_bytes(raw["capsule_hex"]),
                               fixture["noise_radius"], max_candidates=fixture.get("max_candidates", DEFAULT_MAX_CANDIDATES))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    args = parser.parse_args(argv)
    try:
        with args.fixture.open("rb") as handle:
            raw = handle.read(MAX_FIXTURE_BYTES + 1)
        if len(raw) > MAX_FIXTURE_BYTES:
            raise AttackBudgetExceeded("public fixture file exceeds size budget")
        def unique_fields(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise AttackInputError("duplicate public fixture field")
                result[key] = value
            return result
        result = attack_fixture(json.loads(raw, object_pairs_hook=unique_fields))
    except Exception as exc:
        print(json.dumps(dict(schema=SCHEMA, status="error", error_type=type(exc).__name__,
                              error="public input rejected or diagnostic could not execute",
                              security_claim="none", backend_admitted=False)), file=sys.stdout)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    # A clean negative search is a completed diagnostic, not a proven defense.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
