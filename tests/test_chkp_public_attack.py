"""Public algebraic attack fixtures; these are not newly sampled CHKP keys."""

from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from experiments.attacks.chkp_small_dimension import (
    AttackBudgetExceeded, AttackInputError, SCHEMA, attack_fixture, recover_seed_hashes,
)
from ibme.lattice.chkp.identity import ROHIBEContext
from ibme.lattice.chkp.seed_kem import SeedCapsule


def public_fixture(n=2, *, q=65537, m=4, radius=2):
    rows = tuple(tuple((j + 2) ** (i + 1) % q for j in range(m)) for i in range(n))
    oracle = ROHIBEContext(n, m, q, rows, b"TEST-ONLY:PUBLIC-ALGEBRAIC-ATTACK-FIXTURE:v1")
    receiver, sender, seed = b"Bob", b"Alice", bytes(range(32))
    # Explicit non-Gaussian fixture values only construct public test inputs.
    # Neither r nor seed is passed to the attacker.
    r = tuple(13 + 7 * i for i in range(n))
    noise = lambda i: i % (2 * radius + 1) - radius
    matrix, targets = oracle.leaf_rows(receiver, sender), oracle.targets(receiver, sender)
    preamble = tuple((sum(row[j] * x for row, x in zip(matrix, r)) + noise(j)) % q
                     for j in range(oracle.leaf_dimension))
    bits = tuple((byte >> k) & 1 for byte in seed for k in range(7, -1, -1))
    terminals = tuple((sum(a * x for a, x in zip(target, r)) + bit * (q // 2)
                       + noise(j + 1)) % q for j, (target, bit) in enumerate(zip(targets, bits)))
    return oracle, receiver, sender, SeedCapsule(oracle.context, q, preamble, terminals), sha256(seed).hexdigest()


@pytest.mark.parametrize("n", [1, 2])
def test_public_only_seed_recovery_and_no_entropy(n, monkeypatch):
    from ibme.core.randomness import SecureRandom
    oracle, receiver, sender, capsule, expected = public_fixture(n)
    def forbidden(*args, **kwargs):
        pytest.fail("public attacker requested entropy")
    monkeypatch.setattr(SecureRandom, "read", forbidden)
    result = recover_seed_hashes(oracle, receiver, sender, capsule, 2)
    assert result["recovered_seed_sha256"] == [expected]
    assert result["enumerated_error_tuples"] == 5**n
    assert result["surviving_candidates"] == 1
    assert result["private_state_loaded"] is False and result["private_seed_input"] is False
    assert result["security_claim"] == "none" and result["parameters_are_formal"] is False
    assert not any(key in result for key in ("seed", "r", "private_key", "preimages", "encryption_vector"))


def test_frozen_profile_shape_uses_all_381_public_coordinates():
    oracle, receiver, sender, capsule, expected = public_fixture(q=1099511627791, m=127, radius=4)
    result = recover_seed_hashes(oracle, receiver, sender, capsule, 4)
    assert result["preamble_coordinates"] == 381
    assert result["enumerated_error_tuples"] == 81
    assert result["recovered_seed_sha256"] == [expected]


def test_all_preamble_and_terminal_equations_filter_candidates():
    oracle, receiver, sender, capsule, _ = public_fixture()
    changed = replace(capsule, preamble=capsule.preamble[:-1] + ((capsule.preamble[-1] + 1000) % oracle.q,))
    result = recover_seed_hashes(oracle, receiver, sender, changed, 2)
    assert result["preamble_candidates"] == 0
    changed = replace(capsule, terminals=capsule.terminals[:-1] + ((capsule.terminals[-1] + 1000) % oracle.q,))
    result = recover_seed_hashes(oracle, receiver, sender, changed, 2)
    assert result["preamble_candidates"] == 1 and result["surviving_candidates"] == 0
    assert result["status"] == "no_candidate_in_support"


def test_wrong_known_identity_does_not_recover_fixture_seed():
    oracle, receiver, _, capsule, expected = public_fixture()
    result = recover_seed_hashes(oracle, receiver, b"Mallory", capsule, 2)
    assert expected not in result["recovered_seed_sha256"]


@pytest.mark.parametrize("radius,cap,error", [(2, 24, AttackBudgetExceeded), (2, True, AttackInputError),
    (True, 10000, AttackInputError), (2.0, 10000, AttackInputError), (-1, 10000, AttackInputError),
    (20000, 10000, AttackInputError), (2, 0, AttackInputError)])
def test_budget_and_integer_rejection(radius, cap, error):
    oracle, receiver, sender, capsule, _ = public_fixture()
    with pytest.raises(error):
        recover_seed_hashes(oracle, receiver, sender, capsule, radius, max_candidates=cap)


@pytest.mark.parametrize("kind", ["context", "modulus", "dimension", "oracle", "identity", "type", "mutated"])
def test_input_binding_and_shape_rejections(kind):
    oracle, receiver, sender, capsule, _ = public_fixture()
    if kind == "context":
        capsule = replace(capsule, context=b"X" * 64)
    elif kind == "modulus":
        capsule = replace(capsule, q=oracle.q + 2)
    elif kind == "dimension":
        capsule = replace(capsule, preamble=capsule.preamble[:-1])
    elif kind == "oracle":
        oracle = replace(oracle, public_configuration=b"DIFFERENT")
    elif kind == "identity":
        sender = b""
    elif kind == "type":
        capsule = object()
    else:
        object.__setattr__(oracle, "context", b"X" * 64)
    with pytest.raises((AttackInputError, ValueError)):
        recover_seed_hashes(oracle, receiver, sender, capsule, 2)


def test_dimension_three_is_refused_before_search():
    oracle, receiver, sender, capsule, _ = public_fixture(3)
    with pytest.raises(AttackInputError, match="dimension"):
        recover_seed_hashes(oracle, receiver, sender, capsule, 2)


def fixture_json():
    oracle, receiver, sender, capsule, expected = public_fixture()
    return dict(schema=SCHEMA, oracle_hex=oracle.to_bytes().hex(), capsule_hex=capsule.to_bytes().hex(),
                receiver_hex=receiver.hex(), sender_hex=sender.hex(), noise_radius=2), expected


def test_public_fixture_roundtrip_and_unknown_private_fields_are_rejected():
    fixture, expected = fixture_json()
    assert attack_fixture(fixture)["recovered_seed_sha256"] == [expected]
    with pytest.raises(AttackInputError):
        attack_fixture({**fixture, "private_seed": "should-not-be-an-input"})
    with pytest.raises(AttackInputError):
        attack_fixture({**fixture, "oracle_hex": fixture["oracle_hex"].upper()})


def test_real_cli_runs_without_sage_and_invalid_json_fails_closed(tmp_path):
    fixture, expected = fixture_json()
    path = tmp_path / "public.json"
    path.write_text(json.dumps(fixture))
    root = Path(__file__).resolve().parents[1]
    env = {**os.environ, "PYTHONPATH": str(root / "src") + os.pathsep + str(root), "PYTHONDONTWRITEBYTECODE": "1"}
    command = [sys.executable, "-B", "-m", "experiments.attacks.chkp_small_dimension", str(path)]
    result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["recovered_seed_sha256"] == [expected]
    path.write_text('{"schema":"first","schema":"second"}')
    result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=15)
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "error"
