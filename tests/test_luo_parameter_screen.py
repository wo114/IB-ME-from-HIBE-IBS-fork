"""Independent public-attack replay and parameter accounting checks."""

from math import comb, log2

import pytest

from experiments.research.luo_matrix_reference import MatrixParams, setup
from experiments.research.luo_parameter_screen import (
    recover_small_master, public_forgery_controls, screen_row, screening_rows,
)
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.luo import LuoIBSBackend, LuoPublicKey
from ibme.protocol.baseline import DOMAIN_SIGNATURE, encode_signature


def test_publicly_recovered_master_can_forge_with_no_victim_oracles():
    controls = public_forgery_controls()
    assert len(controls) == 2
    backend = LuoIBSBackend()
    for control in controls:
        pk = LuoPublicKey.from_bytes(bytes.fromhex(control["public_key_hex"]))
        signature = backend.load_signature(pk, bytes.fromhex(control["signature_hex"]))
        assert backend.verify(pk, bytes.fromhex(control["identity_hex"]),
                              bytes.fromhex(control["message_hex"]), signature)
        assert control["candidate_vectors_checked"] == 3**8
        assert control["victim_extract_queries"] == control["victim_sign_queries"] == 0
        assert control["private_material_published"] is False


def test_enumeration_budget_guards_large_profiles():
    pk, _ = setup(MatrixParams(m=16), rng=DeterministicRandom(b"luo-m2:budget"))
    with pytest.raises(ValueError, match="budget"):
        recover_small_master(pk, candidate_limit=100000)


def test_recovered_secret_equation_uses_only_public_data():
    pk, _ = setup(MatrixParams(), rng=DeterministicRandom(b"luo-m2:public-equation"))
    # Make a public-only copy, with no master object accessible to the solver.
    pk = type(pk).from_bytes(pk.to_bytes())
    recovered, count = recover_small_master(pk)
    assert count == 6561 and recovered is not None
    for i in range(pk.params.n):
        for j in range(pk.params.k):
            assert sum(pk.A[i][h] * recovered.S[h][j] for h in range(pk.params.m)) % pk.params.q == pk.T[i][j]


@pytest.mark.parametrize("row", screening_rows())
def test_theorem_input_keeps_actual_columns_and_infinity_norm(row):
    name, p, executable = row
    result = screen_row(name, p, executable)
    assert result["estimator_input"] == dict(n=p["n"], m=p["m"], q=p["q"],
                                             length_bound=2*p["gamma2"]+2*p["kappa"]**2*p["eta"],
                                             norm="infinity")
    assert result["security_claim"] == "none" and result["backend_admitted"] is False
    if not executable:
        assert result["current_wire_encodable"] is False
        assert result["current_signature_wire_bytes"] is None


def test_public_master_columns_map_to_bounded_lwe_inputs():
    for name, parameters, _ in screening_rows()[2:]:
        model = screen_row(name, parameters, False)["master_recovery_lwe_input"]
        assert model["secret_dimension"] == parameters["m"] - parameters["n"]
        assert model["sample_count"] == parameters["n"]
        assert model["q"] == parameters["q"]
        assert model["secret_distribution"] == "uniform integers [-1,1], inclusive"
        assert model["error_distribution"] == "uniform integers [-1,1], inclusive"
        assert model["condition"] == "A0 (the first n columns of A) is invertible over Z_q"
        assert model["samples_per_master_column"] == parameters["n"]
        assert model["independent_master_columns"] == parameters["k"]


def test_challenge_cap_cannot_reach_128_bit_even_with_best_weight():
    best_count, best_weight = max((comb(32, weight)*2**weight, weight) for weight in range(1,33))
    assert best_weight == 22
    assert 2**47 < best_count < 2**48
    assert log2(comb(4, 2)*2**2) == log2(24)
    big = screen_row(*screening_rows()[-1])
    assert big["challenge_count_at_least_2pow256"]
    assert big["generic_quantum_challenge_search_exponent"] >= 128


def test_rejection_planning_matches_small_exact_counts():
    result = screen_row(*screening_rows()[0])
    # Independent inclusive Extract and strict Sign lattice-point counts.
    expected_extract = (257/253)**32
    expected_sign = (4097/3583)**8
    assert result["extraction"]["planning_expected_trials"] == pytest.approx(expected_extract)
    assert result["signing"]["planning_expected_trials"] == pytest.approx(expected_sign)
    assert result["extraction"]["unconditional_central_region_log2_acceptance_lower_bound"] == pytest.approx(32*log2(249/257))
    assert result["signing"]["unconditional_central_region_log2_acceptance_lower_bound"] == pytest.approx(8*log2(3071/4097))


@pytest.mark.parametrize("index", [0,1])
def test_current_wire_sizes_equal_real_encoded_objects(index):
    name, values, executable = screening_rows()[index]
    from ibme.ibs.luo import LuoMatrixParams
    backend = LuoIBSBackend(rng=DeterministicRandom(b"luo-m2:wire-size"))
    pk, master = backend.setup(LuoMatrixParams(**values))
    key = backend.key_extract(master, b"A")
    signature = backend.sign(key, b"size")
    result = screen_row(name, values, executable)
    assert result["current_signature_wire_bytes"] == len(signature.to_bytes())
    assert len(encode_signature(signature)) == len(DOMAIN_SIGNATURE) + 4 + result["current_signature_wire_bytes"]


@pytest.mark.parametrize("change", [{"kappa": True}, {"m": 4}, {"q": 8}, {"q": 1}, {"gamma2": 256}])
def test_invalid_screening_inputs_rejected(change):
    _, p, _ = screening_rows()[0]
    with pytest.raises(ValueError):
        screen_row("invalid", {**p, **change}, False)
