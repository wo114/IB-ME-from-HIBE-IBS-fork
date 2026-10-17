"""Exact CUR pairs and conditional signature transforms; no source run is asserted."""

from itertools import product
import json
from math import isqrt
import sys

import pytest

from experiments.research.candidates.srgg.algebra import (
    Params, PublicRelation, constant, recover_commitment,
)
from experiments.research.candidates.srgg.config import Config
from experiments.research.candidates.srgg.cur_obstruction import (
    MAX_BOUND_BITS, MAX_MODULUS_BITS, MAX_RESPONSE_COEFFICIENTS, SCHEMA,
    build_report, coefficient_malleation, collision_pair, configuration_gate,
    main, source_rows, transform_response,
)


def test_public_pair_matches_real_commitment_recovery_with_nonzero_public_blocks():
    p = Params(degree=2, rank=1, p=5, base=3, digits=1)
    public = PublicRelation(p, ((constant(p, 3),),), ((constant(p, 7),),))
    target, challenge = (constant(p, 4),), constant(p, 0)
    checked = collision_pair(p.modulus, 64)
    zero = constant(p, 0)
    plus = (constant(p, checked["plus_coefficient"]),) + (zero,) * p.columns
    minus = (constant(p, checked["minus_coefficient"]),) + (zero,) * p.columns
    assert plus != minus
    assert sum(x*x for row in plus for x in row) == 49
    assert sum(x*x for row in minus for x in row) == 64
    assert recover_commitment(public, target, plus, challenge) == (
        constant(p, 14),)
    assert recover_commitment(public, target, plus, challenge) == recover_commitment(
        public, target, minus, challenge)
    assert checked["cur_obstruction_at_this_cap"] is True
    assert collision_pair(p.modulus, 63)["cur_obstruction_at_this_cap"] is False


@pytest.mark.parametrize("q", [3, 5, 15, 257, 15744063])
def test_inclusive_squared_norm_threshold(q):
    threshold = ((q+1)//2)**2
    below = collision_pair(q, threshold-1)
    at = collision_pair(q, threshold)
    assert below["same_commitment"] and below["distinct_responses"]
    assert not below["both_responses_within_cap"]
    assert not below["cur_certified_if_pair_does_not_fit"]
    assert at["both_responses_within_cap"] and at["cur_obstruction_at_this_cap"]
    assert at["difference_coefficient"] == q
    assert at["plus_commitment_coefficient"] == q-1
    assert at["minus_commitment_coefficient"] == q-1


def test_literal_source_rows_exhibit_obstruction_without_float_cutoffs():
    rows = source_rows()
    assert [row["source_name"] for row in rows] == ["PARAM-I", "PARAM-II", "PARAM-III"]
    for row in rows:
        assert row["modulus_Q"] == 15744063
        assert row["plus_coefficient"] == 7872031
        assert row["minus_coefficient"] == -7872032
        assert row["pair_required_gamma_squared"] == 7872032**2
        assert row["cur_obstruction_at_this_cap"] is True
        assert row["full_fs_forgery"] is False
        assert row["hash_fixed_point_searched"] is False
        attack = row["conditional_strong_malleation"]
        assert attack["sufficient_old_norm_squared_max"] == row["gamma_squared_cap"]-15744063**2
        assert attack["nonnegative_coefficient_independent_margin_exists"]
        assert not attack["source_honest_signature_executed"]
        assert not attack["guaranteed_for_every_valid_signature"]
        assert attack["success_probability"] is None


def test_existing_config_gate_excludes_public_pair_at_one_unit_margin():
    default = configuration_gate()
    assert default["existing_config_gate_excludes_this_pair"] is True
    assert default["cur_obstruction_at_this_cap"] is False
    # Q^2-4B=1.  Rounding sqrt(B) upward would mishandle this valid gate.
    edge = Config(signature_first_squared=305305888679,
                  signature_second_squared=305305888679)
    checked = configuration_gate(edge)
    assert checked["gate_margin_Q_squared_minus_four_B"] == 1
    assert checked["existing_config_gate_excludes_this_pair"] is True
    assert checked["excludes_all_single_Q_shifts_between_norm_valid_responses"]
    assert not checked["other_cur_obstructions_excluded"]
    assert not checked["strong_security_certified"]
    with pytest.raises(ValueError, match="Q>2"):
        Config(signature_first_squared=305305888680,
               signature_second_squared=305305888680)


@pytest.mark.parametrize("q,cap", [
    (True, 9), (False, 9), (3.0, 9), ("3", 9), (1, 9), (-3, 9),
    (4, 9), (16, 100), (3, True), (3, 9.0), (3, "9"), (3, -1),
])
def test_invalid_moduli_and_norm_caps_are_rejected(q, cap):
    with pytest.raises(ValueError):
        collision_pair(q, cap)


def test_integer_resource_cap_boundaries_and_zero_norm_cap():
    largest_bit_modulus = (1 << (MAX_MODULUS_BITS-1)) + 1
    at_modulus_cap = collision_pair(largest_bit_modulus, 0)
    assert at_modulus_cap["modulus_Q"].bit_length() == MAX_MODULUS_BITS
    assert not at_modulus_cap["cur_obstruction_at_this_cap"]
    at_bound_cap = collision_pair(3, (1 << MAX_BOUND_BITS)-1)
    assert at_bound_cap["cur_obstruction_at_this_cap"]
    with pytest.raises(ValueError, match="public audit cap"):
        collision_pair((1 << MAX_MODULUS_BITS)+1, 0)
    with pytest.raises(ValueError, match="public audit cap"):
        collision_pair(3, 1 << MAX_BOUND_BITS)
    with pytest.raises(ValueError, match="Config"):
        configuration_gate({})


def test_report_keeps_cur_and_signature_claims_separate():
    report = build_report()
    assert report["schema"] == SCHEMA
    assert report["security_claim"] == "none"
    for key in ("full_fs_forgery", "hash_fixed_point_searched", "cur_certified",
                "strong_security_proof_verified", "backend_admitted", "parameters_are_formal"):
        assert report[key] is False
    assert all(row["cur_obstruction_at_this_cap"] for row in report["source_parameter_rows"])
    assert not report["source_honest_signature_executed"]
    assert not report["unconditional_source_signature_break_claimed"]
    assert report["conditional_malleation"]["success_probability"] is None


@pytest.mark.parametrize("coefficient,shift", [(3, -15), (-3, 15), (0, 15)])
def test_q_shift_exact_norm_and_inclusive_conditional_success(coefficient, shift):
    old = coefficient*coefficient+5
    new = old+225-30*abs(coefficient)
    at = coefficient_malleation(15, new, coefficient, old)
    assert at["shift"] == shift
    assert at["new_coefficient"] == coefficient+shift
    assert at["new_norm_squared"] == new
    assert at["same_commitment_for_every_unchanged_challenge"]
    assert at["distinct_response"]
    assert at["strong_malleation_if_original_signature_valid"]
    assert not at["original_signature_verified_by_this_check"]
    assert not at["hash_fixed_point_search_required"]
    below = coefficient_malleation(15, new-1, coefficient, old)
    assert not below["strong_malleation_if_original_signature_valid"]


def test_observable_margin_is_sufficient_but_not_necessary():
    # At v=0 the sufficient margin is tight: old=B-Q^2=5.
    edge = coefficient_malleation(15, 230, 0, 5)
    assert edge["coefficient_independent_margin_condition_holds"]
    assert edge["strong_malleation_if_original_signature_valid"]
    # A larger |v| improves the exact bound even without that margin.
    sharper = coefficient_malleation(15, 144, 3, 9)
    assert not sharper["coefficient_independent_margin_condition_holds"]
    assert sharper["strong_malleation_if_original_signature_valid"]
    # No statement about input signature validity follows from a norm check.
    invalid_old_norm = coefficient_malleation(15, 10, 15, 225)
    assert invalid_old_norm["new_norm_within_cap"]
    assert not invalid_old_norm["original_norm_within_cap"]
    assert not invalid_old_norm["strong_malleation_if_original_signature_valid"]


@pytest.mark.parametrize("degree", [2, 4])
@pytest.mark.parametrize("first_coefficient", [0, 3, -3])
def test_transform_preserves_real_recovery_for_every_binary_challenge(degree, first_coefficient):
    p = Params(degree=degree, rank=1, p=5, base=3, digits=1)
    public = PublicRelation(p, ((tuple(range(1, degree+1)),),),
                            ((tuple(x % p.modulus for x in range(-degree, 0)),),))
    target = (tuple(range(degree)),)
    response = [first_coefficient]+[(-1)**i*(i % 3) for i in range(1, (p.columns+1)*degree)]
    before = list(response)
    transformed, check = transform_response(response, p.modulus, 1024)
    assert response == before and transformed != tuple(response)
    assert sum(x*x for x in transformed) == check["new_norm_squared"]
    assert check["strong_malleation_if_original_signature_valid"]
    z = tuple(tuple(response[i:i+degree]) for i in range(0, len(response), degree))
    changed = tuple(tuple(transformed[i:i+degree]) for i in range(0, len(transformed), degree))
    for challenge in product((0, 1), repeat=degree):
        assert recover_commitment(public, target, z, challenge) == recover_commitment(
            public, target, changed, challenge)


def test_q_gt_two_gamma_excludes_every_direction_in_bounded_exhaustive_classes():
    # The general exclusion is triangle inequality; this checks integer edges.
    for q in range(3, 52, 2):
        largest_cap = (q*q-1)//4
        for cap in (0, largest_cap//2, largest_cap):
            assert q*q > 4*cap
            for coefficient in range(-isqrt(cap), isqrt(cap)+1):
                for old in {coefficient*coefficient, cap}:
                    check = coefficient_malleation(q, cap, coefficient, old)
                    assert check["original_norm_within_cap"]
                    assert not check["new_norm_within_cap"]


@pytest.mark.parametrize("q,cap,coefficient,old", [
    (4, 100, 0, 0), (True, 100, 0, 0), (3, True, 0, 0),
    (3, 10, True, 0), (3, 10, 1.0, 1), (3, 10, 2, 3),
    (3, 10, 0, True), (3, 10, 0, -1), (3, 10, 0, 1 << MAX_BOUND_BITS),
    (3, 10, 1 << MAX_MODULUS_BITS, 0),
])
def test_malleation_rejects_inconsistent_or_unbounded_public_inputs(q, cap, coefficient, old):
    with pytest.raises(ValueError):
        coefficient_malleation(q, cap, coefficient, old)


@pytest.mark.parametrize("response", [[], (), "123", [True], [1.0],
                                        [1 << MAX_MODULUS_BITS], [0]*(MAX_RESPONSE_COEFFICIENTS+1)])
def test_transform_has_bounded_exact_flat_input(response):
    with pytest.raises(ValueError):
        transform_response(response, 15, 400)


def test_cli_emits_and_saves_same_json(tmp_path, monkeypatch, capsys):
    output = tmp_path / "audit.json"
    monkeypatch.setattr(sys, "argv", ["cur_obstruction", "--modulus", "15",
                                     "--gamma-squared", "64", "--output", str(output)])
    main()
    emitted = json.loads(capsys.readouterr().out)
    assert json.loads(output.read_text(encoding="utf-8")) == emitted
    assert emitted["requested_pair"]["cur_obstruction_at_this_cap"] is True
    assert emitted["full_fs_forgery"] is False


def test_cli_checks_conditional_malleation_without_claiming_input_verification(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["cur_obstruction", "--modulus", "15",
        "--gamma-squared", "144", "--coefficient", "3", "--old-norm-squared", "9"])
    main()
    result = json.loads(capsys.readouterr().out)
    checked = result["requested_malleation"]
    assert checked["new_norm_squared"] == 144
    assert checked["strong_malleation_if_original_signature_valid"]
    assert not checked["original_signature_verified_by_this_check"]
    assert not result["source_honest_signature_executed"]


@pytest.mark.parametrize("arguments", [
    ["--modulus", "15"], ["--gamma-squared", "64"],
    ["--modulus", "16", "--gamma-squared", "64"],
    ["--coefficient", "0", "--old-norm-squared", "0"],
    ["--modulus", "15", "--gamma-squared", "64", "--coefficient", "0"],
    ["--modulus", "15", "--gamma-squared", "64", "--coefficient", "2", "--old-norm-squared", "3"],
])
def test_cli_rejects_missing_or_invalid_pair_inputs(arguments, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["cur_obstruction", *arguments])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
    assert not capsys.readouterr().out
