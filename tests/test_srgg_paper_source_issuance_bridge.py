"""Authenticated fixed-root source-Schur issuance, with explicit null scopes."""
from fractions import Fraction
from hashlib import sha256
import json

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from experiments.research.candidates.srgg import paper_source_issuance_bridge as bridge
from experiments.research.candidates.srgg.paper_source_issuance_bridge import (
    FINITE, JOINT, _authenticated_reports, source_issuance_certificate,
)


@pytest.fixture(scope="module")
def standard():
    return source_issuance_certificate("PARAM-I", "table-standard-deviation")


@pytest.fixture(scope="module")
def literal():
    return source_issuance_certificate("PARAM-I", "literal-density-width")


def test_original_table4_source_master_to_fixed_root_hnf_reference(standard):
    result = standard
    assert result["schema"] == "IBME/SRGG-SOURCE-SCHUR-FIXED-ROOT-ISSUANCE/1"
    assert result["profile"] == "PARAM-I"
    assert result["interpretation"] == "table-standard-deviation"
    assert result["paper_parameters"]["profile_name"] == "PARAM-I"
    assert result["seed_sha256"] == sha256(
        b"paper-baseline-PARAM-I-table-standard-deviation").hexdigest()
    assert result["inherited_source_manifest_sha256"] == bridge.PREVIOUS_MANIFEST_SHA256
    assert result["setup_attempts"] == result["extraction_calls"] == 1
    assert result["identity_bytes"] == 5 and result["message_bytes"] is None
    assert result["master_plan_numerical_input_replayed_exactly"]
    assert result["trapdoor_public_relation_verified"]
    assert result["gadget_identity_target_and_hnf_equation_verified"]
    assert result["first_key_canonical_roundtrip_verified"]
    assert result["same_root_c_gate"]["certified"]
    assert result["successful_finite_key_object_guard"]["raw_and_key_within_256bit_object_guard"]
    assert result["gadget_fiber_bias_counted_once"]
    assert result["abort_atom_retained"]
    assert result["hnf_deterministic_pushforward_adds_no_tv_cost"]
    assert result["certified"]
    assert 0 < Fraction(result["complete_law_tv_upper_including_abort"]) < 1
    assert result["first_issuance_tv_bound_applies_under_iid_bytes_and_no_external_faults"]
    binding = result["finite_chain_manifest_binding"]
    assert binding["normalized_lf_sha256"] == bridge.FINITE_MANIFEST_LF_SHA256
    assert binding["all_manifest_entries_sha256_verified"]
    assert binding["entry_count"] == 32
    assert set(bridge.FINITE_DEPENDENCIES) == set(binding["dependent_file_sha256"])
    assert binding["dependent_file_sha256"][bridge.FINITE_PREFIX + "finite-fixed-root.json"] == (
        result["finite_report_sha256"])
    assert binding["dependent_file_sha256"][bridge.FINITE_PREFIX + "joint-fixed-root.json"] == (
        result["joint_report_sha256"])


def test_literal_density_does_not_invent_an_issuance_bound(literal):
    result = literal
    assert result["profile"] == "PARAM-I"
    assert result["interpretation"] == "literal-density-width"
    assert result["same_root_c_gate"]["certified"]
    assert 0 < Fraction(result["finite_source_schur_to_joint_master_tv_upper_including_abort"]) < 1
    assert result["certified"] is False
    assert result["complete_law_tv_upper_including_abort"] is None
    assert result["first_issuance_tv_bound_applies_under_iid_bytes_and_no_external_faults"] is False


@pytest.mark.parametrize("profile,interpretation,expected", [
    ("PARAM-II", "table-standard-deviation", True),
    ("PARAM-III", "table-standard-deviation", True),
    ("PARAM-II", "literal-density-width", False),
    ("PARAM-III", "literal-density-width", False),
])
def test_remaining_original_table4_rows_keep_their_distinct_conclusions(
        profile, interpretation, expected):
    result = source_issuance_certificate(profile, interpretation)
    assert result["setup_attempts"] == result["extraction_calls"] == 1
    assert result["paper_parameters"]["profile_name"] == profile
    assert result["same_root_c_gate"]["certified"]
    assert result["gadget_identity_target_and_hnf_equation_verified"]
    assert result["first_issuance_tv_bound_applies_under_iid_bytes_and_no_external_faults"] is expected
    assert (result["complete_law_tv_upper_including_abort"] is not None) is expected
    assert result["all_accepted_setup_roots_tv"] is None


@pytest.mark.parametrize("result_fixture", ["standard", "literal"])
def test_lifecycle_observation_is_separate_from_security_and_histories(request, result_fixture):
    result = request.getfixturevalue(result_fixture)
    assert result["rng"] == "DeterministicRandom TEST FIXTURE ONLY"
    assert result["independent_uniform_bytes_required_for_tv"]
    assert result["mpfr_and_exact_arithmetic_premises_required"]
    assert result["all_accepted_setup_roots_tv"] is None
    assert result["full_issuance_signature_fault_history_tv"] is None
    assert not result["native_strong_security_proven"]
    assert result["private_material_exported"] is False
    assert result["security_claim"] == "none"
    assert result["backend_admitted"] is False
    assert result["parameters_are_formal"] is False
    assert result["nist_security_category"] is None


def test_joint_receipt_tampering_is_rejected_before_root_replay(tmp_path):
    original = json.loads(JOINT.read_text(encoding="utf-8"))
    original["rows"][0]["master"]["finite_vs_joint_integer_gaussian_tv_upper_exact"] = "0"
    changed = tmp_path / "changed-joint.json"
    changed.write_text(json.dumps(original), encoding="utf-8")
    with pytest.raises(ValueError, match="input receipt does not match finite-chain manifest"):
        _authenticated_reports(FINITE, changed)


def test_wrong_identity_and_profile_rejected_before_any_fixture_setup():
    with pytest.raises(ValueError, match="Alice"):
        source_issuance_certificate("PARAM-I", "table-standard-deviation", identity=b"Bob")
    with pytest.raises(ValueError, match="Table 4"):
        source_issuance_certificate("PARAM-IV", "table-standard-deviation")


def test_finite_receipt_tampering_is_rejected(tmp_path):
    altered = tmp_path / "changed-finite.json"
    original = FINITE.read_bytes()
    altered.write_bytes(original.replace(b'"security_claim": "none"', b'"security_claim": "full"', 1))
    assert altered.read_bytes() != original
    with pytest.raises(ValueError, match="input receipt does not match finite-chain manifest"):
        _authenticated_reports(altered, JOINT)


def test_finite_manifest_tampering_is_rejected_before_any_root_draw(tmp_path, monkeypatch):
    altered = tmp_path / "changed-manifest.json"
    original = bridge.FINITE_MANIFEST.read_bytes()
    altered.write_bytes(original.replace(b"IBME/SRGG-FINITE-CHAIN-DELIVERY-MANIFEST/1",
                                         b"IBME/SRGG-FINITE-CHAIN-DELIVERY-MANIFEST/2", 1))
    assert altered.read_bytes() != original
    monkeypatch.setattr(bridge, "FINITE_MANIFEST", altered)
    with pytest.raises(ValueError, match="normalized LF bytes changed"):
        _authenticated_reports(FINITE, JOINT)
