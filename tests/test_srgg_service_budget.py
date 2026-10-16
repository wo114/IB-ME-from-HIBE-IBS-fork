"""Independent accounting checks against frozen public receipts, with no draws."""
from copy import deepcopy
from fractions import Fraction
import json
import subprocess
import sys

import pytest

from experiments.research.candidates.srgg import service_budget as sb


@pytest.fixture(scope="module")
def inputs():
    return sb.load_inputs()[0]


@pytest.fixture(scope="module")
def report():
    return sb.build_report()


def test_finite_only_two_pow40_matches_preexisting_frozen_certificate(inputs, report):
    frozen = inputs["execution"]["finite_sampling_query_certificate"]
    abstract = report["scenarios"][2]
    assert sb.unpack(abstract["finite_sampler_transcript_tv"]) == Fraction(
        frozen["finite_sampling_transcript_hybrid_tv_upper"])
    assert abstract["counts"]["N_S_upper"] == 2**44
    assert abstract["finite_sampler_transcript_tv_at_most_2_minus_128"]


def test_lifecycle_counts_negative_points_once_and_never_reissues_on_restart(report):
    life = report["scenarios"][0]
    assert life["counts"] == {"roots": 1, "N_K": 2, "q_S": 3, "L": 16,
        "N_S_upper": 48, "Q_I_upper": 4, "extra_H2_points_upper": 6,
        "M_H_upper": 54, "q_F_conservative_upper": 54}
    assert life["restart_and_cached_key_reuse_additional_sampler_calls"] == 0
    components = report["per_call_components"]
    key = sb.unpack(components["issuance_finite_only"])
    sign = sb.unpack(components["sign_attempt_finite_only"])
    assert sb.unpack(life["finite_sampler_transcript_tv"]) == 2*key+48*sign


def test_known_direct_numerator_keeps_both_finite_sign_endpoints(report):
    row = report["scenarios"][0]
    terms = row["direct_ibs_equation_7_known_numerator_terms"]
    second = sb.unpack(terms["NS_known_key_second_endpoint_finite"])
    sign = sb.unpack(report["per_call_components"]["sign_attempt_to_sequential_ideal"])
    assert second == 48*sign > 0
    delta0 = sb.unpack(terms["Delta0_known_arithmetic_part"])
    key = sb.unpack(report["per_call_components"]["issuance_to_latent_dual_gate"])
    hash_bad = sb.unpack(row["matrix_and_identity_decode_bad_in_ideal_XOF"])
    assert delta0 == 2*key+48*sign+hash_bad
    assert sb.unpack(row["direct_ibs_known_numerator_partial_sum"]) == sum(
        (sb.unpack(value) for value in terms.values()), Fraction(0))


def test_goodkey_and_issue_failure_charged_per_key_not_per_signature(report):
    life, many_signs = report["scenarios"][:2]
    for name in ("raw_bottom_term_paid_per_new_key", "ideal_GoodKey_failure_paid_per_new_key"):
        assert life[name] == many_signs[name]
        assert sb.unpack(life[name]) == Fraction(2, 2**256)
    assert sb.unpack(life["final_gate_extra_after_raw_pass"]) == 0
    assert sb.unpack(report["per_call_components"]["raw_ideal_gate_bottom"]) > 0


def test_alias_charges_every_effective_identity_touch_and_uses_exact_large_denominator(inputs, report):
    row = report["scenarios"][2]
    value = sb.unpack(row["direct_ibs_equation_7_known_numerator_terms"]["Delta_identity_alias"])
    params = inputs["execution"]["parameters"]
    q = params["p"]*params["base"]**params["digits"]
    assert value == Fraction(2**40*(2**40-1), 2*q**(params["rank"]*params["degree"]))
    assert value.denominator.bit_length() > 50000
    # This must serialize without disabling Python's intentional decimal cap.
    assert json.loads(json.dumps(sb.pack(value))) == sb.pack(value)


def test_global_caps_cover_complete_lifecycle_envelopes(report, inputs):
    value = report["entropy_envelope"]
    assert value["setup_exact_requested_bytes"] == 32800
    assert value["per_new_issue_sum_of_local_caps"] == 18155707
    assert value["per_sign_attempt_sum_of_local_caps"] == 11663274
    assert value["audit_parent_lifecycle_local_cap_envelope"] == 409591510
    assert value["audit_child_one_sign_local_cap_envelope"] == 186612384
    assert value["audit_parent_entropy_cap_bytes"] == 512*1024*1024
    assert value["audit_child_entropy_cap_bytes"] == 256*1024*1024
    assert value["parent_envelope_fits_global_cap"]
    assert sb.unpack(value["extra_parent_global_cap_abort_upper"]) == 0
    assert value["child_envelope_fits_global_cap"]
    assert sb.unpack(value["extra_child_global_cap_abort_upper"]) == 0
    assert not value["all_local_certificates_imply_global_cap_probability_zero"]
    assert not value["FixedIssuer_itself_adds_a_CountingEntropy_cap"]
    # The original smaller parent cap is not implied by the local caps.
    old = sb.entropy_envelope(inputs, parent_cap=256*1024*1024, child_cap=256*1024*1024)
    assert not old["parent_envelope_fits_global_cap"]
    assert old["extra_parent_global_cap_abort_upper"] is None


def test_sampling_abort_is_separate_but_not_recharged_on_top_of_TV(report):
    abort = report["per_call_sampling_abort_upper"]
    assert sb.unpack(abort["gadget_scalar_and_local_aggregate"]) > 0
    assert sb.unpack(abort["public_u"]) > 0
    assert sb.unpack(abort["public_binary_challenge"]) == 0
    for row in report["scenarios"]:
        assert row["abort_is_already_included_in_finite_TV_not_an_extra_TV_charge"]
        assert sb.unpack(row["finite_sampling_abort_union_only_excluding_norm_hash_and_infrastructure"]) <= sb.unpack(
            row["finite_sampler_transcript_tv"])


def test_arithmetic_query_budget_does_not_claim_executable_identity_capacity(report):
    fixed, abstract = report["scenarios"][1:]
    assert fixed["one_service_identity_capacity_possible"] is True
    assert abstract["one_service_identity_capacity_possible"] is False
    assert fixed["snapshot_byte_capacity_certified_for_this_count"] is None
    assert abstract["snapshot_byte_capacity_certified_for_this_count"] is None
    for row in report["scenarios"]:
        assert row["full_service_abort_upper"] is None
        assert row["Delta0_complete_service_to_reference_upper"] is None
        assert row["direct_ibs_complete_numerator_error_upper"] is None
        assert row["p0_or_IBS_advantage_bound"] is None
        assert row["remaining_raw_prefix_kernel_and_adaptive_composition_cost"] is None


def test_security_and_uninstantiated_terms_stay_explicit(report):
    assert report["actual_entropy_bytes"] == 0
    assert not report["draw_performed"] and not report["private_payloads_read"]
    assert not report["new_lifecycle_run"] and not report["production_algorithm_modified"]
    assert report["security_claim"] == "none"
    assert not report["backend_admitted"] and not report["parameters_are_formal"]
    assert report["nist_security_category"] is None
    assert all(value is None for value in report["uninstantiated_terms"].values())
    assert sb.unpack(report["classical_matrix_seed_prequery_hit_2pow40"]) == Fraction(1, 2**216)


@pytest.mark.parametrize("value", [Fraction(0), Fraction(1), Fraction(1, 2**177),
    Fraction(7, 2**181), Fraction(3, 7), Fraction(1, 3**20000)])
def test_probability_record_roundtrip_and_tight_dyadic_upper_without_float(value):
    record = sb.pack(value)
    assert sb.unpack(record) == value
    exponent = record["dyadic_upper_exponent"]
    if value == 0:
        assert exponent is None
    else:
        upper = Fraction(2**exponent) if exponent >= 0 else Fraction(1, 2**-exponent)
        assert upper/2 < value <= upper


@pytest.mark.parametrize("value", [True, False, 0.5, "-1/2", "3/2", None])
def test_nonexact_or_out_of_range_probability_rejected(value):
    with pytest.raises(ValueError):
        sb.pack(value)


@pytest.mark.parametrize("record", [{}, {"numerator_hex": "0x1", "denominator_hex": "0x0",
    "dyadic_upper_exponent": 0}, {"numerator_hex": "0x1", "denominator_hex": "0x1",
    "dyadic_upper_exponent": False}, {"numerator_hex": "0X1", "denominator_hex": "0x1",
    "dyadic_upper_exponent": 0}])
def test_noncanonical_fraction_records_rejected(record):
    with pytest.raises(ValueError):
        sb.unpack(record)


@pytest.mark.parametrize("args", [(True, 3, 4, 6), (2, -1, 4, 6), (2, 3, 1, 6),
    (2, 3, 4, 6, 0), (2, 3, 4, 6, 17), (2, 3, 4, 1.0)])
def test_invalid_operation_budgets_rejected_before_receipt_read(args):
    with pytest.raises(ValueError):
        sb.Counts(*args)


def _patched_reader(monkeypatch, receipts):
    real_read = sb._read
    by_name = {name: label for label, name in sb.INPUTS.items()}
    def patched(root, name, schema):
        _, digest = real_read(root, name, schema)
        return receipts[by_name[name]], digest
    monkeypatch.setattr(sb, "_read", patched)


@pytest.mark.parametrize("change", ["profile", "parameters", "native_premise", "native_input_hash", "frozen_source"])
def test_mismatched_profile_parameters_laws_or_source_evidence_rejected(inputs, monkeypatch, change):
    receipts = deepcopy(inputs)
    if change == "profile":
        receipts["execution"]["numerical_profile"] = "default"
    elif change == "parameters":
        receipts["native"]["profiles"][1]["parameters"]["sign_max_attempts"] = 1
    elif change == "native_premise":
        receipts["native"]["profiles"][1]["finite_sign_tv_premise_exact"] = "0"
    elif change == "native_input_hash":
        receipts["native"]["input_sha256"] = "00"*32
    else:
        name = next(iter(receipts["execution"]["source_sha256"]))
        receipts["execution"]["source_sha256"][name] = "00"*32
    _patched_reader(monkeypatch, receipts)
    with pytest.raises(ValueError):
        sb.load_inputs()


def test_finite_query_law_mismatch_and_raw_final_gate_gap_are_rejected(inputs):
    receipts = deepcopy(inputs)
    receipts["execution"]["finite_sampling_query_certificate"][
        "fresh_issuance_finite_sampling_hybrid_tv_upper"] = "0"
    with pytest.raises(ValueError, match="finite-only"):
        sb.components(receipts)
    receipts = deepcopy(inputs)
    receipts["integrated"]["profiles"][1]["parameters"]["user_norm_cap"] = 1
    with pytest.raises(ValueError, match="raw gate"):
        sb.components(receipts)


def test_no_sage_randomness_or_sample_import_is_needed_in_fresh_python():
    code = "\n".join([
        "import builtins,os",
        "original=builtins.__import__",
        "def guard(name,*args,**kwargs):",
        "    if name.startswith('sage') or name in ('random','secrets','ibme.core.randomness'):",
        "        raise AssertionError('budget imported a sampling dependency')",
        "    return original(name,*args,**kwargs)",
        "builtins.__import__=guard",
        "def forbidden(*args,**kwargs): raise AssertionError('budget requested entropy')",
        "os.urandom=forbidden",
        "from experiments.research.candidates.srgg.service_budget import build_report",
        "r=build_report()",
        "assert r['actual_entropy_bytes']==0 and not r['draw_performed']",
        "print('zero-entropy-budget-ok')",
    ])
    child = subprocess.run([sys.executable, "-c", code], cwd=sb.ROOT,
        capture_output=True, text=True, timeout=30)
    assert child.returncode == 0, child.stderr
    assert child.stdout.strip() == "zero-entropy-budget-ok"


def test_public_receipt_schema_guard_and_size_bound(tmp_path):
    path = tmp_path/"receipt.json"
    path.write_text(json.dumps({"schema": "other"}), encoding="utf-8")
    with pytest.raises(ValueError):
        sb._read(tmp_path, path.name, "required")
    path.write_bytes(b"x"*(2*1024*1024+1))
    with pytest.raises(ValueError):
        sb._read(tmp_path, path.name, "required")


@pytest.mark.parametrize("source", [
    "PARENT_ENTROPY_CAP=512*1024*1024\nCHILD_ENTROPY_CAP=256*1024*1024",
    "PARENT_ENTROPY_CAP=536870912\nCHILD_ENTROPY_CAP=268435456",
])
def test_audit_cap_constants_are_read_without_importing_driver(tmp_path, source):
    folder = tmp_path/"experiments/research"
    folder.mkdir(parents=True)
    (folder/"srgg_structured_service_audit.py").write_text(
        "raise AssertionError('must not import driver')\n"+source, encoding="utf-8")
    assert sb._audit_caps(tmp_path) == (512*1024*1024, 256*1024*1024)


@pytest.mark.parametrize("source", ["", "PARENT_ENTROPY_CAP=True\nCHILD_ENTROPY_CAP=1",
    "PARENT_ENTROPY_CAP=other()\nCHILD_ENTROPY_CAP=1",
    "PARENT_ENTROPY_CAP=512*1024*1024\nPARENT_ENTROPY_CAP=1\nCHILD_ENTROPY_CAP=1",
])
def test_missing_dynamic_boolean_or_duplicate_cap_declarations_rejected(tmp_path, source):
    folder = tmp_path/"experiments/research"
    folder.mkdir(parents=True)
    (folder/"srgg_structured_service_audit.py").write_text(source, encoding="utf-8")
    with pytest.raises(ValueError):
        sb._audit_caps(tmp_path)
