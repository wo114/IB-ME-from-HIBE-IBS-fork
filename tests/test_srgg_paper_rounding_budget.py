"""Independent scalar-theta checks and original-shape budget regression."""

from fractions import Fraction
import json

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")
from sage.all import QQ, RealIntervalField

from experiments.research.candidates.srgg.paper_backend import Backend
from experiments.research.candidates.srgg.paper_parameters import PaperParams
from experiments.research.candidates.srgg.paper_rounding_budget import (
    INTERPRETATIONS, main, profile_report, report, rounding_tv, theta_certificate,
)


@pytest.mark.parametrize("shape", [Fraction(2), Fraction(9), Fraction(841, 625)])
def test_scalar_theta_enumeration_is_below_certified_nonzero_mass(shape):
    certificate = theta_certificate(dimension=1, density_shape=shape)
    field = RealIntervalField(768)
    exact = QQ(shape.numerator)/shape.denominator
    partial = 2*sum(((-field.pi()*exact*k*k).exp() for k in range(1, 17)), field(0))
    # Every omitted term is positive, so this finite sum is a mathematical
    # lower bound on the nonzero scalar theta mass, not an empirical draw.
    lower = partial.lower().exact_rational()
    upper = Fraction(certificate["scalar_nonzero_theta_upper_exact"])
    assert Fraction(int(lower.numerator()), int(lower.denominator())) < upper
    a_interval = (-field.pi()*exact).exp()
    assert QQ(Fraction(certificate["exp_minus_pi_shape_lower_exact"])) <= a_interval.lower()
    assert QQ(Fraction(certificate["exp_minus_pi_shape_upper_exact"])) >= a_interval.upper()


@pytest.mark.parametrize("name", ["PARAM-I", "PARAM-II", "PARAM-III"])
def test_original_standard_deviation_stages_improve_without_changing_shapes(name):
    params = PaperParams(name)
    before = params.record(), params.r_squared
    backend = Backend()
    retries = backend.setup_max_attempts, backend.sign_max_attempts
    rows = profile_report(name)
    assert [row["dimension"] for row in rows] == [params.columns*512, (params.columns+1)*512]
    for row in rows:
        legacy, current = row["legacy_frozen_execution"], row["current_corrected_mathematical_shape"]
        old, new = Fraction(legacy["old_rounding_tv_upper"]), Fraction(legacy["improved_theta_certificate"]["rounding_tv_upper"])
        assert Fraction(1, 2**24) < new < Fraction(1, 2**20)
        assert new*90 < old
        assert Fraction(current["rounding_squared"]) == params.r_squared
        assert current["parameter_record"] == params.record()
        assert current["valid_local_samplef_tv_upper_including_abort"] is None
        assert not current["frozen_finite_components_transferred"]
        assert current["finite_center_numerical_tv_upper"] is None
        assert current["scalar_kernel_tv_including_aggregate_exact"] is None
        assert legacy["valid_local_samplef_tv_upper_including_abort"] is None
        assert not legacy["historical_sum_is_valid_tv_certificate"]
        historical = legacy["unvalidated_finite_components_from_frozen_run"]
        assert not historical["usable_in_valid_tv_certificate"]
        assert historical["status"] == "unvalidated_due_to_endpoint_conversion_bug"
        assert row["full_ibs_tv_upper"] is None
        assert row["full_signature_law_tv_upper"] is None
        assert row["hnf_key_law_tv_upper"] is None
        assert not row["runtime_modified_by_budget_module"] and not row["published_width_inputs_changed"]
        assert not row["samplef_rerun"] and not row["all_witnesses_or_full_histories_certified"]
        assert row["security_claim"] == "none" and not row["parameters_are_formal"]
    assert (params.record(), params.r_squared) == before
    assert retries == (64, 64)


@pytest.mark.parametrize("name", ["PARAM-I", "PARAM-II", "PARAM-III"])
def test_literal_width_certificate_is_explicitly_inconclusive(name):
    rows = profile_report(name, "literal-density-width")
    for row in rows:
        legacy = row["legacy_frozen_execution"]
        current = row["current_corrected_mathematical_shape"]
        cert = legacy["improved_theta_certificate"]
        assert cert["relative_normalizer_error_upper_exact"] is None
        assert not cert["nontrivial_relative_lower_certified"]
        assert not cert["rounding_comparison_prerequisite_passes"]
        assert "inconclusive" in cert["blocker"] and "actual TV is not inferred" in cert["blocker"]
        assert cert["rounding_tv_upper"] == "1"
        assert current["rounding_shape_equals_legacy"]
        assert current["theta_certificate"] == cert


def test_param_iii_private_numerical_failure_is_retained_not_fixed_by_theta():
    rows = profile_report("PARAM-III")
    legacy = rows[1]["legacy_frozen_execution"]
    finite = legacy["unvalidated_finite_components_from_frozen_run"]
    assert finite["finite_center_numerical_tv_upper_as_recorded"] == "1"
    assert not finite["public_coarse_numerical_envelope_passed_as_recorded"]
    assert legacy["historical_arithmetic_sum_only"] == "1"
    assert legacy["valid_local_samplef_tv_upper_including_abort"] is None


def test_modified_current_shape_cannot_inherit_a_legacy_finite_certificate(monkeypatch):
    # Simulate a corrected exact pi conversion independently of its numerical
    # size.  Historical shape authentication must still use the frozen scale.
    from experiments.research.candidates.srgg import paper_parameters
    original = paper_parameters.pi_enclosure
    low, high = original()
    monkeypatch.setattr(paper_parameters, "pi_enclosure", lambda: (low, high+Fraction(1, 2**500)))
    for row in profile_report("PARAM-I"):
        legacy, current = row["legacy_frozen_execution"], row["current_corrected_mathematical_shape"]
        assert not current["rounding_shape_equals_legacy"]
        assert legacy["rounding_squared"] != current["rounding_squared"]
        assert current["theta_certificate"]["density_shape_lower_exact"] == current["rounding_squared"]
        assert legacy["improved_theta_certificate"]["density_shape_lower_exact"] == legacy["rounding_squared"]
        assert current["valid_local_samplef_tv_upper_including_abort"] is None
        assert current["finite_center_numerical_tv_upper"] is None
        assert not current["frozen_finite_components_transferred"]


@pytest.mark.parametrize("mutation", ["same_length_json_edit", "appended_whitespace"])
def test_tampered_real_receipt_is_rejected_by_original_manifest(tmp_path, monkeypatch, mutation):
    from experiments.research.candidates.srgg import paper_rounding_budget as module
    original = module.RECEIPTS
    (tmp_path/"MANIFEST.json").write_bytes((original/"MANIFEST.json").read_bytes())
    data = (original/"PARAM-I.json").read_bytes()
    if mutation == "same_length_json_edit":
        changed = data.replace(b'"repetitions": 1', b'"repetitions": 2', 1)
        assert changed != data and len(changed) == len(data)
        assert json.loads(changed)["repetitions"] == 2
    else:
        changed = data+b" "
        assert json.loads(changed) == json.loads(data)
    (tmp_path/"PARAM-I.json").write_bytes(changed)
    monkeypatch.setattr(module, "RECEIPTS", tmp_path)
    with pytest.raises(ValueError, match="receipt bytes/hash differs from original manifest"):
        module.profile_report("PARAM-I")


def test_tampered_real_manifest_is_rejected_even_if_valid_json(tmp_path, monkeypatch):
    from experiments.research.candidates.srgg import paper_rounding_budget as module
    original = module.RECEIPTS
    data = (original/"MANIFEST.json").read_bytes()
    changed = data.replace(b'"bytes": 17095', b'"bytes": 17096', 1)
    assert len(changed) == len(data) and changed != data
    assert json.loads(changed)["files"]["PARAM-I-density.json"]["bytes"] == 17096
    (tmp_path/"MANIFEST.json").write_bytes(changed)
    (tmp_path/"PARAM-I.json").write_bytes((original/"PARAM-I.json").read_bytes())
    monkeypatch.setattr(module, "RECEIPTS", tmp_path)
    with pytest.raises(ValueError, match="manifest hash mismatch"):
        module.profile_report("PARAM-I")


@pytest.mark.parametrize("kwargs", [
    {"dimension": True}, {"dimension": 1.0}, {"dimension": 0},
    {"dimension": 32769}, {"density_shape": True}, {"density_shape": 8.5},
    {"density_shape": "9"}, {"density_shape": 0}, {"density_shape": -1},
    {"density_shape": 1025}, {"density_shape": Fraction(1, 2**4096)},
    {"precision_bits": True}, {"precision_bits": 64}, {"precision_bits": 2049},
])
def test_exact_type_and_resource_gates(kwargs):
    arguments = {"dimension": 8, "density_shape": Fraction(9), "precision_bits": 512}
    arguments.update(kwargs)
    with pytest.raises(ValueError):
        theta_certificate(**arguments)


def test_rounding_trivial_bound_has_no_actual_distance_assertion():
    assert rounding_tv(None) == 1
    assert rounding_tv(Fraction(3, 4)) == 1
    assert rounding_tv(2) == 1
    assert rounding_tv(Fraction(1, 128)) == Fraction(1, 16)
    with pytest.raises(ValueError):
        rounding_tv(True)


def test_full_report_has_twelve_stages_and_json_cli(tmp_path, monkeypatch):
    result = report(precision_bits=256)
    assert len(result["rows"]) == 12
    assert set(row["interpretation"] for row in result["rows"]) == set(INTERPRETATIONS)
    assert result["new_sampler_draws"] == 0 and result["full_ibs_tv_upper"] is None
    assert json.loads(json.dumps(result)) == result
    output = tmp_path/"rounding-budget.json"
    monkeypatch.setattr("sys.argv", ["paper_rounding_budget", "--precision-bits", "256", "--output", str(output)])
    main()
    assert json.loads(output.read_text()) == result


def test_local_stage_smoothing_passes_do_not_hide_strict_source_dimension_failure():
    result = report()
    epsilon = Fraction(1, 2**24)
    for row in result["rows"]:
        if row["interpretation"] == "table-standard-deviation":
            local = row["current_corrected_mathematical_shape"]["theta_certificate"]
            assert Fraction(local["relative_normalizer_error_upper_exact"]) < epsilon
    source = result["source_max_dimension_necessary_smoothing_check"]
    assert source["dimension"] == 10240
    assert Fraction(source["shortest_dual_mass_lower_exact"]) > epsilon
    assert source["necessary_condition_strictly_fails_for_exact_backend_shape"]
    assert source["local_stage_checks_do_not_replace_source_dimension"]
