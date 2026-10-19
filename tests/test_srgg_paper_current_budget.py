"""Current fixed-plan composition, source binding and evidence boundaries."""

from copy import deepcopy
from fractions import Fraction
import json

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from experiments.research.candidates.srgg import paper_current_budget as module
from experiments.research.candidates.srgg.paper_backend import Backend
from experiments.research.candidates.srgg.paper_parameters import PaperParams


def test_current_fixed_plan_bounds_are_nontrivial_only_where_numerical_envelope_passes():
    result = module.report()
    assert [row["series_error_bits"] for row in result["rows"]] == [160, 192, 160, 192]
    values = {row["plan_label"]: row for row in result["rows"]}
    for label in ("master160_extract", "master192", "signature192"):
        row = values[label]
        upper = Fraction(row["local_perturbation_tv_upper_including_abort"])
        assert Fraction(1, 2**22) < upper < Fraction(1, 2**21)
        assert row["public_numerical_envelope_passes"] and row["local_bound_nontrivial"]
    assert values["signature160"]["finite_center_numerical_tv_upper"] == "1"
    assert values["signature160"]["local_perturbation_tv_upper_including_abort"] == "1"
    assert not values["signature160"]["local_bound_nontrivial"]
    assert values["master160_extract"]["dimension"] == 8192
    assert values["signature192"]["dimension"] == 8704
    assert values["master160_extract"]["local_perturbation_tv_upper_including_abort"] == values["master192"]["local_perturbation_tv_upper_including_abort"]


def test_exact_triangle_composition_retains_abort_and_does_not_cross_distribution_layers():
    for row in module.report()["rows"]:
        numerical = Fraction(row["finite_center_numerical_tv_upper"])
        scalar = Fraction(row["scalar_kernel_tv_including_aggregate_abort_upper"])
        rounding = Fraction(row["rounding_theta_certificate"]["rounding_tv_upper"])
        assert Fraction(row["local_perturbation_tv_upper_including_abort"]) == min(1, numerical+scalar+rounding)
        batch = row["scalar_batch_certificate"]
        assert scalar == Fraction(batch["scalar_kernel_tv_union_upper_exact"])+Fraction(batch["aggregate_budget_abort_upper_exact"])
        assert row["abort_atom_retained"] and not row["success_conditioned"]
        assert row["fixed_witness_only"] and not row["uniform_over_all_witnesses"]
        assert not row["uniform_over_complete_histories"]
        assert row["reference"] == module.REFERENCE and "c=0" in row["reference_center"]
        for key in ("complete_samplef_with_gadget_tv_upper", "hnf_key_law_tv_upper", "final_signature_law_tv_upper", "full_ibs_tv_upper"):
            assert row[key] is None
        assert row["security_claim"] == "none" and not row["parameters_are_formal"]


def test_report_reads_no_entropy_and_keeps_backend_default160(monkeypatch):
    from experiments.research.candidates.srgg import paper_backend
    class NoRead:
        def read(self, count):
            raise AssertionError("budget recomputation must not read entropy")
    monkeypatch.setattr(paper_backend, "SecureRandom", NoRead)
    result = module.report()
    assert result["new_sampler_draws"] == 0
    assert result["backend_default_series_error_bits"] == Backend().series_options.series_error_bits == 160
    assert not result["backend_default_changed"]
    assert not result["historical_endpoint_bug_finite_components_used"]
    assert len(result["current_core_source_sha256_verified"]) == 4


@pytest.mark.parametrize("change", ["rounding", "target", "noise", "dimension", "endpoint", "batch_abort"])
def test_semantic_plan_correspondence_checks_reject_wrong_shapes_and_omitted_abort(change):
    receipt, _ = module._authenticated_receipt()
    certificate = deepcopy(receipt["certificates"]["signature192"])
    if change == "rounding": certificate["rounding_squared"] = "9"
    elif change == "target": certificate["target_top_squared"][0] = "1"
    elif change == "noise": certificate["noise_squared"] = "1"
    elif change == "dimension": certificate["dimension"] = 8192
    elif change == "endpoint": certificate["interval_endpoint_conversion"] = "QQ approximation"
    else: certificate["scalar_batch"]["scalar_kernel_tv_including_aggregate_exact"] = certificate["scalar_batch"]["scalar_kernel_tv_union_upper_exact"]
    with pytest.raises(ValueError):
        module._check_plan(PaperParams("PARAM-III"), certificate, phase="signature", numerical_bits=192)


@pytest.mark.parametrize("target", ["precision_same_size", "precision_size", "manifest_same_size"])
def test_real_frozen_receipt_and_manifest_tampering_are_rejected(tmp_path, monkeypatch, target):
    for name in ("precision.json", "MANIFEST.json"):
        (tmp_path/name).write_bytes((module.RECEIPTS/name).read_bytes())
    if target == "precision_same_size":
        path = tmp_path/"precision.json"
        data = path.read_bytes()
        changed = data.replace(b'"identity_bytes": 5', b'"identity_bytes": 6', 1)
        assert changed != data and len(changed) == len(data)
    elif target == "precision_size":
        path = tmp_path/"precision.json"
        changed = path.read_bytes()+b" "
    else:
        path = tmp_path/"MANIFEST.json"
        data = path.read_bytes()
        changed = data.replace(b'"bytes": 75007', b'"bytes": 75008', 1)
        assert changed != data and len(changed) == len(data)
    json.loads(changed)
    path.write_bytes(changed)
    monkeypatch.setattr(module, "RECEIPTS", tmp_path)
    with pytest.raises(ValueError, match="hash mismatch|byte count mismatch"):
        module.report()


def test_current_core_source_changes_cannot_reuse_frozen_proof(tmp_path, monkeypatch):
    name = module.SOURCE_FILES[0]
    path = tmp_path/name
    path.parent.mkdir(parents=True)
    path.write_bytes((module.ROOT/name).read_bytes()+b"\n")
    monkeypatch.setattr(module, "ROOT", tmp_path)
    with pytest.raises(ValueError, match="current source differs"):
        module.report()


@pytest.mark.parametrize("precision", [True, 64, 2049, 512.0, "512"])
def test_precision_resource_gate_is_exact(precision):
    with pytest.raises(ValueError):
        module.report(theta_precision_bits=precision)


def test_json_cli_uses_fresh_path_and_never_overwrites_receipt(tmp_path, monkeypatch):
    output = tmp_path/"current-budget.json"
    monkeypatch.setattr("sys.argv", ["paper_current_budget", "--output", str(output)])
    module.main()
    assert json.loads(output.read_text()) == module.report()
    before = output.read_bytes()
    with pytest.raises(SystemExit):
        module.main()
    assert output.read_bytes() == before
