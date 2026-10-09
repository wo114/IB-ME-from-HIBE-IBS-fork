"""Handoff integrity and source-unit controls; never grants security admission."""

from copy import deepcopy
from pathlib import Path

import pytest

from experiments.research.candidate_catalog import CATALOG, ROOT, load, render_cards, safe_path, summary, validate
from experiments.research.sageloli_parameter_units import ROWS, audit, parameter_row


def test_all_sources_and_roles_are_present_without_invented_instances():
    data = load()
    result = summary(data)
    assert result["candidate_entries"] == 17 and result["roles"] == {"HIBE": 7, "IBS": 10}
    assert result["cached_sources"] == 17
    assert set(result["research_backend_entries"]) == {"luo-matrix", "luo-module"}
    assert result["selected_representatives"] == [] and result["admitted_secure_combinations"] == 0
    assert result["scenario_performance"].startswith("unknown")
    assert result["security_claim"] == "none" and not result["backend_admitted"]


def test_generated_handoff_is_current():
    expected = render_cards(load())
    target = CATALOG.parent / "候选基础卡与队友接手任务.md"
    assert target.read_text(encoding="utf-8") == expected


@pytest.mark.parametrize("mutation", ["claim", "admission", "schema-bool", "duplicate-id", "unknown-role", "unknown-source", "missing-task", "missing-map", "missing-paper", "work-area"])
def test_invalid_or_misleading_foundation_metadata_rejected(mutation):
    data = deepcopy(load())
    c = data["candidates"][0]
    if mutation == "claim": data["security_claim"] = "128-bit"
    elif mutation == "admission": data["backend_admitted"] = True
    elif mutation == "schema-bool": data["schema_version"] = True
    elif mutation == "duplicate-id": data["candidates"][1]["id"] = c["id"]
    elif mutation == "unknown-role": c["role"] = "IBE"
    elif mutation == "unknown-source": c["sources"] = ["not-archived"]
    elif mutation == "missing-task": c["next_steps"] = []
    elif mutation == "missing-map": c["interface_mapping"] = []
    elif mutation == "missing-paper": data["sources"]["abb"]["path"] = "papers/not-present.pdf"
    else: c["work_area"] = "src/ibme/core/"
    with pytest.raises(ValueError): validate(data)


@pytest.mark.parametrize("path", ["../outside", "C:/secret", "/tmp/outside", "papers\\x.pdf", ""])
def test_file_references_stay_in_repository(path):
    with pytest.raises(ValueError): safe_path(ROOT, path)


def test_duplicate_json_fields_rejected(tmp_path):
    path = tmp_path / "catalog.json"
    path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"): load(path)


def test_source_fidelity_and_size_units_are_kept_separate():
    result = audit()
    one, two = result["rows"]
    assert round(one["log2_sid"], 2) == 20.65 and round(one["log2_ssign"], 2) == 38.92
    assert round(two["log2_sid"], 2) == 21.27 and round(two["log2_ssign"], 2) == 40.16
    assert one["appendix_printed_Mo_numeric"]["public"] == 27.85
    assert one["coefficient_width_bits"]["public"] == 104 and two["coefficient_width_bits"]["public"] == 243
    assert one["fixed_width_public_bytes"] == 3514368 and two["fixed_width_public_bytes"] == 19160064
    for row in result["rows"]:
        for name, bits in row["appendix_E_approximate_information_bits"].items():
            normalized = row["normalized_information_bytes"][name]
            assert 0 <= normalized * 8 - bits < 8
        assert not row["fits_legacy_uint32"] and not row["fits_module_ref_uint64"]
        assert not row["modulus_is_prime"] and not row["implemented_encoding"]
        assert not row["security_estimator_executed"] and row["security_claim"] == "none"


@pytest.mark.parametrize("values", [(True, 8, 22, 16), (9, 7, 22, 16), (9, 8, 21, 16), (9, 8, 23, 16), (9, 8, 22, 0)])
def test_sageloli_table_conditions_not_silently_changed(values):
    with pytest.raises(ValueError): parameter_row("bad", *values)
