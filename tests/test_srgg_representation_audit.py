"""Scope checks against frozen public accounting and actual object receipts."""
import json
import shutil

import pytest

from experiments.research.candidates.srgg.representation_audit import (
    FINAL, OLD, ROOT, build_report, matrix_scenario, units,
)


def test_saved_dense_counts_match_independent_ring_slot_accounting():
    report = build_report()
    master = [row["master"] for row in report["historical_w8_scenarios"]]
    assert [x["dense_payload_bytes"] for x in master] == [6710886400, 15099494400, 26843545600]
    assert [x["ring_payload_bytes"] for x in master] == [13107200, 29491200, 52428800]
    assert all(x["slot_ratio"] == 512 and x["actual_peak_rss_bytes"] is None for x in master)


def test_gb_and_gib_are_not_interchanged():
    assert units(6710886400) == {"MB": "6710.8864", "MiB": "6400", "GB": "6.7108864", "GiB": "6.25"}
    assert units(13107200)["MiB"] == "12.5"


def test_original_parameter_shapes_and_measured_objects_are_separate():
    report = build_report()
    assert [x["master"]["ring_payload_bytes"] for x in report["published_w2_scenarios"]] == [2097152, 4718592, 8388608]
    measured = report["published_w2_measured_json_objects"]
    assert [x["object_sizes_bytes"]["signature"] for x in measured] == [35334, 51126, 67112]
    assert all(x["historical_single_lifecycle_only"] and x["peak_rss_bytes"] is None for x in measured)


def test_wrong_profile_receipt_is_rejected_before_relabeling(tmp_path):
    for relative in (OLD, *(FINAL/f"param-{label}-bounded-final-lifecycle.json" for label in ("i", "ii", "iii"))):
        target = tmp_path/relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT/relative, target)
    target = tmp_path/FINAL/"param-i-bounded-final-lifecycle.json"
    data = json.loads(target.read_text())
    data["published_inputs"]["digits"] = 8
    target.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="scope changed"):
        build_report(tmp_path)


@pytest.mark.parametrize("value", [True, 0, -1, 2**33])
def test_invalid_dimension_does_not_create_a_plausible_cost(value):
    with pytest.raises(ValueError):
        matrix_scenario(degree=value, module_rows=2)
