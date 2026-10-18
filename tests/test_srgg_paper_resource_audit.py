"""Independent wire arithmetic and real SRGG public-constructor preflight."""
from dataclasses import replace
import json

import pytest

from experiments.research.candidates.srgg.paper_resource_audit import (
    _candidates, _execution_guards, build_report, dimensions, nested_array_length,
    repeat_array_length, wire_envelope,
)


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


@pytest.mark.parametrize("count", [0, 1, 2, 7])
@pytest.mark.parametrize("coordinate", [-255, -1, 0, 16])
def test_array_length_arithmetic_matches_independently_encoded_arrays(count, coordinate):
    assert repeat_array_length(len(str(coordinate)), count) == len(_encoded([coordinate] * count))
    assert nested_array_length(len(str(coordinate)), 2, 3, count) == len(
        _encoded([[[coordinate] * count for _ in range(3)] for _ in range(2)]))


def test_envelope_counts_nested_public_master_hex_and_cached_entries():
    # Public format fixtures validate byte arithmetic without constructing keys.
    record = lambda kind, **fields: {"schema": "fixture", "kind": kind, **fields}
    fields = {"schema": "public-fixture", "params": {"example": 1}}
    result = wire_envelope(degree=2, rank=1, digits=2, modulus=17,
        parameters=fields, record=record, max_wire=2**21, max_state_bytes=2**21,
        max_users=3, tail_coordinate_cap=255, signature_norm_cap=49)
    public = _encoded({**fields, "seed": bytes(32).hex(), "b": [[[16, 16], [16, 16]]]})
    tail = [[-255, -255] for _ in range(3)]
    witness = [[[-1, -1] for _ in range(2)] for _ in range(2)]
    identity = bytes(4096).hex()
    key = _encoded(record("key", public=public.hex(), identity=identity, tail=tail))
    assert result["public_bytes_upper"] == len(public)
    assert result["key_bytes_upper"] == len(key)
    empty_master = _encoded(record("master", public=public.hex(), witness=witness, entries=[]))
    assert result["master_no_cache_bytes_upper"] == len(empty_master)
    for count in (1, 2, 3):
        entries = [[identity, "issued", tail] for _ in range(count)]
        master = _encoded(record("master", public=public.hex(), witness=witness, entries=entries))
        issuer = _encoded(record("issuer", status="failed", max_users=count, master=master.hex()))
        envelope = result["service_capacity_envelopes"][str(count)]
        assert envelope["master_bytes_upper"] == len(master)
        assert envelope["issuer_bytes_upper"] == len(issuer)
    signature = _encoded(record("signature", context=bytes(32).hex(),
        response=[[-7, -7] for _ in range(5)], challenge=[1, 1]))
    assert result["accepted_signature_bytes_upper"] == len(signature)


def test_large_candidate_dimensions_cover_signature_extra_polynomial():
    shape = dimensions(2048, 3, 22)
    assert shape["master"]["dimension"] == 147456
    assert shape["signature"]["dimension"] == 149504
    assert shape["master"]["witness_coefficients"] == 811008
    assert shape["signature"]["rows"] == 72


@pytest.mark.parametrize("bad", [True, -1, 1.5])
def test_public_length_arithmetic_rejects_nonexact_or_negative_counts(bad):
    with pytest.raises(ValueError):
        repeat_array_length(2, bad)


@pytest.fixture(scope="module")
def report():
    pytest.importorskip("sage.all", reason="public runtime constructors require designated WSL Sage")
    return build_report()


def test_actual_preflight_retains_original_namespace_and_joint_candidate_rejections(report):
    assert len(report["rows"]) == 8
    papers = [row for row in report["rows"] if row["namespace"] == "paper"]
    candidates = [row for row in report["rows"] if row["namespace"] == "candidate"]
    assert len(papers) == 6
    assert all(row["execution_parameter_preflight"]["actual_constructor"]["passes"] is None for row in papers)
    small, large = candidates
    assert small["execution_parameter_preflight"]["actual_constructor"]["passes"] is True
    assert large["execution_parameter_preflight"]["actual_constructor"]["passes"] is False
    checks = large["execution_parameter_preflight"]["checks"]
    assert not checks["degree_power_of_two_in_2_to_512"]
    assert not checks["digits_le_8"]
    assert not checks["master_dimension_le_32768"]
    assert not large["signature_samplef"]["dimension_guard_passes"]
    assert not large["object_signature_shape_guards"]["response_polynomials_fit"]
    assert not large["object_signature_shape_guards"]["degree_le_512"]


@pytest.mark.parametrize("changes,guard", [
    ({"rank": 5}, "rank_in_1_to_4"),
    ({"base": 65}, "base_le_63"),
    ({"p": 65537}, "p_le_65535"),
    ({"sign_max_attempts": 17}, "sign_attempts_le_16"),
])
def test_joint_validator_checks_more_than_degree_and_dimension(changes, guard):
    pytest.importorskip("sage.all", reason="real ExecutionParams validator required")
    from experiments.research.candidates.srgg.structured_execution import ExecutionParams
    candidate = replace(_candidates()[0], **changes)
    checked = _execution_guards(candidate, ExecutionParams)
    assert not checked["checks"][guard]
    assert checked["actual_constructor"]["passes"] is False


def test_wire_service_capacity_matches_actual_preflight_without_storage_or_entropy(report):
    standard = [row for row in report["rows"] if row["label"].endswith("/table-standard-deviation")]
    assert [row["wire_envelope"]["service_capacities_passing_envelope"] for row in standard] == [
        [1, 2, 3], [1, 2], [1]]
    for row in standard:
        capacity = max(row["wire_envelope"]["service_capacities_passing_envelope"])
        runtime = row["actual_service_constructor_preflight"]
        assert runtime[str(capacity)]["passes"] is True
        assert runtime[str(capacity + 1)]["passes"] is False
        assert row["wire_envelope"]["public_fits_wire"]
        assert row["wire_envelope"]["key_class_fits_wire"]
        coefficients = row["object_coordinate_envelope_conditional_on_prepared_plans"]
        assert coefficients["raw_coordinate_abs_upper"] < 2**37
        assert coefficients["response_coordinate_abs_upper"] < 2**52
        assert coefficients["raw_within_256bit_ring_input_cap"]
        assert coefficients["response_within_256bit_ring_input_cap"]


def test_batch_limits_are_distinct_from_runtime_u_and_global_service_caps(report):
    cap = report["batch_global_limits"]["aggregate_max_bytes"]
    assert cap == 256 * 1024 * 1024
    for row in report["rows"]:
        assert row["global_service_entropy_cap_bytes"] is None
        assert row["global_service_entropy_cap_enforced"] is False
        if row["namespace"] == "paper":
            assert not row["u_aggregate_cap_enforced_in_runtime"]
            scalar_tape = row["scalar_public_constructor"]["per_scalar_hard_tape_cap_bytes"]
            assert row["u_group_hard_cap_bytes"] == row["shape"]["u_draws"] * scalar_tape
            assert row["finite_call_entropy"]["one_sign_call_hard_cap_bytes"] > cap
        else:
            assert row["u_aggregate_cap_enforced_in_runtime"]
            assert row["u_group_hard_cap_bytes"] == row["u_public_batch_diagnostic"]["selected_cap_bytes"]


def test_private_and_unbounded_resource_results_remain_unknown(report):
    assert report["actual_entropy_bytes"] == 0
    assert report["private_state_read"] is False
    assert report["private_witness_constructed"] is False
    assert report["complete_resource_admission"] is None
    for row in report["rows"]:
        assert row["complete_resource_admission"] is None
        assert row["peak_memory_upper_bytes"] is None
        assert row["runtime_upper_seconds"] is None
        for phase in ("master_samplef", "signature_samplef"):
            sampler = row[phase]
            assert sampler["actual_witness_contraction_passes"] is None
            assert sampler["actual_private_terms"] is None
            assert sampler["actual_generated_center_reserve_passes"] is None
            assert sampler["actual_preparation_resource_passes"] is None
    assert report["security_claim"] == "none"
    assert report["parameters_are_formal"] is False
    assert report["backend_admitted"] is False
    assert report["nist_security_category"] is None
    json.dumps(report)


def test_historical_execution_does_not_revalidate_old_numerical_bounds(report):
    coverage = report["historical_execution_coverage"]
    assert len(coverage["paper"]) == 3
    assert all(row["historical_functional_observation_only"] for row in coverage["paper"])
    assert all(row["numerical_bounds_revalidated"] is False for row in coverage["paper"])
    assert coverage["n512"]["manifest_bound"] is True
    assert coverage["n512"]["completed"] is True
    assert coverage["n512"]["numerical_bounds_revalidated"] is False
    assert coverage["n2048"]["full_lifecycle_executed"] is False
