"""HIBE-independent SRGG public registration and assembly contract.

These checks exercise the public parameter/object adapter without running the
Sage sampler or claiming a security level.  The assembly smoke test uses the
explicit TEST-ONLY mock HIBE solely to provide a finite independent suite
context; it does not certify an HIBE/IBS combination.
"""

from dataclasses import asdict, replace
import math

import pytest

from ibme.assembly import (
    BackendRegistry,
    SuiteConfig,
    build_runtime,
    default_registry,
    make_suite,
    validate_suite,
)
from ibme.core.errors import InvalidParameterError, SerializationError


def _srgg_spec():
    return default_registry().get("ibs", "srgg2025")


def _portable_registry():
    """Use the SRGG descriptor with its optional Sage probe disabled.

    This keeps the test about registration/assembly policy.  It does not
    change the production descriptor and never constructs a sampling backend.
    """
    base = default_registry()
    srgg = replace(base.get("ibs", "srgg2025"), validate_environment=None)
    return BackendRegistry([base.get("hibe", "mock"), srgg])


def _suite(**kwargs):
    values = dict(
        hibe="mock",
        ibs="srgg2025",
        transport="direct",
        allow_mock=True,
        registry=_portable_registry(),
    )
    values.update(kwargs)
    return make_suite(**values)


def test_research_snapshot_is_complete_and_round_trips_without_sage():
    spec = _srgg_spec()
    params = spec.presets["research"]
    record = asdict(params)

    assert record == params.record()
    assert type(params).from_record(record) == params
    # ``security_claim`` and ``backend_admitted`` are ClassVar policy labels,
    # intentionally absent from the serialized parameter snapshot.
    from dataclasses import fields
    assert set(record) == {field.name for field in fields(params)}
    assert params.security_claim == "none"
    assert params.backend_admitted is False
    assert spec.object_parameter_binding == "full-parameter-snapshot"
    assert spec.persistent_identity_cache is True

    missing = dict(record)
    missing.pop("message_max_bytes")
    with pytest.raises(InvalidParameterError, match="complete parameter fields"):
        spec.parse_params(missing)
    extra = dict(record, unexpected=1)
    with pytest.raises(InvalidParameterError, match="complete parameter fields"):
        spec.parse_params(extra)


@pytest.mark.parametrize(
    "field,value",
    [
        ("degree", 3),
        ("signature_noise_factor", 1),
        ("max_users", 0),
        ("sign_max_attempts", 0),
        ("precision_bits", 128),
        ("ticket_bits", 256),
        ("scalar_mass_bits", 256),
    ],
)
def test_invalid_parameter_values_are_rejected_before_backend_construction(field, value):
    spec = _srgg_spec()
    data = asdict(spec.presets["research"])
    data[field] = value
    with pytest.raises(InvalidParameterError, match="invalid parameters"):
        spec.parse_params(data)


def test_signature_size_is_the_conservative_wire_bound_for_both_declared_formats():
    spec = _srgg_spec()
    params = spec.presets["research"]
    from experiments.research.candidates.srgg.objects import Signature

    bound = math.isqrt(params.signature_bound_squared)
    signature = Signature(
        bytes(32),
        ((-bound,) * params.degree,) * (params.algebra.columns + 1),
        (1,) * params.degree,
    )
    expected = len(signature.to_bytes())
    assert spec.signature_formats == ("reference", "canonical-json-v1")
    for fmt in spec.signature_formats:
        assert spec.signature_size(params, fmt) == expected
    assert expected == 579


def test_public_object_parameter_snapshot_binding_rejects_changed_config():
    spec = _srgg_spec()
    params = spec.presets["research"]
    from experiments.research.candidates.srgg.objects import PublicKey

    p = params.algebra
    zero_matrix = tuple(
        tuple((0,) * p.degree for _ in range(p.rank * p.digits))
        for _ in range(p.rank)
    )
    public_key = PublicKey(params, bytes(32), zero_matrix)
    assert spec.check_object(public_key, params) is None

    changed = replace(params, message_max_bytes=params.message_max_bytes - 1)
    with pytest.raises(SerializationError, match="object differs from selected parameter snapshot"):
        spec.check_object(public_key, changed)


def test_make_validate_and_build_runtime_bind_srgg_snapshot_and_capacity():
    registry = _portable_registry()
    config = _suite(registry=registry)
    data = config.to_dict()
    spec = registry.get("ibs", "srgg2025")

    assert data["ibs_params"] == asdict(spec.presets["research"])
    report = validate_suite(config, registry=registry)
    assert report.ok, report.errors
    assert report.capacity["signature_max_bytes"] == spec.signature_size(
        spec.presets["research"], "reference"
    )
    assert report.capacity["max_application_bytes"] == 3924
    assert report.metadata["persistent_identity_cache"] is True
    assert report.metadata["preflight_only"] is True
    assert report.metadata["security_claim"] == "none"
    assert report.metadata["backend_admitted"] is False
    assert report.metadata["parameters_are_formal"] is False

    runtime = build_runtime(config, registry=registry)
    assert runtime.ibs_params.record() == data["ibs_params"]
    assert runtime.capacity == report.capacity
    assert runtime.metadata == report.metadata


def test_capacity_and_unsupported_format_are_rejected_by_preflight():
    registry = _portable_registry()
    params = asdict(registry.get("ibs", "srgg2025").presets["research"])
    params["message_max_bytes"] = 1
    too_small = _suite(ibs_params=params, registry=registry)
    report = validate_suite(too_small, registry=registry)
    assert not report.ok
    assert any("capacity" in error for error in report.errors)

    compact = _suite(signature_format="compact", registry=registry)
    report = validate_suite(compact, registry=registry)
    assert not report.ok
    assert any("signature format" in error for error in report.errors)
    with pytest.raises(InvalidParameterError, match="signature format"):
        build_runtime(compact, registry=registry)


def test_suite_snapshot_tampering_is_rejected_without_fallback():
    registry = _portable_registry()
    config = _suite(registry=registry)
    data = config.to_dict()
    data["ibs_version"] = "SRGG-zeta2-research-v0"
    changed_version = SuiteConfig.from_dict(data)
    report = validate_suite(changed_version, registry=registry)
    assert not report.ok
    assert any("backend version mismatch" in error for error in report.errors)
    with pytest.raises(InvalidParameterError, match="backend version mismatch"):
        build_runtime(changed_version, registry=registry)
