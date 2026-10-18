"""Standalone descriptor checks without changing the coordinator's registry."""
from dataclasses import asdict, replace

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.assembly.registry import BackendRegistry
from ibme.ibs.srgg.structured import backend_spec, Backend, Parameters
from ibme.ibs.srgg import structured_registration as registration


def test_complete_independent_descriptor_and_exact_parameter_record():
    spec = backend_spec()
    registry = BackendRegistry([spec])
    assert registry.get("ibs", "srgg2025-structured") is spec
    assert spec.params_type is Parameters
    assert set(spec.presets) == {"research-small", "research-n512"}
    assert spec.default_preset is None
    assert spec.key_binding and spec.persistent_identity_cache
    for params in spec.presets.values():
        assert spec.parse_params(asdict(params)) == params
        spec.validate_configuration(params, {})
        assert spec.signature_size(params, "canonical-json-v1") > 0
    with pytest.raises(InvalidParameterError):
        spec.parse_params({"degree": 512})
    with pytest.raises(InvalidParameterError):
        spec.parse_params(dict(asdict(spec.presets["research-small"]), degree=True))


def test_descriptor_objects_bind_the_entire_snapshot():
    spec = backend_spec()
    params = spec.presets["research-small"]
    backend = Backend()
    public, master = backend.setup(params)
    key = backend.key_extract(master, b"alice")
    for value in (public, master, key):
        spec.check_object(value, params)
        with pytest.raises(SerializationError):
            spec.check_object(value, replace(params, sign_max_attempts=1))
    assert spec.master_public_key(master) == public
    assert spec.signature_size(params, "reference") >= len(backend.sign(key, b"message").to_bytes())


@pytest.mark.parametrize("bad", [None, {}, "compressed", 1])
def test_descriptor_rejects_unknown_format_and_parameter_classes(bad):
    params = backend_spec().presets["research-small"]
    with pytest.raises(InvalidParameterError):
        registration.signature_size(params, bad)
    with pytest.raises(InvalidParameterError):
        registration.factory(None, bad)
    with pytest.raises(InvalidParameterError):
        registration.validate_configuration(bad, {})


def test_service_audit_worker_never_reissues_an_existing_identity():
    from experiments.research.srgg_structured_service_audit import audit
    report = audit(8)
    assert "failed_stage" not in report, report
    # n8 has known public forgeries and occasional hash collisions. Exercise
    # engineering behavior here; retain every attack outcome in the report.
    for name in ("public_roundtrip", "key_roundtrip_0", "key_roundtrip_1",
                 "honest_0", "honest_1", "signature_roundtrip_0", "signature_roundtrip_1",
                 "reopen_public", "reopen_cache", "snapshot_within_envelope",
                 "fresh_process_exit", "fresh_process_lifecycle"):
        assert report["checks"][name], report
    assert report["fresh_process"]["completed"]
    assert report["actual_main_entropy_bytes"] > 0
    assert report["private_payloads_exported"] is False
