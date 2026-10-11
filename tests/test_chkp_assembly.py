"""CHKP registration and entropy-free assembly; no private key generation."""

from dataclasses import asdict, replace
import importlib.util

import pytest

from ibme.assembly import (BackendRegistry, SuiteConfig, build_runtime,
                          default_registry, list_backends, make_suite, validate_suite)
from ibme.core.errors import InvalidParameterError
from ibme.hibe.chkp import CHKPHIBE, CHKPParams, research_params


class NoEntropy:
    def read(self, size):
        pytest.fail("assembly consumed entropy")


def _portable_registry(*, environment=None, factory=None):
    # Test only: replace the environment probe to exercise platform-independent
    # assembly. We do not replace CHKP algorithms or execute any cryptography.
    original = default_registry()
    chkp = original.get("hibe", "chkp")
    fields = dict(validate_environment=(lambda: None) if environment is None else environment)
    if factory is not None:
        fields["factory"] = factory
    return BackendRegistry([replace(chkp, **fields), original.get("ibs", "luo-module"),
                            original.get("ibs", "mock"), original.get("hibe", "mock")])


def test_chkp_registered_without_sage_import_and_has_separate_runtime_status(monkeypatch):
    original = importlib.util.find_spec
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: None if name == "sage" else original(name))
    row = next(row for row in list_backends()["hibe"] if row["id"] == "chkp")
    assert row["available"] is True and row["runtime_available"] is False
    assert "SageMath" in row["runtime_reason"]
    assert row["test_only"] is False and row["persistent_identity_cache"] is True
    assert row["object_parameter_binding"] == "full-parameter-snapshot"
    assert row["parameter_presets"] == ["direct-research", "hybrid-research"]


def test_missing_sage_fails_before_factories_and_preserves_static_capacity(monkeypatch):
    def unavailable():
        raise InvalidParameterError("test runtime unavailable")
    def forbidden(*args, **kwargs):
        pytest.fail("missing runtime instantiated a backend")
    registry = _portable_registry(environment=unavailable, factory=forbidden)
    suite = make_suite(hibe="chkp", ibs="luo-module", transport="hybrid", registry=registry)
    report = validate_suite(suite, registry=registry)
    assert not report.ok and "test runtime unavailable" in " ".join(report.errors)
    assert report.capacity["inner_hibe_ciphertext_max_bytes"] == 3919
    assert report.metadata["runtime_available"] is False
    with pytest.raises(InvalidParameterError):
        build_runtime(suite, registry=registry, ibs_rng=NoEntropy(), ots_rng=NoEntropy())


def test_hybrid_chkp_selection_binds_full_profile_and_does_not_generate_keys():
    registry = _portable_registry()
    suite = make_suite(hibe="chkp", ibs="luo-module", transport="hybrid",
                       signature_format="compact", registry=registry)
    assert suite.to_dict()["hibe_params"] == asdict(research_params())
    assert SuiteConfig.from_json(suite.to_json()) == suite
    report = validate_suite(suite, registry=registry)
    assert report.ok, report.errors
    assert report.capacity["inner_hibe_payload_bytes"] == 32
    assert report.capacity["inner_hibe_identity_bytes"] == 86
    assert report.capacity["inner_hibe_ciphertext_max_bytes"] == 3919
    assert report.capacity["max_application_bytes"] == 3924
    assert report.metadata["security_claim"] == "none"
    assert report.metadata["backend_admitted"] is False
    assert report.metadata["parameters_are_formal"] is False
    assert report.metadata["combination_tested"] is False
    assert report.metadata["primitive_persistent_identity_cache"] == {"hibe": True, "ibs": True}
    runtime = build_runtime(suite, registry=registry, ibs_rng=NoEntropy(), ots_rng=NoEntropy())
    assert isinstance(runtime.hibe.inner_backend, CHKPHIBE)
    assert runtime.hibe_params.inner_params == research_params()
    assert set(runtime.decoders) == {"hpk", "hmsk", "sk1", "sk2", "ipk", "imsk", "sk"}


@pytest.mark.parametrize("mode,transport,expected", [
    ("seed32", "direct", "requires hybrid"),
    ("framed32", "hybrid", "requires direct"),
])
def test_chkp_modes_cannot_be_silently_repurposed(mode, transport, expected):
    registry = _portable_registry()
    suite = make_suite(hibe="chkp", hibe_params=research_params(message_mode=mode),
                       ibs="luo-module", transport=transport, registry=registry)
    report = validate_suite(suite, registry=registry)
    assert not report.ok and expected in " ".join(report.errors)
    with pytest.raises(InvalidParameterError):
        build_runtime(suite, registry=registry, ibs_rng=NoEntropy())


def test_direct_primitive_is_selected_but_full_ibs_payload_capacity_is_not_invented():
    registry = _portable_registry()
    suite = make_suite(hibe="chkp", ibs="luo-module", transport="direct", registry=registry)
    assert suite.to_dict()["hibe_params"]["message_mode"] == "framed32"
    report = validate_suite(suite, registry=registry)
    assert not report.ok and "capacity insufficient" in " ".join(report.errors)
    assert report.capacity["inner_hibe_payload_bytes"] == 28
    assert report.capacity["inner_hibe_ciphertext_max_bytes"] == 3919


def test_hibe_cache_is_reported_even_when_ibs_is_stateless():
    registry = _portable_registry()
    suite = make_suite(hibe="chkp", ibs="mock", transport="hybrid", allow_mock=True,
                       registry=registry)
    report = validate_suite(suite, registry=registry)
    assert report.ok, report.errors
    assert report.metadata["persistent_identity_cache"] is True
    assert report.metadata["primitive_persistent_identity_cache"] == {"hibe": True, "ibs": False}


def test_configuration_and_environment_hooks_apply_to_other_registered_algorithms():
    base = default_registry()
    calls = []
    def configure(params, suite):
        calls.append((params, suite["transport"]))
        raise InvalidParameterError("owner configuration rejected")
    alias = replace(base.get("hibe", "mock"), id="policy-controlled", validate_configuration=configure,
                    default_preset=lambda transport: "education")
    registry = BackendRegistry([alias, base.get("ibs", "mock")])
    suite = make_suite(hibe="policy-controlled", ibs="mock", allow_mock=True, registry=registry)
    report = validate_suite(suite, registry=registry)
    assert not report.ok and "owner configuration rejected" in " ".join(report.errors)
    assert len(calls) == 1 and calls[0][1] == "direct"
    with pytest.raises(InvalidParameterError):
        registry.register(replace(alias, id="bad-hook", validate_environment=True))


def test_full_parameter_type_and_bounds_remain_primitive_owned():
    registry = _portable_registry()
    suite = make_suite(hibe="chkp", ibs="luo-module", transport="hybrid", registry=registry)
    for key, value in (("epsilon_bits", True), ("max_dimension", 513), ("message_mode", "automatic")):
        data = suite.to_dict()
        data["hibe_params"][key] = value
        assert not validate_suite(SuiteConfig.from_dict(data), registry=registry).ok
    data = suite.to_dict()
    del data["hibe_params"]["root_entropy_budget"]
    assert not validate_suite(SuiteConfig.from_dict(data), registry=registry).ok


def test_real_runtime_preflight_matches_dependency_presence_without_setup():
    suite = make_suite(hibe="chkp", ibs="luo-module", transport="hybrid")
    report = validate_suite(suite)
    has_sage = importlib.util.find_spec("sage") is not None
    assert report.metadata["runtime_dependencies"]["hibe"]["runtime_available"] == has_sage
    if has_sage:
        assert report.ok, report.errors
        runtime = build_runtime(suite, ibs_rng=NoEntropy(), ots_rng=NoEntropy())
        assert isinstance(runtime.hibe.inner_backend, CHKPHIBE)
    else:
        assert not report.ok and "SageMath" in " ".join(report.errors)
