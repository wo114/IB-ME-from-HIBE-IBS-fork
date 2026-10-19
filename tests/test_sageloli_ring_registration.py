"""Portable selection/capacity and CLI policy tests; never sample a key."""
from dataclasses import replace
import json

import pytest

from ibme.assembly import default_registry, make_suite, validate_suite
from ibme.cli import main
from ibme.core.errors import InvalidParameterError
from ibme.ibs.sageloli import ring_registration as reg


def limits(payload=8*2**20, backend="mock-hibe-v1"):
    return dict(backend_id=backend, identity_max_bytes=64,
                max_payload_bytes=payload, max_capsule_bytes=4*2**20)


@pytest.mark.parametrize("name,signature", [("PARAM-I", 3227824), ("PARAM-II", 7553200)])
def test_paper_profiles_and_exact_signature_capacity(name, signature):
    spec = default_registry().get("ibs", "sageloli-rsis")
    p = spec.presets[name]
    assert spec.available and spec.version == reg.VERSION
    assert p == reg.paper_params(name)
    assert p.d == 2048 and p.q == 3**p.k
    assert spec.signature_size(p, "reference") == signature
    assert max(reg.state_size_bounds(p).values()) < 2**31
    reg.validate_configuration(p, {})


def test_full_ledger_capacity_is_checked_before_execution():
    with pytest.raises(InvalidParameterError, match="ledger"):
        reg.validate_configuration(replace(reg.paper_params("PARAM-II"), max_users=32), {})
    with pytest.raises(InvalidParameterError):
        reg.signature_size(reg.paper_params(), "compact")


def test_v3_is_the_only_registered_rsis_version_and_small_is_explicit():
    spec = default_registry().get("ibs", "sageloli-rsis")
    assert spec.default_preset("hybrid") == "PARAM-I"
    assert spec.presets["debug-small"].d == 4
    assert "unsafe" in spec.reason
    suite = make_suite(hibe="mock", ibs="sageloli-rsis", transport="hybrid", allow_mock=True,
                       hybrid_limits=limits())
    assert suite.to_dict()["ibs_params"] == reg.paper_params().record()
    bad = suite.to_dict(); bad["ibs_version"] = "Sageloli-RSIS-v2"
    from ibme.assembly import SuiteConfig
    assert not validate_suite(SuiteConfig.from_dict(bad)).ok
    assert not default_registry().get("ibs", "sageloli-sis").available


def test_default_small_transport_budget_does_not_hide_large_signature(monkeypatch):
    monkeypatch.delenv("IBME_SAGELOLI_RING_NATIVE", raising=False)
    suite = make_suite(hibe="mock", ibs="sageloli-rsis", transport="hybrid", allow_mock=True)
    report = validate_suite(suite)
    assert not report.ok and any("capacity insufficient" in error for error in report.errors)
    assert report.capacity["signature_max_bytes"] == 3227824
    assert report.metadata["preflight_only"] and not report.metadata["combination_tested"]


def test_missing_native_preflight_leaves_no_state_or_entropy(monkeypatch, tmp_path):
    from ibme.core.randomness import SecureRandom
    monkeypatch.delenv("IBME_SAGELOLI_RING_NATIVE", raising=False)
    def forbidden(*args): raise AssertionError("preflight consumed entropy")
    monkeypatch.setattr(SecureRandom, "read", forbidden)
    state = tmp_path/"new-state"
    assert main(["setup", "--state", str(state), "--hibe", "mock", "--ibs", "sageloli-rsis",
                 "--allow-mock", "--transport", "hybrid", "--hybrid-limits", json.dumps(limits())]) == 2
    assert not state.exists()


def test_cli_explicit_hybrid_limits_are_recorded_and_validated(capsys):
    args = ["check", "--hibe", "mock", "--ibs", "mock", "--allow-mock", "--transport", "hybrid",
            "--hybrid-limits", json.dumps(limits()), "--json"]
    assert main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["suite"]["hybrid_limits"] == limits()
    assert result["compatibility"]["capacity"]["hibe_payload_bytes"] == 8*2**20
    args[-2] = json.dumps(dict(limits(), extra=True))
    assert main(args) != 0
