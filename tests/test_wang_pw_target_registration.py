"""Target Wang–PW selection and capacity; no target key generation here."""
from dataclasses import asdict, replace
import json
from pathlib import Path
import subprocess
import sys

import pytest

from ibme.assembly import (
    BackendRegistry, SuiteConfig, build_runtime, default_registry, make_suite, validate_suite,
)
from ibme.core.errors import InvalidParameterError


def limits(payload=2**20):
    return dict(backend_id="mock-hibe-v1", identity_max_bytes=64,
                max_payload_bytes=payload, max_capsule_bytes=4*2**20)


def selection(*, registry=None, **overrides):
    values = dict(hibe="mock", ibs="wang-pw-target", transport="hybrid",
                  allow_mock=True, hybrid_limits=limits(), registry=registry)
    values.update(overrides)
    return make_suite(**values)


def static_registry():
    registry = default_registry()
    return BackendRegistry((registry.get("hibe", "mock"),
                            replace(registry.get("ibs", "wang-pw-target"),
                                    validate_environment=lambda: None)))


def test_target_is_separate_from_q17_and_belongs_to_the_same_algorithm_route():
    registry = default_registry()
    target, old = registry.get("ibs", "wang-pw-target"), registry.get("ibs", "wang-pw")
    assert target.version == "WangPW-target-s0-4-v1"
    assert old.version == "WangPW-research-v1" and old.presets["research"].q == 17
    assert target.available and not target.persistent_identity_cache
    assert target.signature_formats == ("reference",)
    assert set(target.presets) == {"s0-4", "debug-small"}
    assert target.presets["s0-4"].n == 512
    assert target.presets["s0-4"].q == 4294967291
    assert target.presets["debug-small"].n < 512
    assert target.default_preset("hybrid") == "s0-4"
    from ibme.assembly.catalog import algorithm_catalog
    catalog = algorithm_catalog(registry=registry)
    assert catalog["counts"] == {"hibe": 8, "ibs": 11}
    route = next(row for row in catalog["routes"] if row["id"] == "wang-pw")
    assert route["backend_ids"] == ["wang-pw", "wang-pw-target"]


def test_fresh_target_discovery_does_not_read_entropy_or_import_numeric_engines():
    script = "import sys; sys.path.insert(0, " + repr(str(Path(__file__).resolve().parents[1] / "src")) + ")\n"
    script += '''import builtins,importlib.util,os,sys
real_find=importlib.util.find_spec
importlib.util.find_spec=lambda name,*args,**kwargs: None if name=='sage' else real_find(name,*args,**kwargs)
real_import=builtins.__import__
def guarded(name,*args,**kwargs):
    if name in ('numpy','scipy','sage.all') or name.startswith(('numpy.','scipy.')):
        raise AssertionError('discovery imported numerical arithmetic: '+name)
    return real_import(name,*args,**kwargs)
builtins.__import__=guarded
from ibme.core.randomness import SecureRandom
def forbidden(*args,**kwargs): raise AssertionError('discovery read entropy')
SecureRandom.read=forbidden;os.urandom=forbidden
from ibme.assembly import default_registry,make_suite
registry=default_registry()
target=registry.get('ibs','wang-pw-target')
assert target.available
config=make_suite(hibe='mock',ibs='wang-pw-target',transport='hybrid',allow_mock=True,registry=registry)
assert config.to_dict()['ibs_params']['n']==512
assert 'ibme.ibs.wang_pw_target.engine' not in sys.modules
'''
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("preset", ["s0-4", "debug-small"])
def test_complete_parameter_snapshot_roundtrip_and_hybrid_capacity(preset):
    registry = static_registry()
    spec = registry.get("ibs", "wang-pw-target")
    params = spec.presets[preset]
    assert spec.parse_params(asdict(params)) == params
    config = selection(registry=registry, ibs_params=preset)
    assert SuiteConfig.from_json(config.to_json()) == config
    report = validate_suite(config, registry=registry)
    assert report.ok, report.errors
    assert report.capacity["signature_max_bytes"] == spec.signature_size(params, "reference")
    assert report.capacity["max_application_bytes"] >= 32
    assert report.capacity["inner_hibe_payload_bytes"] == 32
    assert report.metadata["preflight_only"] and not report.metadata["combination_tested"]
    assert report.metadata["security_claim"] == "none"
    assert not report.metadata["backend_admitted"] and not report.metadata["parameters_are_formal"]


def test_target_does_not_silently_fit_the_default_64k_hybrid_budget():
    registry = static_registry()
    config = selection(registry=registry, hybrid_limits=limits(65536))
    report = validate_suite(config, registry=registry)
    assert not report.ok and any("capacity insufficient" in error for error in report.errors)
    assert 65536 < report.capacity["signature_max_bytes"] < 2**20


@pytest.mark.parametrize("bad", [None, {}, {"n": 512}, {"n": True}])
def test_partial_parameter_snapshots_are_rejected(bad):
    spec = default_registry().get("ibs", "wang-pw-target")
    with pytest.raises((InvalidParameterError, TypeError, ValueError)):
        spec.parse_params(bad)


def test_unknown_parameter_fields_presets_and_formats_do_not_fall_back():
    registry = default_registry()
    spec = registry.get("ibs", "wang-pw-target")
    params = spec.presets["s0-4"]
    with pytest.raises(InvalidParameterError):
        spec.parse_params(dict(asdict(params), implicit_fallback=True))
    for preset in ("research", "s0-2", "automatic"):
        with pytest.raises(InvalidParameterError):
            selection(registry=registry, ibs_params=preset)
    for fmt in ("compact", "canonical-json-v1", "automatic"):
        with pytest.raises(InvalidParameterError):
            spec.signature_size(params, fmt)
        with pytest.raises(InvalidParameterError):
            spec.factory(None, fmt)


def test_wrong_backend_version_is_rejected_without_migration():
    registry = static_registry()
    record = selection(registry=registry).to_dict()
    record["ibs_version"] = "WangPW-research-v1"
    report = validate_suite(SuiteConfig.from_dict(record), registry=registry)
    assert not report.ok and any("version mismatch" in error for error in report.errors)


def test_missing_native_is_rejected_before_state_entropy_and_factory(monkeypatch, tmp_path):
    from ibme.cli import main
    from ibme.core.randomness import SecureRandom
    monkeypatch.delenv("IBME_WANG_PW_TARGET_NATIVE", raising=False)
    def forbidden(*args, **kwargs):
        pytest.fail("dependency preflight reached key generation or entropy")
    monkeypatch.setattr(SecureRandom, "read", forbidden)
    registry = default_registry()
    original = registry.get("ibs", "wang-pw-target")
    registry = BackendRegistry((registry.get("hibe", "mock"), replace(original, factory=forbidden)))
    config = selection(registry=registry)
    report = validate_suite(config, registry=registry)
    assert not report.ok
    with pytest.raises(InvalidParameterError):
        build_runtime(config, registry=registry)
    state = tmp_path / "state"
    assert main(["setup", "--state", str(state), "--hibe", "mock", "--ibs", "wang-pw-target",
                 "--allow-mock", "--transport", "hybrid", "--hybrid-limits", json.dumps(limits())]) == 2
    assert not state.exists()


def test_cli_check_reports_complete_explicit_target_selection(monkeypatch, capsys):
    # No native is needed to establish that CLI preserves selection and budget;
    # the JSON report remains an unexecuted, missing-runtime preflight.
    from ibme.cli import main
    monkeypatch.delenv("IBME_WANG_PW_TARGET_NATIVE", raising=False)
    args = ["check", "--hibe", "mock", "--ibs", "wang-pw-target", "--ibs-params", "s0-4",
            "--allow-mock", "--transport", "hybrid", "--hybrid-limits", json.dumps(limits()), "--json"]
    assert main(args) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["suite"]["ibs"] == "wang-pw-target"
    assert result["suite"]["ibs_params"]["n"] == 512
    assert result["suite"]["hybrid_limits"] == limits()
    assert not result["compatibility"]["ok"]
    assert result["compatibility"]["metadata"]["preflight_only"]
