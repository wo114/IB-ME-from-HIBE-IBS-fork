"""Registry extension/adapter evidence; never a cryptographic security claim."""
import builtins
from dataclasses import asdict, dataclass, replace
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

from ibme.assembly import (
    BackendRegistry, SuiteConfig, build_runtime, default_registry, make_suite, validate_suite,
)
from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.core.randomness import DeterministicRandom
from ibme.protocol.baseline import PublicKey, MasterSecret, SenderKey, ReceiverKey


class NoEntropy:
    def read(self, size):
        pytest.fail("static registry operation consumed entropy")


@pytest.mark.parametrize("role,identifier,direct,hybrid", [
    ("hibe", "abb10", "education", "hybrid-research"),
    ("hibe", "mock", "education", "hybrid-research"),
    ("hibe", "chkp", "direct-research", "hybrid-research"),
    ("ibs", "sis", "education", "education"),
    ("ibs", "mock", "education", "education"),
    ("ibs", "luo-matrix", "research", "research"),
    ("ibs", "luo-module", "research", "research"),
])
@pytest.mark.parametrize("transport", ["direct", "hybrid"])
def test_existing_default_parameter_snapshots(role, identifier, direct, hybrid, transport):
    registry = default_registry()
    config = make_suite(**{role: identifier}, transport=transport, registry=registry)
    expected = registry.get(role, identifier).presets[hybrid if transport == "hybrid" else direct]
    assert config.to_dict()[role + "_params"] == asdict(expected)


def test_default_suite_wire_is_unchanged():
    assert make_suite().digest == "fdfe1dc86423178c423187aa459f02818ba2cc7530c24d8040e2cc1ede9286e8"


@dataclass(frozen=True)
class IndependentHIBEParams:
    identity_bytes: int = 64
    max_message_bytes: int = 2048
    q: int = 257


@dataclass(frozen=True)
class IndependentIBSParams:
    identity_max_bytes: int = 48
    message_max_bytes: int = 1024
    modulus: int = 65537


def extension_registry():
    base = default_registry()
    def never_construct(*args):
        pytest.fail("preflight constructed an algorithm")
    hibe = replace(
        base.get("hibe", "mock"), id="cedar", params_type=IndependentHIBEParams,
        presets={"owner-direct": IndependentHIBEParams(),
                 "owner-hybrid": IndependentHIBEParams(identity_bytes=86, max_message_bytes=32)},
        default_preset=lambda transport: "owner-" + transport, factory=never_construct,
    )
    ibs = replace(
        base.get("ibs", "mock"), id="quartz", params_type=IndependentIBSParams,
        presets={"owner-choice": IndependentIBSParams()}, default_preset=None, factory=never_construct,
    )
    return BackendRegistry([hibe, ibs])


@pytest.mark.parametrize("transport", ["direct", "hybrid"])
def test_unrelated_ids_and_unequal_parameter_types_preflight_without_factories(transport):
    registry = extension_registry()
    config = make_suite(hibe="cedar", ibs="quartz", transport=transport, allow_mock=True, registry=registry)
    report = validate_suite(SuiteConfig.from_json(config.to_json()), registry=registry)
    assert report.ok, report.errors
    assert report.capacity["identity_bytes"] == 48
    assert report.metadata["test_only"] is True
    assert report.metadata["preflight_only"] is True
    assert report.metadata["combination_tested"] is False
    assert config.to_dict()["hibe_params"]["q"] != config.to_dict()["ibs_params"]["modulus"]
    data = config.to_dict()
    del data["ibs_params"]["modulus"]
    assert not validate_suite(SuiteConfig.from_dict(data), registry=registry).ok


def test_ambiguous_default_requires_owner_selection_but_explicit_params_work():
    registry = extension_registry()
    original = registry.get("ibs", "quartz")
    registry.register(replace(original, id="ambiguous", presets={
        "alpha": IndependentIBSParams(), "beta": IndependentIBSParams(message_max_bytes=2048),
    }))
    with pytest.raises(InvalidParameterError, match="no default preset declared"):
        make_suite(hibe="cedar", ibs="ambiguous", registry=registry)
    for selected in ("beta", IndependentIBSParams(message_max_bytes=2048),
                     asdict(IndependentIBSParams(message_max_bytes=2048))):
        config = make_suite(hibe="cedar", ibs="ambiguous", ibs_params=selected, registry=registry)
        assert config.to_dict()["ibs_params"]["message_max_bytes"] == 2048


@pytest.mark.parametrize("choice", [None, "missing", {}])
def test_default_hook_cannot_silently_fall_back(choice):
    registry = extension_registry()
    registry.register(replace(registry.get("ibs", "quartz"), id="invalid-default", default_preset=lambda _: choice))
    with pytest.raises(InvalidParameterError, match="declared preset"):
        make_suite(hibe="cedar", ibs="invalid-default", registry=registry)


@pytest.mark.parametrize("role,edit", [
    ("hibe", {"ciphertext_size": None}), ("ibs", {"signature_size": None}),
    ("ibs", {"master_public_key": None}), ("ibs", {"decoders": {}}),
    ("hibe", {"factory": None}), ("ibs", {"check_object": None}),
    ("hibe", {"key_binding": None}), ("hibe", {"two_level": "unknown"}),
    ("ibs", {"persistent_identity_cache": None}),
])
def test_missing_or_unknown_capabilities_are_not_registered(role, edit):
    spec = replace(default_registry().get(role, "mock"), **edit)
    with pytest.raises(InvalidParameterError):
        BackendRegistry([spec])


def test_unknown_ids_and_required_delegation_binding_are_rejected():
    registry = extension_registry()
    with pytest.raises(InvalidParameterError, match="no fallback"):
        make_suite(hibe="not-registered", ibs="quartz", registry=registry)
    hibe = registry.get("hibe", "cedar")
    registry.register(replace(hibe, id="no-delegation", two_level=False))
    registry.register(replace(hibe, id="no-binding", key_binding=False))
    for identifier, transport, message in (("no-delegation", "direct", "two-level"),
                                           ("no-binding", "hybrid", "key-binding")):
        config = make_suite(hibe=identifier, ibs="quartz", transport=transport, allow_mock=True, registry=registry)
        report = validate_suite(config, registry=registry)
        assert not report.ok and message in " ".join(report.errors)
        with pytest.raises(InvalidParameterError):
            build_runtime(config, ibs_rng=NoEntropy(), registry=registry)


def test_renamed_real_ibs_and_hibe_build_without_algorithm_name_assumptions():
    base = default_registry()
    registry = BackendRegistry([
        replace(base.get("hibe", "mock"), id="cedar"),
        replace(base.get("ibs", "luo-matrix"), id="quartz"),
    ])
    config = make_suite(hibe="cedar", ibs="quartz", allow_mock=True, registry=registry)
    runtime = build_runtime(config, ibs_rng=NoEntropy(), ots_rng=NoEntropy(), registry=registry)
    assert type(runtime.hibe_params) is not type(runtime.ibs_params)
    assert runtime.ibs_params == base.get("ibs", "luo-matrix").presets["research"]


CANDIDATES = [("wang-pw", "2026-10-13-wang-pw", 374, False),
              ("srgg2025", "2026-10-13-srgg-full", 579, True)]


@pytest.mark.parametrize("identifier,delivery,size,cached", CANDIDATES)
def test_delivered_proposal_matches_registered_public_contract(identifier, delivery, size, cached):
    proposal = json.loads((Path(__file__).resolve().parents[1] / "docs/research/team-b-delivery" /
                           delivery / "registration-proposal.json").read_text(encoding="utf-8"))
    spec = default_registry().get("ibs", identifier)
    assert spec.available is True
    assert spec.version == proposal["algorithm_version"]
    assert asdict(spec.presets["research"]) == proposal["parameters"]
    assert spec.persistent_identity_cache is cached
    assert spec.object_parameter_binding == "full-parameter-snapshot"
    backend = spec.factory(NoEntropy(), "reference")
    assert all(callable(getattr(backend, method, None)) for method in
               ("setup", "key_extract", "sign", "verify", "load_signature"))
    for fmt in spec.signature_formats:
        assert spec.signature_size(spec.presets["research"], fmt) == size == proposal["maximum_valid_signature_bytes"]
    with pytest.raises(SerializationError, match="object type"):
        spec.check_object(object(), spec.presets["research"])


@pytest.mark.parametrize("missing", ["experiments", "experiments.research", "experiments.research.candidates"])
def test_optional_candidate_package_absence_is_explicit_not_registered(monkeypatch, missing):
    original = builtins.__import__
    def without_candidates(name, *args, **kwargs):
        if name.startswith("experiments.research.candidates"):
            raise ModuleNotFoundError("candidate package intentionally absent", name=missing)
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", without_candidates)
    registry = default_registry()
    for identifier, _, _, _ in CANDIDATES:
        spec = registry.get("ibs", identifier)
        assert spec.available is False and "not registered" in spec.reason
        config = make_suite(ibs=identifier, registry=registry)
        assert not validate_suite(config, registry=registry).ok
    assert validate_suite(make_suite(registry=registry), registry=registry).ok


def test_fresh_plain_python_listing_and_preflight_never_import_sage_or_samplers():
    # Fresh process catches eager imports even when other tests loaded modules.
    script = """
import importlib.abc
import importlib.util
import sys
class NoSamplers(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith('sage.') or fullname.endswith(('.engine', '.runtime', '.sampling', '.full_sampling')):
            raise AssertionError('static discovery imported runtime: ' + fullname)
sys.meta_path.insert(0, NoSamplers())
original = importlib.util.find_spec
importlib.util.find_spec = lambda name, *a, **kw: None if name == 'sage' else original(name, *a, **kw)
from ibme.assembly import default_registry, make_suite, validate_suite, build_runtime
from ibme.core.errors import InvalidParameterError
registry = default_registry()
rows = {row['id']: row for row in registry.list()['ibs']}
for identifier in ('wang-pw', 'srgg2025'):
    assert rows[identifier]['available'] is True
    assert rows[identifier]['runtime_available'] is False
    config = make_suite(hibe='mock', ibs=identifier, allow_mock=True, registry=registry)
    report = validate_suite(config, registry=registry)
    assert not report.ok and 'SageMath' in ' '.join(report.errors)
    assert report.capacity['signature_max_bytes'] > 0
    assert report.metadata['combination_tested'] is False
    try:
        build_runtime(config, registry=registry)
    except InvalidParameterError:
        pass
    else:
        raise AssertionError('missing runtime was accepted')
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("identifier,delivery,size,cached", CANDIDATES)
def test_real_ibs_recovery_and_protocol_bridge_with_test_only_hibe(identifier, delivery, size, cached):
    pytest.importorskip("sage.all", reason="real candidate sampling requires prescribed WSL Sage")
    config = make_suite(hibe="mock", ibs=identifier, allow_mock=True)
    runtime = build_runtime(config, ibs_rng=DeterministicRandom(b"registry:" + identifier.encode()),
                            ots_rng=DeterministicRandom(b"registry:ots"))
    public, master = runtime.proto.setup(runtime.hibe_params, ibs_params=runtime.ibs_params,
                                         rng=DeterministicRandom(b"registry:hibe"))
    sender = runtime.proto.skgen(master, b"Alice")
    receiver = runtime.proto.rkgen(master, b"Bob")
    ciphertext = runtime.proto.encrypt(public, sender, b"Bob", b"registry bridge")
    assert runtime.proto.decrypt(public, receiver, b"Alice", ciphertext) == b"registry bridge"
    readers = runtime.decoders
    recovered_public = PublicKey.from_bytes(public.to_bytes(), readers["hpk"], readers["ipk"])
    recovered_master = MasterSecret.from_bytes(master.to_bytes(), readers["hmsk"], readers["imsk"])
    recovered_sender = SenderKey.from_bytes(sender.to_bytes(), readers["sk"])
    recovered_receiver = ReceiverKey.from_bytes(receiver.to_bytes(), readers["sk1"])
    runtime.validate_master(recovered_public, recovered_master)
    runtime.validate_sender(recovered_public, recovered_sender)
    runtime.validate_receiver(recovered_public, recovered_receiver)
    assert runtime.proto.decrypt(recovered_public, recovered_receiver, b"Alice", ciphertext.to_bytes()) == b"registry bridge"
    spec = default_registry().get("ibs", identifier)
    with pytest.raises(SerializationError, match="snapshot"):
        spec.check_object(recovered_public.ipk, replace(runtime.ibs_params, message_max_bytes=4095))
    if cached:
        assert spec.factory(NoEntropy(), "reference").key_extract(recovered_master.imsk, b"Alice").to_bytes() == sender.signing_key.to_bytes()
    assert runtime.metadata["test_only"] is True
    assert runtime.metadata["security_claim"] == "none"
