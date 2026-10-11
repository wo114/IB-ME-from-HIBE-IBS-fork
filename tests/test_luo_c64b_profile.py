"""C64B opt-in, public restoration and teaching-Hybrid integration only."""
from dataclasses import asdict, replace
from pathlib import Path
import json
import sys

import pytest

from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.luo_module import LuoModuleParams, LuoModuleIBSBackend
from ibme.ibs.luo_module_codec import compact_layout
from ibme.ibs.luo_module_profiles import C64B_PROFILE_ID, c64b_params, is_c64b_profile
from ibme.protocol.baseline import BOTTOM, PublicKey, MasterSecret, SenderKey, ReceiverKey
from ibme.protocol.luo_hybrid import make_research_runtime, RESEARCH_HIBE_PARAMS, RESEARCH_IBS_PARAMS


class NoEntropy:
    def read(self, count):
        raise AssertionError("preflight/cache/verify must not consume entropy")


def rng(label):
    return DeterministicRandom(b"public-test/step23/c64b/" + label)


def test_all_seventeen_fields_are_pinned_and_wire_unchanged():
    p = c64b_params()
    assert C64B_PROFILE_ID == "luo-module-c64b-v1"
    assert asdict(p) == dict(degree=256, k=11, l=10, q=274877844481,
        root=153250464611, eta=1, kappa=64, gamma1=190000, gamma2=60000000000,
        gamma3=27487784448, dropped_bits=28, identity_max_bytes=64,
        message_max_bytes=4096, max_extract_attempts=4096, max_sign_attempts=4096,
        max_uniform_attempts=128, max_cached_identities=64)
    assert len(p.to_bytes()) == 136
    assert LuoModuleParams.from_bytes(p.to_bytes()) == p
    assert p.security_claim == "none" and p.backend_admitted is False
    assert compact_layout(p)["signature_bytes"] == 16383
    assert is_c64b_profile(p)
    assert not is_c64b_profile(LuoModuleParams())
    assert RESEARCH_IBS_PARAMS == LuoModuleParams()
    assert compact_layout(RESEARCH_IBS_PARAMS)["signature_bytes"] == 16063


def test_factory_matches_frozen_step22_certificate_input():
    # Import the existing certificate without rewriting its historical evidence.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments/research"))
    try:
        from luo_robust_abort_certificate import profile
        assert c64b_params() == profile("availability-k64")
    finally:
        sys.path.pop(0)


def test_handoff_json_has_exact_integer_budget_and_matches_factory():
    path = Path(__file__).resolve().parents[1] / "docs/research/2026-10-11-luo-c64b-handoff/profile.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["params"] == asdict(c64b_params())
    assert record["profile_id"] == C64B_PROFILE_ID
    assert record["availability_example_budget"]["classical_fresh_oracle_queries"] == 2**64
    assert record["parameters_are_formal"] is False
    assert record["backend_admitted"] is False
    assert record["security_claim"] == "none"


def test_c64b_reader_rejects_legacy_public_key():
    pk, _ = LuoModuleIBSBackend(rng=rng(b"legacy-pk")).setup(RESEARCH_IBS_PARAMS)
    _, readers = make_research_runtime(ibs_params=c64b_params(), ibs_rng=NoEntropy(), ots_rng=NoEntropy())
    with pytest.raises(SerializationError, match="different Luo"):
        readers["ipk"].from_bytes(pk.to_bytes())


@pytest.mark.parametrize("change", [dict(gamma1=190001), dict(gamma2=60000000001),
    dict(kappa=63), dict(identity_max_bytes=63), dict(message_max_bytes=4095),
    dict(max_sign_attempts=4095), dict(max_extract_attempts=4095),
    dict(max_uniform_attempts=127), dict(max_cached_identities=63)])
def test_nearby_valid_values_are_not_silently_the_same_profile(change):
    p = replace(c64b_params(), **change)
    assert not is_c64b_profile(p)
    with pytest.raises(InvalidParameterError, match="unsupported research"):
        make_research_runtime(ibs_params=p, ibs_rng=NoEntropy(), ots_rng=NoEntropy())


@pytest.mark.parametrize("bad", [None, True, {}, "c64b", b"c64b"])
def test_profile_identity_is_not_duck_typed(bad):
    assert not is_c64b_profile(bad)


@pytest.mark.parametrize("selected,other", [(c64b_params(), RESEARCH_IBS_PARAMS),
                                            (RESEARCH_IBS_PARAMS, c64b_params())])
def test_setup_mismatch_rejected_before_either_primitive_uses_entropy(selected, other):
    protocol, _ = make_research_runtime(ibs_params=selected, ibs_rng=NoEntropy(), ots_rng=NoEntropy())
    with pytest.raises(InvalidParameterError, match="setup differs"):
        protocol.setup(RESEARCH_HIBE_PARAMS, ibs_params=other, rng=NoEntropy())


@pytest.fixture(scope="module", params=["reference", "compact"])
def integrated(request):
    fmt = request.param
    label = fmt.encode()
    protocol, readers = make_research_runtime(ibs_params=c64b_params(), signature_format=fmt,
        ibs_rng=rng(label+b"/ibs"), ots_rng=rng(label+b"/ots"))
    public, master = protocol.setup(RESEARCH_HIBE_PARAMS, rng=rng(label+b"/setup"))
    sender = protocol.skgen(master, b"Alice")
    receiver = protocol.rkgen(master, b"Bob", rng=rng(label+b"/receiver"))
    ct = protocol.encrypt(public, sender, b"Bob", b"c64b-payload", rng=rng(label+b"/encrypt"))
    return fmt, protocol, readers, public, master, sender, receiver, ct


def test_opt_in_full_roundtrip_public_restore_and_cached_key(integrated):
    fmt, protocol, readers, public, master, sender, receiver, ct = integrated
    restored_public = PublicKey.from_bytes(public.to_bytes(), readers["hpk"], readers["ipk"])
    restored_master = MasterSecret.from_bytes(master.to_bytes(), readers["hmsk"], readers["imsk"])
    restored_sender = SenderKey.from_bytes(sender.to_bytes(), readers["sk"])
    restored_receiver = ReceiverKey.from_bytes(receiver.to_bytes(), readers["sk1"])
    assert restored_public.to_bytes() == public.to_bytes()
    assert restored_master.to_bytes() == master.to_bytes()
    cached = LuoModuleIBSBackend(rng=NoEntropy()).key_extract(restored_master.imsk, b"Alice")
    assert cached.to_bytes() == restored_sender.signing_key.to_bytes()
    assert protocol.decrypt(restored_public, restored_receiver, b"Alice", ct,
                            rng=rng(fmt.encode()+b"/decrypt")) == b"c64b-payload"


@pytest.mark.parametrize("kind", ["ipk", "imsk", "sk"])
def test_old_fixed_profile_explicitly_rejects_c64b_state(integrated, kind):
    _, _, _, public, master, sender, _, _ = integrated
    _, legacy = make_research_runtime(ibs_rng=NoEntropy(), ots_rng=NoEntropy())
    obj = {"ipk": public.ipk, "imsk": master.imsk, "sk": sender.signing_key}[kind]
    with pytest.raises(SerializationError, match="different Luo"):
        legacy[kind].from_bytes(obj.to_bytes())


def test_identity_and_tampering_rejections(integrated):
    fmt, protocol, _, public, master, _, receiver, ct = integrated
    other = protocol.rkgen(master, b"Other", rng=rng(fmt.encode()+b"/other"))
    for key, name in [(receiver, b"Wrong"), (other, b"Alice"), (other, b"Wrong")]:
        assert protocol.decrypt(public, key, name, ct, rng=rng(b"mismatch")) is BOTTOM
    damaged = replace(ct, signature=bytes([ct.signature[0] ^ 1]) + ct.signature[1:])
    assert protocol.decrypt(public, receiver, b"Alice", damaged, rng=NoEntropy()) is BOTTOM


def test_selected_signature_format_and_actual_payload_size(integrated):
    fmt, protocol, _, public, _, _, receiver, ct = integrated
    from ibme.protocol.baseline import BaselineIBME, parse_payload
    baseline = BaselineIBME(protocol.hibe_backend, protocol.ibs_backend)
    inner = baseline.load_ciphertext(ct.inner_bytes)
    child = protocol.hibe_backend.derive(receiver.level1_key, b"Alice", rng=rng(b"size-child"))
    payload = protocol.hibe_backend.decrypt(child, inner.hibe_ct, rng=rng(b"size-decrypt"))
    signature, _ = parse_payload(payload)
    expected = 16383 if fmt == "compact" else 29455
    assert len(signature) == expected
    assert len(payload) == expected + 108 + len(b"c64b-payload")
    # At the unchanged max application length, 20415 is a formula, not a CHKP run.
    if fmt == "compact":
        assert expected + 108 + 3924 == 20415
