"""Actual v3 adapter, exact recovery checks and a bounded full composition."""
from dataclasses import replace
import os

import numpy as np
import pytest

pytest.importorskip("sage.all", reason="prescribed WSL Sage environment required")

from ibme.core.errors import SerializationError
from ibme.core.hashing import hash_identity
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.sageloli import ring_registration as reg
from experiments.research.candidates.sageloli.ring import objects
from experiments.research.candidates.sageloli.ring.native import build


@pytest.fixture(scope="module")
def issued(tmp_path_factory):
    native = build(tmp_path_factory.mktemp("ring-public-native"))
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("IBME_SAGELOLI_RING_NATIVE", str(native))
        backend = reg.factory(DeterministicRandom(b"public adapter test only"), "reference")
        p = reg.backend_spec().presets["debug-small"]
        pk, master = backend.setup(p)
        key = backend.key_extract(master, b"Alice")
        yield p, pk, master, key, backend


@pytest.mark.parametrize("name", ["PARAM-I", "PARAM-II"])
def test_frozen_presets_match_original_outward_rounded_formula(name):
    from experiments.research.candidates.sageloli.ring.params import published
    assert reg.paper_params(name) == published(name.removeprefix("PARAM-"))


def test_public_key_identity_digest_and_unchanged_wire(issued):
    p, pk, master, key, backend = issued
    assert key.identity_digest == hash_identity(b"Alice", 32)
    assert backend.key_extract(master, b"Alice").to_bytes() == key.to_bytes()
    signature = backend.sign(key, b"public adapter")
    assert backend.verify(pk, b"Alice", b"public adapter", signature)
    assert len(signature.to_bytes()) == reg.signature_size(p, "reference")
    restored = backend.load_signature(pk, signature.to_bytes())
    assert backend.verify(pk, b"Alice", b"public adapter", restored)
    for raw in (b"", signature.to_bytes()[:-1], signature.to_bytes()+b"extra"):
        with pytest.raises(SerializationError): backend.load_signature(pk, raw)
    assert backend.security_claim == "none" and backend.backend_admitted is False


def test_private_decoders_validate_exact_equations_without_entropy(issued):
    p, pk, master, key, backend = issued
    spec = reg.backend_spec()
    for name, value in (("ipk", pk), ("imsk", master), ("sk", key)):
        raw = value.to_bytes()
        restored = spec.decoders[name].from_bytes(raw)
        assert restored.to_bytes() == raw
        spec.check_object(restored, p)
        with pytest.raises(SerializationError):
            spec.check_object(restored, replace(p, message_max_bytes=p.message_max_bytes+1))
        for malformed in (raw[:-1], raw+b"!", b"IBME:SAGELOLI-IBS:v2"+raw):
            with pytest.raises(SerializationError): spec.decoders[name].from_bytes(malformed)
    native_key = objects.SigningKey.from_bytes(key.to_bytes())
    corrupt = native_key.trapdoor.copy(); corrupt[0, 0, 0] += 1
    wrong = objects.SigningKey(pk, key.identity, native_key.identity_salt, corrupt)
    with pytest.raises(SerializationError): spec.decoders["sk"].from_bytes(wrong.to_bytes())
    root = master.root.copy()
    root[0, 0, 0] = 0 if root[0, 0, 0] else 4
    wrong_master = objects.MasterSecret(pk, root)
    with pytest.raises(SerializationError): spec.decoders["imsk"].from_bytes(wrong_master.to_bytes())
    assert len(master.to_bytes()) <= reg.state_size_bounds(p)["master_with_full_ledger"]


def test_debug_small_full_real_latte_combination(issued):
    from experiments.run_combination_matrix import run_case
    result = run_case("latte-sageloli-ring-v3-debug", dict(
        hibe="latte", hibe_params="seed32", ibs="sageloli-rsis", ibs_params="debug-small",
        transport="hybrid", protocol="byteauth-v1"))
    assert result["status"] == "pass", result
    assert result["executed_checks"] >= 32
