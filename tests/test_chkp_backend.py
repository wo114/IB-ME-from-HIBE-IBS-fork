"""Public CHKP profile/route tests; these do not execute trapdoor generation."""

from dataclasses import asdict, replace
import json

import pytest

from ibme.core.errors import EncodingError, InvalidParameterError, SerializationError
from ibme.hibe.chkp import (CHKPParams, CHKPHIBE, CHKPPublicKey,
                           ciphertext_size, research_params)
from ibme.hibe.chkp.params import PARAM_MAGIC
from ibme.lattice.chkp.identity import ROHIBEContext


def _public(params=None):
    """Public algebra fixture only, never a generated secure root."""
    p = research_params() if params is None else params
    rows = tuple(tuple(int(i == j) for j in range(p.m)) for i in range(p.n))
    return CHKPPublicKey(p, ROHIBEContext(p.n, p.m, p.q, rows,
                                        p.to_bytes(), identity_bytes=p.identity_bytes))


def test_frozen_profile_matches_independent_parameter_checker():
    from experiments.research.chkp_parameter_profile import selected_profile, check_profile
    expected = selected_profile()
    p = research_params()
    check_profile(expected)
    for name in ("n", "q", "m_bar", "r_width_squared", "root_gs_squared_bound",
                 "parent_width_squared", "leaf_width_squared", "alpha_numerator",
                 "alpha_denominator", "epsilon_bits", "regularity_bits",
                 "parent_max_vectors", "max_dimension", "root_entropy_budget",
                 "parent_entropy_budget", "leaf_entropy_budget"):
        assert getattr(p, name) == expected[name]
    for name, value in expected["finite_options"].items():
        assert getattr(p, name) == value
    assert p.m == 127 and p.leaf_dimension == 381
    assert p.security_claim == "none" and not p.backend_admitted and not p.parameters_are_formal
    assert CHKPParams.from_bytes(p.to_bytes()) == p
    assert len(p.to_bytes()) <= 4096


@pytest.mark.parametrize("change", [
    {"n": True}, {"n": 2.0}, {"q": 15}, {"q": 2**62},
    {"message_mode": "auto"}, {"lll_policy": "fallback"}, {"identity_bytes": 0},
    {"epsilon_bits": 129}, {"max_dimension": 513}, {"max_dimension": 380},
    {"parent_max_vectors": 253}, {"alpha_numerator": 8, "alpha_denominator": 2*1099511627791},
    {"parent_width_squared": 1}, {"leaf_width_squared": 1},
    {"noise_precision_bits": 128, "noise_mass_bits": 128},
    {"parent_entropy_budget": 2**41}, {"max_tape_bytes": 1},
])
def test_invalid_parameter_profiles_fail_without_sampler_import(change):
    with pytest.raises(InvalidParameterError):
        replace(research_params(), **change)


@pytest.mark.parametrize("mutation", ["missing", "unknown", "duplicate", "spaces", "append", "nonascii"])
def test_parameter_wire_is_complete_canonical_and_strict(mutation):
    p = research_params()
    values = asdict(p)
    if mutation == "missing":
        del values["epsilon_bits"]
    elif mutation == "unknown":
        values["auto_admit"] = True
    raw = PARAM_MAGIC + json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
    if mutation == "duplicate":
        raw = raw[:-1] + b',"n":2}'
    elif mutation == "spaces":
        raw += b" "
    elif mutation == "append":
        raw += b"\0"
    elif mutation == "nonascii":
        raw += b"\xff"
    with pytest.raises(SerializationError):
        CHKPParams.from_bytes(raw)


def test_routes_are_explicit_context_bound_and_exact_size():
    seed = research_params()
    framed = replace(seed, message_mode="framed32")
    assert seed.max_message_bytes == 32 and framed.max_message_bytes == 28
    assert _public(seed).context != _public(framed).context
    assert ciphertext_size(seed, 32, 86) == 3919
    assert ciphertext_size(framed, 0, 86) == ciphertext_size(framed, 28, 86) == 3919
    with pytest.raises(InvalidParameterError):
        ciphertext_size(seed, 31, 86)


@pytest.mark.parametrize("mode,length", [("seed32", 0), ("seed32", 31), ("seed32", 33), ("framed32", 29)])
def test_invalid_payload_length_does_not_consume_entropy(mode, length):
    class NoEntropy:
        def read(self, count):
            pytest.fail("invalid message consumed entropy")
    public = _public(replace(research_params(), message_mode=mode))
    with pytest.raises(InvalidParameterError):
        CHKPHIBE().encrypt(public, b"receiver", b"sender", bytes(length), rng=NoEntropy())


@pytest.mark.parametrize("parent,child", [(b"", b"sender"), (b"receiver", b""), (b"a"*87, b"b"), (b"a", b"b"*87)])
def test_identity_validation_precedes_sampling(parent, child):
    with pytest.raises(EncodingError):
        CHKPHIBE().encrypt(_public(), parent, child, bytes(32), rng=object())


def test_public_binding_does_not_accept_arbitrary_objects():
    backend = CHKPHIBE()
    assert backend.validate_key_binding(_public(), object()) is False
    with pytest.raises(TypeError):
        backend.extract(object(), b"receiver")
    with pytest.raises(TypeError):
        backend.derive(object(), b"sender")
    with pytest.raises(TypeError):
        backend.decrypt(object(), object())
