"""Portable same-group complete structured H/G budget checks."""

from dataclasses import replace
import json
import pytest
from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.hibe.mp12_structured.params import StructuredHIBEParams, MAGIC


def test_same_group_complete_width_noise_chain():
    p = StructuredHIBEParams()
    assert (p.w, p.m, p.parent_sample_dimension, p.leaf_dimension) == (80, 84, 88, 252)
    assert p.root_bound == 5120 and p.parent_bound == 199147520000
    assert p.parent_width_squared == 28288000
    assert p.leaf_width_squared == 1083362509235200
    assert p.noise_budget()["conditional_noise_sufficient"] is True
    assert p.noise_budget()["preimage_norm_measured_or_certified"] is False
    assert StructuredHIBEParams.from_bytes(p.to_bytes()) == p
    assert (p.security_claim, p.backend_admitted, p.parameters_are_formal) == ("none", False, False)


@pytest.mark.parametrize("changes", [dict(n=True), dict(q=2**39), dict(root_r_squared=1),
    dict(q_alpha=1024), dict(identity_bytes=87), dict(max_receivers=0), dict(max_children=9),
    dict(n=128, q=65537, root_r_squared=529), dict(q=257)])
def test_full_chain_rejects_invalid_and_resource_or_noise_blocked_inputs(changes):
    with pytest.raises(InvalidParameterError): replace(StructuredHIBEParams(), **changes)


@pytest.mark.parametrize("mutate", [lambda raw: raw+b" ", lambda raw: raw[:-1],
    lambda raw: raw.replace(b'"n":2', b'"n":2.0'),
    lambda raw: raw.replace(b'"n":2', b'"n":2,"n":2'),
    lambda raw: raw.replace(b'"backend_admitted":false', b'"backend_admitted":true'),
    lambda raw: raw.replace(b'"parent_width_squared":"28288000"', b'"parent_width_squared":"1"')])
def test_complete_parameter_snapshot_cannot_be_relaxed_or_reencoded(mutate):
    with pytest.raises(SerializationError): StructuredHIBEParams.from_bytes(mutate(StructuredHIBEParams().to_bytes()))


def test_deep_json_is_a_bounded_serialization_failure():
    with pytest.raises(SerializationError):
        StructuredHIBEParams.from_bytes(MAGIC+b"["*1100+b"0"+b"]"*1100)
