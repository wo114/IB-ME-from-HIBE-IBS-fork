"""Portable, explicit v2 recipe selection; v1 bytes and defaults stay fixed."""

from dataclasses import asdict, replace
from hashlib import sha256
import json

import pytest

from ibme.assembly import BackendRegistry, default_registry, make_suite, validate_suite
from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.hibe.mp12_structured.params import (
    StructuredHIBEParams, StructuredHIBEParams192, FINITE192_VERSION,
    load_structured_parameters,
)
from ibme.hibe.mp12_structured.registration import finite192_backend_spec


def test_v1_parameter_wire_is_byte_identical_and_has_no_added_fields():
    p = StructuredHIBEParams()
    assert sha256(p.to_bytes()).hexdigest() == "d567a43d2799de8086ab501e8d03306eff2b3153e9f587fab227bb964d6f870a"
    assert len(asdict(p)) == len(asdict(StructuredHIBEParams192())) == 7
    assert p.record()["finite_sampler"].endswith("epsilon128/trials512")


def test_v2_has_one_complete_explicit_width_noise_and_finite_recipe():
    p = StructuredHIBEParams192()
    assert p.version == FINITE192_VERSION
    assert p.q == 2**40-87 and p.noise_budget()["conditional_noise_sufficient"]
    assert (p.m, p.parent_sample_dimension, p.leaf_dimension) == (84, 88, 252)
    assert p.parent_width_squared > StructuredHIBEParams().parent_width_squared
    assert p.leaf_width_squared > StructuredHIBEParams().leaf_width_squared
    recipe = p.record()["finite_recipe"]
    assert recipe["epsilon_bits"] == 192 and recipe["decode_error_bits"] == 160
    assert recipe["scalar_uniform_trials"] == 256
    assert recipe["oracle_uniform_trials"] == recipe["ciphertext_uniform_trials"] == 128
    assert recipe["noise_mass_bits"] == recipe["scalar_mass_bits"] == 320
    assert (p.security_claim, p.backend_admitted, p.parameters_are_formal) == ("none", False, False)


@pytest.mark.parametrize("params_type", [StructuredHIBEParams, StructuredHIBEParams192])
def test_individual_parameter_readers_reject_cross_version(params_type):
    p = params_type()
    assert type(load_structured_parameters(p.to_bytes())) is params_type
    assert params_type.from_bytes(p.to_bytes()) == p
    other_type = StructuredHIBEParams192 if params_type is StructuredHIBEParams else StructuredHIBEParams
    with pytest.raises(SerializationError): other_type.from_bytes(p.to_bytes())


@pytest.mark.parametrize("mutate", [
    lambda raw: raw+b" ", lambda raw: raw[:-1],
    lambda raw: raw.replace(b'"epsilon_bits":192', b'"epsilon_bits":128'),
    lambda raw: raw.replace(b'"oracle_uniform_trials":128', b'"oracle_uniform_trials":192'),
    lambda raw: raw.replace(b'"noise_mass_bits":320', b'"noise_mass_bits":256'),
    lambda raw: raw.replace(b'"q":1099511627689', b'"q":1099511627689.0'),
    lambda raw: raw.replace(b'"n":2', b'"n":2,"n":2'),
    lambda raw: raw.replace(b'"backend_admitted":false', b'"backend_admitted":true'),
])
def test_v2_recipe_cannot_be_mutated_downgraded_or_reencoded(mutate):
    with pytest.raises(SerializationError):
        load_structured_parameters(mutate(StructuredHIBEParams192().to_bytes()))


def test_default_registry_and_existing_suite_snapshots_stay_v1():
    registry = default_registry()
    spec = registry.get("hibe", "mp12-structured-hg")
    assert spec.params_type is StructuredHIBEParams
    config = make_suite(hibe="mp12-structured-hg", ibs="sis", transport="hybrid")
    assert config.to_dict()["hibe_params"] == asdict(StructuredHIBEParams())
    assert config.to_dict()["hibe_version"] != FINITE192_VERSION


def test_v2_registration_is_explicit_and_default_registry_cannot_downgrade_it():
    spec = finite192_backend_spec()
    registry = BackendRegistry((spec, default_registry().get("ibs", "sis")))
    config = make_suite(hibe=spec.id, ibs="sis", transport="hybrid", registry=registry)
    assert config.to_dict()["hibe_version"] == FINITE192_VERSION
    assert config.to_dict()["hibe_params"] == asdict(StructuredHIBEParams192())
    report = validate_suite(config)
    assert not report.ok and any("version mismatch" in value for value in report.errors)
    assert type(spec.parse_params(config.to_dict()["hibe_params"])) is StructuredHIBEParams192


def test_omitting_the_v2_recipe_is_not_an_implicit_default():
    p = StructuredHIBEParams192()
    data = p.record()
    del data["finite_recipe"]
    raw = p.parameter_magic+json.dumps(data, sort_keys=True, separators=(",", ":")).encode("ascii")
    with pytest.raises(SerializationError): StructuredHIBEParams192.from_bytes(raw)


@pytest.mark.parametrize("changes", [dict(n=True), dict(q=2**40), dict(q=2**77-1),
    dict(q_alpha=1024), dict(max_receivers=0), dict(n=128, q=65537)])
def test_new_recipe_keeps_existing_dimension_wire_and_correctness_gates(changes):
    with pytest.raises(InvalidParameterError): replace(StructuredHIBEParams192(), **changes)
