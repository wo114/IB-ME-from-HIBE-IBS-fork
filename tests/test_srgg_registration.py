"""SRGG's HIBE-independent public registration contract."""

from dataclasses import replace

import pytest

from ibme.assembly.registry import BackendRegistry
from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.ibs.srgg.registration import (
    BACKEND_ID,
    VERSION,
    backend_spec,
    check_object,
    factory,
    signature_size,
    validate_configuration,
)
from ibme.ibs.srgg import Config, PublicKey


class NoEntropy:
    def read(self, size):
        raise AssertionError("registration/factory must not consume entropy")


def public_key(params):
    p = params.algebra
    zero = (0,) * p.degree
    return PublicKey(params, b"R" * 32, ((zero,) * (p.rank * p.digits),))


def test_descriptor_is_explicit_and_registry_safe():
    spec = backend_spec()
    assert spec.id == BACKEND_ID and spec.version == VERSION
    assert spec.role == "ibs" and spec.available
    assert spec.key_binding and spec.persistent_identity_cache
    assert spec.object_parameter_binding == "full-parameter-snapshot"
    assert spec.signature_formats == ("reference", "canonical-json-v1")
    assert BackendRegistry([spec]).get("ibs", BACKEND_ID) is spec


def test_factory_and_size_are_static():
    params = Config()
    backend = factory(NoEntropy(), "reference")
    assert all(callable(getattr(backend, name, None)) for name in
               ("setup", "key_extract", "sign", "verify", "load_signature"))
    assert signature_size(params, "reference") == 579
    assert signature_size(params, "canonical-json-v1") == 579
    with pytest.raises(InvalidParameterError):
        factory(NoEntropy(), "compact")
    with pytest.raises(InvalidParameterError):
        signature_size(params, "compact")


def test_object_snapshot_binding_and_preflight_do_not_sample():
    params = Config()
    pk = public_key(params)
    check_object(pk, params)
    validate_configuration(params, {"transport": "direct"})
    with pytest.raises(SerializationError, match="snapshot"):
        check_object(pk, replace(params, message_max_bytes=4095))
    with pytest.raises(SerializationError, match="registered"):
        check_object(object(), params)

