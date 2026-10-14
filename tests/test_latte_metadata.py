"""Portable public-only LATTE parameter/codec checks, not cryptographic runs."""
import json
import pytest
from ibme.hibe.latte import LATTEParams,LATTEPublicKey,LATTECiphertext,backend_spec
from ibme.hibe.latte.codec import canonical
from ibme.hibe.latte.params import Q,N
from ibme.core.errors import SerializationError,InvalidParameterError


@pytest.mark.parametrize("change",[{"q":17},{"n":1},{"backend_admitted":0},
    {"source_revision":"unfixed"},{"unknown":1},{"message_mode":"auto"}])
def test_full_public_parameter_snapshot_cannot_be_changed(change):
    p=LATTEParams(); record=LATTEPublicKey(p,(0,)*N).record()
    record["params"].update(change)
    with pytest.raises(SerializationError): LATTEPublicKey.from_bytes(canonical(record))


def test_public_only_wire_is_canonical_without_instantiating_samplers():
    p=LATTEParams(); obj=LATTECiphertext(p,bytes(32),bytes(32),((Q-1,)*N,)*3)
    assert LATTECiphertext.from_bytes(obj.to_bytes()).to_bytes()==obj.to_bytes()
    assert p.record()["security_claim"]=="none"
    assert p.record()["parameters_are_formal"] is False


@pytest.mark.parametrize("raw",[b"{} ",b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":1.0}'])
def test_malformed_records_rejected(raw):
    with pytest.raises(SerializationError): LATTECiphertext.from_bytes(raw)


def test_capacity_and_transport_requirements_precede_any_execution():
    spec=backend_spec(); p=LATTEParams()
    for size in (0,31,33,True):
        with pytest.raises(InvalidParameterError): spec.ciphertext_size(p,size,86)
    spec.validate_configuration(p,{"transport":"hybrid"})
    with pytest.raises(InvalidParameterError): spec.validate_configuration(p,{"transport":"direct"})
    assert spec.ciphertext_size(LATTEParams(message_mode="framed32"),0,86)>24576
