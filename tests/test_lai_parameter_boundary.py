"""Portable rejection at the Lai wire boundary, before arithmetic or entropy."""
from dataclasses import replace

import pytest

from ibme.core.errors import InvalidParameterError
from ibme.hibe.lai import codec
from ibme.hibe.lai import params as module


@pytest.mark.parametrize('q', [True, 3.0, -1, 1 << 40, (1 << 64)-59])
def test_unrepresentable_modulus_rejected_before_primality(monkeypatch, q):
    def forbidden(_value):
        pytest.fail('out-of-domain q reached trial-division primality')
    monkeypatch.setattr(module, '_is_prime', forbidden)
    with pytest.raises(InvalidParameterError):
        module.LaiParams(q=q)


@pytest.mark.parametrize('field', ['sigma', 'sigma_r'])
@pytest.mark.parametrize('value', [2.0000004, 0.0000001, 4294.967296, True,
                                  pytest.param(10**400, id='huge-integer')])
def test_width_cannot_be_silently_rounded_or_overflow_wire(field, value):
    with pytest.raises(InvalidParameterError):
        replace(module.LaiParams(), **{field: value})


@pytest.mark.parametrize('width', [0.000001, 2.125001, 4294.967295])
def test_admitted_widths_roundtrip_exactly(width):
    params = replace(module.LaiParams(), sigma=width, sigma_r=width)
    raw = codec.params_bytes(params)
    restored, end = codec.read_params(raw)
    assert end == len(raw) and restored == params
    assert codec.params_bytes(restored) == raw


def test_message_capacity_matches_one_byte_wire_length():
    with pytest.raises(InvalidParameterError):
        module.LaiParams(max_message_bytes=256)
