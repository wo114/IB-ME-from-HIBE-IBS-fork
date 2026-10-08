"""Exact framed-input equivalence; no quantum/randomness/security claim."""

from itertools import product
import pytest

from ibme.core.hashing import ALL_DOMAINS, PreparedShake256, shake256
from ibme.core.errors import InvalidParameterError


@pytest.mark.parametrize("domain", ALL_DOMAINS)
def test_prepared_matches_frozen_hash_input(domain):
    for prefix, suffix in product([b"", b"a", bytes(range(256))*8], repeat=2):
        p=PreparedShake256(domain,prefix)
        for length in [1,32,137]:
            assert p.digest(suffix,length)==shake256(domain,prefix+suffix,length)


def test_copies_do_not_accumulate_suffixes_or_squeezing():
    p=PreparedShake256(b"d",b"prefix")
    a=p.digest(b"a",32)
    assert a==p.digest(b"a",32)==p.digest(b"a",64)[:32]
    assert p.digest(b"b",32)==shake256(b"d",b"prefixb",32)
    assert p.digest(b"",32)==shake256(b"d",b"prefix",32)


def test_mutable_prefix_and_domain_are_snapshotted():
    domain,prefix=bytearray(b"d"),bytearray(b"private prefix")
    p=PreparedShake256(domain,prefix)
    domain[:]=b"e";prefix[:]=b"other prefix"
    assert p.digest(b"suffix",32)==shake256(b"d",b"private prefixsuffix",32)
    assert "private" not in repr(p)


@pytest.mark.parametrize("domain,prefix",[(b"",b"x"),("d",b"x"),(b"d","x"),(None,b"")])
def test_invalid_prefix_types(domain,prefix):
    with pytest.raises(InvalidParameterError):PreparedShake256(domain,prefix)


@pytest.mark.parametrize("length",[0,-1,True,1.0])
def test_invalid_output_lengths(length):
    with pytest.raises(InvalidParameterError):PreparedShake256(b"d",b"").digest(b"",length)


def test_invalid_suffix():
    with pytest.raises(InvalidParameterError):PreparedShake256(b"d",b"").digest("text",32)
