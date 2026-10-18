"""P1 tests for the Lai ideal-lattice IBE / two-level HIBE research backend.

Run with the prescribed WSL Sage environment::

    PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest \
        tests/test_lai_p1.py -q

The module-level importorskip keeps the default Windows suite green.
"""
from dataclasses import replace

import pytest

pytest.importorskip("sage.all")

from sage.all import GF, PolynomialRing

from ibme.core.randomness import DeterministicRandom
from experiments.research.candidates.lai.backend import (
    Ciphertext,
    DecryptError,
    LaiScheme,
    ParameterError,
    Params,
    SerializationError,
    TEACHING_PARAMS,
    A_POINT_PARAMS,
)


def rng(tag: bytes) -> DeterministicRandom:
    return DeterministicRandom(tag)


@pytest.fixture(scope="module")
def scheme():
    return LaiScheme(TEACHING_PARAMS)


@pytest.fixture(scope="module")
def material(scheme):
    pp, mk = scheme.setup(rng(b"p1-setup"))
    sk1 = scheme.extract(pp, mk, b"alice", rng(b"p1-extract-alice"))
    sk2 = scheme.derive(pp, sk1, b"bob", rng(b"p1-derive-bob"))
    return pp, mk, sk1, sk2


def test_parameters_reject_bad_shapes():
    with pytest.raises(ParameterError):
        Params(q=1009, n=3, k=10, l=2)
    with pytest.raises(ParameterError):
        Params(q=1009, n=4, k=9, l=2)  # k != ceil(log2 q)
    with pytest.raises(ParameterError):
        Params(q=1048609, n=8, k=21, l=2, p=3)


def test_setup_trapgen_relation(scheme, material):
    pp, mk, _, _ = material
    ring = scheme.ring
    a0 = pp.a[: scheme.params.l]
    a1 = pp.a[scheme.params.l:]
    for j in range(scheme.params.k):
        left = sum((a0[i] * mk.trapdoor[i][j]
                    for i in range(scheme.params.l)), ring.zero)
        assert left + a1[j] == ring.g[j]


def test_level1_roundtrip_and_serialization(scheme, material):
    pp, _, sk1, _ = material
    message = b"hello P1"
    ct = scheme.encrypt(pp, [b"alice"], message, rng(b"p1-enc1"))
    assert scheme.decrypt(pp, sk1, ct) == message
    blob = scheme.encode_ciphertext(ct)
    assert scheme.decrypt(pp, sk1, scheme.decode_ciphertext(blob)) == message


def test_level2_roundtrip_and_serialization(scheme, material):
    pp, _, _, sk2 = material
    message = b"world!"
    ct = scheme.encrypt(pp, [b"alice", b"bob"], message, rng(b"p1-enc2"))
    assert scheme.decrypt(pp, sk2, ct) == message
    blob = scheme.encode_ciphertext(ct)
    assert scheme.decrypt(pp, sk2, scheme.decode_ciphertext(blob)) == message


def test_level2_trapdoor_relation(scheme, material):
    pp, _, sk1, sk2 = material
    ring = scheme.ring
    assert list(sk2.base) == list(sk1.base) + list(sk1.a_id)
    for j in range(scheme.params.k):
        left = sum((sk2.base[i] * sk2.trapdoor[i][j]
                    for i in range(len(sk2.base))), ring.zero)
        assert left + sk2.a_id[j] == sk2.tag * ring.g[j]


def test_wrong_identity_rejected(scheme, material):
    pp, mk, _, _ = material
    ct = scheme.encrypt(pp, [b"alice"], b"secret", rng(b"p1-enc3"))
    wrong = scheme.extract(pp, mk, b"carol", rng(b"p1-extract-carol"))
    with pytest.raises(DecryptError):
        scheme.decrypt(pp, wrong, ct)


def test_wrong_child_rejected(scheme, material):
    pp, _, sk1, _ = material
    ct = scheme.encrypt(pp, [b"alice", b"bob"], b"child", rng(b"p1-enc4"))
    wrong = scheme.derive(pp, sk1, b"eve", rng(b"p1-derive-eve"))
    with pytest.raises(DecryptError):
        scheme.decrypt(pp, wrong, ct)


def test_bad_hprime_rejected(scheme, material):
    pp, _, sk1, _ = material
    ct = scheme.encrypt(pp, [b"alice"], b"tag", rng(b"p1-enc5"))
    tampered = replace(ct, hprime=ct.hprime + scheme.ring.one)
    with pytest.raises(DecryptError):
        scheme.decrypt(pp, sk1, tampered)


def test_nonunit_tag_rejected(scheme, material):
    pp, _, sk1, _ = material
    ct = scheme.encrypt(pp, [b"alice"], b"nonunit", rng(b"p1-enc6"))
    ring = scheme.ring
    q, n = scheme.params.q, scheme.params.n
    polynomial = PolynomialRing(GF(q), "x")
    roots = (polynomial.gen() ** n + 1).roots(multiplicities=False)
    assert roots
    root = int(roots[0])
    # x - root is a non-zero zero divisor: (x - root) * (x^n+1)/(x-root) = 0.
    candidate = ring.elem([(-root) % q, 1] + [0] * (n - 2))
    assert not candidate.is_unit()
    tampered = replace(ct, hprime=candidate - sk1.tag)
    with pytest.raises(DecryptError):
        scheme.decrypt(pp, sk1, tampered)


@pytest.mark.parametrize("field", ["u0", "v0"])
def test_tampered_ciphertext_rejected(scheme, material, field):
    pp, _, sk1, _ = material
    ct = scheme.encrypt(pp, [b"alice"], b"tamper", rng(b"p1-enc7"))
    if field == "u0":
        tampered = replace(ct, u=(ct.u[0] + scheme.ring.one,) + ct.u[1:])
    else:
        tampered = replace(ct, v=(ct.v[0] + scheme.ring.one,) + ct.v[1:])
    with pytest.raises(DecryptError):
        scheme.decrypt(pp, sk1, tampered)


def test_truncated_and_appended_ciphertext_rejected(scheme, material):
    pp, _, sk1, _ = material
    ct = scheme.encrypt(pp, [b"alice"], b"wire", rng(b"p1-enc8"))
    blob = scheme.encode_ciphertext(ct)
    with pytest.raises(SerializationError):
        scheme.decode_ciphertext(blob[:-1])
    with pytest.raises(SerializationError):
        scheme.decode_ciphertext(blob + b"\x00")
    with pytest.raises(SerializationError):
        scheme.decode_ciphertext(b"XXXX" + blob[4:])


def test_wrong_level_and_dimensions_rejected(scheme, material):
    pp, _, sk1, _ = material
    ct = scheme.encrypt(pp, [b"alice"], b"level", rng(b"p1-enc9"))
    with pytest.raises(SerializationError):
        scheme.decode_ciphertext(scheme.encode_ciphertext(
            Ciphertext(3, ct.hprime, ct.u, ct.v)))
    with pytest.raises(DecryptError):
        scheme.decrypt(pp, sk1, replace(ct, level=2))


def test_message_encoding_roundtrip(scheme):
    for message in (b"", b"a", b"hello", bytes(range(16))):
        encoded = scheme.encode_message(message)
        assert scheme.decode_message(encoded) == message
    with pytest.raises(ParameterError):
        scheme.encode_message(bytes(32))


@pytest.mark.parametrize("seed", [b"r1", b"r2", b"r3"])
def test_repeated_lifecycle(scheme, seed):
    pp, mk = scheme.setup(rng(b"setup-" + seed))
    sk1 = scheme.extract(pp, mk, b"alice-" + seed, rng(b"ext-" + seed))
    ct1 = scheme.encrypt(pp, [b"alice-" + seed], b"one", rng(b"e1-" + seed))
    assert scheme.decrypt(pp, sk1, ct1) == b"one"
    sk2 = scheme.derive(pp, sk1, b"bob-" + seed, rng(b"der-" + seed))
    ct2 = scheme.encrypt(pp, [b"alice-" + seed, b"bob-" + seed],
                         b"two", rng(b"e2-" + seed))
    assert scheme.decrypt(pp, sk2, ct2) == b"two"


def test_maximum_message_roundtrip(scheme, material):
    pp, _, sk1, _ = material
    message = bytes(range(16))
    ct = scheme.encrypt(pp, [b"alice"], message, rng(b"p1-enc-max"))
    assert scheme.decrypt(pp, sk1, ct) == message


def test_message_padding_rejected(scheme):
    encoded = scheme.encode_message(b"a")
    ring = scheme.ring
    encoded[-1] = encoded[-1] + ring.one
    with pytest.raises(DecryptError):
        scheme.decode_message(encoded)


def test_coefficient_out_of_range_rejected(scheme, material):
    pp, _, _, _ = material
    ct = scheme.encrypt(pp, [b"alice"], b"range", rng(b"p1-enc-range"))
    blob = bytearray(scheme.encode_ciphertext(ct))
    # h' starts at offset 9 (8-byte header + 1-byte level); set its first
    # coefficient to q, which is out of range.
    q = scheme.params.q
    blob[9:12] = q.to_bytes(3, "big")
    with pytest.raises(SerializationError):
        scheme.decode_ciphertext(bytes(blob))


def test_a_point_capacity_and_identity():
    params = A_POINT_PARAMS
    assert params.n == 256 and params.k == 32
    scheme = LaiScheme(params)
    # 32 B seed fits: k*n = 8192 bit, message encoding needs 8 + 256 bit.
    encoded = scheme.encode_message(bytes(range(32)))
    assert scheme.decode_message(encoded) == bytes(range(32))
    left = scheme._identity(1, b"alice")
    right = scheme._identity(1, b"bob")
    assert left != right
    assert all(c in (0, 1) for c in scheme.ring.coeffs(left))
    assert len(set(scheme.ring.coeffs(left))) <= 2


def test_a_point_two_level_lifecycle_and_serialization():
    scheme = LaiScheme(A_POINT_PARAMS)
    message = bytes(range(32))
    pp, mk = scheme.setup(rng(b"a-point-setup"))
    sk1 = scheme.extract(pp, mk, b"alice", rng(b"a-point-extract"))
    sk2 = scheme.derive(pp, sk1, b"bob", rng(b"a-point-derive"))
    ct1 = scheme.encrypt(pp, [b"alice"], message, rng(b"a-point-enc1"))
    assert scheme.decrypt(pp, sk1, ct1) == message
    ct2 = scheme.encrypt(pp, [b"alice", b"bob"], message, rng(b"a-point-enc2"))
    assert scheme.decrypt(pp, sk2, ct2) == message
    blob = scheme.encode_ciphertext(ct2)
    assert scheme.decrypt(pp, sk2, scheme.decode_ciphertext(blob)) == message
    assert len(blob) > 4 * scheme.params.n
