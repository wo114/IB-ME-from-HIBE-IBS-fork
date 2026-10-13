"""Independent regressions for Wang/Pan--Wagner object and outer boundaries.

Uses one module-scoped real setup/extraction at n=1, q=3, m_bar=2.  The
sampler/LLL algorithms are not mocked or assessed here.  H1/H2 use the new
PublicKey-first API; SigningKey must not retain the master trapdoor.
These toy, deterministic implementation checks keep security_claim="none".
They do not prove secrecy, distributions, or the Figure 5 reduction.
"""

from array import array
from dataclasses import dataclass, fields, is_dataclass, replace
from fractions import Fraction

import pytest

from ibme.core import DeterministicRandom, InvalidParameterError, RandomnessError
from ibme.ibs import wang_pw as w


IDENTITY = b"\x00" * 3
MESSAGE = b"\x00" * 4
PK_MAGIC = b"IBM1-WANGPW-PK"
SIG_MAGIC = b"IBM1-WANGPW-SIG"


class _BytesCoercible:
    def __bytes__(self):
        return IDENTITY


class _IntCoercible:
    def __init__(self, value=1):
        self.value = value

    def __int__(self):
        return self.value


class _Entropy:
    """Patch this wrapper's read method without touching a primitive."""

    def __init__(self):
        self.source = DeterministicRandom(b"wang-pw-boundary-regressions-v1")

    def read(self, count):
        return self.source.read(count)


@dataclass(repr=False)
class _Material:
    # Avoid pytest's ordinary fixture repr exposing secret matrix contents.
    params: object
    pk: object
    msk: object
    pw_key: object
    sk: object
    scheme: object
    entropy: object
    first: tuple
    second: tuple
    empty: tuple


@pytest.fixture(scope="module")
def material():
    params = w.WangPWParams(n=1, q=3, m_bar=2, name="wang-pw-boundary-toy")
    entropy = _Entropy()
    scheme = w.WangPWScheme(params, rng=entropy)
    pk, msk = scheme.setup()
    pw_key = scheme.key_extract_pw(IDENTITY)
    sk = pw_key.inner
    first = scheme.sign_pw(IDENTITY, MESSAGE)
    second = scheme.sign_pw(IDENTITY, MESSAGE)
    empty = scheme.sign_pw(IDENTITY, b"")
    return _Material(params, pk, msk, pw_key, sk, scheme, entropy, first, second, empty)


def _unexpected_entropy(_count):
    raise AssertionError("invalid input consumed randomness")


def _replace_first(rows, value):
    return ((value,) + tuple(rows[0][1:]),) + tuple(tuple(r) for r in rows[1:])


def _wire_signature(params, coordinates, width):
    return (
        SIG_MAGIC
        + params.signature_dim.to_bytes(4, "big")
        + width.to_bytes(4, "big")
        + b"".join(x.to_bytes(width, "big", signed=True) for x in coordinates)
    )


def test_honest_outer_lifecycle_and_public_only_verification(material):
    r1, s1, z1 = material.first
    r2, s2, z2 = material.second
    assert r1 == r2
    assert s1 != s2
    assert len(r1) == len(s1) == material.params.salt_bits // 8
    verifier = w.WangPWScheme(material.params)
    verifier.pk = material.pk
    assert verifier.verify_pw(IDENTITY, MESSAGE, r1, s1, z1) is True
    assert verifier.verify_pw(IDENTITY, MESSAGE, r2, s2, z2) is True
    assert verifier.verify_pw(IDENTITY, b"", *material.empty) is True
    assert material.params.security_claim == "none"


def test_cached_extraction_does_not_draw_another_identity_salt(material, monkeypatch):
    # This pins the explicitly chosen fixed-key service, not fresh Figure 5 KeyExt.
    monkeypatch.setattr(material.entropy, "read", _unexpected_entropy)
    same_key = material.scheme.key_extract_pw(IDENTITY) is material.pw_key
    assert same_key


@pytest.mark.parametrize("as_bytes_like", [bytes, bytearray, memoryview])
def test_outer_verifier_accepts_supported_bytes_like(material, as_bytes_like):
    r, s, signature = material.first
    assert material.scheme.verify_pw(
        as_bytes_like(IDENTITY), as_bytes_like(MESSAGE),
        as_bytes_like(r), as_bytes_like(s), signature,
    ) is True


BAD_BYTES = [
    pytest.param(3, id="positive-int"),
    pytest.param(0, id="zero-int"),
    pytest.param(-1, id="negative-int"),
    pytest.param(True, id="bool"),
    pytest.param([0, 0, 0], id="list"),
    pytest.param(None, id="none"),
    pytest.param("alice", id="text"),
    pytest.param(3.0, id="float"),
    pytest.param(_BytesCoercible(), id="bytes-duck-type"),
]


@pytest.mark.parametrize("bad", BAD_BYTES)
@pytest.mark.parametrize("slot", ["identity", "message", "r", "s"])
@pytest.mark.parametrize("api", ["service", "pure"])
def test_outer_verifier_rejects_non_bytes_without_raising(material, slot, bad, api):
    r, s, signature = material.first
    inputs = dict(identity=IDENTITY, message=MESSAGE, r=r, s=s, signature=signature)
    inputs[slot] = bad
    result = (material.scheme.verify_pw(**inputs) if api == "service"
              else w.verify_pw(material.pk, **inputs))
    assert result is False


def test_outer_verifier_does_not_alias_integer_lengths_to_zero_bytes(material):
    r, s, signature = material.first
    assert material.scheme.verify_pw(3, 4, r, s, signature) is False
    assert material.scheme.verify_pw(IDENTITY, 4, r, s, signature) is False
    assert material.scheme.verify_pw(IDENTITY, 0, *material.empty) is False


@pytest.mark.parametrize("bad", BAD_BYTES)
@pytest.mark.parametrize("operation", ["extract", "sign-id", "sign-message"])
@pytest.mark.parametrize("api", ["service", "pure"])
def test_outer_writers_reject_bad_types_before_randomness(
    material, monkeypatch, operation, bad, api,
):
    monkeypatch.setattr(material.entropy, "read", _unexpected_entropy)
    with pytest.raises(InvalidParameterError):
        if api == "pure":
            if operation == "extract":
                w.key_extract_pw(material.msk, bad, rng=material.entropy)
            elif operation == "sign-id":
                # Pure Sign takes a bound key; identity validation is in that key.
                replace(material.pw_key, identity=bad)
            else:
                w.sign_pw(material.pw_key, bad, rng=material.entropy)
        elif operation == "extract":
            material.scheme.key_extract_pw(bad)
        elif operation == "sign-id":
            material.scheme.sign_pw(bad, MESSAGE)
        else:
            material.scheme.sign_pw(IDENTITY, bad)


@pytest.mark.parametrize("operation", ["extract", "sign"])
@pytest.mark.parametrize("fault", ["short", "empty", "long", "integer"])
@pytest.mark.parametrize("api", ["service", "pure"])
def test_outer_salt_draws_fail_closed_on_bad_random_source(
    material, monkeypatch, operation, fault, api,
):
    calls = []

    def bad_read(count):
        calls.append(count)
        if len(calls) > 1:
            raise AssertionError("continued after a malformed salt draw")
        if fault == "integer":
            return count
        length = {"short": count - 1, "empty": 0, "long": count + 1}[fault]
        return b"\x01" * length

    identity = b"unissued-rng-boundary-" + fault.encode()
    history = material.scheme.signed_messages(IDENTITY)
    monkeypatch.setattr(material.entropy, "read", bad_read)
    with pytest.raises(RandomnessError):
        if api == "pure":
            if operation == "extract":
                w.key_extract_pw(material.msk, identity, rng=material.entropy)
            else:
                w.sign_pw(material.pw_key, b"not-signed-" + fault.encode(),
                          rng=material.entropy)
        elif operation == "extract":
            material.scheme.key_extract_pw(identity)
        else:
            material.scheme.sign_pw(IDENTITY, b"not-signed-" + fault.encode())
    assert calls == [material.params.salt_bits // 8]
    assert material.scheme.cached_identity_salt(identity) is None
    assert material.scheme.signed_messages(IDENTITY) == history


def test_message_salt_is_frozen_before_source_buffer_reuse(material, monkeypatch):
    original_read = material.entropy.read
    buffer = bytearray(material.params.salt_bits // 8)
    first_draw = True

    def mutable_read(count):
        nonlocal first_draw
        if first_draw:
            first_draw = False
            assert count == len(buffer)
            buffer[:] = original_read(count)
            return buffer
        # A valid bytes-like source may recycle the previously returned buffer.
        buffer[:] = b"\xff" * len(buffer)
        return original_read(count)

    monkeypatch.setattr(material.entropy, "read", mutable_read)
    r, s, signature = material.scheme.sign_pw(IDENTITY, MESSAGE)
    assert type(s) is bytes
    assert material.scheme.verify_pw(IDENTITY, MESSAGE, r, s, signature) is True
    frozen = bytes(s)
    buffer[:] = b"\x00" * len(buffer)
    assert s == frozen
    assert material.scheme.verify_pw(IDENTITY, MESSAGE, r, s, signature) is True


@pytest.mark.parametrize("field", ["salt_bits", "internal_id_bits", "internal_msg_bits"])
def test_non_byte_aligned_nine_bit_configuration_is_rejected(field):
    with pytest.raises(InvalidParameterError):
        w.WangPWParams(n=1, q=3, m_bar=2, **{field: 9})


def test_canonical_public_key_and_signature_roundtrips(material):
    pk_blob = material.pk.to_bytes()
    assert w.PublicKey.from_bytes(material.params, pk_blob).to_bytes() == pk_blob
    signature = material.first[2]
    blob = signature.to_bytes()
    parsed = w.Signature.from_bytes(material.params, blob)
    assert parsed.to_bytes() == blob
    assert material.scheme.verify_pw(IDENTITY, MESSAGE, *material.first[:2], parsed)


@pytest.mark.parametrize("replacement", ["plus-q", "q", "uint32-max"])
def test_public_key_wire_rejects_noncanonical_field_elements(material, replacement):
    blob = material.pk.to_bytes()
    offset = len(PK_MAGIC) + 8
    first = int.from_bytes(blob[offset:offset + 4], "big")
    value = {"plus-q": first + material.params.q,
             "q": material.params.q, "uint32-max": (1 << 32) - 1}[replacement]
    bad = blob[:offset] + value.to_bytes(4, "big") + blob[offset + 4:]
    with pytest.raises(InvalidParameterError):
        w.PublicKey.from_bytes(material.params, bad)


@pytest.mark.parametrize("width", [2, 8])
def test_signature_wire_rejects_redundant_sign_extension(material, width):
    coordinates = (1, -1) + (0,) * (material.params.signature_dim - 2)
    bad = _wire_signature(material.params, coordinates, width)
    with pytest.raises(InvalidParameterError):
        w.Signature.from_bytes(material.params, bad)


def test_valid_signature_cannot_gain_an_alternative_wider_wire_encoding(material):
    signature = material.first[2]
    blob = signature.to_bytes()
    offset = len(SIG_MAGIC) + 4
    width = int.from_bytes(blob[offset:offset + 4], "big")
    assert width < 8, "toy fixture unexpectedly exhausted the wire width"
    bad = _wire_signature(material.params, signature.z, width + 1)
    with pytest.raises(InvalidParameterError):
        w.Signature.from_bytes(material.params, bad)


@pytest.mark.parametrize("delta", [-1, 1])
@pytest.mark.parametrize("kind", ["pk", "signature"])
def test_wire_rejects_truncation_and_append(material, kind, delta):
    value = material.pk if kind == "pk" else material.first[2]
    decoder = w.PublicKey if kind == "pk" else w.Signature
    blob = value.to_bytes()
    bad = blob[:-1] if delta < 0 else blob + b"\x00"
    with pytest.raises(InvalidParameterError):
        decoder.from_bytes(material.params, bad)


@pytest.mark.parametrize("coordinate", [
    pytest.param(10 ** 400, id="huge-positive"),
    pytest.param(-(10 ** 400), id="huge-negative"),
])
def test_huge_signature_is_rejected_without_arithmetic_exception(material, coordinate):
    coordinates = (coordinate,) + (0,) * (material.params.signature_dim - 1)
    try:
        signature = w.Signature(material.params, coordinates)
    except InvalidParameterError:
        # An explicit constructor bound is also a valid early rejection.
        return
    r, s, _ = material.first
    internal_message = w.j_message(MESSAGE, s, bits=material.params.internal_msg_bits)
    assert w.verify(material.pk, material.sk.identity, internal_message, signature) is False
    assert material.scheme.verify_pw(IDENTITY, MESSAGE, r, s, signature) is False


BAD_INTS = [
    pytest.param(True, id="bool"),
    pytest.param(1.0, id="integral-float"),
    pytest.param(1.75, id="fractional-float"),
    pytest.param("1", id="numeric-string"),
    pytest.param(Fraction(1, 1), id="integral-fraction"),
    pytest.param(_IntCoercible(), id="int-duck-type"),
]


@pytest.mark.parametrize("bad", BAD_INTS)
@pytest.mark.parametrize("owner,field", [
    ("pk", "a_rows"), ("msk", "a_bar_rows"), ("msk", "r_a_rows"),
    ("sk", "a_rows"), ("sk", "h1_rows"), ("sk", "r_x_rows"),
    ("signature", "z"),
])
def test_integer_coordinates_reject_implicit_coercion(material, owner, field, bad):
    value = material.first[2] if owner == "signature" else getattr(material, owner)
    old = getattr(value, field)
    updated = (bad,) + tuple(old[1:]) if field == "z" else _replace_first(old, bad)
    with pytest.raises(InvalidParameterError):
        replace(value, **{field: updated})


@pytest.mark.parametrize("coerce", [
    pytest.param(float, id="integral-float"),
    pytest.param(lambda value: value + 0.75, id="fractional-float"),
    pytest.param(str, id="numeric-string"),
    pytest.param(lambda value: Fraction(value, 1), id="integral-fraction"),
    pytest.param(_IntCoercible, id="int-duck-type"),
])
@pytest.mark.parametrize("field", ["n", "q", "m_bar", "salt_bits",
                                   "internal_id_bits", "internal_msg_bits"])
def test_integer_configuration_rejects_implicit_coercion(field, coerce):
    # Coercion would otherwise produce a VALID value, so a range check cannot
    # accidentally make a missing type check look correct (e.g. q=1.0).
    values = dict(n=1, q=3, m_bar=2, salt_bits=128,
                  internal_id_bits=256, internal_msg_bits=256)
    values[field] = coerce(values[field])
    with pytest.raises(InvalidParameterError):
        w.WangPWParams(**values)


@pytest.mark.parametrize("bad", BAD_BYTES)
def test_public_key_hash_api_rejects_non_bytes_inputs(material, bad):
    with pytest.raises(InvalidParameterError):
        w.hash_identity_matrix(material.pk, bad)
    with pytest.raises(InvalidParameterError):
        w.hash_message_vector(material.pk, bad, MESSAGE)
    with pytest.raises(InvalidParameterError):
        w.hash_message_vector(material.pk, IDENTITY, bad)


def _contains_master_material(value, master, seen=None):
    """Detect retained master objects/matrices, not mathematical recoverability."""
    if seen is None:
        seen = set()
    if id(value) in seen:
        return False
    seen.add(id(value))
    if isinstance(value, w.MasterSecretKey):
        return True
    if isinstance(value, (list, tuple)):
        if value and all(isinstance(row, (list, tuple)) for row in value):
            if tuple(tuple(row) for row in value) == master.r_a_rows:
                return True
        return any(_contains_master_material(item, master, seen) for item in value)
    if isinstance(value, dict):
        return any(_contains_master_material(item, master, seen)
                   for pair in value.items() for item in pair)
    if is_dataclass(value) and not isinstance(value, type):
        return any(_contains_master_material(getattr(value, f.name), master, seen)
                   for f in fields(value))
    return False


def test_signing_key_does_not_export_the_master_trapdoor(material):
    # Do not call or require the legacy SigningKey.r_a() method.
    has_old_field = hasattr(material.sk, "r_a_rows")
    assert not has_old_field, "SigningKey still exports the master trapdoor field"
    leaked = (_contains_master_material(material.sk, material.msk)
              or _contains_master_material(material.pw_key, material.msk))
    assert not leaked, "SigningKey retains master material under another field"


def test_standalone_signing_key_verifies_using_public_key_hash_api(material):
    r, s, signature = material.first
    internal_identity = w.j_identity(IDENTITY, r, bits=material.params.internal_id_bits)
    internal_message = w.j_message(MESSAGE, s, bits=material.params.internal_msg_bits)
    bound = material.sk.identity == internal_identity
    assert bound
    h1_matches = material.sk.h1() == w.hash_identity_matrix(material.pk, internal_identity)
    assert h1_matches
    h2 = w.hash_message_vector(material.pk, internal_identity, internal_message)
    assert len(h2) == material.params.n
    assert all(type(x) is int and 0 <= x < material.params.q for x in h2)
    assert w.verify(material.pk, internal_identity, internal_message, signature) is True


def test_pure_figure5_extraction_is_fresh_and_signing_needs_only_issued_key(material):
    rng = DeterministicRandom(b"wang-pw-boundary-pure-extract")
    first = w.key_extract_pw(material.msk, IDENTITY, rng=rng)
    second = w.key_extract_pw(material.msk, IDENTITY, rng=rng)
    assert isinstance(first, w.PWSigningKey)
    distinct_salts = first.salt != second.salt
    assert distinct_salts
    for key in (first, second):
        r, s, signature = w.sign_pw(key, MESSAGE, rng=rng)
        same_salt = r == key.salt
        assert same_salt
        assert w.verify_pw(material.pk, IDENTITY, MESSAGE, r, s, signature) is True


@pytest.mark.parametrize("field,bad", [
    pytest.param("identity", b"different-id", id="wrong-identity"),
    pytest.param("salt", b"\x00" * 16, id="wrong-salt"),
    pytest.param("salt", b"\x00" * 15, id="short-salt"),
    pytest.param("inner", None, id="foreign-inner"),
])
def test_pw_signing_key_rejects_broken_binding(material, field, bad):
    with pytest.raises(InvalidParameterError):
        replace(material.pw_key, **{field: bad})


def test_pw_signing_key_freezes_mutable_identity_and_salt(material):
    identity = bytearray(material.pw_key.identity)
    salt = bytearray(material.pw_key.salt)
    rebuilt = w.PWSigningKey(memoryview(identity), memoryview(salt), material.sk)
    identity[0] ^= 1
    salt[0] ^= 1
    same_key = rebuilt == material.pw_key
    assert same_key
    assert type(rebuilt.identity) is bytes and type(rebuilt.salt) is bytes


@pytest.mark.parametrize("operation", ["extract", "sign", "verify"])
def test_pure_pw_algorithms_reject_foreign_key_objects(material, operation):
    if operation == "verify":
        assert w.verify_pw(None, IDENTITY, MESSAGE, *material.first) is False
        return
    with pytest.raises(InvalidParameterError):
        if operation == "extract":
            w.key_extract_pw(material.sk, IDENTITY)
        else:
            w.sign_pw(material.sk, MESSAGE)


@pytest.mark.parametrize("bad", BAD_BYTES)
@pytest.mark.parametrize("method", ["cached_identity_salt", "signed_messages"])
def test_cache_queries_reject_non_bytes_identity(material, method, bad):
    with pytest.raises(InvalidParameterError):
        getattr(material.scheme, method)(bad)


@pytest.mark.parametrize("operation", ["extract", "sign"])
def test_salt_source_length_is_measured_in_bytes_not_memoryview_elements(material, operation):
    class WideSalt:
        def __init__(self):
            self.draws = 0

        def read(self, count):
            self.draws += 1
            if self.draws != 1:
                raise AssertionError("continued after an overlong salt buffer")
            # len(view) == count, but the buffer contains 4*count bytes.
            return memoryview(array("I", [1] * count))

    source = WideSalt()
    with pytest.raises(RandomnessError):
        if operation == "extract":
            w.key_extract_pw(material.msk, IDENTITY, rng=source)
        else:
            w.sign_pw(material.pw_key, MESSAGE, rng=source)
    assert source.draws == 1


def test_exact_byte_length_typed_memoryview_is_a_valid_salt_source(material):
    source = DeterministicRandom(b"wang-pw-boundary-exact-byte-view")

    class TypedSalt:
        first = True

        def read(self, count):
            data = source.read(count)
            if self.first:
                self.first = False
                # Here nbytes == count, even though len(view) == count/4.
                return memoryview(data).cast("I")
            return data

    r, s, signature = w.sign_pw(material.pw_key, MESSAGE, rng=TypedSalt())
    assert len(s) == material.params.salt_bits // 8
    assert w.verify_pw(material.pk, IDENTITY, MESSAGE, r, s, signature) is True


@pytest.mark.parametrize("slot", ["identity", "message", "r", "s"])
@pytest.mark.parametrize("api", ["service", "pure"])
def test_released_memoryview_is_rejected_by_verification(material, slot, api):
    view = memoryview(b"released")
    view.release()
    r, s, signature = material.first
    inputs = dict(identity=IDENTITY, message=MESSAGE, r=r, s=s, signature=signature)
    inputs[slot] = view
    result = (material.scheme.verify_pw(**inputs) if api == "service"
              else w.verify_pw(material.pk, **inputs))
    assert result is False


@pytest.mark.parametrize("field", ["s0", "s_del", "s_sig", "verify_width"])
def test_huge_integer_width_is_a_parameter_error_not_float_overflow(material, field):
    with pytest.raises(InvalidParameterError):
        replace(material.params, **{field: 10 ** 400})


@pytest.mark.parametrize("value", [-1, 3])
def test_master_public_block_requires_canonical_field_elements(material, value):
    changed = _replace_first(material.msk.a_bar_rows, value)
    with pytest.raises(InvalidParameterError):
        replace(material.msk, a_bar_rows=changed)
