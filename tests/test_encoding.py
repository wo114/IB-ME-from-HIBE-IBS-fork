"""Core M1 tests: canonical encodings, domain-separated hashing, randomness,
constant-time comparison.

Only the standard library and pytest are used (project rule: no third-party
dependencies in the reference implementation).
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from ibme.core import (
    DOMAIN_HIBE_ID,
    DOMAIN_IBS_H1,
    DOMAIN_IBS_H2,
    DOMAIN_ID,
    DOMAIN_MSG,
    DOMAIN_PAIR,
    ALL_DOMAINS,
    DeterministicRandom,
    EncodingError,
    Identity,
    InvalidParameterError,
    RandomnessError,
    RandomSource,
    SecureRandom,
    constant_time_equal,
    decode_bytes,
    decode_identity,
    decode_message,
    decode_pair,
    encode_bytes,
    encode_identity,
    encode_message,
    encode_pair,
    hash_identity,
    hash_message,
    hash_pair,
    parse_bytes,
    parse_identity,
    parse_message,
    parse_pair,
    shake256,
    validate_bytes,
    validate_identity,
)


def u32(n: int) -> bytes:
    """Test-side uint32 big-endian prefix, independent of the implementation."""
    return n.to_bytes(4, "big")


UTF8_ID = "alice@例え.de/身份-🎯".encode("utf-8")  # multi-byte UTF-8 identity
BIN_DIRTY = bytes(range(256))  # binary dirt: every byte value incl. 0x00/0xff


# ---------------------------------------------------------------------------
# Canonical structure and round trips
# ---------------------------------------------------------------------------

class TestCanonicalEncodings:

    def test_encode_bytes_known_vectors(self):
        assert encode_bytes(b"") == b"\x00\x00\x00\x00"
        assert encode_bytes(b"AB") == b"\x00\x00\x00\x02AB"

    def test_encode_bytes_accepts_bytearray_and_memoryview(self):
        assert encode_bytes(bytearray(b"xyz")) == encode_bytes(b"xyz")
        assert encode_bytes(memoryview(b"xyz")) == encode_bytes(b"xyz")

    def test_encode_identity_structure(self):
        encoded = encode_identity(b"bob")
        assert encoded == DOMAIN_ID + u32(3) + b"bob"

    def test_encode_pair_structure_and_order_sensitivity(self):
        a, b = b"alice", b"bob"
        encoded = encode_pair(a, b)
        assert encoded == DOMAIN_PAIR + u32(5) + a + u32(3) + b
        assert encoded != encode_pair(b, a)

    def test_encode_message_structure(self):
        encoded = encode_message(b"bob", b"hi")
        assert encoded == DOMAIN_MSG + u32(3) + b"bob" + u32(2) + b"hi"

    def test_encodings_are_deterministic(self):
        assert encode_identity(UTF8_ID) == encode_identity(UTF8_ID)
        assert encode_message(UTF8_ID, BIN_DIRTY) == encode_message(UTF8_ID, BIN_DIRTY)


class TestRoundTrips:

    @pytest.mark.parametrize(
        "payload",
        [
            b"",
            b"A",
            b"secret message with spaces and \t tabs",
            BIN_DIRTY,
            b"\x00" * 257,              # zeros (prefix is nonzero)
            b"\xff" * 1000,
            b"x" * 70_001,              # multi-byte uint32 length field
        ],
        ids=["empty", "single", "text", "all-byte-values", "zeros", "high-bytes", "long"],
    )
    def test_bytes_round_trip(self, payload):
        assert parse_bytes(encode_bytes(payload)) == payload

    @pytest.mark.parametrize(
        "identity",
        [b"a", UTF8_ID, BIN_DIRTY, b"\x00\x01\x02\x00", bytes([0xFF]) * 64],
        ids=["short", "utf8", "binary", "embedded-nul", "high-bytes"],
    )
    def test_identity_round_trip(self, identity):
        assert parse_identity(encode_identity(identity)) == identity

    @pytest.mark.parametrize(
        "identity,message",
        [
            (b"bob", b""),
            (UTF8_ID, BIN_DIRTY),
            (b"\x00\xff", b"m" * 5000),
            (BIN_DIRTY, UTF8_ID),
        ],
        ids=["empty-message", "utf8-binary", "long-message", "binary-identity"],
    )
    def test_message_round_trip(self, identity, message):
        assert parse_message(encode_message(identity, message)) == (identity, message)

    @pytest.mark.parametrize(
        "a,b",
        [
            (b"alice", b"bob"),
            (UTF8_ID, b"\x00\x00"),
            (BIN_DIRTY, UTF8_ID),
            (b"x" * 300, b"y" * 300),
        ],
        ids=["ascii", "utf8-nul", "binary", "long"],
    )
    def test_pair_round_trip(self, a, b):
        assert parse_pair(encode_pair(a, b)) == (a, b)

    def test_round_trip_via_decode_offsets(self):
        # Walk a composite buffer with the offset-based decoders.
        inner = encode_pair(b"alice", b"bob")
        buffer = encode_bytes(b"prefix-field") + inner
        value, pos = decode_bytes(buffer, 0)
        assert value == b"prefix-field"
        (a, b), pos2 = decode_pair(buffer, pos)
        assert (a, b) == (b"alice", b"bob")
        assert pos2 == len(buffer)

    def test_decode_message_inside_larger_buffer(self):
        blob = b"XX" + encode_message(b"rcv", b"payload") + b"YY"
        fields, end = decode_message(blob, 2)
        assert fields == (b"rcv", b"payload")
        assert blob[end:] == b"YY"


# ---------------------------------------------------------------------------
# Rejections
# ---------------------------------------------------------------------------

class TestRejections:

    @pytest.mark.parametrize(
        "encoded",
        [
            encode_identity(UTF8_ID),
            encode_pair(b"alice", b"bob"),
            encode_message(b"rcv", b"payload"),
        ],
        ids=["identity", "pair", "message"],
    )
    def test_truncation_of_last_byte(self, encoded):
        with pytest.raises(EncodingError):
            parse_identity(encoded[:-1])
        with pytest.raises(EncodingError):
            parse_pair(encoded[:-1])
        with pytest.raises(EncodingError):
            parse_message(encoded[:-1])

    def test_truncation_inside_domain(self):
        for cut in (1, 2, len(DOMAIN_ID) - 1):
            with pytest.raises(EncodingError):
                parse_identity(encode_identity(b"bob")[:cut])

    def test_truncation_inside_length_field(self):
        with pytest.raises(EncodingError):
            parse_bytes(u32(4)[:2])

    def test_truncation_inside_payload(self):
        with pytest.raises(EncodingError):
            parse_bytes(u32(10) + b"short")

    def test_length_field_larger_than_actual_data(self):
        with pytest.raises(EncodingError):
            parse_bytes(u32(100) + b"abc")
        with pytest.raises(EncodingError):
            parse_identity(DOMAIN_ID + u32(5) + b"ab")

    def test_huge_length_field_rejected_without_allocation(self):
        with pytest.raises(EncodingError):
            parse_bytes(b"\xff\xff\xff\xff")
        with pytest.raises(EncodingError):
            parse_bytes(b"\xff\xff\xff\xff" + b"trailing")
        with pytest.raises(EncodingError):
            decode_identity(DOMAIN_ID + b"\xff\xff\xff\xff", 0)

    def test_encode_bytes_uint32_overflow_guard(self):
        class _HugeLen(bytes):
            def __len__(self):  # pragma: no cover - only used for the guard
                return 2**32

        with pytest.raises(EncodingError):
            encode_bytes(_HugeLen(b"x"))

    def test_appended_garbage(self):
        with pytest.raises(EncodingError):
            parse_identity(encode_identity(b"bob") + b"\x00")
        with pytest.raises(EncodingError):
            parse_pair(encode_pair(b"a", b"b") + b"junk")
        with pytest.raises(EncodingError):
            parse_message(encode_message(b"rcv", b"m") + b"\xff")

    def test_repeated_fields_rejected(self):
        # A second full field after a complete first one is trailing garbage.
        with pytest.raises(EncodingError):
            parse_bytes(encode_bytes(b"a") + encode_bytes(b"b"))
        with pytest.raises(EncodingError):
            parse_identity(encode_identity(b"a") + encode_identity(b"b"))
        with pytest.raises(EncodingError):
            parse_message(encode_message(b"rcv", b"m") + encode_message(b"rcv", b"m"))
        with pytest.raises(EncodingError):
            parse_pair(encode_pair(b"a", b"b") + encode_bytes(b"c"))

    def test_repeated_field_inside_pair_visible_to_offset_decoder(self):
        buffer = encode_pair(b"a", b"b") + encode_bytes(b"c")
        pair, end = decode_pair(buffer, 0)
        assert pair == (b"a", b"b")
        assert end < len(buffer)  # extra data present ...
        with pytest.raises(EncodingError):  # ... and rejected by exact parsing
            parse_pair(buffer)

    def test_domain_mismatch_between_encodings(self):
        pair_enc = encode_pair(b"alice", b"bob")
        with pytest.raises(EncodingError):
            parse_identity(pair_enc)
        with pytest.raises(EncodingError):
            parse_message(pair_enc)
        with pytest.raises(EncodingError):
            parse_pair(encode_identity(b"alice"))
        with pytest.raises(EncodingError):
            parse_message(encode_identity(b"rcv"))  # missing message field

    def test_empty_buffer(self):
        for parser in (parse_bytes, parse_identity, parse_pair, parse_message):
            with pytest.raises(EncodingError):
                parser(b"")

    # -- empty identity ----------------------------------------------------

    def test_empty_identity_rejected_on_encode(self):
        with pytest.raises(EncodingError):
            encode_identity(b"")
        with pytest.raises(EncodingError):
            encode_pair(b"", b"bob")
        with pytest.raises(EncodingError):
            encode_pair(b"alice", b"")
        with pytest.raises(EncodingError):
            encode_message(b"", b"message")

    def test_empty_identity_rejected_on_decode(self):
        with pytest.raises(EncodingError):
            parse_identity(DOMAIN_ID + u32(0))
        with pytest.raises(EncodingError):
            parse_pair(DOMAIN_PAIR + u32(1) + b"a" + u32(0))
        with pytest.raises(EncodingError):
            parse_message(DOMAIN_MSG + u32(0) + u32(0))

    # -- non-bytes inputs ---------------------------------------------------

    @pytest.mark.parametrize("bad", ["alice", None, 42, 3.14, [b"a"]])
    def test_non_bytes_rejected(self, bad):
        with pytest.raises(EncodingError):
            encode_bytes(bad)
        with pytest.raises(EncodingError):
            encode_identity(bad)
        with pytest.raises(EncodingError):
            encode_message(bad, b"m")
        with pytest.raises(EncodingError):
            parse_identity(bad)

    def test_validate_helpers(self):
        assert validate_bytes(b"") == b""
        assert validate_bytes(bytearray(b"ab")) == b"ab"
        assert isinstance(validate_bytes(memoryview(b"ab")), bytes)
        assert validate_identity(b"x") == b"x"
        with pytest.raises(EncodingError):
            validate_identity(b"")
        with pytest.raises(EncodingError):
            validate_identity("str")

    def test_bad_offset_rejected(self):
        buffer = encode_bytes(b"abc")
        with pytest.raises(EncodingError):
            decode_bytes(buffer, -1)
        with pytest.raises(EncodingError):
            decode_bytes(buffer, len(buffer) + 1)
        with pytest.raises(EncodingError):
            decode_bytes(buffer, "0")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Domain-separated hashing
# ---------------------------------------------------------------------------

class TestHashing:

    def test_frozen_domain_constants(self):
        assert DOMAIN_ID == b"IBME:ID:v1"
        assert DOMAIN_PAIR == b"IBME:PAIR:v1"
        assert DOMAIN_MSG == b"IBME:MSG:v1"
        assert DOMAIN_HIBE_ID == b"IBME:HIBE-ID:v1"
        assert DOMAIN_IBS_H1 == b"IBME:IBS-H1:v1"
        assert DOMAIN_IBS_H2 == b"IBME:IBS-H2:v1"
        # pairwise distinct (also prefix-free, which the construction relies on)
        assert len(set(ALL_DOMAINS)) == len(ALL_DOMAINS) == 6
        for i, d1 in enumerate(ALL_DOMAINS):
            for d2 in ALL_DOMAINS[i + 1:]:
                assert not d1.startswith(d2) and not d2.startswith(d1)

    def test_known_answer_pins_construction(self):
        # Documented construction: SHAKE-256 over u32(len(domain))||domain||data
        expected = hashlib.shake_256(u32(len(DOMAIN_ID)) + DOMAIN_ID + b"payload").digest(32)
        assert shake256(DOMAIN_ID, b"payload", 32) == expected
        assert len(shake256(DOMAIN_MSG, b"payload", 64)) == 64

    def test_different_domains_same_data_differ(self):
        data = b"same input for every domain"
        digests = [shake256(d, data, 32) for d in ALL_DOMAINS]
        assert len(set(digests)) == len(digests)
        # prefix-related custom domains are separated by the length prefix too
        assert shake256(b"IBME:ID:v1", data, 32) != shake256(b"IBME:ID:v1:x", data, 32)
        assert shake256(b"A", b"BC", 32) != shake256(b"AB", b"C", 32)

    def test_same_domain_and_data_deterministic(self):
        assert shake256(DOMAIN_IBS_H2, BIN_DIRTY, 48) == shake256(DOMAIN_IBS_H2, BIN_DIRTY, 48)
        assert shake256(DOMAIN_PAIR, b"", 32) == shake256(DOMAIN_PAIR, b"", 32)

    def test_domain_separated_from_raw_shake(self):
        # The wrapper must not equal an un-prefixed domain||data squeeze.
        assert shake256(DOMAIN_ID, b"payload", 32) != hashlib.shake_256(
            DOMAIN_ID + b"payload"
        ).digest(32)

    def test_wrappers_match_canonical_field_encoding(self):
        # Pins hashing.<wrapper> == shake256(domain, encode_bytes-composed data)
        assert hash_identity(UTF8_ID, 32) == shake256(
            DOMAIN_ID, encode_bytes(UTF8_ID), 32
        )
        assert hash_pair(b"alice", b"bob", 32) == shake256(
            DOMAIN_PAIR, encode_bytes(b"alice") + encode_bytes(b"bob"), 32
        )
        assert hash_message(b"rcv", b"", 32) == shake256(
            DOMAIN_MSG, encode_bytes(b"rcv") + encode_bytes(b""), 32
        )

    def test_hash_wrappers_distinguish_inputs(self):
        assert hash_identity(b"alice", 32) != hash_identity(b"alicia", 32)
        assert hash_identity(b"x", 32) != hash_pair(b"x", b"x", 32)
        assert hash_message(b"rcv", b"m1", 32) != hash_message(b"rcv", b"m2", 32)
        # unambiguous: (a, b) fields vs one merged field
        assert hash_pair(b"a", b"b", 32) != hash_identity(b"a" + u32(1) + b"b", 32)

    def test_shake256_invalid_parameters(self):
        with pytest.raises(InvalidParameterError):
            shake256(b"", b"data", 32)  # empty domain
        with pytest.raises(InvalidParameterError):
            shake256("IBME:ID:v1", b"data", 32)  # type: ignore[arg-type]
        with pytest.raises(InvalidParameterError):
            shake256(DOMAIN_ID, "data", 32)  # type: ignore[arg-type]
        for bad_len in (0, -1, "32", 3.5, True):
            with pytest.raises(InvalidParameterError):
                shake256(DOMAIN_ID, b"data", bad_len)

    def test_hash_wrapper_field_validation(self):
        with pytest.raises(EncodingError):
            hash_identity(b"", 32)
        with pytest.raises(EncodingError):
            hash_pair(b"a", b"", 32)
        with pytest.raises(EncodingError):
            hash_message(b"", b"m", 32)
        with pytest.raises(EncodingError):
            hash_message("rcv", b"m", 32)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Randomness
# ---------------------------------------------------------------------------

class TestRandomness:

    def test_deterministic_same_seed_reproducible(self):
        first = DeterministicRandom(b"seed-A")
        second = DeterministicRandom(b"seed-A")
        assert first.read(32) == second.read(32)
        for _ in range(8):
            assert first.read(17) == second.read(17)

    def test_deterministic_stream_chunking_independent(self):
        whole = DeterministicRandom(b"seed-B").read(200)
        pieced = DeterministicRandom(b"seed-B")
        chunks = b"".join(pieced.read(n) for n in (1, 7, 64, 64, 64))
        assert chunks == whole[:200]
        assert pieced.read(10) == DeterministicRandom(b"seed-B").read(210)[200:]

    def test_deterministic_different_seeds_differ(self):
        assert DeterministicRandom(b"seed-A").read(64) != DeterministicRandom(b"seed-B").read(64)
        assert DeterministicRandom(b"A").read(64) != DeterministicRandom(b"B").read(64)
        # prefix-related seeds must not share a prefix of output
        s1 = DeterministicRandom(b"seed").read(64)
        s2 = DeterministicRandom(b"seedX").read(64)
        assert s1 != s2

    def test_deterministic_output_is_balanced(self):
        data = DeterministicRandom(b"statistics").read(1024)
        bits = int.from_bytes(data, "big").bit_count()
        assert 0 < bits < 8 * 1024  # not all-zero / all-one (sanity, not a proof)

    def test_deterministic_seed_validation(self):
        with pytest.raises(RandomnessError):
            DeterministicRandom(b"")
        with pytest.raises(RandomnessError):
            DeterministicRandom("seed")  # type: ignore[arg-type]
        with pytest.raises(RandomnessError):
            DeterministicRandom(123)  # type: ignore[arg-type]

    def test_deterministic_accepts_bytearray_seed(self):
        assert DeterministicRandom(bytearray(b"seed")).read(16) == DeterministicRandom(b"seed").read(16)

    def test_secure_random_differs_between_calls(self):
        rng = SecureRandom()
        assert rng.read(32) != rng.read(32)
        assert SecureRandom().read(32) != SecureRandom().read(32)

    def test_secure_random_rejects_seed(self):
        with pytest.raises(TypeError):
            SecureRandom(b"seed")  # type: ignore[call-arg]

    def test_read_length_validation(self):
        for rng in (SecureRandom(), DeterministicRandom(b"seed")):
            assert rng.read(0) == b""
            with pytest.raises(RandomnessError):
                rng.read(-1)
            with pytest.raises(RandomnessError):
                rng.read("8")  # type: ignore[arg-type]
            with pytest.raises(RandomnessError):
                rng.read(True)

    def test_both_sources_satisfy_frozen_protocol(self):
        assert isinstance(SecureRandom(), RandomSource)
        assert isinstance(DeterministicRandom(b"s"), RandomSource)


# ---------------------------------------------------------------------------
# Constant-time equality
# ---------------------------------------------------------------------------

class TestConstantTimeEqual:

    def test_equal_inputs(self):
        assert constant_time_equal(b"", b"")
        assert constant_time_equal(b"abc", b"abc")
        assert constant_time_equal(UTF8_ID, UTF8_ID)
        assert constant_time_equal(BIN_DIRTY, BIN_DIRTY)

    def test_unequal_same_length(self):
        assert not constant_time_equal(b"abc", b"abd")
        assert not constant_time_equal(b"Xbc", b"abc")
        assert not constant_time_equal(b"abX", b"abc")
        assert not constant_time_equal(b"\x00", b"\x01")
        assert not constant_time_equal(b"a" * 1000, b"a" * 999 + b"b")

    def test_different_lengths(self):
        assert not constant_time_equal(b"a", b"ab")
        assert not constant_time_equal(b"", b"a")
        assert not constant_time_equal(b"ab", b"a")
        assert not constant_time_equal(UTF8_ID, UTF8_ID + b"\x00")

    def test_accepts_bytes_like(self):
        assert constant_time_equal(bytearray(b"abc"), b"abc")
        assert constant_time_equal(memoryview(b"abc"), bytearray(b"abc"))

    def test_rejects_non_bytes(self):
        for bad in ("abc", None, 42, ["a"]):
            with pytest.raises(TypeError):
                constant_time_equal(bad, b"abc")  # type: ignore[arg-type]
            with pytest.raises(TypeError):
                constant_time_equal(b"abc", bad)  # type: ignore[arg-type]

    def test_matches_hmac_reference(self):
        samples = [
            (b"", b""),
            (b"\x00" * 32, b"\x00" * 32),
            (bytes(DeterministicRandom(b"cte-1").read(64)), bytes(DeterministicRandom(b"cte-2").read(64))),
            (bytes(DeterministicRandom(b"cte-3").read(64)), bytes(DeterministicRandom(b"cte-3").read(64))),
        ]
        for a, b in samples:
            assert constant_time_equal(a, b) == hmac.compare_digest(a, b)

    def test_identity_comparison_use_case(self):
        id_a = encode_identity(b"alice@rcv")
        id_b = encode_identity(b"alice@rcv")
        id_c = encode_identity(b"alice@rcw")
        assert constant_time_equal(id_a, id_b)
        assert not constant_time_equal(id_a, id_c)


# ---------------------------------------------------------------------------
# Identity type sanity
# ---------------------------------------------------------------------------

def test_identity_alias_is_bytes():
    # Identity is a static alias; validated identities are plain bytes.
    value: Identity = validate_identity(b"trivial")
    assert isinstance(value, bytes)
    assert value == b"trivial"


# ---------------------------------------------------------------------------
# validate_identity max_bytes (main-AI frozen extension, M3 review)
# ---------------------------------------------------------------------------

class TestValidateIdentityMaxBytes:
    def test_accepts_up_to_limit(self):
        assert validate_identity(b"A" * 8, max_bytes=8) == b"A" * 8

    def test_rejects_over_limit(self):
        with pytest.raises(EncodingError, match="max_bytes=8"):
            validate_identity(b"A" * 9, max_bytes=8)

    def test_none_keeps_historical_behaviour(self):
        assert validate_identity(b"x" * 100, max_bytes=None) == b"x" * 100

    def test_rejects_bad_limit(self):
        for bad in (0, -1, True, "8"):
            with pytest.raises(EncodingError):
                validate_identity(b"abc", max_bytes=bad)
