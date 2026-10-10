"""Canonical transport differential, public Verify, and malformed-wire controls."""

from dataclasses import replace
import os
from pathlib import Path
import subprocess
import sys

import pytest

from ibme.core.encoding import decode_bytes, encode_bytes
from ibme.core.errors import SerializationError
from ibme.core.randomness import DeterministicRandom
from ibme.ibs import LuoModuleCompactIBSBackend, LuoModuleCompactSignature
from ibme.ibs.luo_module import LuoModuleIBSBackend, LuoModuleParams, LuoModulePublicKey, LuoModuleSignature
from ibme.ibs.luo_module_codec import (
    MAGIC_COMPACT, VERSION_COMPACT, MAX_COMPACT_BYTES, MAX_COEFFICIENTS,
    pack_bits, unpack_bits, compact_layout, encode_compact, decode_compact,
)


def oracle_pack(values, width):
    """Independent bit-string definition, not the production streaming loop."""
    bits = "".join(format(x, f"0{width}b") for x in values)
    bits += "0" * (-len(bits) % 8)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def fields(raw):
    version, pos = decode_bytes(raw, len(MAGIC_COMPACT))
    kind, pos = decode_bytes(raw, pos)
    result = []
    while pos < len(raw):
        item, pos = decode_bytes(raw, pos)
        result.append(item)
    return version, kind, result


def frame(items, version=VERSION_COMPACT, kind=b"SIGNATURE"):
    return MAGIC_COMPACT + encode_bytes(version) + encode_bytes(kind) + b"".join(encode_bytes(x) for x in items)


@pytest.mark.parametrize("width", [1, 2, 3, 7, 8, 11, 36, 63])
@pytest.mark.parametrize("count", [0, 1, 2, 9, 41])
def test_bit_stream_against_independent_oracle(width, count):
    values = tuple((i * 13 + i * i) % 2**width for i in range(count))
    if count: values = values[:-1] + (2**width - 1,)
    encoded = pack_bits(values, width)
    assert encoded == oracle_pack(values, width)
    assert unpack_bits(encoded, count, width) == values
    assert unpack_bits(memoryview(encoded), count, width) == values


@pytest.mark.parametrize("width", [True, 0, -1, 64, "11"])
def test_invalid_widths_rejected(width):
    with pytest.raises(SerializationError): pack_bits((0,), width)
    with pytest.raises(SerializationError): unpack_bits(b"", 0, width)


@pytest.mark.parametrize("value", [True, -1, 8, "0"])
def test_invalid_coefficients_rejected(value):
    with pytest.raises(SerializationError): pack_bits((value,), 3)


def test_bit_stream_count_length_and_padding_budgets():
    for count in (True, -1, MAX_COEFFICIENTS + 1, "1"):
        with pytest.raises(SerializationError): unpack_bits(b"", count, 1)
    with pytest.raises(SerializationError): pack_bits((0,) * (MAX_COEFFICIENTS + 1), 1)
    with pytest.raises(SerializationError): pack_bits(iter([0]), 1)
    for raw in (b"", b"\x80\x00", b"\x81", "80"):
        with pytest.raises(SerializationError): unpack_bits(raw, 1, 1)


@pytest.fixture(scope="module")
def tiny():
    p = LuoModuleParams(degree=2, k=1, l=1, q=17, root=4, kappa=1,
                        gamma1=3, gamma2=5, gamma3=4, dropped_bits=1)
    public, _ = LuoModuleIBSBackend(rng=DeterministicRandom(b"compact-padding-codec-only")).setup(p)
    # Range-valid codec vector; no claim that this is an authentic signature.
    signature = LuoModuleSignature(p, public.context, ((-1, 1),), (-1, 0), ((8, 0),), ((1, 1),))
    return public, signature


@pytest.fixture(scope="module")
def large():
    b = LuoModuleIBSBackend(rng=DeterministicRandom(b"compact-large-public-contract"))
    public, master = b.setup(LuoModuleParams())
    key = b.key_extract(master, b"Alice")
    signature = b.sign(key, b"reference")
    return b, public, master, key, signature


def test_large_actual_signature_canonical_fixed_point_and_public_verify(large):
    b, public, _, _, sig = large
    encoded = encode_compact(sig)
    restored = decode_compact(encoded, public)
    assert restored.to_bytes() == sig.to_bytes()
    assert encode_compact(restored) == encoded
    verifier = LuoModuleCompactIBSBackend()
    compact = verifier.load_signature(public, encoded)
    assert compact.to_bytes() == encoded and compact.signature.to_bytes() == sig.to_bytes()
    assert verifier.verify(public, b"Alice", b"reference", compact)
    assert not verifier.verify(public, b"Other", b"reference", compact)
    assert not verifier.verify(public, b"Alice", b"changed", compact)
    assert len(sig.to_bytes()) == 29455 and len(encoded) == 16063
    assert compact_layout(public.params)["field_bytes"] == dict(z=11520, c_presence=32, c_signs=8, w1=3872, h=352)
    assert public.params.security_claim == "none" and not verifier.backend_admitted


def test_endpoint_coefficients_11_bit_carry_and_all_hints_preserved(large):
    _, public, _, _, sig = large
    p, layout = public.params, compact_layout(public.params)
    z = tuple(tuple((-1 if i % 2 else 1) * layout["z_max"] for i in range(p.degree)) for _ in range(p.l))
    c = tuple((-1 if i % 2 else 1) if i < p.kappa - 1 or i == p.degree - 1 else 0 for i in range(p.degree))
    changed = replace(sig, z=z, c=c, w1=((1024,) * p.degree,) * p.k, h=((1,) * p.degree,) * p.k)
    assert layout["z_width"] == 36 and layout["w1_width"] == 11
    restored = decode_compact(encode_compact(changed), public)
    assert restored.to_bytes() == changed.to_bytes()
    # An endpoint vector exercises the codec, not signature validity.
    assert not LuoModuleCompactIBSBackend().verify(public, b"Alice", b"reference", LuoModuleCompactSignature(changed))


def test_decoders_never_fall_back_to_other_transport(large):
    _, public, _, _, sig = large
    with pytest.raises(SerializationError): LuoModuleIBSBackend().load_signature(public, encode_compact(sig))
    with pytest.raises(SerializationError): LuoModuleCompactIBSBackend().load_signature(public, sig.to_bytes())


@pytest.mark.parametrize("index", [2, 3, 4, 6], ids=["z", "presence", "signs", "hints"])
def test_nonzero_tail_padding_in_each_partial_field_rejected(tiny, index):
    public, sig = tiny
    _, _, items = fields(encode_compact(sig))
    items[index] = items[index][:-1] + bytes([items[index][-1] | 1])
    with pytest.raises(SerializationError, match="padding"): decode_compact(frame(items), public)


@pytest.mark.parametrize("mutation", ["z-range", "w1-range", "presence-weight", "sign-length", "context", "parameters"])
def test_semantic_out_of_range_and_cross_context_rejected(tiny, mutation):
    public, sig = tiny
    _, _, items = fields(encode_compact(sig))
    if mutation == "z-range": items[2] = oracle_pack((3, 2), 2)  # Valid 2-bit code outside [-1,1].
    elif mutation == "w1-range": items[5] = oracle_pack((9, 0), 4)
    elif mutation == "presence-weight": items[3] = oracle_pack((1, 1), 1)
    elif mutation == "sign-length": items[4] = b""
    elif mutation == "context": items[1] = bytes([items[1][0] ^ 1]) + items[1][1:]
    else: items[0] = replace(public.params, max_sign_attempts=512).to_bytes()
    with pytest.raises(SerializationError): decode_compact(frame(items), public)


@pytest.mark.parametrize("mutation", ["truncate", "append", "duplicate", "missing", "version", "kind", "magic", "length"])
def test_strict_outer_compact_frame(tiny, mutation):
    public, sig = tiny
    raw = encode_compact(sig)
    _, _, items = fields(raw)
    changes = dict(truncate=raw[:-1], append=raw + b"\0", duplicate=frame(items + [items[-1]]),
                   missing=frame(items[:-1]), version=frame(items, version=b"other"),
                   kind=frame(items, kind=b"MASTER"), magic=b"?" + raw[1:],
                   length=MAGIC_COMPACT + (2**32 - 1).to_bytes(4, "big") + raw[9:])
    with pytest.raises(SerializationError): decode_compact(changes[mutation], public)


def test_total_wire_limit_and_input_types(tiny):
    public, sig = tiny
    for raw in (b"x" * (MAX_COMPACT_BYTES + 1), memoryview(b"x" * (MAX_COMPACT_BYTES + 1)), "signature"):
        with pytest.raises(SerializationError): decode_compact(raw, public)
    with pytest.raises(TypeError): decode_compact(encode_compact(sig), object())
    with pytest.raises(TypeError): encode_compact(object())
    with pytest.raises(TypeError): LuoModuleCompactSignature(object())


def test_verify_hash_domains_and_full_encoded_inputs_unchanged(large, monkeypatch):
    import ibme.ibs.luo_module as module
    b, public, _, _, sig = large
    original, calls = module.challenge, []
    def capture(params, domain, encoded):
        calls.append((domain, encoded))
        return original(params, domain, encoded)
    monkeypatch.setattr(module, "challenge", capture)
    assert b.verify(public, b"Alice", b"reference", sig)
    reference_calls = tuple(calls)
    calls.clear()
    compact = LuoModuleCompactSignature.from_bytes(encode_compact(sig), public)
    assert LuoModuleCompactIBSBackend().verify(public, b"Alice", b"reference", compact)
    assert tuple(calls) == reference_calls
    assert tuple(x[0] for x in calls) == (module.DOMAIN_H1, module.DOMAIN_H2)


def test_four_algorithms_and_rng_consumption_are_identical():
    class CountingRandom:
        def __init__(self): self.source, self.calls, self.bytes = DeterministicRandom(b"codec-differential"), 0, 0
        def read(self, count):
            self.calls += 1
            self.bytes += count
            return self.source.read(count)
    left_rng, right_rng = CountingRandom(), CountingRandom()
    left, right = LuoModuleIBSBackend(rng=left_rng), LuoModuleCompactIBSBackend(rng=right_rng)
    lp, lm = left.setup(LuoModuleParams())
    rp, rm = right.setup(LuoModuleParams())
    assert lp.to_bytes() == rp.to_bytes() and lm.to_bytes() == rm.to_bytes()
    lk, rk = left.key_extract(lm, b"Alice"), right.key_extract(rm, b"Alice")
    assert lk.to_bytes() == rk.to_bytes() and lm.to_bytes() == rm.to_bytes()
    ls, rs = left.sign(lk, b"unchanged inputs"), right.sign(rk, b"unchanged inputs")
    assert rs.signature.to_bytes() == ls.to_bytes()
    assert right.verify(rp, b"Alice", b"unchanged inputs", rs)
    assert (left.last_extract_attempts, left.last_sign_attempts) == (right.last_extract_attempts, right.last_sign_attempts)
    assert (left_rng.calls, left_rng.bytes) == (right_rng.calls, right_rng.bytes)


def test_fresh_process_has_only_public_data(large, tmp_path):
    _, public, _, _, sig = large
    (tmp_path / "public.bin").write_bytes(public.to_bytes())
    (tmp_path / "signature.bin").write_bytes(encode_compact(sig))
    script = """from pathlib import Path
from ibme.ibs import LuoModulePublicKey, LuoModuleCompactIBSBackend
p = LuoModulePublicKey.from_bytes(Path('public.bin').read_bytes())
b = LuoModuleCompactIBSBackend()
s = b.load_signature(p, Path('signature.bin').read_bytes())
assert b.verify(p, b'Alice', b'reference', s)
assert not b.verify(p, b'Other', b'reference', s)
print('compact public-only verification passed')
"""
    source = Path(__file__).resolve().parents[1] / "src"
    result = subprocess.run([sys.executable, "-B", "-c", script], cwd=tmp_path,
                            env={**os.environ, "PYTHONPATH": str(source), "PYTHONDONTWRITEBYTECODE": "1"},
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "compact public-only verification passed"
