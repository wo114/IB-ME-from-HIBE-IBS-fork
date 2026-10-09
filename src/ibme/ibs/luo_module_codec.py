"""Canonical MODULE-COMPACT/1 transport; unchanged Luo mathematical signature.

MSB-first bounded bit packing, explicit challenge signs, zero tail padding.
This codec preserves the existing hash domains/input encodings and parameters.
"""

from dataclasses import dataclass

from ibme.core.encoding import decode_bytes, encode_bytes
from ibme.core.errors import IBMEError, SerializationError
from .api import IBSSignature
from .luo_module import LuoModuleIBSBackend, LuoModuleParams, LuoModulePublicKey, LuoModuleSignature

MAGIC_COMPACT = b"L24C1"
VERSION_COMPACT = b"IBME/LUO2024/MODULE-COMPACT/1"
KIND = b"SIGNATURE"
MAX_COMPACT_BYTES = 2**20
MAX_COEFFICIENTS = 16 * 256


def _width(width):
    if isinstance(width, bool) or not isinstance(width, int) or not 1 <= width <= 63:
        raise SerializationError("invalid compact coefficient bit width")


def pack_bits(values, width):
    """A bounded MSB-first integer stream, with zero low tail padding."""
    _width(width)
    if not isinstance(values, (tuple, list)) or len(values) > MAX_COEFFICIENTS:
        raise SerializationError("compact coefficient count exceeds budget")
    limit, accumulator, bits, output = 2**width, 0, 0, bytearray()
    for value in values:
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < limit:
            raise SerializationError("compact coefficient out of range/type")
        accumulator = (accumulator << width) | value
        bits += width
        while bits >= 8:
            bits -= 8
            output.append((accumulator >> bits) & 255)
        accumulator &= (1 << bits) - 1
    if bits:
        output.append(accumulator << (8 - bits))
    return bytes(output)


def unpack_bits(data, count, width):
    _width(width)
    if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= MAX_COEFFICIENTS:
        raise SerializationError("invalid compact coefficient count")
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise SerializationError("compact coefficient body must be bytes")
    expected = (count * width + 7) // 8
    size = data.nbytes if isinstance(data, memoryview) else len(data)
    if size != expected:
        raise SerializationError("compact coefficient length mismatch")
    raw = bytes(data)
    unused = 8 * len(raw) - count * width
    if unused and raw[-1] & ((1 << unused) - 1):
        raise SerializationError("nonzero compact tail padding")
    mask, accumulator, bits, result = (1 << width) - 1, 0, 0, []
    for byte in raw:
        accumulator = (accumulator << 8) | byte
        bits += 8
        while bits >= width and len(result) < count:
            bits -= width
            result.append((accumulator >> bits) & mask)
        accumulator &= (1 << bits) - 1
    if len(result) != count:
        raise SerializationError("compact coefficient stream truncated")
    return tuple(result)


def compact_layout(params):
    if not isinstance(params, LuoModuleParams):
        raise TypeError("expected LuoModuleParams")
    z_max = params.gamma2 - params.beta2 - 1
    z_width, w1_width = max(1, (2 * z_max).bit_length()), max(1, params.max_w1.bit_length())
    sizes = dict(z=(params.l * params.degree * z_width + 7) // 8,
                 c_presence=(params.degree + 7) // 8, c_signs=(params.kappa + 7) // 8,
                 w1=(params.k * params.degree * w1_width + 7) // 8,
                 h=(params.k * params.degree + 7) // 8)
    fixed = (len(MAGIC_COMPACT) + 4 + len(VERSION_COMPACT) + 4 + len(KIND)
             + 7 * 4 + len(params.to_bytes()) + 64)
    return dict(z_max=z_max, z_width=z_width, w1_width=w1_width,
                field_bytes=sizes, fixed_frame_parameter_context_bytes=fixed,
                signature_bytes=fixed + sum(sizes.values()))


def _frame(fields):
    raw = MAGIC_COMPACT + encode_bytes(VERSION_COMPACT) + encode_bytes(KIND) + b"".join(encode_bytes(x) for x in fields)
    if len(raw) > MAX_COMPACT_BYTES:
        raise SerializationError("compact signature exceeds budget")
    return raw


def _unframe(data):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise SerializationError("compact signature must be bytes")
    size = data.nbytes if isinstance(data, memoryview) else len(data)
    if size > MAX_COMPACT_BYTES:
        raise SerializationError("compact signature exceeds budget")
    raw = bytes(data)
    if not raw.startswith(MAGIC_COMPACT):
        raise SerializationError("unknown compact signature magic")
    try:
        version, pos = decode_bytes(raw, len(MAGIC_COMPACT))
        kind, pos = decode_bytes(raw, pos)
        if version != VERSION_COMPACT or kind != KIND:
            raise SerializationError("unknown compact signature version/kind")
        fields = []
        for _ in range(7):
            item, pos = decode_bytes(raw, pos)
            fields.append(item)
        if pos != len(raw):
            raise SerializationError("appended/duplicate compact fields")
        return fields
    except IBMEError as exc:
        raise SerializationError(str(exc)) from exc


def _flat(vector): return tuple(x for poly in vector for x in poly)


def _rows(values, degree): return tuple(tuple(values[i:i + degree]) for i in range(0, len(values), degree))


def encode_compact(signature):
    if not isinstance(signature, LuoModuleSignature):
        raise TypeError("expected LuoModuleSignature")
    # A validated local copy prevents normalization/mutation of caller objects.
    signature = LuoModuleSignature(signature.params, signature.context, signature.z,
                                   signature.c, signature.w1, signature.h)
    p, layout = signature.params, compact_layout(signature.params)
    presence = tuple(int(value != 0) for value in signature.c)
    signs = tuple(int(value < 0) for value in signature.c if value)
    fields = (p.to_bytes(), signature.context,
              pack_bits(tuple(x + layout["z_max"] for x in _flat(signature.z)), layout["z_width"]),
              pack_bits(presence, 1), pack_bits(signs, 1),
              pack_bits(_flat(signature.w1), layout["w1_width"]), pack_bits(_flat(signature.h), 1))
    raw = _frame(fields)
    if len(raw) != layout["signature_bytes"]:
        raise SerializationError("compact signature layout invariant failed")
    return raw


def decode_compact(data, public):
    if not isinstance(public, LuoModulePublicKey):
        raise TypeError("expected LuoModulePublicKey")
    params, context, z_body, presence_body, signs_body, w1_body, hints_body = _unframe(data)
    p = public.params
    # Bounds/counts come from the already validated public key, not an
    # attacker-supplied allocation request in the embedded parameter field.
    if params != p.to_bytes() or context != public.context:
        raise SerializationError("compact signature parameter/public-context mismatch")
    layout = compact_layout(p)
    z = tuple(x - layout["z_max"] for x in unpack_bits(z_body, p.l * p.degree, layout["z_width"]))
    presence = unpack_bits(presence_body, p.degree, 1)
    if sum(presence) != p.kappa:
        raise SerializationError("compact challenge presence weight mismatch")
    signs = iter(unpack_bits(signs_body, p.kappa, 1))
    c = tuple((-1 if next(signs) else 1) if present else 0 for present in presence)
    w1 = unpack_bits(w1_body, p.k * p.degree, layout["w1_width"])
    hints = unpack_bits(hints_body, p.k * p.degree, 1)
    return LuoModuleSignature(p, context, _rows(z, p.degree), c, _rows(w1, p.degree), _rows(hints, p.degree))


@dataclass(frozen=True, eq=False, repr=False)
class LuoModuleCompactSignature(IBSSignature):
    signature: LuoModuleSignature

    def __post_init__(self):
        if not isinstance(self.signature, LuoModuleSignature):
            raise TypeError("expected a Luo mathematical signature")
        raw = self.signature
        object.__setattr__(self, "signature", LuoModuleSignature(raw.params, raw.context, raw.z, raw.c, raw.w1, raw.h))

    def to_bytes(self): return encode_compact(self.signature)

    @classmethod
    def from_bytes(cls, data, public): return cls(decode_compact(data, public))

    def __repr__(self): return "LuoModuleCompactSignature(security_claim='none')"


class LuoModuleCompactIBSBackend(LuoModuleIBSBackend):
    """Same four algorithms and state; explicit compact wire at the boundary."""

    def sign(self, sk, message): return LuoModuleCompactSignature(super().sign(sk, message))

    def verify(self, public, identity, message, signature):
        if isinstance(signature, LuoModuleCompactSignature):
            signature = signature.signature
        return super().verify(public, identity, message, signature)

    def load_signature(self, public, data): return LuoModuleCompactSignature.from_bytes(data, public)
