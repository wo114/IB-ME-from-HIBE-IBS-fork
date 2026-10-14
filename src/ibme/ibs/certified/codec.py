"""Bounded, ordered tagged fields for the certification construction."""
import struct

from ibme.core.errors import SerializationError

MAX_OBJECT = 8 * 1024 * 1024


def blob(value):
    return struct.pack(">I", len(value)) + value


def framed(domain, *values):
    return b"".join(blob(value) for value in (domain, *values))


def encode(magic, *values):
    return magic + b"".join(bytes([tag]) + blob(value) for tag, value in enumerate(values, 1))


def decode(data, magic, count, *, limit=MAX_OBJECT):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise SerializationError("certified IBS object must be bytes")
    try:
        # nbytes counts the entire view, including non-byte formats and extra
        # dimensions. Holding a view also prevents resizing a bytearray between
        # the limit check and the bounded copy.
        with memoryview(data) as view:
            if view.nbytes > limit:
                raise SerializationError("certified IBS object exceeds resource limit")
            data = view.tobytes()
    except ValueError as exc:
        raise SerializationError("invalid or released certified IBS input buffer") from exc
    if not data.startswith(magic):
        raise SerializationError("certified IBS object magic/version mismatch")
    offset = len(magic)
    values = []
    for tag in range(1, count + 1):
        if offset + 5 > len(data) or data[offset] != tag:
            raise SerializationError("missing, duplicate, unordered or unknown certified IBS tag")
        size = struct.unpack_from(">I", data, offset + 1)[0]
        offset += 5
        if size > len(data) - offset:
            raise SerializationError("truncated certified IBS field")
        values.append(data[offset:offset + size])
        offset += size
    if offset != len(data):
        raise SerializationError("appended or duplicate certified IBS field")
    return values


class Cursor:
    """Inner length framing; never allocate from an untrusted length."""
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def take(self, size):
        if size > len(self.data) - self.offset:
            raise SerializationError("truncated certified IBS issuance state")
        value = self.data[self.offset:self.offset + size]
        self.offset += size
        return value

    def number(self):
        return int.from_bytes(self.take(4), "big")

    def field(self):
        return self.take(self.number())

    def end(self):
        if self.offset != len(self.data):
            raise SerializationError("appended certified IBS issuance state")
