"""Byte-identical prepared SHAKE streams for combined canonical contexts.

An optional research adapter; the teammate's original stream and snapshots are
unchanged. Only SHAKE absorption is cached, never noise, samples or signatures.
"""

from ibme.core.encoding import encode_bytes
from ibme.core.hashing import PreparedShake256
from .foo_li_runtime_reference import AddressStream, DOMAINS, VERSION, framed
from .gaussian_reference import SamplingAbort
from .online_gaussian_reference import exact_integer


class PreparedAddressStream:
    BLOCK = AddressStream.BLOCK

    def __init__(self, address, length):
        if not isinstance(address, bytes):
            raise ValueError("Prepared addresses must be immutable bytes")
        self.remaining = exact_integer(length, "stream length", maximum=2**40)
        self.counter, self.buffer = 0, b""
        self._prefix = PreparedShake256(b"IBME:FooLi:stream:v1", encode_bytes(address))

    def read(self, size):
        size = exact_integer(size, "read size", maximum=256*1024*1024)
        if size > self.remaining:
            raise SamplingAbort("Address stream exhausted; no fallback")
        parts, needed = [], size
        while needed:
            if not self.buffer:
                suffix = encode_bytes(self.counter.to_bytes(8, "big"))
                self.buffer = self._prefix.digest(suffix, self.BLOCK)
                self.counter += 1
            take = min(needed, len(self.buffer))
            parts.append(self.buffer[:take])
            self.buffer = self.buffer[take:]
            needed -= take
        self.remaining -= size
        return b"".join(parts)


class PreparedShakeOracleCandidate:
    def stream(self, domain, context, fields, length):
        if domain not in DOMAINS:
            raise ValueError("Unknown Foo-Li domain")
        return PreparedAddressStream(framed(VERSION.encode(), domain, context, *fields), length)
