"""Lazy random-function *model harness*, conditional on its injected byte source.

Not a new production backend or a proof that OS entropy/SHAKE is uniform.
The table belongs to one experiment and must survive repeated calls/restore.
No addresses or secret bytes are logged. No default entropy source is provided.
"""

from .foo_li_runtime_reference import (
    AddressStream, DOMAINS, VERSION, checked_read, framed,
)
from .gaussian_reference import SamplingAbort
from .online_gaussian_reference import exact_integer


class LazyBlockOracle:
    """An ideal block RO if and only if source reads are independent uniform bytes.

    A deterministic test source only checks interface semantics. Distinct keys
    may have equal values: independence does not mean collision impossibility.
    This in-memory, single-threaded harness deliberately does not export a table.
    """

    def __init__(self, source):
        self._source = source
        self._table = {}

    @property
    def fresh_blocks(self):
        return len(self._table)

    def _block(self, address, counter):
        key = (address, counter)
        if key not in self._table:
            self._table[key] = checked_read(self._source, AddressStream.BLOCK)
        return self._table[key]

    def stream(self, domain, context, fields, length):
        if domain not in DOMAINS:
            raise ValueError("Unknown Foo-Li domain")
        address = framed(VERSION.encode(), domain, context, *fields)
        return _ModelStream(self, address, length)


class _ModelStream:
    def __init__(self, oracle, address, length):
        self._oracle, self._address = oracle, address
        self.remaining = exact_integer(length, "stream length", maximum=2**40)
        self._offset = 0

    def read(self, size):
        size = exact_integer(size, "read size", maximum=256*1024*1024)
        if size > self.remaining:
            raise SamplingAbort("Model stream exhausted; no fallback")
        parts, needed = [], size
        while needed:
            counter, offset = divmod(self._offset, AddressStream.BLOCK)
            block = self._oracle._block(self._address, counter)
            take = min(needed, AddressStream.BLOCK-offset)
            parts.append(block[offset:offset+take])
            self._offset += take
            needed -= take
        self.remaining -= size
        return b"".join(parts)
