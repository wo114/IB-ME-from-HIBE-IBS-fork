"""Bounded explicit test tape; never expands a seed or falls back to entropy."""
from operator import index
from .gaussian import SamplingAbort

class FiniteByteTape:
    def __init__(self, data):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise ValueError("Random tape must be bytes")
        self.data, self.position = bytes(data), 0

    def read(self, size):
        if isinstance(size, bool):
            raise ValueError("read size must be a nonnegative integer")
        try:
            size = index(size)
        except TypeError as exc:
            raise ValueError("read size must be a nonnegative integer") from exc
        if size < 0:
            raise ValueError("read size must be nonnegative")
        if self.position + size > len(self.data):
            raise SamplingAbort("Finite random tape exhausted; no entropy fallback")
        result = self.data[self.position:self.position + size]
        self.position += size
        return result
