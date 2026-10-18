"""Canonical bounded integer matrices with a compact column-block backing.

Private matrices must only be written to a private state store. The byte
width follows a declared coordinate bound, never the observed secret maximum.
Only bounded native blocks are decoded; no dense transpose is materialized.
The packed backing itself is resident in this first prototype.
"""

from collections import OrderedDict

from sage.all import ZZ, matrix, vector

from .scalar import exact_integer

MAGIC = b"IBME:PACKED-ZZ-MATRIX:v1\0"
MAX_ENTRIES = 2**24
MAX_BYTES = 512*2**20


def coordinate_bytes(bound, signed):
    bound = exact_integer(bound, "coordinate bound", maximum=2**256-1)
    if type(signed) is not bool:
        raise ValueError("explicit signed matrix flag required")
    return max(1, (bound.bit_length()+int(signed)+7)//8)


class PackedMatrix:
    """Immutable column-major bytes plus a bounded, disposable native cache."""

    def __setattr__(self, name, value):
        if getattr(self, "_sealed", False) and name != "_cache_size":
            raise AttributeError("packed matrix fields are immutable")
        object.__setattr__(self, name, value)

    def __init__(self, rows, cols, bound, signed, data, *, block_columns=32,
                 cache_bytes=16*2**20):
        self.nrows = exact_integer(rows, "packed rows", minimum=1, maximum=2**20)
        self.ncols = exact_integer(cols, "packed columns", minimum=1, maximum=2**20)
        self.bound = exact_integer(bound, "coordinate bound", maximum=2**256-1)
        self.width = coordinate_bytes(self.bound, signed)
        self.signed = signed
        self.block_columns = exact_integer(block_columns, "block columns", minimum=1, maximum=1024)
        self.cache_bytes = exact_integer(cache_bytes, "native cache budget", maximum=256*2**20)
        expected = self.nrows*self.ncols*self.width
        if self.nrows*self.ncols > MAX_ENTRIES or expected > MAX_BYTES:
            raise ValueError("packed matrix resource limit")
        if type(data) is not bytes or len(data) != expected:
            raise ValueError("packed matrix payload length")
        # Reject alternate negative-zero/range representations before native work.
        for offset in range(0, expected, self.width):
            value = int.from_bytes(data[offset:offset+self.width], "big", signed=signed)
            if (signed and abs(value) > self.bound) or (not signed and value > self.bound):
                raise ValueError("packed coordinate outside its declared bound")
        self._data = data
        self._cache = OrderedDict()
        self._cache_size = 0
        self._sealed = True

    def __repr__(self):
        return f"PackedMatrix(shape=({self.nrows},{self.ncols}), private_values_hidden=True)"

    @classmethod
    def from_columns(cls, rows, cols, bound, signed, columns, **kwargs):
        rows = exact_integer(rows, "packed rows", minimum=1, maximum=2**20)
        cols = exact_integer(cols, "packed columns", minimum=1, maximum=2**20)
        width = coordinate_bytes(bound, signed)
        if rows*cols > MAX_ENTRIES or rows*cols*width > MAX_BYTES:
            raise ValueError("packed matrix resource limit")
        raw = bytearray()
        count = 0
        for column in columns:
            if count >= cols or len(column) != rows:
                raise ValueError("packed column shape")
            for item in column:
                if isinstance(item, bool) or not isinstance(item, (int, type(ZZ(0)))):
                    raise ValueError("packed matrices require exact integers")
                value = int(item)
                if abs(value) > bound or not signed and value < 0:
                    raise ValueError("packed coordinate outside its declared bound")
                raw.extend(value.to_bytes(width, "big", signed=signed))
            count += 1
        if count != cols:
            raise ValueError("packed column count")
        return cls(rows, cols, bound, signed, bytes(raw), **kwargs)

    @classmethod
    def from_rows(cls, rows, bound, signed, **kwargs):
        rows = tuple(tuple(row) for row in rows)
        if not rows or not rows[0] or any(len(row) != len(rows[0]) for row in rows):
            raise ValueError("packed row shape")
        return cls.from_columns(len(rows), len(rows[0]), bound, signed,
            (tuple(row[j] for row in rows) for j in range(len(rows[0]))), **kwargs)

    def column(self, j):
        j = exact_integer(j, "column", maximum=self.ncols-1)
        start = j*self.nrows*self.width
        raw = self._data
        return tuple(int.from_bytes(raw[i:i+self.width], "big", signed=self.signed)
                     for i in range(start, start+self.nrows*self.width, self.width))

    def columns(self):
        return (self.column(j) for j in range(self.ncols))

    def rows(self):
        # Public/toy boundary only; live secret arithmetic uses blocks below.
        result = [[] for _ in range(self.nrows)]
        for col in self.columns():
            for row, value in zip(result, col):
                row.append(value)
        return tuple(tuple(row) for row in result)

    def _block(self, start):
        if start in self._cache:
            block, cost = self._cache.pop(start)
            self._cache[start] = (block, cost)
            return block
        count = min(self.block_columns, self.ncols-start)
        block = matrix(ZZ, count, self.nrows,
                       [x for j in range(start, start+count) for x in self.column(j)]).transpose()
        block.set_immutable()
        # Conservative accounting for GMP cells; RSS is measured separately.
        cost = self.nrows*count*(64+self.width)
        if cost <= self.cache_bytes:
            while self._cache and self._cache_size+cost > self.cache_bytes:
                _, (_, old_cost) = self._cache.popitem(last=False)
                self._cache_size -= old_cost
            self._cache[start] = (block, cost)
            self._cache_size += cost
        return block

    def multiply(self, values, *, transpose=False):
        expected = self.nrows if transpose else self.ncols
        if len(values) != expected:
            raise ValueError("packed product dimension")
        if any(isinstance(x, bool) or not isinstance(x, (int, type(ZZ(0)))) for x in values):
            raise ValueError("packed product needs exact integer values")
        if transpose:
            source, out = vector(ZZ, values), []
            for start in range(0, self.ncols, self.block_columns):
                out.extend(self._block(start).transpose()*source)
            return vector(ZZ, out)
        out = vector(ZZ, self.nrows)
        for start in range(0, self.ncols, self.block_columns):
            block = self._block(start)
            out += block*vector(ZZ, values[start:start+block.ncols()])
        return out

    def norm_squared(self):
        return sum(x*x for col in self.columns() for x in col)

    def to_bytes(self):
        return (MAGIC+self.nrows.to_bytes(4, "big")+self.ncols.to_bytes(4, "big")
                +bytes([int(self.signed)])+self.bound.to_bytes(32, "big")+self._data)

    @classmethod
    def from_bytes(cls, raw, **kwargs):
        header = len(MAGIC)+41
        if type(raw) is not bytes or not header <= len(raw) <= MAX_BYTES+header or not raw.startswith(MAGIC):
            raise ValueError("packed matrix wire/version")
        pos = len(MAGIC)
        rows, cols = int.from_bytes(raw[pos:pos+4], "big"), int.from_bytes(raw[pos+4:pos+8], "big")
        flag = raw[pos+8]
        if flag not in (0, 1):
            raise ValueError("packed signed flag")
        bound = int.from_bytes(raw[pos+9:header], "big")
        return cls(rows, cols, bound, bool(flag), raw[header:], **kwargs)
