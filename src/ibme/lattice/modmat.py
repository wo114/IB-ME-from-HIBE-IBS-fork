"""Dense matrices and vectors over Z_q (pure Python integers).

约定
----
- 所有元素在构造时统一规范化到 ``[0, q)``；输入允许任意 int（含负数）；
- ``q`` 必须是满足 ``2 <= q < 2**32`` 的整数（序列化头部使用 uint32）；
- 所有二元运算先检查模数一致（``ModulusMismatchError``），再检查维度一致
  （``DimensionError``）；构造参数非法抛 ``InvalidParameterError``；
- 范数（``norm2``/``norm_inf``/``centered``）基于中心化代表元
  （``(-q/2, q/2]``），使用精确整数运算；
- ``ModMatrix.uniform`` 生成**均匀**随机矩阵（对 MP12 的公开块 Ā 是正确
  语义），与离散高斯采样（gaussian.py）是两回事，不得混用。

序列化格式（定长、自描述、行优先）
----------------------------------
::

    ModMatrix: uint32_be(rows) || uint32_be(cols) || uint32_be(q)
               || rows*cols 个 uint_be 元素（每个 ceil(bit_length(q)/8) 字节）
    ModVector: uint32_be(length) || uint32_be(q) || length 个同格式元素

反序列化严格拒绝截断、尾随垃圾、非法维度、非法 q 以及 >= q 的元素，
一律抛 ``SerializationError``。

本模块是 lattice 任务的一部分（见仓库 AGENTS.md 的修改边界）。
"""

from __future__ import annotations

from ibme.core.errors import (
    DimensionError,
    InvalidParameterError,
    ModulusMismatchError,
    RandomnessError,
    SerializationError,
)

__all__ = ["ModMatrix", "ModVector"]

_HEADER_BYTES = 4
_Q_LIMIT = 1 << 32


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_modulus(q, where: str) -> int:
    if not _is_int(q):
        raise InvalidParameterError(
            f"{where}: modulus q must be an int, got {type(q).__name__}"
        )
    if q < 2:
        raise InvalidParameterError(f"{where}: modulus q must be >= 2, got {q}")
    if q >= _Q_LIMIT:
        raise InvalidParameterError(
            f"{where}: modulus q must be < 2**32 (uint32 serialization header), got {q}"
        )
    return q


def _check_dims(rows, cols, where: str) -> None:
    if not _is_int(rows) or not _is_int(cols):
        raise InvalidParameterError(
            f"{where}: rows and cols must be ints, got {rows!r}x{cols!r}"
        )
    if rows < 1 or cols < 1:
        raise InvalidParameterError(
            f"{where}: rows and cols must be >= 1, got {rows}x{cols}"
        )


def _check_rng(rng):
    if not (hasattr(rng, "read") and callable(rng.read)):
        raise RandomnessError(
            "randomness source must provide a callable read(n: int) -> bytes"
        )
    return rng


def _elem_size(q: int) -> int:
    return (q.bit_length() + 7) // 8


class ModVector:
    """Column/row-agnostic integer vector over Z_q, entries normalized to [0, q)."""

    __slots__ = ("_data", "_q")

    def __init__(self, entries, q) -> None:
        q = _check_modulus(q, "ModVector")
        try:
            raw = list(entries)
        except TypeError as exc:
            raise InvalidParameterError(
                "ModVector entries must be an iterable of ints"
            ) from exc
        if len(raw) < 1:
            raise InvalidParameterError("ModVector length must be >= 1")
        for value in raw:
            if not _is_int(value):
                raise InvalidParameterError(
                    f"ModVector entries must be int, got {type(value).__name__}"
                )
        self._data = tuple(value % q for value in raw)
        self._q = q

    # -- basic accessors ---------------------------------------------------

    @property
    def q(self) -> int:
        return self._q

    @property
    def length(self) -> int:
        return len(self._data)

    def to_list(self) -> list[int]:
        return list(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __iter__(self):
        return iter(self._data)

    def __getitem__(self, index):
        return self._data[index]

    def __eq__(self, other) -> bool:
        if not isinstance(other, ModVector):
            return NotImplemented
        return self._q == other.q and self._data == other._data

    def __repr__(self) -> str:
        return f"ModVector(length={len(self._data)}, q={self._q})"

    # -- arithmetic --------------------------------------------------------

    def _binary(self, other, combine, op_name: str) -> "ModVector":
        if not isinstance(other, ModVector):
            raise TypeError(
                f"{op_name} expects a ModVector, got {type(other).__name__}"
            )
        if self._q != other.q:
            raise ModulusMismatchError(
                f"{op_name}: moduli {self._q} and {other.q} differ"
            )
        if len(self._data) != other.length:
            raise DimensionError(
                f"{op_name}: lengths {len(self._data)} and {other.length} differ"
            )
        return ModVector(
            [combine(a, b) for a, b in zip(self._data, other._data)], self._q
        )

    def __add__(self, other) -> "ModVector":
        return self._binary(other, lambda a, b: a + b, "vector addition")

    def __sub__(self, other) -> "ModVector":
        return self._binary(other, lambda a, b: a - b, "vector subtraction")

    def __neg__(self) -> "ModVector":
        return ModVector([-value for value in self._data], self._q)

    def scale(self, k: int) -> "ModVector":
        """Multiply every entry by the integer k modulo q."""
        if not _is_int(k):
            raise InvalidParameterError(f"scale factor must be an int, got {type(k).__name__}")
        return ModVector([k * value for value in self._data], self._q)

    def dot(self, other: "ModVector") -> int:
        """Inner product reduced modulo q."""
        return self._dot_checked(other)

    def _dot_checked(self, other: "ModVector") -> int:
        if not isinstance(other, ModVector):
            raise TypeError(f"dot expects a ModVector, got {type(other).__name__}")
        if self._q != other.q:
            raise ModulusMismatchError(
                f"dot: moduli {self._q} and {other.q} differ"
            )
        if len(self._data) != other.length:
            raise DimensionError(
                f"dot: lengths {len(self._data)} and {other.length} differ"
            )
        total = sum(a * b for a, b in zip(self._data, other._data))
        return total % self._q

    # -- norms ---------------------------------------------------------------

    def centered(self) -> list[int]:
        """Representatives in (-q/2, q/2]."""
        return [value if 2 * value < self._q else value - self._q for value in self._data]

    def norm2_squared(self) -> int:
        """Exact squared Euclidean norm of the centered representative."""
        return sum(c * c for c in self.centered())

    def norm_inf(self) -> int:
        """Infinity norm of the centered representative."""
        return max(abs(c) for c in self.centered())

    # -- serialization -------------------------------------------------------

    def to_bytes(self) -> bytes:
        elem = _elem_size(self._q)
        return (
            len(self._data).to_bytes(_HEADER_BYTES, "big")
            + self._q.to_bytes(_HEADER_BYTES, "big")
            + b"".join(value.to_bytes(elem, "big") for value in self._data)
        )

    @classmethod
    def from_bytes(cls, data) -> "ModVector":
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise SerializationError("ModVector.from_bytes expects bytes")
        raw = bytes(data)
        if len(raw) < 2 * _HEADER_BYTES:
            raise SerializationError("truncated header")
        length = int.from_bytes(raw[:_HEADER_BYTES], "big")
        q = int.from_bytes(raw[_HEADER_BYTES : 2 * _HEADER_BYTES], "big")
        if not 1 <= length < _Q_LIMIT:
            raise SerializationError(f"invalid vector length {length}")
        if not 2 <= q < _Q_LIMIT:
            raise SerializationError(f"invalid modulus {q} in serialized vector")
        elem = _elem_size(q)
        expected = 2 * _HEADER_BYTES + length * elem
        if len(raw) != expected:
            raise SerializationError(
                f"serialized vector length mismatch: expected {expected} bytes, got {len(raw)}"
            )
        entries = [
            int.from_bytes(raw[2 * _HEADER_BYTES + i * elem : 2 * _HEADER_BYTES + (i + 1) * elem], "big")
            for i in range(length)
        ]
        for value in entries:
            if value >= q:
                raise SerializationError(
                    f"serialized entry {value} is out of range [0, {q})"
                )
        return cls(entries, q)


class ModMatrix:
    """Dense matrix over Z_q, entries normalized to [0, q), row-major storage."""

    __slots__ = ("_rows", "_cols", "_q")

    def __init__(self, rows, q) -> None:
        q = _check_modulus(q, "ModMatrix")
        try:
            raw_rows = [list(row) for row in rows]
        except TypeError as exc:
            raise InvalidParameterError(
                "ModMatrix rows must be an iterable of integer rows"
            ) from exc
        _check_dims(len(raw_rows), len(raw_rows[0]) if raw_rows else 0, "ModMatrix")
        for row in raw_rows:
            for value in row:
                if not _is_int(value):
                    raise InvalidParameterError(
                        f"ModMatrix entries must be int, got {type(value).__name__}"
                    )
        width = len(raw_rows[0])
        for row in raw_rows:
            if len(row) != width:
                raise InvalidParameterError(
                    f"ModMatrix rows must be rectangular: got widths {width} and {len(row)}"
                )
        self._rows = tuple(tuple(value % q for value in row) for row in raw_rows)
        self._cols = width
        self._q = q

    # -- constructors --------------------------------------------------------

    @classmethod
    def zeros(cls, rows: int, cols: int, q: int) -> "ModMatrix":
        _check_dims(rows, cols, "ModMatrix.zeros")
        _check_modulus(q, "ModMatrix.zeros")
        return cls([[0] * cols for _ in range(rows)], q)

    @classmethod
    def identity(cls, n: int, q: int) -> "ModMatrix":
        _check_dims(n, n, "ModMatrix.identity")
        _check_modulus(q, "ModMatrix.identity")
        return cls(
            [[1 if i == j else 0 for j in range(n)] for i in range(n)], q
        )

    @classmethod
    def uniform(cls, rows: int, cols: int, q: int, rng=None) -> "ModMatrix":
        """Uniformly random matrix over [0, q).

        ``rng`` 必须遵循 ``read(n: int) -> bytes`` 协议；``None`` 表示
        系统随机源（gaussian.py 的默认源）。字节拒绝采样消除模偏差。
        注意这是**均匀**采样，只用于公开均匀块，不是高斯采样。
        """
        from ibme.lattice.gaussian import uniform_integer

        _check_dims(rows, cols, "ModMatrix.uniform")
        _check_modulus(q, "ModMatrix.uniform")
        rng = _check_rng(rng) if rng is not None else rng
        return cls(
            [[uniform_integer(rng, q) for _ in range(cols)] for _ in range(rows)],
            q,
        )

    # -- basic accessors -----------------------------------------------------

    @property
    def rows(self) -> int:
        return len(self._rows)

    @property
    def cols(self) -> int:
        return self._cols

    @property
    def q(self) -> int:
        return self._q

    def to_lists(self) -> list[list[int]]:
        return [list(row) for row in self._rows]

    def row(self, i: int) -> ModVector:
        return ModVector(list(self._rows[i]), self._q)

    def col(self, j: int) -> ModVector:
        return ModVector([self._rows[i][j] for i in range(len(self._rows))], self._q)

    def __getitem__(self, index):
        return self._rows[index]

    def __eq__(self, other) -> bool:
        if not isinstance(other, ModMatrix):
            return NotImplemented
        return (
            self._q == other.q
            and self._rows == other._rows
        )

    def __repr__(self) -> str:
        return f"ModMatrix(rows={len(self._rows)}, cols={self._cols}, q={self._q})"

    # -- checked helpers -----------------------------------------------------

    def _require_same_modulus(self, other: "ModMatrix", op_name: str) -> None:
        if self._q != other.q:
            raise ModulusMismatchError(
                f"{op_name}: moduli {self._q} and {other.q} differ"
            )

    def _require_same_shape(self, other: "ModMatrix", op_name: str) -> None:
        if len(self._rows) != other.rows or self._cols != other.cols:
            raise DimensionError(
                f"{op_name}: shapes {len(self._rows)}x{self._cols} and "
                f"{other.rows}x{other.cols} differ"
            )

    # -- arithmetic ----------------------------------------------------------

    def __add__(self, other: "ModMatrix") -> "ModMatrix":
        if not isinstance(other, ModMatrix):
            return NotImplemented
        self._require_same_modulus(other, "matrix addition")
        self._require_same_shape(other, "matrix addition")
        return ModMatrix(
            [
                [a + b for a, b in zip(row_a, row_b)]
                for row_a, row_b in zip(self._rows, other._rows)
            ],
            self._q,
        )

    def __sub__(self, other: "ModMatrix") -> "ModMatrix":
        if not isinstance(other, ModMatrix):
            return NotImplemented
        self._require_same_modulus(other, "matrix subtraction")
        self._require_same_shape(other, "matrix subtraction")
        return ModMatrix(
            [
                [a - b for a, b in zip(row_a, row_b)]
                for row_a, row_b in zip(self._rows, other._rows)
            ],
            self._q,
        )

    def __neg__(self) -> "ModMatrix":
        return ModMatrix([[-value for value in row] for row in self._rows], self._q)

    def scale(self, k: int) -> "ModMatrix":
        """Multiply every entry by the integer k modulo q."""
        if not _is_int(k):
            raise InvalidParameterError(
                f"scale factor must be an int, got {type(k).__name__}"
            )
        return ModMatrix([[k * value for value in row] for row in self._rows], self._q)

    def __mul__(self, other):
        if _is_int(other):
            return self.scale(other)
        return NotImplemented

    def mul_matrix(self, other: "ModMatrix") -> "ModMatrix":
        if not isinstance(other, ModMatrix):
            raise TypeError(f"matrix product expects a ModMatrix, got {type(other).__name__}")
        self._require_same_modulus(other, "matrix product")
        if self._cols != other.rows:
            raise DimensionError(
                f"matrix product: {len(self._rows)}x{self._cols} @ {other.rows}x{other.cols}"
            )
        other_cols = other.cols
        result = [
            [
                sum(a * b for a, b in zip(row_a, col_b)) % self._q
                for col_b in zip(*other._rows)
            ]
            for row_a in self._rows
        ]
        return ModMatrix(result, self._q)

    def matvec(self, vector: ModVector) -> ModVector:
        """Matrix-vector product with an integer vector modulo q."""
        if not isinstance(vector, ModVector):
            raise TypeError(f"matvec expects a ModVector, got {type(vector).__name__}")
        if self._q != vector.q:
            raise ModulusMismatchError(
                f"matvec: moduli {self._q} and {vector.q} differ"
            )
        if self._cols != vector.length:
            raise DimensionError(
                f"matvec: matrix has {self._cols} columns but vector has length {vector.length}"
            )
        data = vector.to_list()
        return ModVector(
            [sum(a * x for a, x in zip(row, data)) % self._q for row in self._rows],
            self._q,
        )

    def __matmul__(self, other):
        if isinstance(other, ModMatrix):
            return self.mul_matrix(other)
        if isinstance(other, ModVector):
            return self.matvec(other)
        return NotImplemented

    def hstack(self, other: "ModMatrix") -> "ModMatrix":
        """Horizontal concatenation [A | B]."""
        if not isinstance(other, ModMatrix):
            raise TypeError(f"hstack expects a ModMatrix, got {type(other).__name__}")
        self._require_same_modulus(other, "hstack")
        if len(self._rows) != other.rows:
            raise DimensionError(
                f"hstack: row counts {len(self._rows)} and {other.rows} differ"
            )
        return ModMatrix(
            [list(row_a) + list(row_b) for row_a, row_b in zip(self._rows, other._rows)],
            self._q,
        )

    def transpose(self) -> "ModMatrix":
        return ModMatrix(
            [list(col) for col in zip(*self._rows)] if self._rows else [],
            self._q,
        )

    # -- serialization -------------------------------------------------------

    def to_bytes(self) -> bytes:
        elem = _elem_size(self._q)
        payload = b"".join(
            value.to_bytes(elem, "big") for row in self._rows for value in row
        )
        return (
            len(self._rows).to_bytes(_HEADER_BYTES, "big")
            + self._cols.to_bytes(_HEADER_BYTES, "big")
            + self._q.to_bytes(_HEADER_BYTES, "big")
            + payload
        )

    @classmethod
    def from_bytes(cls, data) -> "ModMatrix":
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise SerializationError("ModMatrix.from_bytes expects bytes")
        raw = bytes(data)
        if len(raw) < 3 * _HEADER_BYTES:
            raise SerializationError("truncated header")
        rows = int.from_bytes(raw[:_HEADER_BYTES], "big")
        cols = int.from_bytes(raw[_HEADER_BYTES : 2 * _HEADER_BYTES], "big")
        q = int.from_bytes(raw[2 * _HEADER_BYTES : 3 * _HEADER_BYTES], "big")
        if not 1 <= rows < _Q_LIMIT or not 1 <= cols < _Q_LIMIT:
            raise SerializationError(f"invalid matrix dimensions {rows}x{cols}")
        if not 2 <= q < _Q_LIMIT:
            raise SerializationError(f"invalid modulus {q} in serialized matrix")
        elem = _elem_size(q)
        expected = 3 * _HEADER_BYTES + rows * cols * elem
        if len(raw) != expected:
            raise SerializationError(
                f"serialized matrix length mismatch: expected {expected} bytes, got {len(raw)}"
            )
        offset = 3 * _HEADER_BYTES
        values = [
            int.from_bytes(raw[offset + i * elem : offset + (i + 1) * elem], "big")
            for i in range(rows * cols)
        ]
        for value in values:
            if value >= q:
                raise SerializationError(
                    f"serialized entry {value} is out of range [0, {q})"
                )
        grid = [values[i * cols : (i + 1) * cols] for i in range(rows)]
        return cls(grid, q)
