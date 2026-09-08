"""统一的二进制 gadget 矩阵与按 gadget 基的分解辅助函数。

对模数 ``q`` 取 ``k = ceil(log2 q)``（即 ``(q-1).bit_length()``），

- ``g = (1, 2, 4, ..., 2^{k-1}) mod q``；
- ``G ∈ Z_q^{n×n·k}`` 为块对角矩阵：第 ``i`` 个对角块是行向量 ``g``，
  其余元素为 0。

由 ``k`` 的取法，任何 ``x ∈ [0, q)`` 满足 ``x < 2^k``，因此
``bit_decompose`` 给出的二进制分解满足 ``Σ_j b_j·2^j = x`` 这一**精确整数
等式**（不涉及模回绕），从而 ``G · bit_decompose(v) = v (mod q)`` 恒成立。
"""

from __future__ import annotations

from ibme.core.errors import InvalidParameterError
from ibme.lattice.modmat import ModMatrix, ModVector

__all__ = ["gadget_width", "g_vector", "gadget_matrix", "bit_decompose"]


def _check_q(q) -> None:
    if not isinstance(q, int) or isinstance(q, bool):
        raise InvalidParameterError(
            f"gadget modulus q must be an int, got {type(q).__name__}"
        )
    if q < 2:
        raise InvalidParameterError(f"gadget modulus q must be >= 2, got {q}")


def _check_dim(value, name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise InvalidParameterError(f"{name} must be an int >= 1, got {value!r}")


def gadget_width(q) -> int:
    """Return k = ceil(log2 q)（等价于 ``(q - 1).bit_length()``）。"""
    _check_q(q)
    return (q - 1).bit_length()


def g_vector(q) -> ModVector:
    """Return g = (1, 2, 4, ..., 2^{k-1}) mod q."""
    _check_q(q)
    k = (q - 1).bit_length()
    return ModVector([(1 << j) % q for j in range(k)], q)


def gadget_matrix(n, q) -> ModMatrix:
    """Return the block-diagonal binary gadget matrix G ∈ Z_q^{n×n·k}."""
    _check_dim(n, "n")
    _check_q(q)
    k = (q - 1).bit_length()
    g = [(1 << j) % q for j in range(k)]
    rows = []
    for i in range(n):
        row = [0] * (n * k)
        for j in range(k):
            row[i * k + j] = g[j]
        rows.append(row)
    return ModMatrix(rows, q)


def bit_decompose(vector: ModVector) -> ModVector:
    """Decompose v ∈ Z_q^n into {0,1}^{n·k} along the gadget basis.

    返回值的模数与输入相同（元素只会是 0/1，落在 [0, q) 内），因此可以直接
    计算 ``gadget_matrix(n, q) @ bit_decompose(v) == v``。
    """
    if not isinstance(vector, ModVector):
        raise TypeError(f"bit_decompose expects a ModVector, got {type(vector).__name__}")
    q = vector.q
    k = (q - 1).bit_length()
    bits: list[int] = []
    for value in vector:
        for j in range(k):
            bits.append((value >> j) & 1)
    return ModVector(bits, q)
