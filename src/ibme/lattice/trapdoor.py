"""MP12 风格 G-陷门适配层（简化版，所有偏离证明级要求之处均已标注）。

结构
----
``Trapdoor`` 保存公开均匀块 ``a_bar``（n × m_bar）与短高斯**整数**矩阵
``r``（m_bar × n·k，元素不做模规范化），满足 MP12 的基本代数关系::

    public_matrix() = [ a_bar | G - a_bar·R mod q ]

等价不变式（与上式互推）::

    public_matrix() · [R ; I_{n·k}] == G   (mod q)

trapgen
-------
按上述关系采样 Ā（均匀，``ModMatrix.uniform``）与 R（离散高斯，宽度
``sigma_r`` 默认 ``params.s0``）。**注意**：教学参数下 ``m_bar`` 远小于
MP12 渐近要求（m_bar = Ω(n log q)），R 的统计质量没有渐近保证；本实现
只保证代数关系成立，不宣称陷门质量。

del_trap（陷门委派）
--------------------
MP12 风格的列扩展委派：给定 (Ā, R)，采样新的均匀块 Ā2 和短高斯 R2，
输出扩展陷门::

    a_bar' = [ Ā | Ā2 ],   r' = [ R ; R2 ],
    public' = [ Ā | Ā2 | G - Ā·R - Ā2·R2 mod q ]

代数关系与 trapgen 相同（``public' · [R; R2; I] = G``）。未做 MP12 的
平滑参数传递分析；宽度 ``sigma_r`` 由调用方显式给出。

sample_pre
----------
**简化实现，未达到证明级分布**：缺少 MP12 的扰动采样（perturbation），
输出分布与 Λ_u^⊥(A) 上的目标离散高斯存在可证明的偏差。功能上保证：

- ``A·z = u (mod q)`` 精确成立；
- ``z`` 由二进制 gadget 分解与短高斯误差线性组合而成，范数有界。

做法（G-格上采样再线性组合）：采样短高斯 ``e``，令 ``t = u - Ā·e``，
``z_g = G^{-1}(t)``（即 ``bit_decompose``），``z_1 = R·z_g + e``（整数
乘加，不做模运算），返回 ``z = (z_1, z_g)``。在安全使用前必须替换为带
扰动的完整 SamplePre；当前版本不得用于任何依赖采样分布的安全声明。

SageMath 说明：本模块为纯 Python 参考实现；基于 SageMath 的优化与完整
分布采样是后续独立工作，不在本任务范围。
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from ibme.core.errors import (
    DimensionError,
    InvalidParameterError,
    ModulusMismatchError,
)
from ibme.lattice.gadget import bit_decompose, gadget_matrix, gadget_width
from ibme.lattice.gaussian import sample_vector_gaussian
from ibme.lattice.modmat import ModMatrix, ModVector
from ibme.lattice.params import Params

__all__ = ["Trapdoor", "trapgen", "del_trap", "sample_pre"]


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_positive(value, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidParameterError(
            f"{name} must be a real number > 0, got {type(value).__name__}"
        )
    number = float(value)
    if not math.isfinite(number) or number <= 0.0:
        raise InvalidParameterError(f"{name} must be finite and > 0, got {value!r}")
    return number


@dataclass(frozen=True)
class Trapdoor:
    """MP12-style G-trapdoor: short integer matrix R with A = [a_bar | G - a_bar·R mod q]."""

    a_bar: ModMatrix
    r: tuple[tuple[int, ...], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.a_bar, ModMatrix):
            raise InvalidParameterError(
                f"Trapdoor.a_bar must be a ModMatrix, got {type(self.a_bar).__name__}"
            )
        try:
            rows = [list(row) for row in self.r]
        except TypeError as exc:
            raise InvalidParameterError(
                "Trapdoor.r must be a sequence of integer rows"
            ) from exc
        expected_cols = self.a_bar.rows * gadget_width(self.a_bar.q)
        if len(rows) != self.a_bar.cols:
            raise DimensionError(
                f"Trapdoor.r must have {self.a_bar.cols} rows (one per a_bar "
                f"column), got {len(rows)}"
            )
        for row in rows:
            if len(row) != expected_cols:
                raise DimensionError(
                    f"Trapdoor.r rows must have length {expected_cols}, got {len(row)}"
                )
            for value in row:
                if not _is_int(value):
                    raise InvalidParameterError(
                        f"Trapdoor.r entries must be int, got {type(value).__name__}"
                    )
        object.__setattr__(self, "r", tuple(tuple(row) for row in rows))

    @property
    def n(self) -> int:
        return self.a_bar.rows

    @property
    def m_bar(self) -> int:
        return self.a_bar.cols

    @property
    def q(self) -> int:
        return self.a_bar.q

    @property
    def k(self) -> int:
        return gadget_width(self.a_bar.q)

    def public_matrix(self) -> ModMatrix:
        """Return A = [a_bar | G - a_bar·R mod q]."""
        g = gadget_matrix(self.n, self.q)
        r_mod = ModMatrix([list(row) for row in self.r], self.q)
        return self.a_bar.hstack(g - self.a_bar @ r_mod)


def trapgen(params, rng=None, *, m_bar=None, sigma_r=None) -> Trapdoor:
    """Sample a uniform a_bar and a short gaussian R; return the G-trapdoor.

    ``m_bar`` 缺省为 ``params.m_matrix - n*k``（MP12 结构要求
    ``m_matrix = m_bar + n*k``）；显式传入时可覆盖，但必须 >= 1。
    ``sigma_r`` 缺省为 ``params.s0``。
    """
    if not isinstance(params, Params):
        raise InvalidParameterError(
            f"trapgen expects a Params object, got {type(params).__name__}"
        )
    n, q = params.n, params.q
    nk = n * gadget_width(q)
    if m_bar is None:
        m_bar = params.m_matrix - nk
        if m_bar < 1:
            raise InvalidParameterError(
                f"params.m_matrix ({params.m_matrix}) leaves no columns for "
                f"a_bar: need m_matrix > n*k = {nk}"
            )
    elif not _is_int(m_bar) or m_bar < 1:
        raise InvalidParameterError(f"m_bar must be an int >= 1, got {m_bar!r}")
    sigma = _check_positive(params.s0 if sigma_r is None else sigma_r, "sigma_r")
    a_bar = ModMatrix.uniform(n, m_bar, q, rng)
    r = tuple(
        tuple(sample_vector_gaussian(nk, sigma, rng=rng)) for _ in range(m_bar)
    )
    return Trapdoor(a_bar=a_bar, r=r)


def del_trap(td, rng=None, *, extra_cols, sigma_r) -> Trapdoor:
    """Delegate the trapdoor by appending a uniform block and extending R.

    输出满足 ``public' = [Ā | Ā2 | G - Ā·R - Ā2·R2 mod q]``，
    即 ``public' · [R; R2; I] = G (mod q)``。``extra_cols`` 与 ``sigma_r``
    为必需关键字参数（宽度选择属于调用方/HIBE 层的参数决策）。
    """
    if not isinstance(td, Trapdoor):
        raise InvalidParameterError(
            f"del_trap expects a Trapdoor, got {type(td).__name__}"
        )
    if not _is_int(extra_cols) or extra_cols < 1:
        raise InvalidParameterError(f"extra_cols must be an int >= 1, got {extra_cols!r}")
    sigma = _check_positive(sigma_r, "sigma_r")
    a2 = ModMatrix.uniform(td.n, extra_cols, td.q, rng)
    r2 = tuple(
        tuple(sample_vector_gaussian(td.n * td.k, sigma, rng=rng))
        for _ in range(extra_cols)
    )
    return Trapdoor(a_bar=td.a_bar.hstack(a2), r=td.r + r2)


def sample_pre(td, u, rng=None, *, sigma_e=None) -> list[int]:
    """Sample a short integer z with public_matrix()·z = u (mod q).

    简化版（**未达到证明级分布**，见模块 docstring）。``u`` 必须是与陷门
    同模、长度为 n 的 ``ModVector``。``sigma_e`` 是误差 e 的高斯宽度，
    缺省取 ``sqrt(n*k)``（教学启发式，无分布意义）。返回原始整数列表
    （可含负数），长度 ``m_bar + n*k``。
    """
    if not isinstance(td, Trapdoor):
        raise InvalidParameterError(
            f"sample_pre expects a Trapdoor, got {type(td).__name__}"
        )
    if not isinstance(u, ModVector):
        raise TypeError(f"u must be a ModVector, got {type(u).__name__}")
    if u.q != td.q:
        raise ModulusMismatchError(f"u has modulus {u.q}, trapdoor q is {td.q}")
    if u.length != td.n:
        raise DimensionError(f"u must have length n={td.n}, got {u.length}")
    n, q = td.n, td.q
    nk = n * td.k
    sigma = _check_positive(
        math.sqrt(nk) if sigma_e is None else sigma_e, "sigma_e"
    )
    e = sample_vector_gaussian(td.m_bar, sigma, rng=rng)
    w = td.a_bar.matvec(ModVector(e, q))
    t = u - w  # ModVector 运算，已规范化到 [0, q)
    bits = bit_decompose(t).to_list()
    z_head = [
        sum(r_ij * b_j for r_ij, b_j in zip(row, bits)) + e_i
        for row, e_i in zip(td.r, e)
    ]
    return z_head + bits
