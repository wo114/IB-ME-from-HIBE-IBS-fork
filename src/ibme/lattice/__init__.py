"""Lattice tools: params, mod-q matrices, gadget, discrete gaussian, trapdoors.

纯 Python 参考实现（仅标准库）；基于 SageMath 的优化与完整分布采样
（扰动采样、CDT 等）是后续独立工作，不在本任务范围。
模块所有权与修改边界见仓库 AGENTS.md 与 DELEGATION_PROMPTS.md 任务 B。
"""

from ibme.lattice.params import EDUCATION_PARAMS, Params, get_preset
from ibme.lattice.modmat import ModMatrix, ModVector
from ibme.lattice.gadget import bit_decompose, g_vector, gadget_matrix, gadget_width
from ibme.lattice.gaussian import (
    DEFAULT_TAIL_WIDTH,
    SeededRandom,
    sample_integer_gaussian,
    sample_vector_gaussian,
    uniform_integer,
)
from ibme.lattice.trapdoor import Trapdoor, del_trap, sample_pre, trapgen

__all__ = [
    "DEFAULT_TAIL_WIDTH",
    "EDUCATION_PARAMS",
    "Params",
    "SeededRandom",
    "Trapdoor",
    "ModMatrix",
    "ModVector",
    "bit_decompose",
    "del_trap",
    "get_preset",
    "g_vector",
    "gadget_matrix",
    "gadget_width",
    "sample_integer_gaussian",
    "sample_pre",
    "sample_vector_gaussian",
    "trapgen",
    "uniform_integer",
]
