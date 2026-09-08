"""Lattice parameter objects (owner: lattice task).

``Params`` 的字段列表与 IMPLEMENTATION_SPEC.md §2 完全一致，不得增删或改名
（``m_matrix`` 表示矩阵列数，消息一律叫 ``message``）。所有密码算法参数都
必须从 ``Params`` 对象读取（ARCHITECTURE.md §6），不允许在代码中散落常数。

本模块当前只内置一个极小的教学参数预设 ``EDUCATION_PARAMS``：

- security_claim: none —— 未做任何格安全估计（没有 LWE/SIS 估计器输出）；
- 仅用于纯 Python 功能调试与测试（秒级完成），不得用于任何安全声明、
  性能宣称或生产部署；
- 对应的纯文档记录见仓库根目录 ``params/education.yaml``（运行时不解析
  YAML，不引入 PyYAML 依赖；代码中的权威定义是本文件的 ``EDUCATION_PARAMS``）。
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from ibme.core.errors import InvalidParameterError

__all__ = ["Params", "EDUCATION_PARAMS", "get_preset"]

# 序列化头部把 q 编码为 uint32（见 modmat.py），因此 q 必须 < 2**32。
_Q_LIMIT = 1 << 32

_INT_FIELDS = (
    "security_parameter",
    "n",
    "m_matrix",
    "q",
    "identity_bytes",
    "max_message_bytes",
)
_WIDTH_FIELDS = ("s0", "s", "s_prime")


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass(frozen=True)
class Params:
    """Lattice parameter set; fields exactly per IMPLEMENTATION_SPEC.md §2.

    教学参数不得用于任何安全声明（见 EDUCATION_PARAMS 的文档）。
    """

    name: str
    security_parameter: int
    n: int
    m_matrix: int
    q: int
    s0: float
    s: float
    s_prime: float
    identity_bytes: int
    max_message_bytes: int

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise InvalidParameterError(
                f"Params.name must be a non-empty str, got {self.name!r}"
            )
        for field_name in _INT_FIELDS:
            value = getattr(self, field_name)
            if not _is_int(value):
                raise InvalidParameterError(
                    f"Params.{field_name} must be an int, got {type(value).__name__}"
                )
            if value < 1:
                raise InvalidParameterError(
                    f"Params.{field_name} must be >= 1, got {value}"
                )
        if self.q < 2:
            raise InvalidParameterError(f"Params.q must be >= 2, got {self.q}")
        if self.q >= _Q_LIMIT:
            raise InvalidParameterError(
                "Params.q must be < 2**32 (uint32 serialization header limit)"
            )
        for field_name in _WIDTH_FIELDS:
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise InvalidParameterError(
                    f"Params.{field_name} must be a real number > 0, "
                    f"got {type(value).__name__}"
                )
            if not math.isfinite(float(value)) or value <= 0:
                raise InvalidParameterError(
                    f"Params.{field_name} must be finite and > 0, got {value!r}"
                )


#: 极小教学参数预设：**仅调试用途，security_claim: none**。
#: 未做格安全估计，不得用于任何安全声明。
EDUCATION_PARAMS = Params(
    name="education",
    security_parameter=8,
    n=8,
    m_matrix=80,  # = n + n*k，其中 k = ceil(log2 257) = 9
    q=257,
    s0=4.0,
    s=10.0,
    s_prime=12.0,
    identity_bytes=8,
    max_message_bytes=32,
)

_PRESETS = {"education": EDUCATION_PARAMS}


def get_preset(name: str) -> Params:
    """Return a built-in parameter preset by name (currently only 'education')."""
    if not isinstance(name, str) or name not in _PRESETS:
        raise InvalidParameterError(
            f"unknown parameter preset {name!r}; available: {sorted(_PRESETS)}"
        )
    return _PRESETS[name]
