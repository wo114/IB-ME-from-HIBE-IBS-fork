"""IBS 原语层冻结接口与共享序列化工具（owner: DELEGATION_PROMPTS.md 任务 D）。

冻结接口（ARCHITECTURE.md §4）::

    class IBSBackend(Protocol):
        def setup(self, params) -> tuple[IBSPublicKey, IBSMasterSecret]: ...
        def key_extract(self, msk, identity: bytes) -> IBSSigningKey: ...
        def sign(self, sk, message: bytes) -> IBSSignature: ...
        def verify(self, pk, identity: bytes, message: bytes, signature) -> bool: ...

所有 IBS 后端（mock 与 SIS-IBS）必须遵守的行为约定，contract tests
（tests/test_ibs_contract.py）据此对两个后端参数化运行同一契约：

1. ``verify`` 永远返回 ``bool``：身份/消息/签名类型不符、维度不符、
   方程不满足或范数超界一律返回 ``False``，不抛异常。
2. ``setup`` / ``key_extract`` / ``sign`` 是调用方编程错误的检查点：
   对象类型错误抛 ``TypeError``，参数对象非法抛 ``InvalidParameterError``，
   空身份或非字节身份抛 ``EncodingError``（复用 core 的校验器）。
3. 签名密钥绑定身份：``sign`` 的冻结签名**没有**身份参数，签名始终使用
   sk 在 ``key_extract`` 时绑定的身份，调用方无法在签名阶段“误传”另一个
   身份。sk 同时保存规范化身份 ``identity``（非空字节串）与其摘要
   ``identity_digest``（``hash_identity(identity, 32)``）。为身份 A 提取的
   sk 产生的签名，用身份 B 调用 ``verify`` 必须返回 ``False``。
4. 随机性经后端构造函数注入 ``rng``（``read(n) -> bytes`` 协议，
   ``ibme.core.randomness``），缺省 ``SecureRandom``（生产）；测试注入
   ``DeterministicRandom`` 获得逐字节可复现的输出。冻结的方法签名不变。
5. 所有可序列化对象 ``to_bytes`` 采用定长/长度前缀编码（core 约定），
   ``from_bytes`` 严格解析：拒绝截断、追加、重复字段与维度不符，往返一致。

本模块只定义接口与工具，不包含任何密码学构造。
"""

from __future__ import annotations

import math
import struct
from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable

from ibme.core.errors import (
    InvalidParameterError,
    SerializationError,
)
from ibme.lattice.params import Params

__all__ = [
    "IBSBackend",
    "IBSError",
    "IBSPublicKey",
    "IBSMasterSecret",
    "IBSSigningKey",
    "IBSSignature",
    "expect_magic",
    "f64be",
    "is_bytes_like",
    "is_identity_like",
    "read_blob",
    "read_f64",
    "read_u32",
    "require_exact_end",
    "u32be",
    "write_blob",
]


class IBSError(Exception):
    """IBS 层内部不变量被破坏（例如采样后代数关系不成立）。

    继承自项目异常基类层次之外——注意 core 的 ``IBMEError`` 是冻结层次，
    本模块按 ARCHITECTURE.md 的分层为 IBS 层追加此子类，语义上等价于
    “实现不可能到达的状态”，永远不应在正常操作中出现。
    """

    # 显式继承 Exception 而非 IBMEError：core/errors.py 属于 core 任务的
    # 冻结边界，IBS 任务不得向其追加类；此处保持独立基类以避免歧义。


@runtime_checkable
class IBSBackend(Protocol):
    """IBS 后端冻结接口（ARCHITECTURE.md §4）。

    ``setup(params)`` 返回 ``(IBSPublicKey, IBSMasterSecret)``；
    ``key_extract(msk, identity)`` 返回绑定该身份的 ``IBSSigningKey``；
    ``sign(sk, message)`` 返回 ``IBSSignature``（只使用 sk 绑定的身份）；
    ``verify(pk, identity, message, signature)`` 返回 ``bool``。
    """

    def setup(self, params: Params) -> tuple["IBSPublicKey", "IBSMasterSecret"]: ...

    def key_extract(self, msk: "IBSMasterSecret", identity: bytes) -> "IBSSigningKey": ...

    def sign(self, sk: "IBSSigningKey", message: bytes) -> "IBSSignature": ...

    def verify(
        self,
        pk: "IBSPublicKey",
        identity: bytes,
        message: bytes,
        signature: "IBSSignature",
    ) -> bool: ...

    def load_signature(
        self, pk: "IBSPublicKey", data: bytes
    ) -> "IBSSignature":
        """从规范字节串重建本后端的签名对象（严格解析，拒绝畸形输入）。

        主 AI 冻结（M3 前接口扩展）：协议层与 CLI 统一经由此方法重建
        签名，不直接依赖各后端的具体签名类（部分后端反序列化需要 pk）。
        """
        ...


# ---------------------------------------------------------------------------
# 对象基类
# ---------------------------------------------------------------------------

class IBSPublicKey(ABC):
    """IBS 公钥基类：要求规范的 ``to_bytes``/``from_bytes`` 与值相等。"""

    __slots__ = ()

    @abstractmethod
    def to_bytes(self) -> bytes:
        """规范的、确定性的序列化。"""

    @classmethod
    @abstractmethod
    def from_bytes(cls, data: bytes) -> "IBSPublicKey":
        """严格解析：拒绝截断、追加、重复字段与维度不符。"""

    def __eq__(self, other: object) -> bool:
        if type(self) is not type(other):
            return NotImplemented
        return self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        return hash((type(self), self.to_bytes()))


class IBSMasterSecret(ABC):
    """IBS 主密钥基类。"""

    __slots__ = ()

    @abstractmethod
    def to_bytes(self) -> bytes: ...

    @classmethod
    @abstractmethod
    def from_bytes(cls, data: bytes) -> "IBSMasterSecret": ...

    def __eq__(self, other: object) -> bool:
        if type(self) is not type(other):
            return NotImplemented
        return self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        return hash((type(self), self.to_bytes()))


class IBSSigningKey(ABC):
    """IBS 签名密钥基类：必须绑定规范化身份及其摘要（模块 docstring 约定 3）。"""

    __slots__ = ()

    @property
    @abstractmethod
    def identity(self) -> bytes:
        """key_extract 时绑定的规范化身份（非空字节串）。"""

    @property
    @abstractmethod
    def identity_digest(self) -> bytes:
        """``hash_identity(identity, 32)``，构造时校验一致性。"""

    @abstractmethod
    def to_bytes(self) -> bytes: ...

    @classmethod
    @abstractmethod
    def from_bytes(cls, data: bytes) -> "IBSSigningKey": ...

    def __eq__(self, other: object) -> bool:
        if type(self) is not type(other):
            return NotImplemented
        return self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        return hash((type(self), self.to_bytes()))


class IBSSignature(ABC):
    """IBS 签名基类。

    ``from_bytes`` 的参数表由各后端定义（SIS 签名解析需要公钥提供范数界
    与维度上下文，mock 只需原始字节）；共性要求是严格解析与往返一致。
    """

    __slots__ = ()

    @abstractmethod
    def to_bytes(self) -> bytes: ...

    def __eq__(self, other: object) -> bool:
        if type(self) is not type(other):
            return NotImplemented
        return self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        return hash((type(self), self.to_bytes()))


# ---------------------------------------------------------------------------
# 共享的严格序列化工具（全部抛 core 的 SerializationError / InvalidParameterError）
# ---------------------------------------------------------------------------

_U32_SIZE = 4
_U32_MAX = (1 << 32) - 1
_BYTES_LIKE = (bytes, bytearray, memoryview)


def _as_bytes(data: object, what: str) -> bytes:
    if not isinstance(data, _BYTES_LIKE):
        raise SerializationError(f"{what} must be bytes-like, got {type(data).__name__}")
    return bytes(data)


def is_bytes_like(value: object) -> bool:
    """verify 使用的宽松类型探测：任意 bytes-like（允许空，消息可为空）。"""
    return isinstance(value, _BYTES_LIKE)


def is_identity_like(value: object) -> bool:
    """verify 使用的宽松类型探测：非空 bytes-like。"""
    return isinstance(value, _BYTES_LIKE) and len(value) > 0


def u32be(n: int) -> bytes:
    """uint32 大端编码（编码方使用；非法值抛 InvalidParameterError）。"""
    if not isinstance(n, int) or isinstance(n, bool):
        raise InvalidParameterError(f"u32be expects an int, got {type(n).__name__}")
    if not 0 <= n <= _U32_MAX:
        raise InvalidParameterError(f"u32be value {n} out of uint32 range")
    return n.to_bytes(_U32_SIZE, "big")


def read_u32(data: bytes, offset: int, what: str = "field") -> tuple[int, int]:
    """在 ``offset`` 处读取一个 uint32 大端字段，返回 ``(值, 新 offset)``。"""
    raw = _as_bytes(data, "buffer")
    if not isinstance(offset, int) or isinstance(offset, bool):
        raise SerializationError(f"offset must be an int, got {type(offset).__name__}")
    if offset < 0 or offset > len(raw):
        raise SerializationError(f"offset {offset} out of range for buffer of {len(raw)} bytes")
    if len(raw) - offset < _U32_SIZE:
        raise SerializationError(f"truncated uint32 header for {what}")
    return int.from_bytes(raw[offset : offset + _U32_SIZE], "big"), offset + _U32_SIZE


def expect_magic(data: bytes, magic: bytes) -> int:
    """校验并消费固定 magic 前缀，返回其后 offset；不符抛 SerializationError。"""
    if not isinstance(magic, _BYTES_LIKE) or not magic:
        raise InvalidParameterError("magic must be non-empty bytes-like")
    raw = _as_bytes(data, "buffer")
    if len(raw) < len(magic) or raw[: len(magic)] != bytes(magic):
        raise SerializationError(
            "malformed object: missing or mismatched magic prefix "
            f"(expected {bytes(magic)!r})"
        )
    return len(magic)


def require_exact_end(data: bytes, end: int, what: str) -> None:
    """拒绝尾部多余字节（追加/重复字段的统一检查）。"""
    raw = _as_bytes(data, "buffer")
    if end != len(raw):
        raise SerializationError(
            f"malformed {what}: {len(raw) - end} trailing byte(s) after the last "
            "field (appended or duplicated data is rejected)"
        )


def f64be(x: float) -> bytes:
    """float64 大端编码；非法值抛 InvalidParameterError。"""
    if isinstance(x, bool) or not isinstance(x, (int, float)):
        raise InvalidParameterError(f"expected a real number, got {type(x).__name__}")
    if not math.isfinite(float(x)):
        raise InvalidParameterError("expected a finite real number")
    return struct.pack(">d", float(x))


def read_f64(data: bytes, offset: int, what: str = "field") -> tuple[float, int]:
    """读取 float64 大端字段；非有限值抛 SerializationError。"""
    raw = _as_bytes(data, "buffer")
    if not isinstance(offset, int) or isinstance(offset, bool):
        raise SerializationError(f"offset must be an int, got {type(offset).__name__}")
    if offset < 0 or offset > len(raw) or len(raw) - offset < 8:
        raise SerializationError(f"truncated float64 field for {what}")
    value = struct.unpack(">d", raw[offset : offset + 8])[0]
    if not math.isfinite(value):
        raise SerializationError(f"{what} is not a finite float64")
    return value, offset + 8


def write_blob(blob: bytes) -> bytes:
    """长度前缀子对象编码：``u32be(len) || blob``。"""
    if not isinstance(blob, _BYTES_LIKE):
        raise InvalidParameterError("blob must be bytes-like")
    return u32be(len(blob)) + bytes(blob)


def read_blob(data: bytes, offset: int, what: str = "blob") -> tuple[bytes, int]:
    """读取 ``u32be(len) || blob`` 子对象，先校验长度再切片（严格解析）。"""
    raw = _as_bytes(data, "buffer")
    length, offset = read_u32(raw, offset, f"{what} length")
    if len(raw) - offset < length:
        raise SerializationError(
            f"malformed {what}: length field announces {length} bytes but only "
            f"{len(raw) - offset} remain"
        )
    return raw[offset : offset + length], offset + length
