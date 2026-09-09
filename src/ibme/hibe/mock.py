"""TEST-ONLY mock HIBE 后端 —— 测试组件，不得用于生产。

.. warning::
   **本模块没有任何密码学安全性，仅供协议层契约测试使用。**
   它是一个基于 SHAKE-256 对称掩码的"假 HIBE"：加密密钥可以从公开信息
   （pk_seed + 身份）直接推导，任何人都能解密；它只保证满足
   :mod:`ibme.hibe.api` 的接口契约（匹配解密、不匹配返回 ``None``、
   密文不含身份明文、序列化严格往返、固定 rng 可复现），从而让协议层
   在真实格后端可用之前先通过 contract tests。

构造（全部域分隔，全部长度前缀）：

* ``setup``: ``master ← rng.read(32)``，``pk_seed = H_PK(master)``；
* ``extract``: 第一层密钥 ``k1 = H_K1(master, rcv)``（秘密链，仅保持
  密钥层级的形状，不参与解密路径——见上文警告）；
* ``derive``: ``k12 = H_K12(pk_seed, rcv, phi)``；
* ``encrypt``: 同一 ``k12`` 派生掩码 ``mask = H_MASK(k12, len)`` 与
  认证标签 ``tag = H_TAG(k12, len, masked)``；密文 = len || masked || tag；
* ``decrypt``: 用 sk2 中的 ``k12`` 重算掩码与标签；标签不匹配返回
  ``None``（因此子/父身份任一不匹配都会失败）。
"""

from __future__ import annotations

from dataclasses import dataclass

from ibme.core.encoding import decode_bytes, encode_bytes
from ibme.core.errors import (
    EncodingError,
    InvalidParameterError,
    RandomnessError,
    SerializationError,
)
from ibme.core.hashing import shake256
from ibme.core.randomness import SecureRandom
from ibme.core.types import constant_time_equal, validate_bytes, validate_identity

__all__ = [
    "MockHIBE",
    "MockHIBEPublicKey",
    "MockHIBEMasterSecret",
    "MockHIBELevel1SecretKey",
    "MockHIBELevel2SecretKey",
    "MockHIBECiphertext",
]

# 域分隔常量（本模块私有；与 core 冻结域无关的 mock 内部标签）。
_DOM_PK = b"IBME:HIBE-MOCK:PK:v1"
_DOM_K1 = b"IBME:HIBE-MOCK:K1:v1"
_DOM_K12 = b"IBME:HIBE-MOCK:K12:v1"
_DOM_MASK = b"IBME:HIBE-MOCK:MASK:v1"
_DOM_TAG = b"IBME:HIBE-MOCK:TAG:v1"

_MAGIC_PK = b"IBME:HIBE-MOCK:SER-PK:v1"
_MAGIC_MSK = b"IBME:HIBE-MOCK:SER-MSK:v1"
_MAGIC_SK1 = b"IBME:HIBE-MOCK:SER-SK1:v1"
_MAGIC_SK2 = b"IBME:HIBE-MOCK:SER-SK2:v1"
_MAGIC_CT = b"IBME:HIBE-MOCK:SER-CT:v1"

_SEED_LEN = 32
_TAG_LEN = 16


def _strip_magic(data: object, magic: bytes, what: str) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise SerializationError(f"{what}: from_bytes expects bytes")
    raw = bytes(data)
    if not raw.startswith(magic):
        raise SerializationError(f"malformed {what}: unknown version (magic mismatch)")
    return raw[len(magic):]


def _decode_field(raw: bytes, offset: int, what: str) -> tuple[bytes, int]:
    """解析一个长度前缀字段；畸形输入统一抛 ``SerializationError``。"""
    try:
        return decode_bytes(raw, offset)
    except EncodingError as exc:
        raise SerializationError(f"malformed {what}: {exc}") from exc


def _u32be(n: int) -> bytes:
    return n.to_bytes(4, "big")


def _check_seed(value: bytes, what: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)) or len(bytes(value)) != _SEED_LEN:
        raise SerializationError(f"malformed {what}: seed must be {_SEED_LEN} bytes")
    return bytes(value)


@dataclass(frozen=True)
class MockHIBEPublicKey:
    """TEST-ONLY mock 公钥：公开种子 + 消息上限。"""

    seed: bytes
    max_message_bytes: int

    def to_bytes(self) -> bytes:
        _check_seed(self.seed, "MockHIBEPublicKey")
        return _MAGIC_PK + encode_bytes(self.seed) + _u32be(self.max_message_bytes)

    @classmethod
    def from_bytes(cls, data: bytes) -> "MockHIBEPublicKey":
        raw = _strip_magic(data, _MAGIC_PK, "MockHIBEPublicKey")
        seed, off = _decode_field(raw, 0, "MockHIBEPublicKey")
        _check_seed(seed, "MockHIBEPublicKey")
        if len(raw) - off != 4:
            raise SerializationError("malformed MockHIBEPublicKey: bad trailer length")
        limit = int.from_bytes(raw[off:], "big")
        if limit < 1:
            raise SerializationError("malformed MockHIBEPublicKey: max_message_bytes < 1")
        return cls(seed=seed, max_message_bytes=limit)


@dataclass(frozen=True)
class MockHIBEMasterSecret:
    """TEST-ONLY mock 主密钥：32 字节主种子。"""

    master: bytes
    max_message_bytes: int

    def to_bytes(self) -> bytes:
        _check_seed(self.master, "MockHIBEMasterSecret")
        return _MAGIC_MSK + encode_bytes(self.master) + _u32be(self.max_message_bytes)

    @classmethod
    def from_bytes(cls, data: bytes) -> "MockHIBEMasterSecret":
        raw = _strip_magic(data, _MAGIC_MSK, "MockHIBEMasterSecret")
        master, off = _decode_field(raw, 0, "MockHIBEMasterSecret")
        _check_seed(master, "MockHIBEMasterSecret")
        if len(raw) - off != 4:
            raise SerializationError("malformed MockHIBEMasterSecret: bad trailer length")
        limit = int.from_bytes(raw[off:], "big")
        if limit < 1:
            raise SerializationError("malformed MockHIBEMasterSecret: max_message_bytes < 1")
        return cls(master=master, max_message_bytes=limit)


@dataclass(frozen=True)
class MockHIBELevel1SecretKey:
    """TEST-ONLY mock 第一层密钥：身份 + 公开种子副本 + 秘密链种子。"""

    identity: bytes
    pk_seed: bytes
    k1: bytes

    def to_bytes(self) -> bytes:
        _check_seed(self.pk_seed, "MockHIBELevel1SecretKey")
        _check_seed(self.k1, "MockHIBELevel1SecretKey")
        return (
            _MAGIC_SK1
            + encode_bytes(self.identity)
            + encode_bytes(self.pk_seed)
            + encode_bytes(self.k1)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "MockHIBELevel1SecretKey":
        raw = _strip_magic(data, _MAGIC_SK1, "MockHIBELevel1SecretKey")
        ident, off = _decode_field(raw, 0, "MockHIBELevel1SecretKey")
        if not ident:
            raise SerializationError("malformed MockHIBELevel1SecretKey: empty identity")
        seed, off = _decode_field(raw, off, "MockHIBELevel1SecretKey")
        _check_seed(seed, "MockHIBELevel1SecretKey")
        k1, off = _decode_field(raw, off, "MockHIBELevel1SecretKey")
        _check_seed(k1, "MockHIBELevel1SecretKey")
        if off != len(raw):
            raise SerializationError("malformed MockHIBELevel1SecretKey: trailing bytes")
        return cls(identity=ident, pk_seed=seed, k1=k1)


@dataclass(frozen=True)
class MockHIBELevel2SecretKey:
    """TEST-ONLY mock 第二层密钥：身份对 + 会话密钥种子 k12。"""

    parent_identity: bytes
    child_identity: bytes
    k12: bytes

    def to_bytes(self) -> bytes:
        _check_seed(self.k12, "MockHIBELevel2SecretKey")
        return (
            _MAGIC_SK2
            + encode_bytes(self.parent_identity)
            + encode_bytes(self.child_identity)
            + encode_bytes(self.k12)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "MockHIBELevel2SecretKey":
        raw = _strip_magic(data, _MAGIC_SK2, "MockHIBELevel2SecretKey")
        parent, off = _decode_field(raw, 0, "MockHIBELevel2SecretKey")
        child, off = _decode_field(raw, off, "MockHIBELevel2SecretKey")
        k12, off = _decode_field(raw, off, "MockHIBELevel2SecretKey")
        _check_seed(k12, "MockHIBELevel2SecretKey")
        if off != len(raw):
            raise SerializationError("malformed MockHIBELevel2SecretKey: trailing bytes")
        if not parent or not child:
            raise SerializationError("malformed MockHIBELevel2SecretKey: empty identity")
        return cls(parent_identity=parent, child_identity=child, k12=k12)


@dataclass(frozen=True)
class MockHIBECiphertext:
    """TEST-ONLY mock 密文：长度前缀 + 掩码字节 + 认证标签（无身份明文）。"""

    payload_len: int
    masked: bytes
    tag: bytes

    def to_bytes(self) -> bytes:
        if len(self.tag) != _TAG_LEN:
            raise SerializationError("MockHIBECiphertext: tag must be 16 bytes")
        return _MAGIC_CT + _u32be(self.payload_len) + encode_bytes(self.masked) + self.tag

    @classmethod
    def from_bytes(cls, data: bytes) -> "MockHIBECiphertext":
        raw = _strip_magic(data, _MAGIC_CT, "MockHIBECiphertext")
        if len(raw) < 4:
            raise SerializationError("malformed MockHIBECiphertext: truncated length field")
        payload_len = int.from_bytes(raw[:4], "big")
        masked, off = _decode_field(raw, 4, "MockHIBECiphertext")
        if len(raw) - off != _TAG_LEN:
            raise SerializationError("malformed MockHIBECiphertext: bad tag length")
        if payload_len != len(masked):
            raise SerializationError(
                "malformed MockHIBECiphertext: payload length does not match masked data"
            )
        return cls(payload_len=payload_len, masked=masked, tag=raw[off:])


def _derive_k12(pk_seed: bytes, parent_id: bytes, child_id: bytes) -> bytes:
    data = encode_bytes(parent_id) + encode_bytes(child_id)
    return shake256(_DOM_K12, pk_seed + data, _SEED_LEN)


class MockHIBE:
    """TEST-ONLY mock HIBE 后端 —— 测试组件，不得用于生产。

    满足 :class:`ibme.hibe.api.HIBEBackend` 的全部接口契约，但加密密钥可
    由公开信息推导，没有任何安全性；生产代码必须使用真实格基后端。
    """

    def setup(self, params, *, rng=None):
        rng = rng if rng is not None else SecureRandom()
        if not hasattr(rng, "read") or not callable(rng.read):
            raise RandomnessError("rng must provide read(n: int) -> bytes")
        master = validate_bytes(rng.read(_SEED_LEN), name="master seed")
        if len(master) != _SEED_LEN:
            raise InvalidParameterError("rng.read() returned a wrong-length master seed")
        pk_seed = shake256(_DOM_PK, master, _SEED_LEN)
        return (
            MockHIBEPublicKey(seed=pk_seed, max_message_bytes=params.max_message_bytes),
            MockHIBEMasterSecret(master=master, max_message_bytes=params.max_message_bytes),
        )

    def extract(self, msk, parent_id: bytes, *, rng=None):
        if not isinstance(msk, MockHIBEMasterSecret):
            raise TypeError("extract expects a MockHIBEMasterSecret")
        ident = validate_identity(parent_id, name="parent_id")
        k1 = shake256(_DOM_K1, msk.master + encode_bytes(ident), _SEED_LEN)
        pk_seed = shake256(_DOM_PK, msk.master, _SEED_LEN)
        return MockHIBELevel1SecretKey(identity=ident, pk_seed=pk_seed, k1=k1)

    def derive(self, sk_parent, child_id: bytes, *, rng=None):
        if not isinstance(sk_parent, MockHIBELevel1SecretKey):
            raise TypeError("derive expects a MockHIBELevel1SecretKey")
        phi = validate_identity(child_id, name="child_id")
        k12 = _derive_k12(sk_parent.pk_seed, sk_parent.identity, phi)
        return MockHIBELevel2SecretKey(
            parent_identity=sk_parent.identity, child_identity=phi, k12=k12
        )

    def encrypt(self, pk, parent_id: bytes, child_id: bytes, payload: bytes, *, rng=None):
        if not isinstance(pk, MockHIBEPublicKey):
            raise TypeError("encrypt expects a MockHIBEPublicKey")
        rcv = validate_identity(parent_id, name="parent_id")
        phi = validate_identity(child_id, name="child_id")
        message = validate_bytes(payload, name="payload")
        if len(message) > pk.max_message_bytes:
            raise InvalidParameterError(
                f"payload of {len(message)} bytes exceeds max_message_bytes={pk.max_message_bytes}"
            )
        k12 = _derive_k12(pk.seed, rcv, phi)
        # 空 payload 的掩码为空串（core.shake256 要求 out_len > 0）。
        mask = (
            shake256(_DOM_MASK, k12 + _u32be(len(message)), len(message))
            if message
            else b""
        )
        masked = bytes(a ^ b for a, b in zip(message, mask))
        tag = shake256(_DOM_TAG, k12 + _u32be(len(masked)) + masked, _TAG_LEN)
        return MockHIBECiphertext(payload_len=len(masked), masked=masked, tag=tag)

    def decrypt(self, sk_child, ct, *, rng=None):
        if not isinstance(sk_child, MockHIBELevel2SecretKey):
            raise TypeError("decrypt expects a MockHIBELevel2SecretKey")
        if not isinstance(ct, MockHIBECiphertext):
            raise TypeError("decrypt expects a MockHIBECiphertext")
        k12 = sk_child.k12
        mask = (
            shake256(_DOM_MASK, k12 + _u32be(ct.payload_len), ct.payload_len)
            if ct.payload_len
            else b""
        )
        payload = bytes(a ^ b for a, b in zip(ct.masked, mask))
        tag = shake256(_DOM_TAG, k12 + _u32be(ct.payload_len) + ct.masked, _TAG_LEN)
        if not constant_time_equal(tag, ct.tag):
            return None
        return payload

    def load_ciphertext(self, data: bytes) -> "MockHIBECiphertext":
        """从规范字节串重建 MockHIBECiphertext（严格解析；主 AI 冻结的接口）。"""
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise SerializationError(
                f"ciphertext bytes expected, got {type(data).__name__}"
            )
        return MockHIBECiphertext.from_bytes(bytes(data))
