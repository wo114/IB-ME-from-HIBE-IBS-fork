"""TEST-ONLY mock IBS 后端（HMAC-SHAKE 风格）。

**TEST-ONLY / 测试组件，不得用于生产。**
**TEST-ONLY / 测试组件，不得用于生产。**
（重复两遍以防被忽略。）

本模块的唯一目的是为协议层和 contract tests（tests/test_ibs_contract.py）
提供一个满足 :class:`~ibme.ibs.api.IBSBackend` 契约的轻量替身，使 M2 之后的
协议组合工作不必等待真实格实现。

安全性声明（必须随任何使用本模块的报告一同写明）：

* 本 mock **没有任何安全性**。``verify`` 必须能从"公钥"为任意身份重导出
  每身份密钥，因此 :class:`MockPublicKey` 内部直接携带主密钥材料——等价于
  把 msk 公开。这只保证接口行为（诚实签名通过、篡改/随机伪造仅按
  SHAKE-256 碰撞概率失败），不提供任何不可伪造性或隐私性。
* 绝不能用于生产、安全演示、性能对比或安全声明。

构造（全部为哈希运算，无格运算）::

    msk     = rng.read(32)                     # 测试种子或 CSPRNG
    k_id    = SHAKE256(KEY_DOMAIN, msk || enc(id), 32)
    tag     = SHAKE256(SIG_DOMAIN, k_id || enc(id) || enc(m), 32)
    verify  = 常数时间比较 tag

序列化格式（严格解析，见 ibme.ibs.api 的工具函数）::

    MockPublicKey   "IBS1-M-PK"  || master(32)
    MockMasterSecret "IBS1-M-MSK" || master(32)
    MockSigningKey  "IBS1-M-SK"  || enc(identity) || digest(32) || k_id(32)
    MockSignature   "IBS1-M-SIG" || tag(32)
"""

from __future__ import annotations

from ibme.core import (
    EncodingError,
    InvalidParameterError,
    RandomnessError,
    SecureRandom,
    SerializationError,
    constant_time_equal,
    decode_bytes,
    encode_bytes,
    hash_identity,
    shake256,
    validate_bytes,
    validate_identity,
)
from ibme.lattice.params import Params

from .api import (
    IBSPublicKey,
    IBSMasterSecret,
    IBSSignature,
    IBSSigningKey,
    expect_magic,
    is_bytes_like,
    is_identity_like,
)

__all__ = [
    "MockIBSBackend",
    "MockMasterSecret",
    "MockPublicKey",
    "MockSignature",
    "MockSigningKey",
]

_KEY_DOMAIN = b"IBME:IBS-MOCK:KEY:v1"
_SIG_DOMAIN = b"IBME:IBS-MOCK:SIG:v1"
_KEY_LEN = 32
_DIGEST_LEN = 32

_MAG_PK = b"IBS1-M-PK"
_MAG_MSK = b"IBS1-M-MSK"
_MAG_SK = b"IBS1-M-SK"
_MAG_SIG = b"IBS1-M-SIG"

_BYTES_LIKE = (bytes, bytearray, memoryview)


def _require_bytes32(value: object, name: str) -> bytes:
    if not isinstance(value, _BYTES_LIKE) or len(value) != _KEY_LEN:
        got_len = len(value) if isinstance(value, _BYTES_LIKE) else "n/a"
        raise InvalidParameterError(
            f"{name} must be {_KEY_LEN} bytes, got "
            f"{type(value).__name__} of length {got_len}"
        )
    return bytes(value)


class MockPublicKey(IBSPublicKey):
    """TEST-ONLY mock 公钥：内部携带主密钥材料（等于公开 msk，见模块 docstring）。"""

    __slots__ = ("_master",)

    def __init__(self, master: bytes) -> None:
        self._master = _require_bytes32(master, "MockPublicKey.master")

    @property
    def master(self) -> bytes:
        """TEST-ONLY：这就是主密钥材料，仅测试可读。"""
        return self._master

    def to_bytes(self) -> bytes:
        return _MAG_PK + self._master

    @classmethod
    def from_bytes(cls, data: bytes) -> "MockPublicKey":
        offset = expect_magic(data, _MAG_PK)
        raw = bytes(data)
        if len(raw) - offset != _KEY_LEN:
            raise SerializationError(
                f"malformed MockPublicKey: expected exactly {offset + _KEY_LEN} "
                f"bytes, got {len(raw)} (truncated or trailing data is rejected)"
            )
        return cls(raw[offset:])


class MockMasterSecret(IBSMasterSecret):
    """TEST-ONLY mock 主密钥（32 字节种子；pk 由同一材料导出）。"""

    __slots__ = ("_master", "_pk")

    def __init__(self, master: bytes, public_key: MockPublicKey | None = None) -> None:
        self._master = _require_bytes32(master, "MockMasterSecret.master")
        derived = MockPublicKey(self._master)
        if public_key is not None:
            if not isinstance(public_key, MockPublicKey) or public_key != derived:
                raise InvalidParameterError(
                    "public_key does not match the master material"
                )
        self._pk = derived

    @property
    def master(self) -> bytes:
        return self._master

    @property
    def public_key(self) -> MockPublicKey:
        return self._pk

    def to_bytes(self) -> bytes:
        return _MAG_MSK + self._master

    @classmethod
    def from_bytes(cls, data: bytes) -> "MockMasterSecret":
        offset = expect_magic(data, _MAG_MSK)
        raw = bytes(data)
        if len(raw) - offset != _KEY_LEN:
            raise SerializationError(
                f"malformed MockMasterSecret: expected exactly {offset + _KEY_LEN} "
                f"bytes, got {len(raw)} (truncated or trailing data is rejected)"
            )
        return cls(raw[offset:])


class MockSigningKey(IBSSigningKey):
    """TEST-ONLY mock 签名密钥：绑定身份与身份摘要（接口约定 3）。"""

    __slots__ = ("_identity", "_digest", "_key")

    def __init__(self, identity: bytes, identity_digest: bytes, key: bytes) -> None:
        ident = validate_identity(identity)
        digest = _require_bytes32(identity_digest, "identity_digest")
        k = _require_bytes32(key, "key")
        if digest != hash_identity(ident, _DIGEST_LEN):
            raise InvalidParameterError(
                "identity_digest does not match hash_identity(identity)"
            )
        self._identity = ident
        self._digest = digest
        self._key = k

    @property
    def identity(self) -> bytes:
        return self._identity

    @property
    def identity_digest(self) -> bytes:
        return self._digest

    @property
    def key(self) -> bytes:
        return self._key

    def to_bytes(self) -> bytes:
        return (
            _MAG_SK
            + encode_bytes(self._identity)
            + self._digest
            + self._key
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "MockSigningKey":
        offset = expect_magic(data, _MAG_SK)
        raw = bytes(data)
        try:
            identity, offset = decode_bytes(raw, offset)
        except EncodingError as exc:
            raise SerializationError(f"malformed MockSigningKey: {exc}") from exc
        if not identity:
            raise SerializationError("malformed MockSigningKey: empty identity")
        if len(raw) - offset != _DIGEST_LEN + _KEY_LEN:
            raise SerializationError(
                f"malformed MockSigningKey: expected {_DIGEST_LEN + _KEY_LEN} "
                f"bytes after the identity, got {len(raw) - offset}"
            )
        digest = raw[offset : offset + _DIGEST_LEN]
        key = raw[offset + _DIGEST_LEN :]
        try:
            return cls(identity=identity, identity_digest=digest, key=key)
        except InvalidParameterError as exc:
            raise SerializationError(
                f"malformed MockSigningKey: {exc}"
            ) from exc


class MockSignature(IBSSignature):
    """TEST-ONLY mock 签名（32 字节 tag）。"""

    __slots__ = ("_tag",)

    def __init__(self, tag: bytes) -> None:
        self._tag = _require_bytes32(tag, "MockSignature.tag")

    @property
    def tag(self) -> bytes:
        return self._tag

    def to_bytes(self) -> bytes:
        return _MAG_SIG + self._tag

    @classmethod
    def from_bytes(cls, data: bytes) -> "MockSignature":
        offset = expect_magic(data, _MAG_SIG)
        raw = bytes(data)
        if len(raw) - offset != _KEY_LEN:
            raise SerializationError(
                f"malformed MockSignature: expected exactly {offset + _KEY_LEN} "
                f"bytes, got {len(raw)} (truncated or trailing data is rejected)"
            )
        return cls(raw[offset:])


class MockIBSBackend:
    """TEST-ONLY mock IBS 后端：满足 IBSBackend 契约，无任何安全性。

    .. warning::
        **测试组件，不得用于生产。** ``MockPublicKey`` 携带主密钥材料
        （见模块 docstring 的安全性声明）。本类只用于 contract tests 与
        协议层的接口联调。

    随机性经构造函数注入 ``rng``（``read(n) -> bytes`` 协议）；缺省
    ``SecureRandom``。固定随机源下 ``setup`` 输出可复现。
    """

    def __init__(self, rng=None) -> None:
        if rng is None:
            rng = SecureRandom()
        if not (hasattr(rng, "read") and callable(rng.read)):
            raise RandomnessError(
                "rng must provide a callable read(n: int) -> bytes"
            )
        self._rng = rng

    def setup(self, params: Params) -> tuple[MockPublicKey, MockMasterSecret]:
        if not isinstance(params, Params):
            raise InvalidParameterError(
                f"setup expects a Params object, got {type(params).__name__}"
            )
        master = self._rng.read(_KEY_LEN)
        if not isinstance(master, _BYTES_LIKE) or len(master) != _KEY_LEN:
            raise RandomnessError("rng.read() returned malformed bytes")
        return MockPublicKey(master), MockMasterSecret(master)

    def key_extract(self, msk: MockMasterSecret, identity: bytes) -> MockSigningKey:
        if not isinstance(msk, MockMasterSecret):
            raise TypeError(
                f"key_extract expects a MockMasterSecret, got {type(msk).__name__}"
            )
        ident = validate_identity(identity)
        k_id = shake256(
            _KEY_DOMAIN, msk.master + encode_bytes(ident), _KEY_LEN
        )
        return MockSigningKey(
            identity=ident,
            identity_digest=hash_identity(ident, _DIGEST_LEN),
            key=k_id,
        )

    def sign(self, sk: MockSigningKey, message: bytes) -> MockSignature:
        if not isinstance(sk, MockSigningKey):
            raise TypeError(
                f"sign expects a MockSigningKey, got {type(sk).__name__}"
            )
        msg = validate_bytes(message, name="message")
        tag = shake256(
            _SIG_DOMAIN,
            sk.key + encode_bytes(sk.identity) + encode_bytes(msg),
            _KEY_LEN,
        )
        return MockSignature(tag)

    def verify(
        self,
        pk: MockPublicKey,
        identity: bytes,
        message: bytes,
        signature: MockSignature,
    ) -> bool:
        """常数时间比较重算的 tag；任何输入不符契约一律返回 ``False``。"""
        if not isinstance(pk, MockPublicKey) or not isinstance(signature, MockSignature):
            return False
        if not is_identity_like(identity) or not is_bytes_like(message):
            return False
        ident = bytes(identity)
        msg = bytes(message)
        # TEST-ONLY：从公钥重导出每身份密钥（主密钥材料公开，见模块 docstring）。
        k_id = shake256(_KEY_DOMAIN, pk.master + encode_bytes(ident), _KEY_LEN)
        expected = shake256(
            _SIG_DOMAIN, k_id + encode_bytes(ident) + encode_bytes(msg), _KEY_LEN
        )
        return constant_time_equal(expected, signature.tag)
