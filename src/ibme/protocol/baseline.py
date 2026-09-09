"""基线 IB-ME 协议组合：两层 HIBE + IBS（M3，指导论文第三章构造 3.3.1）。

严格按 IMPLEMENTATION_SPEC.md §4 实现五个算法（语义不得改动）::

    setup(params, *, ibs_params=None):
        (hpk, hmsk) ← hibe.setup(params)
        (ipk, imsk) ← ibs.setup(ibs_params or params)
        return PublicKey(hpk, ipk), MasterSecret(hmsk, imsk)

    skgen(msk, sender_id):
        return SenderKey(ibs.key_extract(msk.imsk, sender_id))

    rkgen(msk, receiver_id, *, rng=None):
        return ReceiverKey(hibe.extract(msk.hmsk, receiver_id, rng=rng))

    encrypt(public, ek, receiver_id, message, *, rng=None):
        signed  ← encode_message(receiver_id, message)          # core 冻结编码
        sig     ← ibs.sign(ek.signing_key, signed)
        payload ← encode_signature(sig) || encode_bytes(message)
        ct      ← hibe.encrypt(public.hpk, receiver_id, ek.identity, payload, rng=rng)

    decrypt(public, dk, sender_id, ciphertext, *, rng=None):
        child   ← hibe.derive(dk.level1_key, sender_id, rng=rng)
        payload ← hibe.decrypt(child, ct, rng=rng)              # None → BOTTOM
        (sig_raw, message) ← parse_payload(payload)             # 失败 → BOTTOM
        sig ← ibs.load_signature(public.ipk, sig_raw)           # 失败 → BOTTOM
        ok  ← ibs.verify(public.ipk, sender_id,
                         encode_message(dk.identity, message), sig)
        return message if ok else BOTTOM

冻结的实现决策（主 AI，任务 E，勿自行变更）
--------------------------------------------

1. **BOTTOM**：模块级哨兵单例（falsy、清晰 ``repr``）。``decrypt`` 的一切
   数据失败路径——HIBE 解密失败、payload 组帧解析失败、签名重建失败、
   验签失败——都返回 ``BOTTOM``，绝不返回部分结果。参数类编程错误
   （对象类型错误、空身份）仍按项目约定抛 ``TypeError``/``EncodingError``，
   与两个原语层的检查点语义一致。
2. **payload 组帧**（协议层冻结格式）::

       payload = DOMAIN_SIGNATURE
                 || encode_bytes(signature.to_bytes())   # core 长度前缀
                 || encode_bytes(message)

   ``DOMAIN_SIGNATURE = b"IBME:SIG:v1"`` 是协议层冻结域常量。解析
   (:func:`parse_payload`) 严格拒绝：无域前缀、域错配、截断、追加、
   重复字段。签名重建一律走 ``ibs_backend.load_signature(pk, raw)``
   （主 AI 冻结的后端接口），不依赖具体签名类。
3. **HIBE 与 IBS 允许独立参数**：``setup(params, *, ibs_params=None)``。
   组合正确性只依赖两个组件各自的正确性，二者模数相互独立；推荐
   params 取 ABB10 可用参数、ibs_params 取 ``IBS_EDUCATION_PARAMS``
   （SIS 签名约 322 B，HIBE 的 ``max_message_bytes`` 只需 >= 约 400 B，
   见 :data:`BASELINE_DEBUG_PARAMS`）。
4. **身份只以 HIBE 加密形态进入密文**：协议层不 import 任何后端的
   内部矩阵或私有字段，只调用后端公共方法（setup/extract/derive/
   encrypt/decrypt/load_ciphertext 与 setup/key_extract/sign/verify/
   load_signature）和 ``api`` 层协议类型。
5. **rng 策略**：HIBE 五个方法的 ``rng`` 关键字只由协议层转发给 HIBE
   后端；IBS 的 rng 是构造函数注入（M2 冻结），协议层不碰。固定 rng
   （HIBE 侧）+ 固定种子的 IBS 后端下全流程逐字节可复现。
6. **协议对象序列化**（组合序列化：域前缀 + 长度前缀 + 组件 to_bytes）::

       PublicKey     MAGIC_PUBLIC_KEY   || blob(hpk)  || blob(ipk)
       MasterSecret  MAGIC_MASTER_SECRET|| blob(hmsk) || blob(imsk)
       SenderKey     MAGIC_SENDER_KEY   || enc(identity) || blob(sk)
       ReceiverKey   MAGIC_RECEIVER_KEY || enc(identity) || blob(sk1)
       Ciphertext    MAGIC_CIPHERTEXT   || blob(hibe_ct)

   （``blob(x) = u32be(len(x)) || x``，``enc`` 为 core ``encode_bytes``。）
   所有解析严格拒绝截断/追加/重复字段；SenderKey/ReceiverKey 中的身份
   字段必须与组件密钥绑定的身份一致。``from_bytes`` 需要显式传入组件类
   （协议层不假设具体后端）；密文重建统一走
   :meth:`BaselineIBME.load_ciphertext`。

安全声明：本模块只是组合层，不产生新的安全性质；基线版仅应声明
正确性、原始隐私与强可认证性（ARCHITECTURE.md §1），其成立依赖两个
组件后端各自的安全声明。``BASELINE_DEBUG_PARAMS``/
``BASELINE_DEBUG_IBS_PARAMS`` 均为教学/调试参数
（**security_claim: none**），不得用于宣称任何安全等级。
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import replace as _dataclass_replace

from ibme.core.encoding import decode_bytes, encode_bytes, encode_message
from ibme.core.errors import (
    EncodingError,
    IBMEError,
    InvalidParameterError,
    SerializationError,
)
from ibme.core.types import validate_bytes, validate_identity
from ibme.hibe.abb10 import ABB10_DEBUG_PARAMS
from ibme.ibs.api import (
    IBSError,
    expect_magic,
    read_blob,
    require_exact_end,
    write_blob,
)
from ibme.ibs.sis_ibs import IBS_EDUCATION_PARAMS
from ibme.lattice.params import EDUCATION_PARAMS

__all__ = [
    "BOTTOM",
    "BASELINE_DEBUG_PARAMS",
    "BASELINE_DEBUG_IBS_PARAMS",
    "BASELINE_MOCK_PARAMS",
    "BaselineIBME",
    "Ciphertext",
    "DOMAIN_SIGNATURE",
    "MasterSecret",
    "MAGIC_CIPHERTEXT",
    "MAGIC_MASTER_SECRET",
    "MAGIC_PUBLIC_KEY",
    "MAGIC_RECEIVER_KEY",
    "MAGIC_SENDER_KEY",
    "PublicKey",
    "ReceiverKey",
    "SenderKey",
    "encode_signature",
    "is_bottom",
    "parse_payload",
]

# ---------------------------------------------------------------------------
# 冻结的域/魔数常量（协议层序列化格式的一部分，不得改动）
# ---------------------------------------------------------------------------

#: payload 中签名段的域分隔前缀（冻结）。
DOMAIN_SIGNATURE = b"IBME:SIG:v1"

MAGIC_PUBLIC_KEY = b"IBME:PROTO-PK:v1"
MAGIC_MASTER_SECRET = b"IBME:PROTO-MSK:v1"
MAGIC_SENDER_KEY = b"IBME:PROTO-EK:v1"
MAGIC_RECEIVER_KEY = b"IBME:PROTO-DK:v1"
MAGIC_CIPHERTEXT = b"IBME:PROTO-CT:v1"

# ---------------------------------------------------------------------------
# 参数预设（security_claim: none，仅调试）
# ---------------------------------------------------------------------------

#: HIBE 侧调试参数：ABB10 调试预设 + 扩大的明文容量与身份上限。
#: payload = 11B 域前缀 + 4B 长度 + SIS 签名(~322B) + 4B 长度 + 消息，
#: 32B 消息时约 373B，取 400B 留出裕量；identity_bytes 提到 32 以容纳
#: 现实身份长度（含基准脚本与 CLI 的 16B 身份）。
#: **security_claim: none，仅调试**。
BASELINE_DEBUG_PARAMS = _dataclass_replace(
    ABB10_DEBUG_PARAMS,
    name="baseline-hibe-abb10-debug",
    max_message_bytes=400,
    identity_bytes=32,
)

#: IBS 侧调试参数：直接复用 SIS-IBS 教学预设。
#: **security_claim: none，仅调试**（见 ibme.ibs.sis_ibs 模块声明）。
BASELINE_DEBUG_IBS_PARAMS = IBS_EDUCATION_PARAMS

#: mock 组合（TEST-ONLY）用的参数：教育参数 + 明文容量与身份上限放宽。
#: mock 后端读取 ``max_message_bytes`` 与 ``identity_bytes``（主 AI 冻结的
#: 最大身份长度语义），格参数值不参与运算。
BASELINE_MOCK_PARAMS = _dataclass_replace(
    EDUCATION_PARAMS,
    name="baseline-mock-debug",
    max_message_bytes=400,
    identity_bytes=64,
)

#: ``decrypt`` 捕获并映射为 BOTTOM 的异常（core 冻结层次 + IBS 层内部错）。
_BOTTOM_CAUGHT_ERRORS = (IBMEError, IBSError)


# ---------------------------------------------------------------------------
# BOTTOM 哨兵
# ---------------------------------------------------------------------------


class _Bottom:
    """解密失败哨兵（模块级单例 :data:`BOTTOM`）。

    * falsy：``not BOTTOM`` 为真，便于测试断言；
    * ``repr`` 明确显示 ``BOTTOM``；
    * 禁止 pickle/拷贝，防止意外产生第二个哨兵实例。
    """

    __slots__ = ()

    def __bool__(self) -> bool:
        return False

    def __repr__(self) -> str:
        return "BOTTOM"

    def __reduce__(self):  # pragma: no cover - 防御性
        raise TypeError("the BOTTOM sentinel cannot be pickled or copied")


#: IB-ME 解密失败哨兵（单例）。一切失败路径返回它，绝不返回部分结果。
BOTTOM = _Bottom()


def is_bottom(value: object) -> bool:
    """``value is BOTTOM`` 的显式判断（与 ``not value`` 等价于哨兵场景）。"""
    return value is BOTTOM


# ---------------------------------------------------------------------------
# payload 组帧（冻结格式，见模块 docstring 决策 2）
# ---------------------------------------------------------------------------


def encode_signature(signature) -> bytes:
    """编码签名段：``DOMAIN_SIGNATURE || encode_bytes(signature.to_bytes())``。

    ``signature`` 只要求实现冻结的 ``to_bytes() -> bytes``（IBSSignature
    协议）；本函数不读取签名内部结构。
    """
    to_bytes = getattr(signature, "to_bytes", None)
    if not callable(to_bytes):
        raise TypeError(
            f"signature must provide to_bytes(), got {type(signature).__name__}"
        )
    return DOMAIN_SIGNATURE + encode_bytes(to_bytes())


def parse_payload(payload: bytes) -> tuple[bytes, bytes]:
    """严格解析 ``DOMAIN_SIGNATURE || enc(sig) || enc(message)``。

    返回 ``(sig_raw, message)``；``sig_raw`` 是后端签名的规范字节串，由
    调用方经 ``load_signature(pk, raw)`` 重建。拒绝：非字节输入、域缺失/
    错配、长度字段截断、声明的长度超出缓冲区、以及任何尾部多余字节
    （追加或重复字段）。畸形输入抛 :class:`SerializationError`。
    """
    data = validate_bytes(payload, name="payload")
    offset = expect_magic(data, DOMAIN_SIGNATURE)
    try:
        sig_raw, offset = decode_bytes(data, offset)
        message, offset = decode_bytes(data, offset)
    except EncodingError as exc:
        raise SerializationError(f"malformed IB-ME payload: {exc}") from exc
    require_exact_end(data, offset, "IB-ME payload")
    return sig_raw, message


# ---------------------------------------------------------------------------
# 协议数据结构（组合序列化；相等性基于规范字节串）
# ---------------------------------------------------------------------------


def _as_component(value, name: str):
    to_bytes = getattr(value, "to_bytes", None)
    if not callable(to_bytes):
        raise TypeError(
            f"{name} must be a serializable backend object "
            f"(to_bytes()), got {type(value).__name__}"
        )
    return value


def _identity_component(value, name: str) -> bytes:
    """读取组件密钥绑定的身份（api 层冻结属性），并规范化校验。"""
    identity = getattr(value, "identity", None)
    return validate_identity(identity, name=f"{name}.identity")


@dataclass(frozen=True, eq=False)
class PublicKey:
    """IB-ME 公钥：``hpk``（HIBE 公钥）+ ``ipk``（IBS 公钥）。"""

    hpk: object
    ipk: object

    def __post_init__(self) -> None:
        _as_component(self.hpk, "hpk")
        _as_component(self.ipk, "ipk")

    def to_bytes(self) -> bytes:
        return (
            MAGIC_PUBLIC_KEY
            + write_blob(self.hpk.to_bytes())
            + write_blob(self.ipk.to_bytes())
        )

    @classmethod
    def from_bytes(cls, data: bytes, hibe_cls, ibs_cls) -> "PublicKey":
        """从规范字节串重建；``hibe_cls``/``ibs_cls`` 是组件的类对象。

        协议层不假设具体后端，因此组件类必须由调用方显式提供（其
        ``from_bytes(data)`` 是 api 层冻结接口）。
        """
        raw = validate_bytes(data, name="data")
        offset = expect_magic(raw, MAGIC_PUBLIC_KEY)
        hpk_blob, offset = read_blob(raw, offset, "HIBE public key blob")
        ipk_blob, offset = read_blob(raw, offset, "IBS public key blob")
        require_exact_end(raw, offset, "PublicKey")
        return cls(hpk=hibe_cls.from_bytes(hpk_blob), ipk=ibs_cls.from_bytes(ipk_blob))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PublicKey):
            return NotImplemented
        return self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        return hash((PublicKey, self.to_bytes()))

    def __repr__(self) -> str:
        return (
            f"PublicKey(hpk={type(self.hpk).__name__}, "
            f"ipk={type(self.ipk).__name__})"
        )


@dataclass(frozen=True, eq=False)
class MasterSecret:
    """IB-ME 主密钥：``hmsk`` + ``imsk``（最高秘密；签发 ek/dk 的输入）。"""

    hmsk: object
    imsk: object

    def __post_init__(self) -> None:
        _as_component(self.hmsk, "hmsk")
        _as_component(self.imsk, "imsk")

    def to_bytes(self) -> bytes:
        return (
            MAGIC_MASTER_SECRET
            + write_blob(self.hmsk.to_bytes())
            + write_blob(self.imsk.to_bytes())
        )

    @classmethod
    def from_bytes(cls, data: bytes, hibe_cls, ibs_cls) -> "MasterSecret":
        raw = validate_bytes(data, name="data")
        offset = expect_magic(raw, MAGIC_MASTER_SECRET)
        hmsk_blob, offset = read_blob(raw, offset, "HIBE master secret blob")
        imsk_blob, offset = read_blob(raw, offset, "IBS master secret blob")
        require_exact_end(raw, offset, "MasterSecret")
        return cls(hmsk=hibe_cls.from_bytes(hmsk_blob), imsk=ibs_cls.from_bytes(imsk_blob))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MasterSecret):
            return NotImplemented
        return self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        return hash((MasterSecret, self.to_bytes()))

    def __repr__(self) -> str:
        # 秘密对象：repr 只显示组件类型与尺寸，不导出内容。
        return (
            f"MasterSecret(hmsk={type(self.hmsk).__name__}:"
            f"{len(self.hmsk.to_bytes())}B, imsk={type(self.imsk).__name__}:"
            f"{len(self.imsk.to_bytes())}B)"
        )


@dataclass(frozen=True, eq=False)
class SenderKey:
    """发送者密钥 ``ek``：IBS 签名密钥（身份在 key_extract 时已绑定）。"""

    signing_key: object

    @property
    def identity(self) -> bytes:
        """签发时绑定的发送者身份（api 层冻结属性）。"""
        return _identity_component(self.signing_key, "signing_key")

    def __post_init__(self) -> None:
        _as_component(self.signing_key, "signing_key")
        _identity_component(self.signing_key, "signing_key")

    def to_bytes(self) -> bytes:
        return (
            MAGIC_SENDER_KEY
            + encode_bytes(self.identity)
            + write_blob(self.signing_key.to_bytes())
        )

    @classmethod
    def from_bytes(cls, data: bytes, ibs_cls) -> "SenderKey":
        raw = validate_bytes(data, name="data")
        offset = expect_magic(raw, MAGIC_SENDER_KEY)
        try:
            identity, offset = decode_bytes(raw, offset)
        except EncodingError as exc:
            raise SerializationError(f"malformed SenderKey: {exc}") from exc
        if not identity:
            raise SerializationError("malformed SenderKey: empty identity")
        sk_blob, offset = read_blob(raw, offset, "IBS signing key blob")
        require_exact_end(raw, offset, "SenderKey")
        signing_key = ibs_cls.from_bytes(sk_blob)
        if getattr(signing_key, "identity", None) != identity:
            raise SerializationError(
                "malformed SenderKey: identity field does not match the "
                "identity bound to the signing key"
            )
        return cls(signing_key=signing_key)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SenderKey):
            return NotImplemented
        return self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        return hash((SenderKey, self.to_bytes()))

    def __repr__(self) -> str:
        return f"SenderKey(identity={self.identity!r})"


@dataclass(frozen=True, eq=False)
class ReceiverKey:
    """接收者密钥 ``dk``：HIBE 第一层密钥（绑定接收者身份，可派生第二层）。"""

    level1_key: object

    @property
    def identity(self) -> bytes:
        """签发时绑定的接收者身份（api 层冻结属性）。"""
        return _identity_component(self.level1_key, "level1_key")

    def __post_init__(self) -> None:
        _as_component(self.level1_key, "level1_key")
        _identity_component(self.level1_key, "level1_key")

    def to_bytes(self) -> bytes:
        return (
            MAGIC_RECEIVER_KEY
            + encode_bytes(self.identity)
            + write_blob(self.level1_key.to_bytes())
        )

    @classmethod
    def from_bytes(cls, data: bytes, hibe_cls) -> "ReceiverKey":
        raw = validate_bytes(data, name="data")
        offset = expect_magic(raw, MAGIC_RECEIVER_KEY)
        try:
            identity, offset = decode_bytes(raw, offset)
        except EncodingError as exc:
            raise SerializationError(f"malformed ReceiverKey: {exc}") from exc
        if not identity:
            raise SerializationError("malformed ReceiverKey: empty identity")
        sk_blob, offset = read_blob(raw, offset, "HIBE level-1 key blob")
        require_exact_end(raw, offset, "ReceiverKey")
        level1_key = hibe_cls.from_bytes(sk_blob)
        if getattr(level1_key, "identity", None) != identity:
            raise SerializationError(
                "malformed ReceiverKey: identity field does not match the "
                "identity bound to the level-1 key"
            )
        return cls(level1_key=level1_key)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ReceiverKey):
            return NotImplemented
        return self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        return hash((ReceiverKey, self.to_bytes()))

    def __repr__(self) -> str:
        return f"ReceiverKey(identity={self.identity!r})"


@dataclass(frozen=True, eq=False)
class Ciphertext:
    """IB-ME 密文：包装 HIBE 密文（身份只以 HIBE 加密形态存在）。

    重建统一走 :meth:`BaselineIBME.load_ciphertext`（经冻结的
    ``hibe_backend.load_ciphertext``），故本类不提供 ``from_bytes``。
    """

    hibe_ct: object

    def __post_init__(self) -> None:
        _as_component(self.hibe_ct, "hibe_ct")

    def to_bytes(self) -> bytes:
        return MAGIC_CIPHERTEXT + write_blob(self.hibe_ct.to_bytes())

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Ciphertext):
            return NotImplemented
        return self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        return hash((Ciphertext, self.to_bytes()))

    def __repr__(self) -> str:
        return (
            f"Ciphertext(hibe_ct={type(self.hibe_ct).__name__}:"
            f"{len(self.hibe_ct.to_bytes())}B)"
        )


# ---------------------------------------------------------------------------
# 协议组合
# ---------------------------------------------------------------------------

_HIBE_METHODS = (
    "setup",
    "extract",
    "derive",
    "encrypt",
    "decrypt",
    "load_ciphertext",
)
_IBS_METHODS = (
    "setup",
    "key_extract",
    "sign",
    "verify",
    "load_signature",
)


class BaselineIBME:
    """基线 IB-ME 协议（持有 HIBE 与 IBS 两个后端实例）。

    HIBE 与 IBS 可使用不同参数（见 :meth:`setup`）；组合正确性只依赖
    各组件自身的正确性，两个组件的模数相互独立。

    ``rng`` 关键字（``setup``/``rkgen``/``encrypt``/``decrypt``）只转发给
    HIBE 后端；IBS 的随机性由其构造函数注入（M2 冻结接口），协议层不碰。
    ``rng=None`` 表示生产随机源。
    """

    def __init__(self, hibe_backend, ibs_backend) -> None:
        for method in _HIBE_METHODS:
            if not callable(getattr(hibe_backend, method, None)):
                raise InvalidParameterError(
                    f"hibe_backend must implement {method}() "
                    f"(got {type(hibe_backend).__name__})"
                )
        for method in _IBS_METHODS:
            if not callable(getattr(ibs_backend, method, None)):
                raise InvalidParameterError(
                    f"ibs_backend must implement {method}() "
                    f"(got {type(ibs_backend).__name__})"
                )
        self._hibe = hibe_backend
        self._ibs = ibs_backend

    # -- 只读访问（CLI/测试经公共后端 API 构造畸形输入时使用）-----------

    @property
    def hibe_backend(self):
        return self._hibe

    @property
    def ibs_backend(self):
        return self._ibs

    # -- 五个协议算法 -------------------------------------------------------

    def setup(self, params, *, ibs_params=None, rng=None):
        """生成 ``(PublicKey, MasterSecret)``。

        ``params`` 给 HIBE；``ibs_params=None`` 时 IBS 复用 ``params``，
        否则用 ``ibs_params``（推荐 ABB10 参数 + ``IBS_EDUCATION_PARAMS``，
        使 IBS 签名小、HIBE 容量需求低）。``rng`` 只转发给 HIBE 的 setup。
        """
        if ibs_params is None:
            ibs_params = params
        hpk, hmsk = self._hibe.setup(params, rng=rng)
        ipk, imsk = self._ibs.setup(ibs_params)
        return PublicKey(hpk=hpk, ipk=ipk), MasterSecret(hmsk=hmsk, imsk=imsk)

    def skgen(self, msk: MasterSecret, sender_id: bytes) -> SenderKey:
        """为发送者身份签发 ``ek``（IBS key_extract；随机性由 IBS 后端注入）。"""
        if not isinstance(msk, MasterSecret):
            raise TypeError(
                f"skgen expects a MasterSecret, got {type(msk).__name__}"
            )
        return SenderKey(signing_key=self._ibs.key_extract(msk.imsk, sender_id))

    def rkgen(self, msk: MasterSecret, receiver_id: bytes, *, rng=None) -> ReceiverKey:
        """为接收者身份签发 ``dk``（HIBE extract；``rng`` 只转发给 HIBE）。"""
        if not isinstance(msk, MasterSecret):
            raise TypeError(
                f"rkgen expects a MasterSecret, got {type(msk).__name__}"
            )
        return ReceiverKey(
            level1_key=self._hibe.extract(msk.hmsk, receiver_id, rng=rng)
        )

    def encrypt(
        self,
        public: PublicKey,
        ek: SenderKey,
        receiver_id: bytes,
        message: bytes,
        *,
        rng=None,
    ) -> Ciphertext:
        """在 (receiver_id, ek.identity) 下加密 message（SPEC §4）。

        签名对 ``encode_message(receiver_id, message)`` 生成；HIBE 加密的
        payload 为 ``encode_signature(sig) || encode_bytes(message)``。
        参数类错误（类型、空身份、消息超容量）按原语层约定抛异常。
        """
        if not isinstance(public, PublicKey):
            raise TypeError(
                f"encrypt expects a PublicKey, got {type(public).__name__}"
            )
        if not isinstance(ek, SenderKey):
            raise TypeError(f"encrypt expects a SenderKey, got {type(ek).__name__}")
        rcv = validate_identity(receiver_id, name="receiver_id")
        msg = validate_bytes(message, name="message")
        signed = encode_message(rcv, msg)
        signature = self._ibs.sign(ek.signing_key, signed)
        payload = encode_signature(signature) + encode_bytes(msg)
        hibe_ct = self._hibe.encrypt(public.hpk, rcv, ek.identity, payload, rng=rng)
        return Ciphertext(hibe_ct=hibe_ct)

    def decrypt(
        self,
        public: PublicKey,
        dk: ReceiverKey,
        sender_id: bytes,
        ciphertext,
        *,
        rng=None,
    ) -> bytes:
        """按 (dk.identity, sender_id) 尝试解密；一切失败返回 :data:`BOTTOM`。

        ``ciphertext`` 是 :class:`Ciphertext` 或其规范字节串（字节串经
        :meth:`load_ciphertext` 严格重建，畸形输入同样映射为 BOTTOM）。
        ``rng`` 只转发给 HIBE（derive/decrypt）。
        """
        if not isinstance(public, PublicKey):
            raise TypeError(
                f"decrypt expects a PublicKey, got {type(public).__name__}"
            )
        if not isinstance(dk, ReceiverKey):
            raise TypeError(
                f"decrypt expects a ReceiverKey, got {type(dk).__name__}"
            )
        snd = validate_identity(sender_id, name="sender_id")
        try:
            if isinstance(ciphertext, Ciphertext):
                wrapped = ciphertext
            else:
                wrapped = self.load_ciphertext(ciphertext)
            child = self._hibe.derive(dk.level1_key, snd, rng=rng)
            payload = self._hibe.decrypt(child, wrapped.hibe_ct, rng=rng)
            if payload is None:
                return BOTTOM
            sig_raw, message = parse_payload(payload)
            signature = self._ibs.load_signature(public.ipk, sig_raw)
            verify_message = encode_message(dk.identity, message)
        except _BOTTOM_CAUGHT_ERRORS:
            # 数据失败路径（密文畸形/不匹配/验签失败）统一 BOTTOM，
            # 不向调用方外泄堆栈或部分结果。
            return BOTTOM
        if not self._ibs.verify(public.ipk, snd, verify_message, signature):
            return BOTTOM
        return message

    def load_ciphertext(self, data: bytes) -> Ciphertext:
        """从规范字节串重建 IB-ME 密文（严格解析；冻结接口）。

        格式：``MAGIC_CIPHERTEXT || blob(hibe_ct.to_bytes())``；内部经
        ``hibe_backend.load_ciphertext`` 重建，不依赖具体密文类。
        """
        raw = validate_bytes(data, name="data")
        offset = expect_magic(raw, MAGIC_CIPHERTEXT)
        hibe_blob, offset = read_blob(raw, offset, "HIBE ciphertext blob")
        require_exact_end(raw, offset, "Ciphertext")
        return Ciphertext(hibe_ct=self._hibe.load_ciphertext(hibe_blob))
