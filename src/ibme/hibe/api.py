"""HIBE 原语层的冻结接口与数据类型协议（ARCHITECTURE.md §4）。

本模块只定义契约，不含任何实现。具体后端：

* :mod:`ibme.hibe.mock` —— TEST-ONLY 的 SHAKE 对称掩码假后端（仅测试用）；
* :mod:`ibme.hibe.abb10` —— Agrawal–Boneh–Boyen 2010 风格的两层格基后端
  （教学参数，``security_claim: none``）。

接口契约（contract tests 对每个后端按同一契约参数化验证）：

1. 身份顺序固定为 ``(parent_id, child_id) = (rcv, phi)``：

   * ``extract(msk, parent_id)`` 生成第一层（接收者 ρ）密钥；
   * ``derive(sk_parent, child_id)`` 派生第二层（发送者 φ）密钥；
   * ``encrypt(pk, parent_id, child_id, payload)`` 在身份对 (rcv, phi) 下
     加密。

2. ``decrypt`` 失败返回 ``None``（协议层映射为 BOTTOM），绝不返回部分
   结果；成功时返回原始 payload 字节串（允许空 payload）。
3. 密文不得明文携带身份（匿名性要求）：身份只参与密钥派生与哈希。
4. 所有随机性经可注入的 ``rng``（core 冻结的 ``read(n) -> bytes`` 协议）
   进入；``rng=None`` 一律表示生产随机源（``core.SecureRandom``）。固定
   rng 下整套流程可复现。 ARCHITECTURE.md §4 的方法签名在此基础上以
   ``rng`` 关键字参数扩展，位置参数形式保持兼容。
5. 公钥、主密钥、两级私钥和密文都实现 ``to_bytes``/``from_bytes``；
   解析必须严格拒绝截断、追加、维度不符和未知版本（magic 不匹配），
   往返一致。

本模块没有任何安全声明；安全口径由各后端自行标注。
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

__all__ = [
    "HIBESerializable",
    "HIBEPublicKey",
    "HIBEMasterSecret",
    "HIBELevel1SecretKey",
    "HIBELevel2SecretKey",
    "HIBECiphertext",
    "HIBEBackend",
]


@runtime_checkable
class HIBESerializable(Protocol):
    """所有可序列化 HIBE 对象的基契约：严格往返、拒绝畸形输入。"""

    def to_bytes(self) -> bytes:
        """规范序列化（定长头部 + 长度前缀字段，无歧义）。"""
        ...

    @classmethod
    def from_bytes(cls, data: bytes) -> "HIBESerializable":
        """严格解析；截断、追加、维度不符、坏 magic 抛 ``SerializationError``。"""
        ...


@runtime_checkable
class HIBEPublicKey(HIBESerializable, Protocol):
    """HIBE 公钥（结构由后端自定，但必须可严格序列化）。"""


@runtime_checkable
class HIBEMasterSecret(HIBESerializable, Protocol):
    """HIBE 主密钥（最高秘密；第一层密钥提取的输入）。"""


@runtime_checkable
class HIBELevel1SecretKey(HIBESerializable, Protocol):
    """第一层密钥：绑定接收者身份，可派生第二层密钥。"""

    @property
    def identity(self) -> bytes:
        """该密钥绑定的第一层身份（parent_id = rcv）原始字节串。"""
        ...


@runtime_checkable
class HIBELevel2SecretKey(HIBESerializable, Protocol):
    """第二层密钥：绑定身份对 (rcv, phi)，用于解密。"""

    @property
    def parent_identity(self) -> bytes:
        """第一层身份（rcv）原始字节串。"""
        ...

    @property
    def child_identity(self) -> bytes:
        """第二层身份（phi）原始字节串。"""
        ...


@runtime_checkable
class HIBECiphertext(HIBESerializable, Protocol):
    """HIBE 密文：不得明文携带身份（匿名性）。"""


@runtime_checkable
class HIBEBackend(Protocol):
    """HIBE 后端冻结接口（ARCHITECTURE.md §4）。

    身份顺序固定为 ``(parent_id, child_id) = (rcv, phi)``。
    """

    def setup(
        self, params, *, rng=None
    ) -> tuple[HIBEPublicKey, HIBEMasterSecret]:
        """生成 (pk, msk)。``rng`` 为 ``read(n) -> bytes`` 随机源。"""
        ...

    def extract(
        self, msk: HIBEMasterSecret, parent_id: bytes, *, rng=None
    ) -> HIBELevel1SecretKey:
        """用主密钥为第一层身份 parent_id=rcv 生成密钥。"""
        ...

    def derive(
        self, sk_parent: HIBELevel1SecretKey, child_id: bytes, *, rng=None
    ) -> HIBELevel2SecretKey:
        """由第一层密钥派生 (parent_id, child_id)=(rcv, phi) 的第二层密钥。"""
        ...

    def encrypt(
        self,
        pk: HIBEPublicKey,
        parent_id: bytes,
        child_id: bytes,
        payload: bytes,
        *,
        rng=None,
    ) -> HIBECiphertext:
        """在身份对 (rcv, phi) 下加密 payload（可为空）。"""
        ...

    def decrypt(
        self, sk_child: HIBELevel2SecretKey, ct: HIBECiphertext, *, rng=None
    ) -> bytes | None:
        """解密；任何失败返回 ``None``（BOTTOM），绝不返回部分结果。"""
        ...
