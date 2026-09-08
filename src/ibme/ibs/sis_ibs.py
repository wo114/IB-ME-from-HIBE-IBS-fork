"""改进版 SIS-IBS（指导论文第三章构造 3.4.1；蒸馏设计见 notes/ib-me-hibe-ibs-design.md §4.3）。

必须保持的关键关系（IMPLEMENTATION_SPEC.md §3）::

    H1(mpk, id) = A·R̂_id + G (mod q)        R̂_id ∈ Z^{m×n·k} 为短用户陷门 T_id
    F_id        = [A | H1(mpk, id)]
    sign:       h2 = H2(mpk, id, message) ∈ Z_q^n，
                F_id·z = h2 (mod q)
    verify:     z ≠ 0、F_id·z = h2 (mod q)、‖z‖₂ ≤ s'·sqrt(m + n·k)

其中 A ∈ Z_q^{n×m} 来自 ``lattice.trapdoor.trapgen`` 的
``A = [ā | G − ā·R_A]``（主陷门 T_A = (ā, R_A)），G 为二进制 gadget
矩阵，k = ceil(log2 q)，s' = ``params.s_prime``，范数界公式与 notes §4.3
一致（``m + n·k`` 恰为 F_id 的总列数）。

算法
----
**setup(params)**：``trapgen(params, rng)`` 生成 (ā, R_A)，A = 公开矩阵；
mpk = (A, s', name)，msk = (pk, T_A, sigma)。R_A 的离散高斯宽度取
``params.s0``（trapgen 缺省）；sigma = ``params.s``（委派与签名共用，
避免散落常数）。

**key_extract(msk, id)**（DelTrap 风格委派）：H1 = H1(mpk, id) 由域分隔
哈希确定，逐列求解 ``A·r_j = (H1 − G)[:, j] (mod q)``。列采样沿用
``lattice.sample_pre`` 的模式（短高斯 e + gadget 原像 + 线性组合），但把
其中的**确定性 bit_decompose 换成零均值的 G-格陪集采样**
（:func:`_sample_gadget_coset`，MP12 G-coset 采样的简化版）：确定性比特
每个位置均值为 1/2，会使 R̂ 的行携带 (1/2)·rowsum(R_A) 的公共偏移，进而
在签名的 R̂·y 中放大成 (pop/2)·rowsum(R_A) 量级的大均值项（实测把 ‖z‖
推高到 ~1.8e3，必然超出任何合理范数界）。零均值陪集采样消除该偏移。
r_j = (R_A·ŷ_j + e_j, ŷ_j)，R̂_id = [r_0 … r_{n·k−1}] 即用户陷门 T_id。
构造后做整矩阵代数自检 ``A·R̂ + G == H1``（精确成立，不靠概率）。

**sign(sk, m)**：h2 = H2(mpk, id, m)；采样短高斯 x ∈ Z^m（宽度
``sigma``，存于 sk）；令 t = h2 − A·x、y = bit_decompose(t)，
输出::

    z = ( x − R̂·y ,  y )  ∈ Z^{m + n·k}

正确性（精确恒等式；notes §4.3 提示 ``F_id·(−R̂·y; y) = G·y``，本实现
是其加噪版本，bit_decompose + 高斯噪声在本模块内完成，不包装成
Trapdoor 对象）::

    F_id·z = A·(x − R̂·y) + (A·R̂ + G)·y = A·x + G·y = A·x + t = h2 (mod q)

sign 内部重算 F_id 并自检该等式（违反则抛 :class:`~ibme.ibs.api.IBSError`，
正常不可能出现）。若 z 超范数界（教学参数下单次采样实测 ~0.3% 概率）则重新
采样，最多 8 次。**身份绑定**：sign 只使用 sk 在 key_extract 时绑定的
身份（冻结接口无身份参数）；sk 保存规范化身份与
``hash_identity(identity, 32)`` 摘要，调用方无法在签名阶段误传另一个身份。

**verify(pk, id, m, sig)**：重算 H1、F_id、h2，检查长度、z ≠ 0、
``F_id·z ≡ h2``、``‖z‖₂ ≤ s'·sqrt(m + n·k)``；任何输入不符契约返回
``False`` 而非抛异常。

哈希到 Z_q 的说明
-----------------
H1/H2 用 ``core.shake256``（域 ``DOMAIN_IBS_H1``/``DOMAIN_IBS_H2``），
输入为长度前缀编码 ``enc(A_bytes) || enc(id) [|| enc(message)]``。摘要按
每元素 ``bpe = ceil(bit_length(q)/8)`` 字节大端读出后 ``% q``：该约简存在
微小统计偏差（哈希映射，非机密采样），对代数关系与测试无影响；如需无偏
映射应改用拒绝采样（已知限制，见文末）。

序列化格式（严格解析：拒绝截断/追加/重复/维度不符；往返一致）
---------------------------------------------------------------
::

    SisPublicKey     "IBS1-S-PK"  || u32(name_len) || name || f64(s')
                                 || A.to_bytes()（ModMatrix 定长格式）
    SisMasterSecret  "IBS1-S-MSK" || blob(pk) || blob(a_bar) || f64(sigma)
                                 || 签名整数矩阵(m_bar × n·k)
    SisSigningKey    "IBS1-S-SK"  || enc(identity) || digest(32) || blob(pk)
                                 || f64(sigma) || 签名整数矩阵(m × n·k)
    SisSignature     "IBS1-S-SIG" || u32(vec_len) || u32(width)
                                 || vec_len × width 字节二补码大端系数

签名整数矩阵：``u32(rows) || u32(cols) || u32(width) || rows·cols × width``
字节二补码大端（定长、含符号）；``to_bytes`` 输出最小宽度，``from_bytes``
接受 1..8 字节的任意合法声明宽度。签名向量同样用二补码定长编码（``z`` 是
整数向量，不做模规范化，系数可为负）；解析时校验 ``vec_len == F_id 列数``
（维度不符拒绝）并在反序列化阶段即拒绝超范数界的签名——该检查需要 pk
上下文，故 ``SisSignature.from_bytes(data, pk)`` 带公钥参数。

参数预设与安全声明
------------------
``IBS_EDUCATION_PARAMS``：与 ``lattice.EDUCATION_PARAMS``（n=8, q=257,
m_matrix=80, s0=4, s=10）相同，仅把 s_prime 从 12 提高到 64。原因：无
扰动的简化采样链（lattice.sample_pre 模式 + 本模块的陪集采样）使诚实签
名的 ‖z‖ 实测落在 ~2.7e2–5.8e2 区间（E‖z‖² ≈ 2.1e5），
s'=12 给出的界 148 必然拒绝诚实签名；s'=64 给出界 64·sqrt(152) ≈ 789，
诚实签名以约 3 倍方差裕量通过（sign 在返回前自检范数，偶发超界即重采样，
故诚实签名必过验签），同时仍拒绝中心化代表元均匀向量（‖·‖ 可达
128·sqrt(152) ≈ 1578 > 789）。**security_claim: none；仅用于调试，不得
用于任何安全声明**；该宽松界不对应论文的渐近参数关系。

已知限制
--------
- 教学参数 + 简化 sample_pre：不提供任何安全性质，也不能作为性能结论；
- H1/H2 到 Z_q 的约简存在微小统计偏差（见上）；
- 采样非常数时间（继承 lattice.gaussian 的拒绝采样）；
- sk 序列化内嵌 pk（签名需要 A），以尺寸换自包含；
- ``IBSError`` 继承自 ``Exception`` 而非 ``IBMEError``：core 的异常层次是
  冻结边界，IBS 层按 ARCHITECTURE.md 分层追加本层异常。
"""

from __future__ import annotations

import math

from ibme.core import (
    DOMAIN_IBS_H1,
    DOMAIN_IBS_H2,
    DimensionError,
    EncodingError,
    InvalidParameterError,
    RandomnessError,
    SecureRandom,
    SerializationError,
    decode_bytes,
    encode_bytes,
    hash_identity,
    shake256,
    validate_bytes,
    validate_identity,
)
from ibme.lattice.gadget import bit_decompose, gadget_matrix, gadget_width
from ibme.lattice.gaussian import sample_integer_gaussian, sample_vector_gaussian
from ibme.lattice.modmat import ModMatrix, ModVector
from ibme.lattice.params import Params
from ibme.lattice.trapdoor import Trapdoor, trapgen

from .api import (
    IBSError,
    IBSPublicKey,
    IBSMasterSecret,
    IBSSignature,
    IBSSigningKey,
    expect_magic,
    f64be,
    is_bytes_like,
    is_identity_like,
    read_blob,
    read_f64,
    read_u32,
    u32be,
    write_blob,
)

__all__ = [
    "IBS_EDUCATION_PARAMS",
    "SisIBSBackend",
    "SisMasterSecret",
    "SisPublicKey",
    "SisSignature",
    "SisSigningKey",
    "f_id_matrix",
    "h1_matrix",
    "h2_vector",
    "signature_bound",
]

# ---------------------------------------------------------------------------
# 参数预设（IBS 模块内；禁止修改 lattice/params.py）
# ---------------------------------------------------------------------------

#: SIS-IBS 教学参数预设。**security_claim: none，仅调试用**。
#: 与 lattice.EDUCATION_PARAMS 唯一的差别是 s_prime: 12.0 -> 64.0，
#: 原因见模块 docstring（简化 sample_pre 链的范数膨胀）。
IBS_EDUCATION_PARAMS = Params(
    name="ibs-education",
    security_parameter=8,
    n=8,
    m_matrix=80,  # = m_bar + n·k（k = ceil(log2 257) = 9）
    q=257,
    s0=4.0,
    s=10.0,
    s_prime=64.0,  # 论文范数界参数；此处为容纳简化采样链的教学放宽值
    identity_bytes=8,
    max_message_bytes=32,
)

_MAX_SIGN_ATTEMPTS = 8
_NAME_LEN_LIMIT = 128
_DIGEST_LEN = 32

#: key_extract 中 G-格陪集采样的离散高斯宽度（内部实现参数，作用类似
#: lattice.sample_pre 的缺省 sigma_e；教学值）。每个 gadget 位置采样一个
#: 奇偶条件离散高斯（见 _sample_parity_gaussian），宽度 1.0 时输出基本
#: 取值于 {-3..3}，零均值。
_COSET_SIGMA = 1.0

_MAG_PK = b"IBS1-S-PK"
_MAG_MSK = b"IBS1-S-MSK"
_MAG_SK = b"IBS1-S-SK"
_MAG_SIG = b"IBS1-S-SIG"

_BYTES_LIKE = (bytes, bytearray, memoryview)


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


# ---------------------------------------------------------------------------
# 有符号整数矩阵编解码（模块 docstring 中定义的格式）
# ---------------------------------------------------------------------------

def _signed_entry_width(values) -> int:
    max_abs = 0
    for value in values:
        max_abs = max(max_abs, abs(value))
    for width in range(1, 9):
        if max_abs < (1 << (8 * width - 1)):
            return width
    raise InvalidParameterError(
        f"integer magnitude {max_abs} exceeds the 8-byte signed encoding"
    )


def _encode_signed_matrix(rows) -> bytes:
    try:
        raw_rows = [list(row) for row in rows]
    except TypeError as exc:
        raise InvalidParameterError(
            "signed matrix must be an iterable of integer rows"
        ) from exc
    if not raw_rows or not raw_rows[0]:
        raise InvalidParameterError("signed matrix must be non-empty")
    cols = len(raw_rows[0])
    flat: list[int] = []
    for row in raw_rows:
        if len(row) != cols:
            raise InvalidParameterError("signed matrix rows must be rectangular")
        for value in row:
            if not _is_int(value):
                raise InvalidParameterError(
                    f"signed matrix entries must be int, got {type(value).__name__}"
                )
            flat.append(value)
    width = _signed_entry_width(flat)
    modulus = 1 << (8 * width)
    payload = b"".join((value % modulus).to_bytes(width, "big") for value in flat)
    return u32be(len(raw_rows)) + u32be(cols) + u32be(width) + payload


def _decode_signed_matrix(data, offset: int):
    """解析签名整数矩阵；总是消费到缓冲区末尾（末字段的严格性）。"""
    raw = bytes(data)
    rows, offset = read_u32(raw, offset, "matrix rows")
    cols, offset = read_u32(raw, offset, "matrix cols")
    width, offset = read_u32(raw, offset, "matrix width")
    if rows < 1 or cols < 1:
        raise SerializationError(f"invalid signed matrix dimensions {rows}x{cols}")
    if not 1 <= width <= 8:
        raise SerializationError(f"invalid signed matrix entry width {width}")
    total = rows * cols * width
    if len(raw) - offset != total:
        raise SerializationError(
            f"malformed signed matrix: expected {total} bytes of entries, got "
            f"{len(raw) - offset} (truncated or trailing data is rejected)"
        )
    entries = [
        int.from_bytes(
            raw[offset + i * width : offset + (i + 1) * width], "big", signed=True
        )
        for i in range(rows * cols)
    ]
    grid = [entries[i * cols : (i + 1) * cols] for i in range(rows)]
    return grid, len(raw)


# ---------------------------------------------------------------------------
# 公共哈希/矩阵辅助（verify 内部使用；测试可直接检验代数关系）
# ---------------------------------------------------------------------------

def _bytes_per_entry(q: int) -> int:
    return max(1, (q.bit_length() + 7) // 8)


def _require_sis_pk(pk) -> "SisPublicKey":
    if not isinstance(pk, SisPublicKey):
        raise TypeError(f"expected a SisPublicKey, got {type(pk).__name__}")
    return pk


def h1_matrix(pk: "SisPublicKey", identity: bytes) -> ModMatrix:
    """H1(mpk, id) ∈ Z_q^{n×n·k}：SHAKE-256(DOMAIN_IBS_H1) 域分隔映射。"""
    pk = _require_sis_pk(pk)
    ident = validate_identity(identity)
    q, n, nk = pk.q, pk.n, pk.nk
    bpe = _bytes_per_entry(q)
    digest = shake256(
        DOMAIN_IBS_H1,
        encode_bytes(pk.a.to_bytes()) + encode_bytes(ident),
        n * nk * bpe,
    )
    rows = []
    for i in range(n):
        base = i * nk * bpe
        rows.append(
            [
                int.from_bytes(digest[base + j * bpe : base + (j + 1) * bpe], "big") % q
                for j in range(nk)
            ]
        )
    return ModMatrix(rows, q)


def h2_vector(pk: "SisPublicKey", identity: bytes, message: bytes) -> ModVector:
    """H2(mpk, id, m) ∈ Z_q^n：SHAKE-256(DOMAIN_IBS_H2) 域分隔映射。"""
    pk = _require_sis_pk(pk)
    ident = validate_identity(identity)
    msg = validate_bytes(message, name="message")
    q, n = pk.q, pk.n
    bpe = _bytes_per_entry(q)
    digest = shake256(
        DOMAIN_IBS_H2,
        encode_bytes(pk.a.to_bytes()) + encode_bytes(ident) + encode_bytes(msg),
        n * bpe,
    )
    return ModVector(
        [
            int.from_bytes(digest[i * bpe : (i + 1) * bpe], "big") % q
            for i in range(n)
        ],
        q,
    )


def f_id_matrix(pk: "SisPublicKey", identity: bytes) -> ModMatrix:
    """F_id = [A | H1(mpk, id)] ∈ Z_q^{n×(m+n·k)}。"""
    pk = _require_sis_pk(pk)
    ident = validate_identity(identity)
    return pk.a.hstack(h1_matrix(pk, ident))


def signature_bound(pk: "SisPublicKey") -> float:
    """论文范数界（notes §4.3）：``s'·sqrt(m + n·ceil(log2 q))``。"""
    pk = _require_sis_pk(pk)
    return pk.norm_bound


def _sample_parity_gaussian(sigma: float, parity: int, rng) -> int:
    """从奇偶条件离散高斯 ``{z ≡ parity (mod 2)}``（中心 0，宽度 sigma）采样。

    精确实现（无拒绝采样）：``z = parity + 2w``，其中
    ``w ~ D_{Z, sigma/2, center=-parity/2}``（lattice 的真离散高斯原语，
    支持非整数中心）。代入验证：``exp(-(w+p/2)²/(2(sigma/2)²)) ==
    exp(-z²/(2·sigma²))``，与奇偶条件高斯的权函数逐点一致。零均值。
    """
    w = sample_integer_gaussian(sigma / 2.0, center=-parity / 2.0, rng=rng)
    return parity + 2 * w


def _sample_gadget_coset(target: ModVector, sigma: float, rng) -> list[int]:
    """零均值 G-格陪集采样：返回 y ∈ Z^{n·k} 使 ``G·y ≡ target (mod q)``。

    MP12 G-coset 采样的简化版（无 CDT 表）：逐行做进位递推
    ``v ← (v − z_b)/2``，前 k−1 个位置 z_b 取奇偶条件离散高斯（零均值），
    末位 z_{k−1} = v 确定收尾（|v| 经折半后保持个位数）。恒等式
    ``Σ_b 2^b·z_b = τ``（τ 为 target 的中心化代表元）精确成立，因此
    ``G·y = target (mod q)`` 精确成立。

    与确定性 bit_decompose 的区别：后者每个位置均值为 1/2，使 R̂ 的行携带
    (1/2)·rowsum(R_A) 的公共偏移，在签名中放大为超界的均值项；本采样器
    的输出零均值，消除该偏移（见模块 docstring 的 key_extract 说明）。
    """
    q = target.q
    k = gadget_width(q)
    out: list[int] = []
    for tau in target.centered():
        v = tau
        row: list[int] = []
        for _ in range(k - 1):
            z = _sample_parity_gaussian(sigma, v & 1, rng)
            row.append(z)
            v = (v - z) // 2  # 精确整除：v ≡ z (mod 2)
        row.append(v)
        out.extend(row)
    return out


# ---------------------------------------------------------------------------
# 对象类型
# ---------------------------------------------------------------------------

class SisPublicKey(IBSPublicKey):
    """SIS-IBS 公钥：公开矩阵 A、范数界参数 s'、参数预设名。"""

    __slots__ = ("_a", "_s_prime", "_name")

    def __init__(self, a: ModMatrix, s_prime: float, name: str) -> None:
        if not isinstance(a, ModMatrix):
            raise InvalidParameterError(
                f"a must be a ModMatrix, got {type(a).__name__}"
            )
        if isinstance(s_prime, bool) or not isinstance(s_prime, (int, float)):
            raise InvalidParameterError(
                f"s_prime must be a real number, got {type(s_prime).__name__}"
            )
        if not math.isfinite(float(s_prime)) or float(s_prime) <= 0.0:
            raise InvalidParameterError(
                f"s_prime must be finite and > 0, got {s_prime!r}"
            )
        if not isinstance(name, str) or not name:
            raise InvalidParameterError("name must be a non-empty str")
        self._a = a
        self._s_prime = float(s_prime)
        self._name = name

    @property
    def a(self) -> ModMatrix:
        return self._a

    @property
    def s_prime(self) -> float:
        return self._s_prime

    @property
    def name(self) -> str:
        return self._name

    @property
    def n(self) -> int:
        return self._a.rows

    @property
    def q(self) -> int:
        return self._a.q

    @property
    def k(self) -> int:
        return gadget_width(self._a.q)

    @property
    def nk(self) -> int:
        return self.n * self.k

    @property
    def m(self) -> int:
        return self._a.cols

    @property
    def f_id_cols(self) -> int:
        """F_id 的总列数 = m + n·k（范数界中的列数）。"""
        return self.m + self.nk

    @property
    def norm_bound(self) -> float:
        """‖z‖₂ 的验证界：``s_prime·sqrt(f_id_cols)``。"""
        return self._s_prime * math.sqrt(self.f_id_cols)

    @property
    def norm_bound_squared(self) -> float:
        return self.norm_bound * self.norm_bound

    def to_bytes(self) -> bytes:
        name_bytes = self._name.encode("utf-8")
        if len(name_bytes) > _NAME_LEN_LIMIT:
            raise InvalidParameterError(
                f"name exceeds {_NAME_LEN_LIMIT} bytes and cannot be serialized"
            )
        return (
            _MAG_PK
            + u32be(len(name_bytes))
            + name_bytes
            + f64be(self._s_prime)
            + self._a.to_bytes()
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "SisPublicKey":
        offset = expect_magic(data, _MAG_PK)
        raw = bytes(data)
        name_len, offset = read_u32(raw, offset, "name length")
        if name_len > _NAME_LEN_LIMIT or len(raw) - offset < name_len:
            raise SerializationError(
                f"malformed SisPublicKey: invalid name length {name_len}"
            )
        try:
            name = raw[offset : offset + name_len].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SerializationError(
                "malformed SisPublicKey: bad name encoding"
            ) from exc
        offset += name_len
        s_prime, offset = read_f64(raw, offset, "s_prime")
        if s_prime <= 0.0:
            raise SerializationError("malformed SisPublicKey: s_prime must be > 0")
        try:
            a = ModMatrix.from_bytes(raw[offset:])
        except SerializationError as exc:
            raise SerializationError(f"malformed SisPublicKey: {exc}") from exc
        return cls(a=a, s_prime=s_prime, name=name)


class SisMasterSecret(IBSMasterSecret):
    """SIS-IBS 主密钥：pk、MP12 风格主陷门 T_A 与委派用高斯宽度 sigma。"""

    __slots__ = ("_pk", "_td", "_sigma")

    def __init__(
        self, public_key: SisPublicKey, trapdoor: Trapdoor, sigma: float
    ) -> None:
        if not isinstance(public_key, SisPublicKey):
            raise InvalidParameterError(
                f"public_key must be a SisPublicKey, got {type(public_key).__name__}"
            )
        if not isinstance(trapdoor, Trapdoor):
            raise InvalidParameterError(
                f"trapdoor must be a Trapdoor, got {type(trapdoor).__name__}"
            )
        if isinstance(sigma, bool) or not isinstance(sigma, (int, float)):
            raise InvalidParameterError(
                f"sigma must be a real number, got {type(sigma).__name__}"
            )
        if not math.isfinite(float(sigma)) or float(sigma) <= 0.0:
            raise InvalidParameterError(
                f"sigma must be finite and > 0, got {sigma!r}"
            )
        if trapdoor.q != public_key.q or trapdoor.n != public_key.n:
            raise InvalidParameterError(
                "trapdoor dimensions/modulus do not match the public key"
            )
        # 完整代数一致性：A 必须等于 [ā | G − ā·R_A]。
        if trapdoor.public_matrix() != public_key.a:
            raise InvalidParameterError(
                "trapdoor does not derive the public matrix A"
            )
        self._pk = public_key
        self._td = trapdoor
        self._sigma = float(sigma)

    @property
    def public_key(self) -> SisPublicKey:
        return self._pk

    @property
    def trapdoor(self) -> Trapdoor:
        return self._td

    @property
    def sigma(self) -> float:
        return self._sigma

    def to_bytes(self) -> bytes:
        return (
            _MAG_MSK
            + write_blob(self._pk.to_bytes())
            + write_blob(self._td.a_bar.to_bytes())
            + f64be(self._sigma)
            + _encode_signed_matrix(self._td.r)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "SisMasterSecret":
        offset = expect_magic(data, _MAG_MSK)
        raw = bytes(data)
        pk_blob, offset = read_blob(raw, offset, "public key blob")
        a_bar_blob, offset = read_blob(raw, offset, "a_bar blob")
        sigma, offset = read_f64(raw, offset, "sigma")
        if sigma <= 0.0:
            raise SerializationError("malformed SisMasterSecret: sigma must be > 0")
        grid, _end = _decode_signed_matrix(raw, offset)
        try:
            pk = SisPublicKey.from_bytes(pk_blob)
            a_bar = ModMatrix.from_bytes(a_bar_blob)
            td = Trapdoor(a_bar=a_bar, r=tuple(tuple(row) for row in grid))
            return cls(public_key=pk, trapdoor=td, sigma=sigma)
        except SerializationError as exc:
            raise SerializationError(f"malformed SisMasterSecret: {exc}") from exc
        except (InvalidParameterError, DimensionError) as exc:
            raise SerializationError(f"malformed SisMasterSecret: {exc}") from exc


class SisSigningKey(IBSSigningKey):
    """SIS-IBS 签名密钥：身份 + 身份摘要 + 用户陷门 R̂_id + pk + sigma。

    R̂_id 为 ``m × n·k`` 的短整数矩阵（用户陷门 T_id），满足
    ``A·R̂_id + G = H1(mpk, identity)``。内嵌 pk 是因为 sign 需要公开
    矩阵 A（t = h2 − A·x）。
    """

    __slots__ = ("_identity", "_digest", "_r_hat", "_pk", "_sigma")

    def __init__(
        self,
        identity: bytes,
        r_hat,
        public_key: SisPublicKey,
        sigma: float,
        identity_digest: bytes | None = None,
    ) -> None:
        ident = validate_identity(identity)
        digest = (
            hash_identity(ident, _DIGEST_LEN)
            if identity_digest is None
            else identity_digest
        )
        if not isinstance(digest, _BYTES_LIKE) or len(digest) != _DIGEST_LEN:
            raise InvalidParameterError(
                f"identity_digest must be {_DIGEST_LEN} bytes"
            )
        if digest != hash_identity(ident, _DIGEST_LEN):
            raise InvalidParameterError(
                "identity_digest does not match hash_identity(identity)"
            )
        if not isinstance(public_key, SisPublicKey):
            raise InvalidParameterError(
                f"public_key must be a SisPublicKey, got {type(public_key).__name__}"
            )
        if isinstance(sigma, bool) or not isinstance(sigma, (int, float)):
            raise InvalidParameterError(
                f"sigma must be a real number, got {type(sigma).__name__}"
            )
        if not math.isfinite(float(sigma)) or float(sigma) <= 0.0:
            raise InvalidParameterError(
                f"sigma must be finite and > 0, got {sigma!r}"
            )
        try:
            raw_rows = [list(row) for row in r_hat]
        except TypeError as exc:
            raise InvalidParameterError(
                "r_hat must be an iterable of integer rows"
            ) from exc
        expected_rows = public_key.a.cols
        expected_cols = public_key.nk
        if len(raw_rows) != expected_rows:
            raise InvalidParameterError(
                f"r_hat must have {expected_rows} rows (columns of A), got {len(raw_rows)}"
            )
        for row in raw_rows:
            if len(row) != expected_cols:
                raise InvalidParameterError(
                    f"r_hat rows must have length n·k = {expected_cols}"
                )
            for value in row:
                if not _is_int(value):
                    raise InvalidParameterError(
                        f"r_hat entries must be int, got {type(value).__name__}"
                    )
        self._identity = ident
        self._digest = bytes(digest)
        self._r_hat = tuple(tuple(row) for row in raw_rows)
        self._pk = public_key
        self._sigma = float(sigma)

    @property
    def identity(self) -> bytes:
        return self._identity

    @property
    def identity_digest(self) -> bytes:
        return self._digest

    @property
    def r_hat(self) -> tuple[tuple[int, ...], ...]:
        return self._r_hat

    @property
    def public_key(self) -> SisPublicKey:
        return self._pk

    @property
    def sigma(self) -> float:
        return self._sigma

    def to_bytes(self) -> bytes:
        return (
            _MAG_SK
            + encode_bytes(self._identity)
            + self._digest
            + write_blob(self._pk.to_bytes())
            + f64be(self._sigma)
            + _encode_signed_matrix(self._r_hat)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "SisSigningKey":
        offset = expect_magic(data, _MAG_SK)
        raw = bytes(data)
        try:
            identity, offset = decode_bytes(raw, offset)
        except EncodingError as exc:
            raise SerializationError(f"malformed SisSigningKey: {exc}") from exc
        if not identity:
            raise SerializationError("malformed SisSigningKey: empty identity")
        if len(raw) - offset < _DIGEST_LEN:
            raise SerializationError(
                "malformed SisSigningKey: truncated identity digest"
            )
        digest = raw[offset : offset + _DIGEST_LEN]
        offset += _DIGEST_LEN
        pk_blob, offset = read_blob(raw, offset, "public key blob")
        sigma, offset = read_f64(raw, offset, "sigma")
        if sigma <= 0.0:
            raise SerializationError("malformed SisSigningKey: sigma must be > 0")
        grid, _end = _decode_signed_matrix(raw, offset)
        try:
            pk = SisPublicKey.from_bytes(pk_blob)
        except SerializationError as exc:
            raise SerializationError(f"malformed SisSigningKey: {exc}") from exc
        if digest != hash_identity(identity, _DIGEST_LEN):
            raise SerializationError(
                "malformed SisSigningKey: identity digest does not bind the identity"
            )
        if len(grid) != pk.a.cols or (grid and len(grid[0]) != pk.nk):
            raise SerializationError(
                "malformed SisSigningKey: r_hat dimensions "
                f"{len(grid)}x{len(grid[0]) if grid else 0} do not match "
                f"{pk.a.cols}x{pk.nk}"
            )
        try:
            return cls(
                identity=identity,
                r_hat=grid,
                public_key=pk,
                sigma=sigma,
                identity_digest=digest,
            )
        except InvalidParameterError as exc:
            raise SerializationError(f"malformed SisSigningKey: {exc}") from exc


class SisSignature(IBSSignature):
    """SIS-IBS 签名：短整数向量 z ∈ Z^{m+n·k}（不做模规范化，系数可负）。

    序列化：``"IBS1-S-SIG" || u32(vec_len) || u32(width) || 系数``，系数为
    width 字节二补码大端（定长含符号）；``to_bytes`` 选最小可容纳宽度。
    """

    __slots__ = ("_z",)

    def __init__(self, z) -> None:
        try:
            raw = list(z)
        except TypeError as exc:
            raise InvalidParameterError("z must be an iterable of ints") from exc
        if not raw:
            raise InvalidParameterError("z must be non-empty")
        for value in raw:
            if not _is_int(value):
                raise InvalidParameterError(
                    f"z entries must be int, got {type(value).__name__}"
                )
        self._z = tuple(raw)

    @property
    def z(self) -> tuple[int, ...]:
        return self._z

    @property
    def norm_squared(self) -> int:
        return sum(value * value for value in self._z)

    def __len__(self) -> int:
        return len(self._z)

    def to_bytes(self) -> bytes:
        width = _signed_entry_width(self._z)
        modulus = 1 << (8 * width)
        payload = b"".join(
            (value % modulus).to_bytes(width, "big") for value in self._z
        )
        return _MAG_SIG + u32be(len(self._z)) + u32be(width) + payload

    @classmethod
    def from_bytes(cls, data: bytes, pk: SisPublicKey) -> "SisSignature":
        """严格解析并做维度/范数界校验（需要 pk 上下文）。

        拒绝：magic 不符、截断、追加/重复字节、``vec_len ≠ pk.f_id_cols``
        （维度不符）、width ∉ [1,8]，以及 ``‖z‖₂ > s'·sqrt(f_id_cols)``
        的超范数界签名。
        """
        _require_sis_pk(pk)
        offset = expect_magic(data, _MAG_SIG)
        raw = bytes(data)
        vec_len, offset = read_u32(raw, offset, "signature length")
        width, offset = read_u32(raw, offset, "signature width")
        if vec_len != pk.f_id_cols:
            raise SerializationError(
                f"signature length {vec_len} does not match F_id columns "
                f"{pk.f_id_cols}"
            )
        if not 1 <= width <= 8:
            raise SerializationError(f"invalid signature entry width {width}")
        total = vec_len * width
        if len(raw) - offset != total:
            raise SerializationError(
                f"malformed signature: expected {total} bytes of coefficients, "
                f"got {len(raw) - offset} (truncated or trailing data is rejected)"
            )
        entries = [
            int.from_bytes(
                raw[offset + i * width : offset + (i + 1) * width], "big", signed=True
            )
            for i in range(vec_len)
        ]
        norm_sq = sum(value * value for value in entries)
        if norm_sq > pk.norm_bound_squared:
            raise SerializationError(
                "signature exceeds the verification norm bound: "
                f"‖z‖₂² = {norm_sq} > (s'·sqrt(cols))² = {pk.norm_bound_squared:.0f}"
            )
        return cls(entries)


# ---------------------------------------------------------------------------
# 后端
# ---------------------------------------------------------------------------

class SisIBSBackend:
    """改进版 SIS-IBS 后端（指导论文构造 3.4.1）。

    随机性经构造函数注入 ``rng``（``read(n) -> bytes`` 协议）；缺省
    ``SecureRandom``（生产）。固定随机源下 setup/key_extract/sign 全部
    可复现。安全声明：教学参数 + 简化采样，**不得宣称任何安全级别**。
    """

    def __init__(self, rng=None) -> None:
        if rng is None:
            rng = SecureRandom()
        if not (hasattr(rng, "read") and callable(rng.read)):
            raise RandomnessError(
                "rng must provide a callable read(n: int) -> bytes"
            )
        self._rng = rng

    # -- Setup ---------------------------------------------------------------

    def setup(self, params: Params) -> tuple[SisPublicKey, SisMasterSecret]:
        """trapgen 生成 (A, T_A)；mpk = (A, s')，msk = (pk, T_A, sigma)。"""
        if not isinstance(params, Params):
            raise InvalidParameterError(
                f"setup expects a Params object, got {type(params).__name__}"
            )
        k = gadget_width(params.q)
        if params.m_matrix - params.n * k < 1:
            raise InvalidParameterError(
                f"params.m_matrix ({params.m_matrix}) leaves no columns for "
                f"a_bar: need m_matrix > n*k = {params.n * k}"
            )
        td = trapgen(params, self._rng)
        pk = SisPublicKey(
            a=td.public_matrix(),
            s_prime=float(params.s_prime),
            name=params.name,
        )
        msk = SisMasterSecret(public_key=pk, trapdoor=td, sigma=float(params.s))
        return pk, msk

    # -- KeyExt（DelTrap 风格委派）-------------------------------------------

    def key_extract(self, msk: SisMasterSecret, identity: bytes) -> SisSigningKey:
        """逐列采样短 R̂_id，使 A·R̂_id + G = H1(mpk, id)（DelTrap 风格委派）。

        列采样沿用 lattice.sample_pre 的模式（短高斯 e + gadget 原像 + 线性
        组合 r_j = (R_A·ŷ_j + e_j, ŷ_j)），但 gadget 原像 ŷ_j 用零均值陪集
        采样（见模块 docstring）：确定性比特的均值偏移会使诚实签名超范数界。
        每列满足 A·r_j = (H1 − G)[:, j] (mod q)，构造后做整矩阵代数自检。
        """
        if not isinstance(msk, SisMasterSecret):
            raise TypeError(
                f"key_extract expects a SisMasterSecret, got {type(msk).__name__}"
            )
        ident = validate_identity(identity)
        pk = msk.public_key
        n, q, nk = pk.n, pk.q, pk.nk
        td = msk.trapdoor
        h1 = h1_matrix(pk, ident)
        gadget = gadget_matrix(n, q)
        target = h1 - gadget  # 逐列求解 A·r_j = (H1 − G)[:, j]
        m_bar = td.m_bar
        r_a_rows = td.r  # m_bar × nk 的短高斯整数矩阵
        columns: list[list[int]] = []
        for j in range(nk):
            e = sample_vector_gaussian(m_bar, msk.sigma, rng=self._rng)
            w = td.a_bar.matvec(ModVector(e, q))
            y_hat = _sample_gadget_coset(target.col(j) - w, _COSET_SIGMA, self._rng)
            r_j_head = [
                sum(r_ij * y_l for r_ij, y_l in zip(r_a_row, y_hat)) + e_i
                for r_a_row, e_i in zip(r_a_rows, e)
            ]
            columns.append(r_j_head + y_hat)
        m = pk.a.cols
        rows = tuple(
            tuple(columns[j][i] for j in range(nk)) for i in range(m)
        )
        # 整矩阵代数自检：A·R̂ + G == H1（精确成立，违反即为实现错误）。
        r_hat_mod = ModMatrix([list(row) for row in rows], q)
        if pk.a.mul_matrix(r_hat_mod) + gadget != h1:
            raise IBSError(
                "key_extract: delegated trapdoor does not satisfy A·R̂ + G = H1"
            )
        return SisSigningKey(
            identity=ident, r_hat=rows, public_key=pk, sigma=msk.sigma
        )

    # -- Sign ----------------------------------------------------------------

    def sign(self, sk: SisSigningKey, message: bytes) -> SisSignature:
        """签名 z = (x − R̂·y, y)，使 F_id·z = H2(mpk, id, m) (mod q)。

        身份绑定：只使用 ``sk.identity``（key_extract 时固定）；冻结接口
        无身份参数，调用方无法在此处误传另一个身份——若想为其他身份签名，
        必须先对该身份执行 key_extract。为身份 A 的 sk 产生的签名在
        ``verify(pk, B, ...)`` 下必然失败（H1/H2 随身份改变）。
        """
        if not isinstance(sk, SisSigningKey):
            raise TypeError(
                f"sign expects a SisSigningKey, got {type(sk).__name__}"
            )
        msg = validate_bytes(message, name="message")
        pk = sk.public_key
        a = pk.a
        q = pk.q
        h2 = h2_vector(pk, sk.identity, msg)
        f_id = a.hstack(h1_matrix(pk, sk.identity))
        bound_sq = pk.norm_bound_squared
        for _ in range(_MAX_SIGN_ATTEMPTS):
            x = sample_vector_gaussian(a.cols, sk.sigma, rng=self._rng)
            t = h2 - a.matvec(ModVector(x, q))
            y = bit_decompose(t).to_list()
            z_head = [
                xi - sum(rij * yj for rij, yj in zip(row, y))
                for xi, row in zip(x, sk.r_hat)
            ]
            z = z_head + y
            norm_sq = sum(value * value for value in z)
            if norm_sq == 0 or norm_sq > bound_sq:
                continue
            # 代数自检（恒等式，违反即为实现错误）。
            if f_id.matvec(ModVector(z, q)) != h2:
                raise IBSError("sign: produced a vector violating F_id·z = h2")
            return SisSignature(z)
        raise IBSError(
            f"sign: exhausted {_MAX_SIGN_ATTEMPTS} attempts without meeting the "
            f"norm bound ‖z‖₂ ≤ s'·sqrt(cols) = {math.sqrt(bound_sq):.1f}; check "
            "the parameter preset (s_prime) against the sampling widths"
        )

    # -- Verify --------------------------------------------------------------

    def verify(
        self,
        pk: SisPublicKey,
        identity: bytes,
        message: bytes,
        signature: SisSignature,
    ) -> bool:
        """重算 H1/F_id/h2 并检查 z ≠ 0、F_id·z ≡ h2、范数界；契约违规返回 False。"""
        if not isinstance(pk, SisPublicKey) or not isinstance(signature, SisSignature):
            return False
        if not is_identity_like(identity) or not is_bytes_like(message):
            return False
        if len(signature.z) != pk.f_id_cols:
            return False
        if not any(signature.z):
            return False
        if signature.norm_squared > pk.norm_bound_squared:
            return False
        ident = bytes(identity)
        msg = bytes(message)
        try:
            h2 = h2_vector(pk, ident, msg)
            f_id = f_id_matrix(pk, ident)
        except EncodingError:
            return False
        return f_id.matvec(ModVector(list(signature.z), pk.q)) == h2
