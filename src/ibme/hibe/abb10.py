"""Agrawal–Boneh–Boyen 2010 风格的两层格基 HIBE 参考实现（教学/调试）。

SECURITY CLAIM: none —— 本模块不宣称任何安全级别；参数未做格安全估计，
仅用于功能调试与契约测试。功能测试成功不构成 LWE/SIS 或 HIBE 安全性证明。

构造（按任务 C 规范与 notes/ib-me-hibe-ibs-design.md §4.4，维度记
k = ceil(log2 q)、nk = n·k、m = m_bar + nk）::

    setup(params, rng):
        trapgen 采样主 G-陷门 (Ā, R)（高斯宽度 params.s0），公开矩阵
        A = [Ā | G - Ā·R] ∈ Z_q^{n×m}，公开向量 u ← Z_q^n 均匀采样
        （公开随机量，允许均匀）。
    extract(msk, rcv, rng):
        H(rcv) = SHAKE256(DOMAIN_HIBE_ID, "L1"||enc(rcv)) → Z_q^{n×nk}；
        逐列零均值原像采样（随机化 gadget 分解基，见
        :func:`_sample_pre_centered`）得短整数矩阵 R1 使
            A·R1 = H(rcv) - G   (mod q)，
        于是 [-R1; I_nk] 是 B_rcv = [A | H(rcv)] 的 G-陷门。
        第一层密钥 = (rcv, A, u, R1)。
    derive(sk_rcv, phi, rng):
        H(rcv, phi) = SHAKE256(DOMAIN_HIBE_ID, "L2"||enc(rcv)||enc(phi))；
        用 B_rcv 的陷门 [-R1; I] 逐列采样 R2 使
            B_rcv·R2 = H(rcv, phi) - G   (mod q)，
        于是 [-R2; I_nk] 是 B_full = [A | H(rcv) | H(rcv, phi)] 的陷门。
        第二层密钥 = (rcv, phi, A, u, R2)。
    encrypt(pk, rcv, phi, payload, rng):
        B_full = [A | H(rcv) | H(rcv, phi)]；Regev 比特加密，全部比特共享
        (s, e2)：s ← Z_q^n 均匀（公开随机量）、e1_j/e2 高斯（宽度
        params.s）。加密明文是绑定身份的结构化串::
            m = enc(rcv) || enc(phi) || enc(payload)
            c2  = B_full^T·s + e2 ∈ Z_q^{m+2nk}
            c1_j = u·s + e1_j + m_j·⌊q/2⌉
        身份放在 LWE 明文中而不是密文里：密文字节不含身份明文（匿名性
        的功能要求），语义上的不泄露依赖 LWE（教学参数下不做声明）。
    decrypt(sk2, ct, rng):
        解密方用自己的 (ρ, snd) 重算 B(ρ, snd)，用陷门 [-R2; I] 对 u 做
        零均值原像采样，取其前 m+2nk 个分量为短向量 x（B_full·x = u，
        运行时验证），恢复::
            v_j = c1_j - <x, c2> = m_j·⌊q/2⌉ + (e1_j - <x, e2>)，
        以 q/4 为阈值解码出 m'，严格解析出 (rcv', phi', payload')，并与
        解密方身份做常数时间比较。任何失败——维度/模数不符、原像验证
        失败、解析错误、身份不匹配——返回 None。

    身份绑定是必要的：所有比特共享 (s, e2)，不匹配身份下的解密噪声是
    全局共享偏移（来自 ΔH·x_tail），比特要么整体"正确"要么整体翻转，
    解码本身无法检测不匹配；只有显式的身份比对才能把不匹配映射为
    BOTTOM (None)。

噪声预算（ABB10_DEBUG_PARAMS：n=8, q=2^19, k=19, nk=152, m_bar=16,
σ0=3.0, σ_pre=1.0, σ_enc=1.0；中心化分解位 bits_c 的方差为 1/2，记
α = sqrt(nk/2) ≈ 8.72）：

* 委派链每过一层零均值原像采样，主导行的标准差乘 α（因
  ``z_head = R_prev·bits_c + e``，bits_c 各位方差 1/2）：
  ``σ(R1 主导行) ≈ sqrt((nk/2)·σ0² + σ_pre²) ≈ 26``；
  ``σ(R2 主导行) ≈ σ0·α² ≈ 228``；
  ``σ(x  主导行) ≈ σ0·α³ ≈ 1990``，从而 ``||x||₂ ≈ 8·10³``。
* 每比特解密噪声 ``e1_j - <x, e2>`` 的标准差 ≈ ``||x||₂·σ_enc ≈ 8·10³``；
  解码阈值 ``q/4 = 131072 ≈ 16σ``，单比特解码失败概率（高斯尾近似）
  低于 1e-57，多比特 payload 下仍可忽略。
* 以上是启发式估计：原像采样是无扰动的简化分布（见
  :func:`_sample_pre_centered` 的说明与 lattice.trapdoor 的限制声明），
  因此本后端不得用于任何安全声明；教育参数 EDUCATION_PARAMS (q=257)
  的噪声预算不足以正确解码，本模块自带 ABB10_DEBUG_PARAMS 预设
  （security_claim: none，仅调试）。

与 ABB10 论文实例的已知差异（教学简化，已列入交付风险）：

* H(·) 用 SHAKE-256 哈希到均匀矩阵（ROM 风格工程实例），不是论文标准
  模型下的目标函数构造；身份矩阵不与 mpk 绑定；
* 陷门/原像采样复用 M1 的简化 trapgen 与无扰动原像采样，并在 hibe 层
  加了随机化 gadget 分解基以消除均值累积（见
  :func:`_sample_pre_centered`）；输出分布均未达证明级。

序列化格式（全部严格解析：magic、维度交叉验证、拒绝截断/追加）::

    pk  : MAGIC || meta(40B: n,m_bar,q,max_msg,s0,s_enc,s_pre) || A || u
    msk : MAGIC || meta || Ā || R(shift 编码为 mod-q 矩阵)
    sk1 : MAGIC || meta || enc(rcv) || A || u || R1(shift 编码)
    sk2 : MAGIC || meta || enc(rcv) || enc(phi) || A || u || R2(shift 编码)
    ct  : MAGIC || u32(bit_count) || c2 || c1 元素 (elem(q) 字节/个)

ct 的加密明文是 ``enc(rcv) || enc(phi) || enc(payload)``，bit_count 是
该明文的总比特数（即 len(c1)）。

短整数矩阵的 shift 编码：``v ∈ [-⌊q/2⌋, ⌊q/2⌋) ↔ (v + ⌊q/2⌋) mod q``，
半开区间保证往返无歧义（避免 ±q/2 同余碰撞）。
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass

from ibme.core.encoding import decode_bytes, encode_bytes
from ibme.core.errors import (
    IBMEError,
    InvalidParameterError,
    SerializationError,
)
from ibme.core.hashing import DOMAIN_HIBE_ID, shake256
from ibme.core.randomness import DeterministicRandom, SecureRandom
from ibme.core.types import constant_time_equal, validate_bytes, validate_identity
from ibme.lattice.gadget import bit_decompose, gadget_matrix, gadget_width
from ibme.lattice.gaussian import (
    sample_integer_gaussian,
    sample_vector_gaussian,
    uniform_integer,
)
from ibme.lattice.modmat import ModMatrix, ModVector
from ibme.lattice.params import Params
from ibme.lattice.trapdoor import Trapdoor, trapgen

__all__ = [
    "ABB10HIBE",
    "ABB10_DEBUG_PARAMS",
    "ABB10PublicKey",
    "ABB10MasterSecret",
    "ABB10Level1SecretKey",
    "ABB10Level2SecretKey",
    "ABB10Ciphertext",
    "hash_identity_matrix",
    "hash_pair_matrix",
    "verify_level1_key",
    "verify_level2_key",
]

_MAGIC_PK = b"IBME:HIBE-ABB10:PK:v1"
_MAGIC_MSK = b"IBME:HIBE-ABB10:MSK:v1"
_MAGIC_SK1 = b"IBME:HIBE-ABB10:SK1:v1"
_MAGIC_SK2 = b"IBME:HIBE-ABB10:SK2:v1"
_MAGIC_CT = b"IBME:HIBE-ABB10:CT:v1"

#: 层级标签：保证单身份与身份对的哈希输入无碰撞歧义（"L1"/"L2" 前缀
#: 加长度前缀编码，任何不同输入串都不会产生相同的 SHAKE-256 输入）。
_LAYER1_TAG = b"L1"
_LAYER2_TAG = b"L2"

_U32 = 4
_Q_LIMIT = 1 << 32
# n, m_bar, q, max_message_bytes 为 uint32；s0, s_enc, s_pre 为 float64。
_META_STRUCT = struct.Struct(">IIIIddd")
_META_SIZE = _META_STRUCT.size

#: ABB10 调试参数预设（security_claim: none，仅调试）。
#: 噪声预算分析见模块 docstring；未做任何格安全估计。
ABB10_DEBUG_PARAMS = Params(
    name="hibe-abb10-debug",
    security_parameter=8,  # 仅为标签，不对应任何安全等级
    n=8,
    m_matrix=168,  # = m_bar(16) + n*k(152)，k = ceil(log2 2^19) = 19
    q=524288,  # 2^19；q/4 = 131072 ≈ 16 个解密噪声标准差
    s0=3.0,  # trapgen 中主陷门 R 的离散高斯宽度
    s=1.0,  # 加密侧高斯噪声宽度（e1、e2）
    s_prime=1.0,  # sample_pre 误差宽度（extract/derive/decrypt 共用）
    identity_bytes=16,
    max_message_bytes=32,
)


# ---------------------------------------------------------------------------
# 参数快照与序列化辅助
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ParamsMeta:
    """pk/sk 中内嵌的参数快照（从 Params 派生；序列化自描述）。"""

    n: int
    m_bar: int
    q: int
    max_message_bytes: int
    s0: float
    s_enc: float
    s_pre: float


def _meta_from_params(params: Params) -> _ParamsMeta:
    return _ParamsMeta(
        n=params.n,
        m_bar=params.m_matrix - params.n * gadget_width(params.q),
        q=params.q,
        max_message_bytes=params.max_message_bytes,
        s0=params.s0,
        s_enc=params.s,
        s_pre=params.s_prime,
    )


def _encode_meta(meta: _ParamsMeta) -> bytes:
    return _META_STRUCT.pack(
        meta.n, meta.m_bar, meta.q, meta.max_message_bytes, meta.s0, meta.s_enc, meta.s_pre
    )


def _decode_meta(raw: bytes, offset: int) -> tuple[_ParamsMeta, int]:
    if len(raw) - offset < _META_SIZE:
        raise SerializationError("truncated parameter metadata")
    n, m_bar, q, max_msg, s0, s_enc, s_pre = _META_STRUCT.unpack_from(raw, offset)
    if not 1 <= n < _Q_LIMIT or not 1 <= m_bar < _Q_LIMIT:
        raise SerializationError(f"invalid metadata dimensions n={n}, m_bar={m_bar}")
    if not 2 <= q < _Q_LIMIT:
        raise SerializationError(f"invalid metadata modulus q={q}")
    if max_msg < 1:
        raise SerializationError(f"invalid metadata max_message_bytes={max_msg}")
    for name, value in (("s0", s0), ("s_enc", s_enc), ("s_pre", s_pre)):
        if not math.isfinite(value) or value <= 0:
            raise SerializationError(f"invalid metadata width {name}={value!r}")
    return (
        _ParamsMeta(
            n=n, m_bar=m_bar, q=q, max_message_bytes=max_msg, s0=s0, s_enc=s_enc, s_pre=s_pre
        ),
        offset + _META_SIZE,
    )


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
    except IBMEError as exc:
        raise SerializationError(f"malformed {what}: {exc}") from exc


def _elem_size(q: int) -> int:
    return (q.bit_length() + 7) // 8


def _slice_matrix(raw: bytes, offset: int, what: str) -> tuple[ModMatrix, int]:
    """从 offset 解析一个自描述 ModMatrix，返回 (矩阵, 新 offset)。"""
    if len(raw) - offset < 3 * _U32:
        raise SerializationError(f"truncated {what} header")
    rows = int.from_bytes(raw[offset : offset + _U32], "big")
    cols = int.from_bytes(raw[offset + _U32 : offset + 2 * _U32], "big")
    if not 1 <= rows < _Q_LIMIT or not 1 <= cols < _Q_LIMIT:
        raise SerializationError(f"invalid {what} dimensions {rows}x{cols}")
    total = 3 * _U32 + rows * cols * _elem_size(int.from_bytes(raw[offset + 2 * _U32 : offset + 3 * _U32], "big"))
    end = offset + total
    if end > len(raw):
        raise SerializationError(f"truncated {what} body")
    return ModMatrix.from_bytes(raw[offset:end]), end


def _slice_vector(raw: bytes, offset: int, what: str) -> tuple[ModVector, int]:
    """从 offset 解析一个自描述 ModVector，返回 (向量, 新 offset)。"""
    if len(raw) - offset < 2 * _U32:
        raise SerializationError(f"truncated {what} header")
    length = int.from_bytes(raw[offset : offset + _U32], "big")
    if not 1 <= length < _Q_LIMIT:
        raise SerializationError(f"invalid {what} length {length}")
    total = 2 * _U32 + length * _elem_size(int.from_bytes(raw[offset + _U32 : offset + 2 * _U32], "big"))
    end = offset + total
    if end > len(raw):
        raise SerializationError(f"truncated {what} body")
    return ModVector.from_bytes(raw[offset:end]), end


def _short_to_modmat(rows: tuple[tuple[int, ...], ...], q: int, what: str) -> ModMatrix:
    """短整数矩阵 → mod-q 矩阵（shift 编码，半开区间无歧义）。"""
    half = q // 2
    encoded = []
    for row in rows:
        out_row = []
        for value in row:
            if not -half <= value < half:
                raise SerializationError(
                    f"{what}: entry {value} outside [-{half}, {half}) cannot be "
                    "shift-encoded losslessly"
                )
            out_row.append(value + half)
        encoded.append(out_row)
    return ModMatrix(encoded, q)


def _modmat_to_short(mat: ModMatrix) -> tuple[tuple[int, ...], ...]:
    """mod-q 矩阵 → 短整数矩阵（shift 编码的逆）。"""
    half = mat.q // 2
    return tuple(
        tuple(value - half for value in row) for row in mat.to_lists()
    )


def _check_short_matrix(rows: object, n_rows: int, n_cols: int, what: str) -> tuple[tuple[int, ...], ...]:
    if not isinstance(rows, tuple) or len(rows) != n_rows:
        raise InvalidParameterError(
            f"{what}: expected a {n_rows}x{n_cols} integer matrix, "
            f"got {type(rows).__name__} with {len(rows) if isinstance(rows, tuple) else '?'} rows"
        )
    fixed = []
    for row in rows:
        if not isinstance(row, tuple) or len(row) != n_cols:
            raise InvalidParameterError(f"{what}: rows must have length {n_cols}")
        for value in row:
            if not isinstance(value, int) or isinstance(value, bool):
                raise InvalidParameterError(f"{what}: entries must be int")
        fixed.append(tuple(row))
    return tuple(fixed)


# ---------------------------------------------------------------------------
# 身份哈希（公开辅助，供测试/审计复算）
# ---------------------------------------------------------------------------


def _hash_to_matrix(data: bytes, n: int, q: int) -> ModMatrix:
    """SHAKE-256(DOMAIN_HIBE_ID, data) 种子化的均匀矩阵 Z_q^{n×nk}。"""
    nk = n * gadget_width(q)
    seed = shake256(DOMAIN_HIBE_ID, data, 32)
    rng = DeterministicRandom(seed)
    return ModMatrix(
        [[uniform_integer(rng, q) for _ in range(nk)] for _ in range(n)], q
    )


def hash_identity_matrix(identity: bytes, n: int, q: int) -> ModMatrix:
    """H(id)：第一层身份矩阵 Z_q^{n×n·k}（域分隔 + 长度前缀 + 层标签）。

    输入为 ``"L1" || encode_bytes(id)``；与身份对哈希的输入
    ``"L2" || encode_bytes(a) || encode_bytes(b)`` 因层标签与长度前缀而
    无碰撞歧义。
    """
    ident = validate_identity(identity)
    return _hash_to_matrix(_LAYER1_TAG + encode_bytes(ident), n, q)


def hash_pair_matrix(parent_id: bytes, child_id: bytes, n: int, q: int) -> ModMatrix:
    """H(a, b)：第二层身份对矩阵 Z_q^{n×n·k}（域分隔 + 长度前缀 + 层标签）。"""
    parent = validate_identity(parent_id, name="parent_id")
    child = validate_identity(child_id, name="child_id")
    data = _LAYER2_TAG + encode_bytes(parent) + encode_bytes(child)
    return _hash_to_matrix(data, n, q)


# ---------------------------------------------------------------------------
# 采样与代数辅助
# ---------------------------------------------------------------------------


def _sample_pre_matrix(
    td: Trapdoor, target: ModMatrix, rng, sigma: float, head_rows: int
) -> tuple[tuple[int, ...], ...]:
    """逐列零均值原像采样，返回短整数矩阵。

    ``td`` 表示的公开矩阵是 ``[a_bar | G - a_bar·R]``，每列输出 ``z =
    [z_head; bits_c]``（长度 ``a_bar.cols + n·k``）。``head_rows`` 指定
    保留的行数：

    * 第一层 R1：``head_rows = a_bar.cols + n·k``（完整 z，覆盖公开
      矩阵 A 的全部 m 列，A·R1 = H - G）；
    * 第二层 R2：``head_rows = a_bar.cols``（只取 z_head；当陷门满足
      ``a_bar·R ≡ G`` 时右 gadget 列块为零，z_head 单独满足
      ``a_bar·z_head = target``，即 B_rcv·R2 = H - G）。
    """
    if not 1 <= head_rows <= td.a_bar.cols + td.n * td.k:
        raise InvalidParameterError(
            f"head_rows must be in [1, {td.a_bar.cols + td.n * td.k}], got {head_rows}"
        )
    columns = [
        _sample_pre_centered(td, target.col(j), rng, sigma)[:head_rows]
        for j in range(target.cols)
    ]
    return tuple(tuple(column[i] for column in columns) for i in range(head_rows))


def _sample_pre_centered(td: Trapdoor, u: ModVector, rng, sigma: float) -> list[int]:
    """零均值化的原像采样：``[a_bar | G - a_bar·R]·z = u`` 且 ``E[z] ≈ 0``。

    与 ``ibme.lattice.trapdoor.sample_pre`` 的代数关系相同，但把 gadget
    分解基先随机平移：每列采 ``b* ← {0,1}^{n·k}``，令::

        v   = u + G·b* - a_bar·e   (mod q)
        z   = [R·(bit_decompose(v) - b*) + e ;  bit_decompose(v) - b*]

    则 ``a_bar·z_head + (G - a_bar·R)·bits_c = a_bar·e + G·bits_c = v - G·b* + a_bar·e = u``
    精确成立，且 ``E[bits_c] = 0`` 逐位成立（否则 ``E[bits] = 1/2`` 会在
    委派链的每一层把 ``R·bits`` 的行均值按 ``(1/2)·Σ R_ij`` 系统性放大，
    使解密原像范数远超噪声预算——这是对 M1 简化 sample_pre 的 hibe 层
    补偿，不修改 lattice 模块）。

    该采样仍是简化分布（无 MP12 扰动），不用于任何安全声明。
    """
    n, q, k = td.n, td.q, td.k
    nk = n * k
    e = sample_vector_gaussian(td.m_bar, sigma, rng=rng)
    b_star = [uniform_integer(rng, 2) for _ in range(nk)]
    g = gadget_matrix(n, q)
    v = (
        u
        + g.matvec(ModVector(b_star, q))
        - td.a_bar.matvec(ModVector(e, q))
    )
    bits_c = [
        bit - star for bit, star in zip(bit_decompose(v).to_list(), b_star)
    ]
    z_head = [
        sum(r_ij * b_j for r_ij, b_j in zip(row, bits_c)) + e_i
        for row, e_i in zip(td.r, e)
    ]
    return z_head + bits_c


def _neg_stack_identity(
    rows: tuple[tuple[int, ...], ...], nk: int
) -> tuple[tuple[int, ...], ...]:
    """构造 [-R; I_nk]（B 的 G-陷门，当 B·R = H - G 时）。"""
    top = [tuple(-value for value in row) for row in rows]
    bottom = [
        tuple(1 if i == j else 0 for j in range(nk)) for i in range(nk)
    ]
    return tuple(top) + tuple(bottom)


def _require_rng(rng, what: str):
    resolved = rng if rng is not None else SecureRandom()
    if not hasattr(resolved, "read") or not callable(resolved.read):
        raise InvalidParameterError(f"{what}: rng must provide read(n: int) -> bytes")
    return resolved


# ---------------------------------------------------------------------------
# 数据类型
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ABB10PublicKey:
    """ABB10 公钥：参数快照、公开矩阵 A ∈ Z_q^{n×m} 与公开向量 u ∈ Z_q^n。"""

    meta: _ParamsMeta
    a: ModMatrix
    u: ModVector

    def __post_init__(self) -> None:
        if not isinstance(self.meta, _ParamsMeta):
            raise InvalidParameterError("meta must be an ABB10 parameter snapshot")
        if not isinstance(self.a, ModMatrix) or not isinstance(self.u, ModVector):
            raise InvalidParameterError("a must be a ModMatrix and u a ModVector")
        n, q = self.meta.n, self.meta.q
        if self.a.q != q or self.a.rows != n:
            raise InvalidParameterError("a must be n x (m_bar + n*k) over Z_q")
        if self.a.cols != self.meta.m_bar + n * gadget_width(q):
            raise InvalidParameterError("a must be n x (m_bar + n*k) over Z_q")
        if self.u.q != q or self.u.length != n:
            raise InvalidParameterError("u must have length n over Z_q")

    def to_bytes(self) -> bytes:
        return _MAGIC_PK + _encode_meta(self.meta) + self.a.to_bytes() + self.u.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "ABB10PublicKey":
        raw = _strip_magic(data, _MAGIC_PK, "ABB10PublicKey")
        meta, off = _decode_meta(raw, 0)
        a, off = _slice_matrix(raw, off, "public matrix")
        u, off = _slice_vector(raw, off, "public vector")
        if off != len(raw):
            raise SerializationError("ABB10PublicKey: trailing bytes")
        return cls(meta=meta, a=a, u=u)


@dataclass(frozen=True)
class ABB10MasterSecret:
    """ABB10 主密钥：均匀块 Ā 与短高斯主陷门 R（主密钥为陷门，须保密）。"""

    meta: _ParamsMeta
    a_bar: ModMatrix
    r: tuple[tuple[int, ...], ...]
    u: ModVector

    def __post_init__(self) -> None:
        if not isinstance(self.meta, _ParamsMeta):
            raise InvalidParameterError("meta must be an ABB10 parameter snapshot")
        n, q = self.meta.n, self.meta.q
        if not isinstance(self.a_bar, ModMatrix) or self.a_bar.q != q or self.a_bar.rows != n:
            raise InvalidParameterError("a_bar must be n x m_bar over Z_q")
        if self.a_bar.cols != self.meta.m_bar:
            raise InvalidParameterError("a_bar must be n x m_bar over Z_q")
        object.__setattr__(
            self,
            "r",
            _check_short_matrix(self.r, self.meta.m_bar, n * gadget_width(q), "master trapdoor r"),
        )
        if not isinstance(self.u, ModVector) or self.u.q != q or self.u.length != n:
            raise InvalidParameterError("u must have length n over Z_q")

    def to_bytes(self) -> bytes:
        encoded_r = _short_to_modmat(self.r, self.meta.q, "master trapdoor r")
        return (
            _MAGIC_MSK
            + _encode_meta(self.meta)
            + self.a_bar.to_bytes()
            + encoded_r.to_bytes()
            + self.u.to_bytes()
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "ABB10MasterSecret":
        raw = _strip_magic(data, _MAGIC_MSK, "ABB10MasterSecret")
        meta, off = _decode_meta(raw, 0)
        a_bar, off = _slice_matrix(raw, off, "a_bar")
        r_mat, off = _slice_matrix(raw, off, "trapdoor r")
        u, off = _slice_vector(raw, off, "public vector u")
        if off != len(raw):
            raise SerializationError("ABB10MasterSecret: trailing bytes")
        expected = (meta.m_bar, meta.n * gadget_width(meta.q))
        if (a_bar.rows, a_bar.cols) != (meta.n, meta.m_bar):
            raise SerializationError("ABB10MasterSecret: a_bar dimensions mismatch metadata")
        if (r_mat.rows, r_mat.cols) != expected:
            raise SerializationError(
                f"ABB10MasterSecret: trapdoor must be {expected[0]}x{expected[1]}, "
                f"got {r_mat.rows}x{r_mat.cols}"
            )
        return cls(meta=meta, a_bar=a_bar, r=_modmat_to_short(r_mat), u=u)


@dataclass(frozen=True)
class ABB10Level1SecretKey:
    """第一层密钥：身份 rcv、公开矩阵 A、公开向量 u 与委派矩阵 R1。"""

    meta: _ParamsMeta
    identity: bytes
    a: ModMatrix
    u: ModVector
    r1: tuple[tuple[int, ...], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.meta, _ParamsMeta):
            raise InvalidParameterError("meta must be an ABB10 parameter snapshot")
        self_identity = validate_identity(self.identity, name="identity")
        object.__setattr__(self, "identity", self_identity)
        n, q = self.meta.n, self.meta.q
        m = self.meta.m_bar + n * gadget_width(q)
        if not isinstance(self.a, ModMatrix) or (self.a.rows, self.a.cols, self.a.q) != (n, m, q):
            raise InvalidParameterError("a must be n x (m_bar + n*k) over Z_q")
        if not isinstance(self.u, ModVector) or self.u.q != q or self.u.length != n:
            raise InvalidParameterError("u must have length n over Z_q")
        object.__setattr__(
            self, "r1", _check_short_matrix(self.r1, m, n * gadget_width(q), "level-1 key r1")
        )

    def to_bytes(self) -> bytes:
        encoded = _short_to_modmat(self.r1, self.meta.q, "level-1 key r1")
        return (
            _MAGIC_SK1
            + _encode_meta(self.meta)
            + encode_bytes(self.identity)
            + self.a.to_bytes()
            + self.u.to_bytes()
            + encoded.to_bytes()
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "ABB10Level1SecretKey":
        raw = _strip_magic(data, _MAGIC_SK1, "ABB10Level1SecretKey")
        meta, off = _decode_meta(raw, 0)
        identity, off = _decode_field(raw, off, "ABB10Level1SecretKey")
        if not identity:
            raise SerializationError("ABB10Level1SecretKey: empty identity")
        a, off = _slice_matrix(raw, off, "public matrix")
        u, off = _slice_vector(raw, off, "public vector")
        r_mat, off = _slice_matrix(raw, off, "r1")
        if off != len(raw):
            raise SerializationError("ABB10Level1SecretKey: trailing bytes")
        n, q = meta.n, meta.q
        m = meta.m_bar + n * gadget_width(q)
        if (a.rows, a.cols, a.q) != (n, m, q):
            raise SerializationError("ABB10Level1SecretKey: matrix dimensions mismatch metadata")
        if (r_mat.rows, r_mat.cols) != (m, n * gadget_width(q)):
            raise SerializationError("ABB10Level1SecretKey: r1 dimensions mismatch metadata")
        return cls(meta=meta, identity=identity, a=a, u=u, r1=_modmat_to_short(r_mat))


@dataclass(frozen=True)
class ABB10Level2SecretKey:
    """第二层密钥：身份对 (rcv, phi)、A、u 与委派矩阵 R2。"""

    meta: _ParamsMeta
    parent_identity: bytes
    child_identity: bytes
    a: ModMatrix
    u: ModVector
    r2: tuple[tuple[int, ...], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.meta, _ParamsMeta):
            raise InvalidParameterError("meta must be an ABB10 parameter snapshot")
        parent = validate_identity(self.parent_identity, name="parent_identity")
        child = validate_identity(self.child_identity, name="child_identity")
        object.__setattr__(self, "parent_identity", parent)
        object.__setattr__(self, "child_identity", child)
        n, q = self.meta.n, self.meta.q
        m = self.meta.m_bar + n * gadget_width(q)
        if not isinstance(self.a, ModMatrix) or (self.a.rows, self.a.cols, self.a.q) != (n, m, q):
            raise InvalidParameterError("a must be n x (m_bar + n*k) over Z_q")
        if not isinstance(self.u, ModVector) or self.u.q != q or self.u.length != n:
            raise InvalidParameterError("u must have length n over Z_q")
        object.__setattr__(
            self,
            "r2",
            _check_short_matrix(self.r2, m + n * gadget_width(q), n * gadget_width(q), "level-2 key r2"),
        )

    def to_bytes(self) -> bytes:
        encoded = _short_to_modmat(self.r2, self.meta.q, "level-2 key r2")
        return (
            _MAGIC_SK2
            + _encode_meta(self.meta)
            + encode_bytes(self.parent_identity)
            + encode_bytes(self.child_identity)
            + self.a.to_bytes()
            + self.u.to_bytes()
            + encoded.to_bytes()
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "ABB10Level2SecretKey":
        raw = _strip_magic(data, _MAGIC_SK2, "ABB10Level2SecretKey")
        meta, off = _decode_meta(raw, 0)
        parent, off = _decode_field(raw, off, "ABB10Level2SecretKey")
        child, off = _decode_field(raw, off, "ABB10Level2SecretKey")
        if not parent or not child:
            raise SerializationError("ABB10Level2SecretKey: empty identity")
        a, off = _slice_matrix(raw, off, "public matrix")
        u, off = _slice_vector(raw, off, "public vector")
        r_mat, off = _slice_matrix(raw, off, "r2")
        if off != len(raw):
            raise SerializationError("ABB10Level2SecretKey: trailing bytes")
        n, q = meta.n, meta.q
        m = meta.m_bar + n * gadget_width(q)
        if (a.rows, a.cols, a.q) != (n, m, q):
            raise SerializationError("ABB10Level2SecretKey: matrix dimensions mismatch metadata")
        if (r_mat.rows, r_mat.cols) != (m + n * gadget_width(q), n * gadget_width(q)):
            raise SerializationError("ABB10Level2SecretKey: r2 dimensions mismatch metadata")
        return cls(
            meta=meta,
            parent_identity=parent,
            child_identity=child,
            a=a,
            u=u,
            r2=_modmat_to_short(r_mat),
        )


@dataclass(frozen=True)
class ABB10Ciphertext:
    """Regev 密文：每比特一个 c1 系数 + 共享的 c2 向量（不含身份明文）。"""

    c1: tuple[int, ...]
    c2: ModVector

    def __post_init__(self) -> None:
        if not isinstance(self.c2, ModVector):
            raise InvalidParameterError("c2 must be a ModVector")
        if not isinstance(self.c1, tuple):
            raise InvalidParameterError("c1 must be a tuple of ints")
        if len(self.c1) % 8 != 0:
            raise InvalidParameterError("c1 must encode whole bytes (length % 8 == 0)")
        for value in self.c1:
            if not isinstance(value, int) or isinstance(value, bool):
                raise InvalidParameterError("c1 entries must be int")
            if not 0 <= value < self.c2.q:
                raise InvalidParameterError("c1 entries must lie in [0, q)")

    def to_bytes(self) -> bytes:
        elem = _elem_size(self.c2.q)
        c1_blob = b"".join(value.to_bytes(elem, "big") for value in self.c1)
        return (
            _MAGIC_CT
            + len(self.c1).to_bytes(_U32, "big")
            + self.c2.to_bytes()
            + c1_blob
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "ABB10Ciphertext":
        raw = _strip_magic(data, _MAGIC_CT, "ABB10Ciphertext")
        if len(raw) < _U32:
            raise SerializationError("ABB10Ciphertext: truncated bit-count field")
        n_bits = int.from_bytes(raw[:_U32], "big")
        if n_bits % 8 != 0:
            raise SerializationError("ABB10Ciphertext: bit count must be a multiple of 8")
        c2, off = _slice_vector(raw, _U32, "c2")
        elem = _elem_size(c2.q)
        expected = n_bits * elem
        if len(raw) - off != expected:
            raise SerializationError(
                f"ABB10Ciphertext: c1 region must be {expected} bytes, got {len(raw) - off}"
            )
        c1 = [
            int.from_bytes(raw[off + i * elem : off + (i + 1) * elem], "big")
            for i in range(n_bits)
        ]
        for value in c1:
            if value >= c2.q:
                raise SerializationError(
                    f"ABB10Ciphertext: c1 entry {value} out of range [0, {c2.q})"
                )
        return cls(c1=tuple(c1), c2=c2)


# ---------------------------------------------------------------------------
# 代数关系验证（公开辅助，供测试与审计）
# ---------------------------------------------------------------------------


def verify_level1_key(sk1: ABB10Level1SecretKey) -> bool:
    """验证第一层代数关系 ``A·R1 + G == H(rcv) (mod q)``。"""
    n, q = sk1.meta.n, sk1.meta.q
    a_r1 = sk1.a @ ModMatrix([list(row) for row in sk1.r1], q)
    lhs = a_r1 + gadget_matrix(n, q)
    return lhs == hash_identity_matrix(sk1.identity, n, q)


def verify_level2_key(sk2: ABB10Level2SecretKey) -> bool:
    """验证第二层代数关系 ``B_rcv·R2 + G == H(rcv, phi) (mod q)``。"""
    n, q = sk2.meta.n, sk2.meta.q
    b_rcv = sk2.a.hstack(hash_identity_matrix(sk2.parent_identity, n, q))
    b_r2 = b_rcv @ ModMatrix([list(row) for row in sk2.r2], q)
    lhs = b_r2 + gadget_matrix(n, q)
    return lhs == hash_pair_matrix(sk2.parent_identity, sk2.child_identity, n, q)


# ---------------------------------------------------------------------------
# 后端
# ---------------------------------------------------------------------------


class ABB10HIBE:
    """ABB10 风格两层格基 HIBE 后端（教学参考实现，security_claim: none）。

    身份顺序固定 ``(parent_id, child_id) = (rcv, phi)``；decrypt 失败返回
    ``None``；密文不含身份明文。所有随机性经 ``rng`` 注入（``None`` 表示
    生产随机源）；均匀采样仅用于公开随机量（s、u），噪声与陷门采样均为
    真离散高斯（复用 ibme.lattice 采样器）。
    """

    def setup(self, params, *, rng=None):
        if not isinstance(params, Params):
            raise InvalidParameterError(
                f"setup expects a Params object, got {type(params).__name__}"
            )
        rng = _require_rng(rng, "setup")
        td = trapgen(params, rng, sigma_r=params.s0)
        meta = _meta_from_params(params)
        u = ModVector([uniform_integer(rng, meta.q) for _ in range(meta.n)], meta.q)
        return (
            ABB10PublicKey(meta=meta, a=td.public_matrix(), u=u),
            ABB10MasterSecret(meta=meta, a_bar=td.a_bar, r=td.r, u=u),
        )

    def extract(self, msk, parent_id: bytes, *, rng=None):
        if not isinstance(msk, ABB10MasterSecret):
            raise TypeError("extract expects an ABB10MasterSecret")
        ident = validate_identity(parent_id, name="parent_id")
        rng = _require_rng(rng, "extract")
        meta = msk.meta
        n, q = meta.n, meta.q
        td = Trapdoor(a_bar=msk.a_bar, r=msk.r)
        a = td.public_matrix()
        target = hash_identity_matrix(ident, n, q) - gadget_matrix(n, q)
        # R1 覆盖公开矩阵 A 的全部 m 列：A·R1 = H(rcv) - G。
        r1 = _sample_pre_matrix(td, target, rng, meta.s_pre, head_rows=a.cols)
        return ABB10Level1SecretKey(meta=meta, identity=ident, a=a, u=msk.u, r1=r1)

    def derive(self, sk_parent, child_id: bytes, *, rng=None):
        if not isinstance(sk_parent, ABB10Level1SecretKey):
            raise TypeError("derive expects an ABB10Level1SecretKey")
        phi = validate_identity(child_id, name="child_id")
        rng = _require_rng(rng, "derive")
        meta = sk_parent.meta
        n, q = meta.n, meta.q
        nk = n * gadget_width(q)
        b_rcv = sk_parent.a.hstack(hash_identity_matrix(sk_parent.identity, n, q))
        td_rcv = Trapdoor(a_bar=b_rcv, r=_neg_stack_identity(sk_parent.r1, nk))
        target = hash_pair_matrix(sk_parent.identity, phi, n, q) - gadget_matrix(n, q)
        # R2 只需 B_rcv 部分的原像（右 gadget 列块为零）：B_rcv·R2 = H - G。
        r2 = _sample_pre_matrix(td_rcv, target, rng, meta.s_pre, head_rows=b_rcv.cols)
        return ABB10Level2SecretKey(
            meta=meta,
            parent_identity=sk_parent.identity,
            child_identity=phi,
            a=sk_parent.a,
            u=sk_parent.u,
            r2=r2,
        )

    def encrypt(self, pk, parent_id: bytes, child_id: bytes, payload: bytes, *, rng=None):
        if not isinstance(pk, ABB10PublicKey):
            raise TypeError("encrypt expects an ABB10PublicKey")
        rcv = validate_identity(parent_id, name="parent_id")
        phi = validate_identity(child_id, name="child_id")
        message = validate_bytes(payload, name="payload")
        if len(message) > pk.meta.max_message_bytes:
            raise InvalidParameterError(
                f"payload of {len(message)} bytes exceeds max_message_bytes="
                f"{pk.meta.max_message_bytes}"
            )
        rng = _require_rng(rng, "encrypt")
        meta = pk.meta
        n, q = meta.n, meta.q
        b_full = (
            pk.a.hstack(hash_identity_matrix(rcv, n, q))
            .hstack(hash_pair_matrix(rcv, phi, n, q))
        )
        # 加密明文绑定身份对（解密方比对后才返回 payload；见模块 docstring）。
        plaintext = encode_bytes(rcv) + encode_bytes(phi) + encode_bytes(message)
        # 公开随机量 s：均匀采样（非高斯，仅公开 LWE 秘密）。
        s = ModVector([uniform_integer(rng, q) for _ in range(n)], q)
        e2 = sample_vector_gaussian(b_full.cols, meta.s_enc, rng=rng)
        c2 = b_full.transpose().matvec(s) + ModVector(e2, q)
        us = pk.u.dot(s)
        half = q // 2
        c1 = []
        for byte in plaintext:
            for shift in range(7, -1, -1):
                bit = (byte >> shift) & 1
                e1 = sample_integer_gaussian(meta.s_enc, rng=rng)
                c1.append((us + e1 + bit * half) % q)
        return ABB10Ciphertext(c1=tuple(c1), c2=c2)

    def decrypt(self, sk_child, ct, *, rng=None):
        if not isinstance(sk_child, ABB10Level2SecretKey):
            raise TypeError("decrypt expects an ABB10Level2SecretKey")
        if not isinstance(ct, ABB10Ciphertext):
            raise TypeError("decrypt expects an ABB10Ciphertext")
        rng = _require_rng(rng, "decrypt")
        try:
            meta = sk_child.meta
            n, q = meta.n, meta.q
            nk = n * gadget_width(q)
            b_full = (
                sk_child.a.hstack(
                    hash_identity_matrix(sk_child.parent_identity, n, q)
                )
                .hstack(
                    hash_pair_matrix(
                        sk_child.parent_identity, sk_child.child_identity, n, q
                    )
                )
            )
            if ct.c2.q != q or ct.c2.length != b_full.cols:
                return None
            td_full = Trapdoor(
                a_bar=b_full, r=_neg_stack_identity(sk_child.r2, nk)
            )
            z = _sample_pre_centered(td_full, sk_child.u, rng, meta.s_pre)
            x = ModVector(z[: b_full.cols], q)
            if b_full.matvec(x) != sk_child.u:
                return None
            dot = x.dot(ct.c2)
            quarter = q // 4
            out = bytearray(len(ct.c1) // 8)
            for idx, coefficient in enumerate(ct.c1):
                value = (coefficient - dot) % q
                if value > q // 2:
                    value -= q
                if abs(value) > quarter:
                    out[idx >> 3] |= 1 << (7 - (idx & 7))
            # 严格解析明文结构（翻转/乱码在此被拒绝），并比对解密方身份。
            rcv_seen, off = decode_bytes(bytes(out), 0)
            phi_seen, off = decode_bytes(bytes(out), off)
            payload, off = decode_bytes(bytes(out), off)
            if off != len(out):
                return None
            if not rcv_seen or not phi_seen:
                return None
            if not constant_time_equal(rcv_seen, sk_child.parent_identity):
                return None
            if not constant_time_equal(phi_seen, sk_child.child_identity):
                return None
            return payload
        except IBMEError:
            return None
