"""Wang Fig.4 IBS + Pan–Wagner Fig.5 conversion, standalone research code.

Sampling implementation: MP12 Lemma 5.3 converts the supplied G-trapdoor to a
complete integer kernel basis; exact integer basis reduction then GPV08 §4.2
randomized nearest-plane sampling produces preimages. This is a full-basis
implementation of SamplePre, NOT MP12 Algorithm 3 perturbation sampling.

Sources: papers/2022_identity_matchmaking_wang.pdf (Fig.4);
papers/2021_short_ibs_pan.pdf (Fig.5);
papers/2011_lattice_trapdoors_micciancio.pdf (Lemma 5.3, Algorithms 3/4);
papers/2008_gpv_trapdoors_full.pdf (§4.2).
H1/H2 include the complete canonical public key and parameter context.

Only delegated R_x is issued to a user: the master R_A never enters SigningKey.
Gaussian sampling uses a finite window, 80-digit Decimal weights and 128-bit
accept/reject thresholds with a finite attempt budget. These are documented
numerical approximations, not exact unbounded Gaussians. GPV statistical
closeness still requires appropriate widths; formal parameter admission and
security reductions are outside this standalone implementation audit.
security_claim="none"; parameters_are_formal=False; backend_admitted=False.
"""

from __future__ import annotations

import hashlib
import math
import json
import itertools
from decimal import Decimal, localcontext
from functools import cached_property
from dataclasses import dataclass, field
from fractions import Fraction

from ibme.core import InvalidParameterError, RandomnessError, SecureRandom
from ibme.core.hashing import DOMAIN_IBS_H1, DOMAIN_IBS_H2, hash_identity, shake256

__all__ = [
    "DOMAIN_PW_ID",
    "DOMAIN_PW_MSG",
    "MasterSecretKey",
    "PublicKey",
    "Signature",
    "SigningKey",
    "WangPWParams",
    "WangPWScheme",
    "PWSigningKey",
    "key_extract_pw",
    "sign_pw",
    "verify_pw",
    "basis_width",
    "gadget_matrix",
    "hash_identity_matrix",
    "hash_message_vector",
    "identity_matrix_from_public",
    "is_probable_prime",
    "j_identity",
    "j_message",
    "check_kernel_saturation",
    "integer_kernel_basis",
    "verify_kernel_basis_is_complete",
    "key_extract",
    "lll_reduce",
    "public_key_from_trapdoor",
    "sample_coset",
    "setup",
    "sign",
    "verify",
]

#: PW 外层身份盐 → 内部身份空间的域标签（与 H1/H2 分离）。
DOMAIN_PW_ID = b"IBME-IBS-PW-ID-v1"
#: PW 外层消息盐 → 内部消息空间的域标签（与 H1/H2 分离）。
DOMAIN_PW_MSG = b"IBME-IBS-PW-MSG-v1"

_INT_LIMIT = 1 << 32


# ---------------------------------------------------------------------------
# 参数
# ---------------------------------------------------------------------------


def _require_int(value, name, *, low, high=_INT_LIMIT):
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidParameterError(f"{name} must be an int, got {type(value).__name__}")
    if not low <= value <= high:
        raise InvalidParameterError(f"{name} must be in [{low}, {high}], got {value}")
    return value


def is_probable_prime(value) -> bool:
    """Deterministic Miller–Rabin on the explicitly supported 64-bit domain."""
    if not isinstance(value, int) or isinstance(value, bool) or not 2 <= value < (1 << 64):
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if value % p == 0:
            return value == p
    d, s = value - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        a %= value
        if a == 0:
            continue
        x = pow(a, d, value)
        if x in (1, value - 1):
            continue
        for _ in range(s - 1):
            x = x * x % value
            if x == value - 1:
                break
        else:
            return False
    return True


@dataclass(frozen=True)
class WangPWParams:
    """Wang Figure 4 的格维度/宽度与 PW 外层盐长度。

    维度：``n`` 安全维、``q`` 素数模数、``k = ⌈log2 q⌉``、``w = n·k``、``m_bar``
    冗余列（``d_ā = m_bar − n`` 为 ``ker(ā)`` 维数）、``m = m_bar + w``。原文要求
    ``m ≥ 2n⌈log q⌉``，即 ``m_bar ≥ w``。

    宽度：``s0`` 主陷门宽度（``R_A`` 元素按 ``σ = s0/sqrt(2π)`` 采样）、``s_del`` 委派
    采样倍数（乘以 GS 宽度与 sqrt(m)）、``s_sig`` 诊断 gadget 高斯标准差（默认签名不使用）、``verify_width = s'`` 决定
    验签界 ``s'·sqrt(m + w)``。

    外层：``salt_bits`` 身份盐/消息盐长度；``internal_id_bits``/``internal_msg_bits``
    为内部空间比特长度（决定 J_id/J_msg 输出长度）。
    """

    n: int
    q: int
    m_bar: int
    s0: float = 3.0
    s_del: float = 1.0
    s_sig: float = 1.0
    verify_width: float = 200.0
    salt_bits: int = 128
    internal_id_bits: int = 256
    internal_msg_bits: int = 256
    name: str = "wang-pw-toy"
    security_claim: str = field(default="none", init=False)
    parameters_are_formal: bool = field(default=False, init=False)
    backend_admitted: bool = field(default=False, init=False)

    def __post_init__(self):
        n = _require_int(self.n, "n", low=1, high=8)
        q = _require_int(self.q, "q", low=3, high=1 << 16)
        if not is_probable_prime(q):
            raise InvalidParameterError(f"q must be a proven prime, got {q}")
        m_bar = _require_int(self.m_bar, "m_bar", low=1, high=64)
        object.__setattr__(self, "n", n)
        object.__setattr__(self, "q", q)
        object.__setattr__(self, "m_bar", m_bar)
        if m_bar < n:
            raise InvalidParameterError(f"m_bar must be >= n, got {m_bar} < {n}")
        for name in ("s0", "s_del", "s_sig", "verify_width"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise InvalidParameterError(f"{name} must be a real number")
            try:
                value = float(value)
            except OverflowError as exc:
                raise InvalidParameterError(f"{name} exceeds the reference range") from exc
            if not math.isfinite(value) or not 0.0 < value <= 1_000_000.0:
                raise InvalidParameterError(f"{name} must be in (0, 1000000]")
            object.__setattr__(self, name, value)
        for name in ("salt_bits", "internal_id_bits", "internal_msg_bits"):
            object.__setattr__(self, name,
                               _require_int(getattr(self, name), name, low=8, high=4096))
        if any(getattr(self, name) % 8 for name in ("salt_bits", "internal_id_bits", "internal_msg_bits")):
            raise InvalidParameterError("salt and internal hash bit lengths must be byte-aligned")
        if not isinstance(self.name, str) or not self.name:
            raise InvalidParameterError("name must be a non-empty str")
        if m_bar < self.w:
            raise InvalidParameterError(
                f"Wang parameters need m >= 2n⌈log2 q⌉, i.e. m_bar >= w; "
                f"got m_bar={m_bar} < w={self.w}"
            )

    # -- 派生维度/界 --------------------------------------------------------

    @property
    def k(self) -> int:
        """``⌈log2 q⌉``（与 core 的 gadget 取法一致）。"""
        return (self.q - 1).bit_length()

    @property
    def w(self) -> int:
        return self.n * self.k

    @property
    def m(self) -> int:
        return self.m_bar + self.w

    @property
    def kernel_dim(self) -> int:
        """Linear nullity over F_q for a full-row-rank A; the integer kernel has rank m."""
        return self.m - self.n

    @property
    def signature_dim(self) -> int:
        """签名向量维数 ``m + w``（原文的 ``m + n⌈log q⌉``）。"""
        return self.m + self.w

    @property
    def verify_bound(self) -> float:
        """``B_verify = s'·sqrt(m + w)``。"""
        return self.verify_width * math.sqrt(self.signature_dim)

    def context(self) -> bytes:
        """Canonical, length-delimited public parameter context (not the mpk)."""
        values = {name: getattr(self, name) for name in (
            "name", "n", "q", "m_bar", "s0", "s_del", "s_sig", "verify_width",
            "salt_bits", "internal_id_bits", "internal_msg_bits")}
        return b"IBME-WANGPW-v2" + json.dumps(
            values, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

    def as_dict(self) -> dict:
        return {
            "name": self.name, "n": self.n, "q": self.q, "k": self.k,
            "w": self.w, "m_bar": self.m_bar, "m": self.m,
            "s0": self.s0, "s_del": self.s_del, "s_sig": self.s_sig,
            "verify_width": self.verify_width, "verify_bound": self.verify_bound,
            "salt_bits": self.salt_bits,
            "internal_id_bits": self.internal_id_bits,
            "internal_msg_bits": self.internal_msg_bits,
            "security_claim": self.security_claim,
            "parameters_are_formal": self.parameters_are_formal,
            "backend_admitted": self.backend_admitted,
        }


# ---------------------------------------------------------------------------
# 整数 / 模 q 线性代数（纯标准库）
# ---------------------------------------------------------------------------


def _mat_mul(a, b, q):
    n, k, m = len(a), len(b), len(b[0])
    out = [[0] * m for _ in range(n)]
    for i in range(n):
        ai, oi = a[i], out[i]
        for t in range(k):
            v = ai[t]
            if v:
                bt = b[t]
                for j in range(m):
                    oi[j] += v * bt[j]
    return [[x % q for x in row] for row in out]


def _mat_vec(a, v, q):
    return [sum(x * y for x, y in zip(row, v)) % q for row in a]


def _mat_sub(a, b, q):
    return [[(x - y) % q for x, y in zip(ra, rb)] for ra, rb in zip(a, b)]


def _hstack(a, b):
    return [ra + rb for ra, rb in zip(a, b)]


def gadget_matrix(n: int, q: int) -> list[list[int]]:
    """``G = I_n ⊗ g^T ∈ Z_q^{n×n·k}``，``g = (1,2,4,…,2^{k−1})``。"""
    _require_int(n, "n", low=1, high=64)
    if not is_probable_prime(q):
        raise InvalidParameterError("gadget construction requires a supported prime q")
    k = (q - 1).bit_length()
    g = [(1 << j) % q for j in range(k)]
    rows = []
    for i in range(n):
        row = [0] * (n * k)
        for j in range(k):
            row[i * k + j] = g[j]
        rows.append(row)
    return rows


def _gf_solve(rows, rhs, q):
    """解 ``rows·x = rhs (mod q)``，返回特解（自由变量取 0）或 ``None``。"""
    n, m = len(rows), len(rows[0])
    aug = [[rows[i][j] % q for j in range(m)] + [rhs[i] % q] for i in range(n)]
    pivots = []
    r = 0
    for c in range(m):
        piv = next((i for i in range(r, n) if aug[i][c]), None)
        if piv is None:
            continue
        aug[r], aug[piv] = aug[piv], aug[r]
        inv = pow(aug[r][c], q - 2, q)
        aug[r] = [(x * inv) % q for x in aug[r]]
        for i in range(n):
            if i != r and aug[i][c]:
                f = aug[i][c]
                aug[i] = [(x - f * y) % q for x, y in zip(aug[i], aug[r])]
        pivots.append(c)
        r += 1
        if r == n:
            break
    if any(aug[i][m] % q for i in range(r, n)):
        return None
    x = [0] * m
    for i, c in enumerate(pivots):
        x[c] = aug[i][m] % q
    return x


# ---------------------------------------------------------------------------
# 精确 LLL（列向量约定，无浮点判据）
# ---------------------------------------------------------------------------


def _gf_rank(rows, q):
    """``GF(q)`` 秩（消元，不改变输入；``q`` 为素数时即域秩）。"""
    A = [[x % q for x in r] for r in rows]
    n, m = len(A), len(A[0])
    r = 0
    for c in range(m):
        piv = next((i for i in range(r, n) if A[i][c]), None)
        if piv is None:
            continue
        A[r], A[piv] = A[piv], A[r]
        inv = pow(A[r][c], q - 2, q)
        A[r] = [(x * inv) % q for x in A[r]]
        for i in range(n):
            if i != r and A[i][c]:
                f = A[i][c]
                A[i] = [(x - f * y) % q for x, y in zip(A[i], A[r])]
        r += 1
        if r == n:
            break
    return r


def _gram_schmidt_full(columns):
    """Exact rational Gram-Schmidt, retaining zero-norm positions.

    Indices of stars and norms match the original vectors.
    """
    star, norms = [], []
    for b in columns:
        v = [Fraction(int(x)) for x in b]
        for s, nrm in zip(star, norms):
            if nrm:
                mu = sum(x * y for x, y in zip(v, s)) / nrm
                if mu:
                    v = [a - mu * c for a, c in zip(v, s)]
        nrm = sum(x * x for x in v)
        star.append(v)
        norms.append(nrm if nrm else Fraction(0))
    return star, norms


def _gram_schmidt(columns):
    """精确有理 Gram–Schmidt，**容忍线性相关输入**。

    返回 ``(star, norms)``（``list[Fraction]``）。线性相关的列会产生零范数正交向量；
    此处直接丢弃该方向（不计入 ``star``/``norms``），使调用方能在**生成组**上工作。
    注意：丢弃后 ``len(norms)`` 可能小于输入列数，调用方必须以 ``norms`` 的长度为准。
    """
    star, norms = [], []
    for b in columns:
        v = [Fraction(int(x)) for x in b]
        for s, nrm in zip(star, norms):
            mu = sum(x * y for x, y in zip(v, s)) / nrm
            if mu:
                v = [a - mu * c for a, c in zip(v, s)]
        nrm = sum(x * x for x in v)
        if nrm:
            star.append(v)
            norms.append(nrm)
    return star, norms


def _integer_vectors(columns, *, label="basis"):
    try:
        result = [list(col) for col in columns]
    except TypeError as exc:
        raise InvalidParameterError(f"{label} must contain integer vectors") from exc
    if not result or not result[0] or any(len(v) != len(result[0]) for v in result):
        raise InvalidParameterError(f"{label} must be nonempty and rectangular")
    if any(isinstance(x, bool) or not isinstance(x, int) for v in result for x in v):
        raise InvalidParameterError(f"{label} coordinates must be integers")
    return result


def _extended_gcd(a, b):
    old_r, r, old_s, ss, old_t, tt = a, b, 1, 0, 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, ss = ss, old_s - q * ss
        old_t, tt = tt, old_t - q * tt
    sign = 1 if old_r >= 0 else -1
    return sign * old_r, sign * old_s, sign * old_t


def _integer_span_basis(columns):
    """Row-style integer elimination using only unimodular operations.

    Entries of 'columns' are vectors. Treating this list as rows here preserves
    precisely their Z-span, including rationally dependent generators.
    """
    b = _integer_vectors(columns)
    rank = 0
    for col in range(len(b[0])):
        pivot = next((j for j in range(rank, len(b)) if b[j][col]), None)
        if pivot is None:
            continue
        b[rank], b[pivot] = b[pivot], b[rank]
        for j in range(rank + 1, len(b)):
            if not b[j][col]:
                continue
            a, d = b[rank][col], b[j][col]
            g, u, v = _extended_gcd(a, d)
            top, bottom = b[rank][:], b[j][:]
            b[rank] = [u*x + v*y for x, y in zip(top, bottom)]
            b[j] = [-(d//g)*x + (a//g)*y for x, y in zip(top, bottom)]
        if b[rank][col] < 0:
            b[rank] = [-x for x in b[rank]]
        for j in range(rank):
            quotient = b[j][col] // b[rank][col]
            b[j] = [x - quotient*y for x, y in zip(b[j], b[rank])]
        rank += 1
        if rank == len(b):
            break
    return b[:rank]


def lll_reduce(columns, delta=Fraction(3, 4), *, max_swaps=200_000):
    """Exact, Z-span-preserving reduction of an integer generating set."""
    try:
        delta = Fraction(delta)
    except (TypeError, ValueError, OverflowError, ZeroDivisionError) as exc:
        raise InvalidParameterError("LLL delta must be finite and rational") from exc
    if not Fraction(1, 4) < delta < 1:
        raise InvalidParameterError("LLL delta must be strictly between 1/4 and 1")
    _require_int(max_swaps, "max_swaps", low=0)
    b = _integer_span_basis(columns)
    if not b:
        raise InvalidParameterError("input spans the zero lattice")
    star, norms = _gram_schmidt_full(b)
    k, swaps = 1, 0
    while k < len(b):
        for j in range(k - 1, -1, -1):
            mu = sum(Fraction(x)*y for x, y in zip(b[k], star[j])) / norms[j]
            coefficient = round(mu)
            if coefficient:
                b[k] = [x - coefficient*y for x, y in zip(b[k], b[j])]
                star, norms = _gram_schmidt_full(b)
        mu = sum(Fraction(x)*y for x, y in zip(b[k], star[k-1])) / norms[k-1]
        if norms[k] >= (delta - mu*mu) * norms[k-1]:
            k += 1
        else:
            if swaps >= max_swaps:
                raise RuntimeError("LLL exceeded its swap budget")
            b[k], b[k-1] = b[k-1], b[k]
            star, norms = _gram_schmidt_full(b)
            swaps += 1
            k = max(k-1, 1)
    return b

def _read_exact(rng, n):
    if not callable(getattr(rng, "read", None)):
        raise RandomnessError("rng must provide read(n)")
    data = rng.read(n)
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise RandomnessError("rng.read(n) must return bytes-like data")
    try:
        data = bytes(data)
    except ValueError as exc:
        raise RandomnessError("rng returned an invalid memory view") from exc
    if len(data) != n:
        raise RandomnessError("rng.read(n) must return exactly n bytes")
    return data


class _Stream:
    """Validated random source with bounded, unbiased integer rejection."""
    __slots__ = ("_rng",)

    def __init__(self, rng):
        if not callable(getattr(rng, "read", None)):
            raise RandomnessError("rng must provide read(n)")
        self._rng = rng

    def word64(self):
        return int.from_bytes(_read_exact(self._rng, 8), "big")

    def below(self, bound):
        if isinstance(bound, bool) or not isinstance(bound, int) or bound < 1:
            raise InvalidParameterError("bound must be a positive integer")
        if bound == 1:
            return 0
        bits = (bound - 1).bit_length()
        if bits > 4096:
            raise InvalidParameterError("integer draw exceeds the reference bit budget")
        size = (bits + 7) // 8
        mask = (1 << bits) - 1
        for _ in range(4096):
            candidate = int.from_bytes(_read_exact(self._rng, size), "big") & mask
            if candidate < bound:
                return candidate
        raise RandomnessError("uniform rejection exceeded its attempt budget")


def _sample_gaussian_z(stream, sigma, center, *, max_attempts=4096):
    """Finite-window D_Z with stddev convention exp(-(x-c)^2/(2*sigma^2)).

    Decimal weights and a 128-bit threshold approximate the discrete law.
    Normalization by the nearest point's weight avoids zero-acceptance loops
    for narrow Gaussians centered halfway between integers. No 'exact' claim.
    """
    if isinstance(sigma, bool) or not isinstance(sigma, (int, float)):
        raise InvalidParameterError("sigma must be a real number")
    try:
        sigma = float(sigma)
    except OverflowError as exc:
        raise InvalidParameterError("sigma exceeds the reference range") from exc
    if not math.isfinite(sigma) or not 0 < sigma <= 1_000_000:
        raise InvalidParameterError("sigma is outside the finite reference range")
    _require_int(max_attempts, "max_attempts", low=1)
    try:
        center = Fraction(center)
    except (TypeError, ValueError, OverflowError, ZeroDivisionError) as exc:
        raise InvalidParameterError("center must be a finite rational value") from exc
    base = center.numerator // center.denominator
    frac = center - base
    radius = math.ceil(12*sigma) + 1
    nearest_sq = min(frac*frac, (1-frac)*(1-frac))
    sigma_sq = Fraction.from_float(sigma) ** 2
    with localcontext() as ctx:
        ctx.prec = 80
        for _ in range(max_attempts):
            offset = stream.below(2*radius + 1) - radius
            exponent = ((Fraction(offset) - frac)**2 - nearest_sq) / (2*sigma_sq)
            # We quantize acceptance to 128 bits; probabilities below 2^-128
            # have a zero threshold. Avoid Decimal exponent under/overflow.
            if exponent > 128:
                continue
            if exponent == 0:
                return base + offset
            x = Decimal(exponent.numerator) / Decimal(exponent.denominator)
            threshold = int((-x).exp() * Decimal(1 << 128))
            draw = (stream.word64() << 64) | stream.word64()
            if draw < threshold:
                return base + offset
    raise RandomnessError("Gaussian rejection exceeded its attempt budget")


def sample_coset(stream, basis, particular, sigma):
    """GPV08 §4.2 on center -t, followed by translation by t.

    Uses original basis vectors for center updates and sigma/||b_i*|| for
    each scalar Gaussian. A correct GPV procedure is statistically close to
    a spherical coset Gaussian only under the usual width hypotheses.
    """
    basis = _integer_vectors(basis)
    particular = _integer_vectors([particular], label="particular")[0]
    if len(particular) != len(basis[0]):
        raise InvalidParameterError("basis and particular dimensions differ")
    star, norms = _gram_schmidt_full(basis)
    if any(not norm for norm in norms):
        raise InvalidParameterError("GPV requires an independent basis")
    if isinstance(sigma, bool) or not isinstance(sigma, (int, float)) or not 0 < sigma <= 1_000_000:
        raise InvalidParameterError("sigma must be finite and positive")
    center = [-Fraction(x) for x in particular]
    out = list(particular)
    for i in range(len(basis)-1, -1, -1):
        ci = sum(x*y for x, y in zip(center, star[i])) / norms[i]
        try:
            sigma_i = sigma / math.sqrt(float(norms[i]))
        except (OverflowError, ZeroDivisionError) as exc:
            raise InvalidParameterError("basis exceeds the numerical GPV range") from exc
        zi = _sample_gaussian_z(stream, sigma_i, ci)
        center = [x - zi*b for x, b in zip(center, basis[i])]
        out = [x + zi*b for x, b in zip(out, basis[i])]
    return out


# ---------------------------------------------------------------------------
# Trapdoors, complete kernels and quality measurements
# ---------------------------------------------------------------------------

def _sample_gaussian_matrix(stream, rows, cols, sigma):
    return [[_sample_gaussian_z(stream, sigma, Fraction(0)) for _ in range(cols)]
            for _ in range(rows)]


def public_key_from_trapdoor(a_bar, r_a, q):
    """``A = [ā | G − ā·R_A]``（MP12 形态，满足 ``A·[R_A; I_w] = G``）。"""
    a_bar = _integer_vectors(a_bar, label="a_bar")
    r_a = _integer_vectors(r_a, label="R_A")
    g = gadget_matrix(len(a_bar), q)
    if len(r_a) != len(a_bar[0]) or len(r_a[0]) != len(g[0]):
        raise InvalidParameterError("trapdoor/public-prefix dimensions mismatch")
    if any(not 0 <= x < q for row in a_bar for x in row):
        raise InvalidParameterError("public prefix must be canonical [0,q)")
    return _hstack(a_bar, _mat_sub(g, _mat_mul(a_bar, r_a, q), q))


def _gf_kernel_basis(rows, q):
    """``{x ∈ F_q^dim : rows·x = 0}`` 的核基（每个向量取 ``[0, q)`` 整数提升）。

    做法：对 ``rows`` 做 ``F_q`` 消元取主元列，自由列逐个取 1 回代。输出向量个数
    ``dim − rank_q(rows)``，元素均在 ``[0, q)``。
    """
    dim = len(rows[0])
    n = len(rows)
    work = [[x % q for x in row] for row in rows]
    pivots = []
    r = 0
    for c in range(dim):
        piv = next((i for i in range(r, n) if work[i][c]), None)
        if piv is None:
            continue
        work[r], work[piv] = work[piv], work[r]
        inv = pow(work[r][c], q - 2, q)
        work[r] = [(x * inv) % q for x in work[r]]
        for i in range(n):
            if i != r and work[i][c]:
                f = work[i][c]
                work[i] = [(x - f * y) % q for x, y in zip(work[i], work[r])]
        pivots.append(c)
        r += 1
        if r == n:
            break
    out = []
    for free_col in (c for c in range(dim) if c not in pivots):
        vec = [0] * dim
        vec[free_col] = 1
        for i, pivot_col in enumerate(pivots):
            vec[pivot_col] = (-work[i][free_col]) % q
        out.append(vec)
    return out


def integer_kernel_basis(rows, q):
    """Full-rank integer basis for {x: A*x = 0 mod prime q}.

    Lifts of a GF(q) kernel basis plus q*e_i generate the full lattice.
    Integer elimination and exact LLL preserve their Z-span. Membership and
    index q^rank_q(A) are checked before returning. No empirical width claim.
    """
    rows = _integer_vectors(rows, label="matrix")
    if not is_probable_prime(q):
        raise InvalidParameterError("kernel construction requires a prime q")
    dim = len(rows[0])
    gens = _gf_kernel_basis(rows, q)
    for i in range(dim):
        col = [0] * dim
        col[i] = q
        gens.append(col)
    if not gens:
        raise InvalidParameterError("kernel has rank 0; no basis to sample")
    basis = lll_reduce(gens)
    if len(basis) != dim:
        raise InvalidParameterError(
            f"kernel basis has {len(basis)} vectors, expected {dim}")
    if not check_kernel_saturation(basis, rows, q):
        raise InvalidParameterError(
            "integer kernel basis failed its correctness check; refusing to sample")
    if not verify_kernel_basis_is_complete(basis, rows, q):
        raise InvalidParameterError(
            "integer kernel basis spans a strict sublattice; refusing to sample")
    return basis


def verify_kernel_basis_is_complete(basis, rows, q):
    """Exact necessary/sufficient predicate for a full-rank square kernel basis.

    AB=0 mod q AND |det(B)|=q^rank_q(A). Redundant generators are not a basis.
    """
    try:
        a = _integer_vectors(rows, label="matrix")
        b = _integer_vectors(basis)
        if not is_probable_prime(q):
            return False
        dim = len(a[0])
        if len(b) != dim or any(len(v) != dim for v in b):
            return False
        return (all(not any(_mat_vec(a, v, q)) for v in b)
                and abs(_det_bareiss(list(map(list, zip(*b))))) == q ** _gf_rank(a, q))
    except (InvalidParameterError, TypeError, ValueError):
        return False

def check_kernel_saturation(basis, rows, q, *, trials=4000, seed=b"ibme-wangpw-sat"):
    """Compatibility predicate: shape and kernel membership, not completeness."""
    try:
        if not is_probable_prime(q):
            return False
        a = _integer_vectors(rows, label="matrix")
        b = _integer_vectors(basis)
        return (len(b) == len(a[0]) and all(len(v) == len(a[0]) for v in b)
                and all(not any(_mat_vec(a, v, q)) for v in b))
    except (InvalidParameterError, TypeError, ValueError):
        return False

def _det_bareiss(matrix):
    """Bareiss 分数无关消元的整数行列式（精确）。"""
    n = len(matrix)
    if n == 0:
        return 1
    A = [[int(x) for x in row] for row in matrix]
    sign = 1
    prev = 1
    for k in range(n - 1):
        if A[k][k] == 0:
            piv = next((i for i in range(k + 1, n) if A[i][k]), None)
            if piv is None:
                return 0
            A[k], A[piv] = A[piv], A[k]
            sign = -sign
        for i in range(k + 1, n):
            for j in range(k + 1, n):
                A[i][j] = (A[i][j] * A[k][k] - A[i][k] * A[k][j]) // prev
        prev = A[k][k]
    return sign * A[n - 1][n - 1]


def basis_width(basis) -> float:
    """Maximum GS length; a diagnostic, not a certificate of GPV width conditions."""
    _, norms = _gram_schmidt_full(_integer_vectors(basis))
    if any(not n for n in norms):
        raise InvalidParameterError("basis width requires independent vectors")
    try:
        return max(math.sqrt(float(n)) for n in norms)
    except OverflowError as exc:
        raise InvalidParameterError("basis exceeds the numerical width range") from exc


# ---------------------------------------------------------------------------
# 哈希到 Z_q（无偏拒绝采样）
# ---------------------------------------------------------------------------


class _HashedStream:
    """由 64 字节种子展开的确定性字节流（哈希输出展开，不是生产随机源）。"""

    __slots__ = ("_seed", "_counter", "_buf")

    def __init__(self, seed: bytes):
        self._seed = seed
        self._counter = 0
        self._buf = b""

    def read(self, n: int) -> bytes:
        while len(self._buf) < n:
            self._buf += hashlib.shake_256(
                self._seed + self._counter.to_bytes(8, "big")
            ).digest(256)
            self._counter += 1
        out, self._buf = self._buf[:n], self._buf[n:]
        return out


def _uniform_field_coefficients(domain, data, q, *, label):
    """确定性**无偏** ``Z_q`` 系数流（64 位拒绝采样，不用「读字节后取模」）。"""
    seed = hashlib.shake_256(
        len(domain).to_bytes(4, "big") + domain
        + len(data).to_bytes(4, "big") + data
        + len(label).to_bytes(4, "big") + label
    ).digest(64)
    stream = _Stream(_HashedStream(seed))
    while True:
        yield stream.below(q)


def _bytes(value, label, *, nonempty=False):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise InvalidParameterError(f"{label} must be bytes-like")
    try:
        value = bytes(value)
    except ValueError as exc:
        raise InvalidParameterError(f"{label} is an invalid memory view") from exc
    if nonempty and not value:
        raise InvalidParameterError(f"{label} must be nonempty")
    return value


def _framed(*parts):
    return b"".join(len(part).to_bytes(4, "big") + part for part in parts)


def _public_hash_context(public):
    if not isinstance(public, PublicKey):
        raise InvalidParameterError("H1/H2 require the full PublicKey, not just parameters")
    return _framed(public.params.context(), public.to_bytes())


def hash_identity_matrix(public: "PublicKey", identity: bytes) -> list[list[int]]:
    """Wang H1(mpk,id), including the actual public matrix A."""
    identity = _bytes(identity, "identity", nonempty=True)
    data = _framed(_public_hash_context(public), identity)
    params = public.params
    gen = _uniform_field_coefficients(DOMAIN_IBS_H1, data, params.q, label=b"identity-matrix")
    return [[next(gen) for _ in range(params.w)] for _ in range(params.n)]


def hash_message_vector(public: "PublicKey", identity: bytes, message: bytes) -> list[int]:
    """Wang H2(mpk,id,m), including the actual public matrix A."""
    identity = _bytes(identity, "identity", nonempty=True)
    message = _bytes(message, "message")
    data = _framed(_public_hash_context(public), identity, message)
    gen = _uniform_field_coefficients(DOMAIN_IBS_H2, data, public.params.q, label=b"message-vector")
    return [next(gen) for _ in range(public.params.n)]


def identity_matrix_from_public(public: "PublicKey", identity: bytes) -> list[list[int]]:
    return _hstack(public.matrix(), hash_identity_matrix(public, identity))

# ---------------------------------------------------------------------------
# Pan–Wagner 外层哈希
# ---------------------------------------------------------------------------


def _check_salt(salt, what):
    return _bytes(salt, what, nonempty=True)


def j_identity(identity: bytes, salt: bytes, *, bits: int) -> bytes:
    """PW ``J_id(id, r)``：域 ``DOMAIN_PW_ID``，长度前缀编码，输出 ``⌈bits/8⌉`` 字节。"""
    identity = _bytes(identity, "identity", nonempty=True)
    salt = _check_salt(salt, "identity salt")
    data = _framed(identity, salt)
    _require_int(bits, "bits", low=8, high=4096)
    if bits % 8:
        raise InvalidParameterError("internal hash size must be byte-aligned")
    return shake256(DOMAIN_PW_ID, data, bits // 8)


def j_message(message: bytes, salt: bytes, *, bits: int) -> bytes:
    """PW ``J_msg(M, s)``：域 ``DOMAIN_PW_MSG``，长度前缀编码，输出 ``⌈bits/8⌉`` 字节。"""
    message = _bytes(message, "message")
    salt = _check_salt(salt, "message salt")
    data = _framed(message, salt)
    _require_int(bits, "bits", low=8, high=4096)
    if bits % 8:
        raise InvalidParameterError("internal hash size must be byte-aligned")
    return shake256(DOMAIN_PW_MSG, data, bits // 8)


# ---------------------------------------------------------------------------
# 对象
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PublicKey:
    """``mpk = (A, 参数)``；``A`` 以行优先整数元组保存（元素已 mod q）。"""

    params: WangPWParams
    a_rows: tuple

    def __post_init__(self):
        if not isinstance(self.params, WangPWParams):
            raise InvalidParameterError("params must be WangPWParams")
        rows = tuple(map(tuple, _integer_vectors(self.a_rows, label="A")))
        if any(not 0 <= x < self.params.q for row in rows for x in row):
            raise InvalidParameterError("public matrix coefficients must be canonical [0,q)")
        if len(rows) != self.params.n or any(len(r) != self.params.m for r in rows):
            raise InvalidParameterError(
                f"A must be {self.params.n}x{self.params.m}, got "
                f"{len(rows)}x{len(rows[0]) if rows else 0}"
            )
        object.__setattr__(self, "a_rows", rows)

    def matrix(self) -> list[list[int]]:
        return [list(row) for row in self.a_rows]

    def a_bar(self) -> list[list[int]]:
        """``ā``（``A`` 的前 ``m_bar`` 列），用于构造 ``ker(ā)`` 生成元。"""
        return [list(row[: self.params.m_bar]) for row in self.a_rows]

    def to_bytes(self) -> bytes:
        """规范编码：``magic || n || m || 系数（各 4 字节大端）``。"""
        out = bytearray(b"IBM1-WANGPW-PK")
        out += self.params.n.to_bytes(4, "big") + self.params.m.to_bytes(4, "big")
        for row in self.a_rows:
            for x in row:
                out += int(x).to_bytes(4, "big")
        return bytes(out)

    @classmethod
    def from_bytes(cls, params: WangPWParams, data: bytes) -> "PublicKey":
        if not isinstance(params, WangPWParams):
            raise InvalidParameterError("params must be WangPWParams")
        raw = _bytes(data, "public key bytes")
        magic = b"IBM1-WANGPW-PK"
        if len(raw) < len(magic) + 8 or raw[: len(magic)] != magic:
            raise InvalidParameterError("malformed public key: bad magic")
        n = int.from_bytes(raw[len(magic): len(magic) + 4], "big")
        m = int.from_bytes(raw[len(magic) + 4: len(magic) + 8], "big")
        if n != params.n or m != params.m:
            raise InvalidParameterError("public key dimensions do not match params")
        body = raw[len(magic) + 8:]
        if len(body) != n * m * 4:
            raise InvalidParameterError("malformed public key: length mismatch")
        rows = []
        for i in range(n):
            chunk = body[i * m * 4: (i + 1) * m * 4]
            rows.append(tuple(int.from_bytes(chunk[j * 4:(j + 1) * 4], "big")
                              for j in range(m)))
        return cls(params, tuple(rows))


@dataclass(frozen=True)
class MasterSecretKey:
    """``msk = (ā, R_A, 公共参数)``：``R_A`` 是 ``A`` 的短 G-陷门。"""

    params: WangPWParams
    a_bar_rows: tuple
    r_a_rows: tuple = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.params, WangPWParams):
            raise InvalidParameterError("params must be WangPWParams")
        a_bar = tuple(map(tuple, _integer_vectors(self.a_bar_rows, label="a_bar")))
        r_a = tuple(map(tuple, _integer_vectors(self.r_a_rows, label="R_A")))
        p = self.params
        if any(not 0 <= x < p.q for row in a_bar for x in row):
            raise InvalidParameterError("a_bar coefficients must be canonical [0,q)")
        if len(a_bar) != p.n or any(len(r) != p.m_bar for r in a_bar):
            raise InvalidParameterError("a_bar has the wrong shape")
        if len(r_a) != p.m_bar or any(len(r) != p.w for r in r_a):
            raise InvalidParameterError("R_A has the wrong shape")
        object.__setattr__(self, "a_bar_rows", a_bar)
        object.__setattr__(self, "r_a_rows", r_a)

    def a_bar(self) -> list[list[int]]:
        return [list(r) for r in self.a_bar_rows]

    def r_a(self) -> list[list[int]]:
        return [list(r) for r in self.r_a_rows]


@dataclass(frozen=True)
class SigningKey:
    """An identity's delegated trapdoor ONLY; no master R_A is retained."""
    params: WangPWParams
    identity: bytes
    identity_digest: bytes
    a_rows: tuple
    h1_rows: tuple
    r_x_rows: tuple = field(repr=False)
    verify_bound: float

    def __post_init__(self):
        if not isinstance(self.params, WangPWParams):
            raise InvalidParameterError("params must be WangPWParams")
        p = self.params
        public = PublicKey(p, self.a_rows)
        identity = _bytes(self.identity, "identity", nonempty=True)
        h1 = tuple(map(tuple, _integer_vectors(self.h1_rows, label="H1")))
        rx = tuple(map(tuple, _integer_vectors(self.r_x_rows, label="R_x")))
        if len(h1) != p.n or any(len(row) != p.w for row in h1):
            raise InvalidParameterError("H1 has the wrong shape")
        if len(rx) != p.m or any(len(row) != p.w for row in rx):
            raise InvalidParameterError("R_x has the wrong shape")
        digest = hash_identity(identity, 32)
        if _bytes(self.identity_digest, "identity digest") != digest:
            raise InvalidParameterError("identity digest mismatch")
        if h1 != tuple(map(tuple, hash_identity_matrix(public, identity))):
            raise InvalidParameterError("H1 is not bound to this public key and identity")
        if _mat_mul(public.matrix(), list(map(list, rx)), p.q) != _mat_sub(
                list(map(list, h1)), gadget_matrix(p.n, p.q), p.q):
            raise InvalidParameterError("delegated trapdoor relation does not hold")
        if isinstance(self.verify_bound, bool) or self.verify_bound != p.verify_bound:
            raise InvalidParameterError("signing bound must equal the public bound")
        object.__setattr__(self, "identity", identity)
        object.__setattr__(self, "identity_digest", digest)
        object.__setattr__(self, "a_rows", public.a_rows)
        object.__setattr__(self, "h1_rows", h1)
        object.__setattr__(self, "r_x_rows", rx)

    def matrix(self):
        return list(map(list, self.a_rows))

    def a_bar(self):
        return [list(row[:self.params.m_bar]) for row in self.a_rows]

    def h1(self):
        return list(map(list, self.h1_rows))

    def r_x(self):
        return list(map(list, self.r_x_rows))

    def identity_matrix(self):
        return _hstack(self.matrix(), self.h1())

    def trapdoor_columns(self):
        return [[-self.r_x_rows[i][j] for i in range(self.params.m)]
                + [int(i == j) for i in range(self.params.w)] for j in range(self.params.w)]

    @cached_property
    def sampling_basis(self):
        # Immutable result; only public A/H1 and this user's R_x are inputs.
        return tuple(map(tuple, _trapdoor_kernel_basis(
            self.identity_matrix(), [[-x for x in row] for row in self.r_x()], self.params.q)))

@dataclass(frozen=True)
class Signature:
    """内层签名 ``z ∈ Z^{m+w}``（有符号整数向量）。"""

    params: WangPWParams
    z: tuple

    def __post_init__(self):
        p = self.params
        if not isinstance(p, WangPWParams):
            raise InvalidParameterError("params must be WangPWParams")
        z = tuple(_integer_vectors([self.z], label="signature")[0])
        if len(z) != p.signature_dim:
            raise InvalidParameterError(
                f"signature must have {p.signature_dim} coordinates, got {len(z)}"
            )
        object.__setattr__(self, "z", z)

    def norm(self) -> float:
        try:
            return math.sqrt(sum(x*x for x in self.z))
        except OverflowError:
            return math.inf

    def to_bytes(self) -> bytes:
        """规范编码：``magic || 维数 || 系数宽度 || 定宽二补码系数``。"""
        width = max(1, max(((x if x >= 0 else ~x).bit_length() + 8) // 8 for x in self.z))
        if width > 8:
            raise InvalidParameterError("signature exceeds the signed 64-bit wire range")
        out = bytearray(b"IBM1-WANGPW-SIG")
        out += len(self.z).to_bytes(4, "big") + width.to_bytes(4, "big")
        for x in self.z:
            out += int(x).to_bytes(width, "big", signed=True)
        return bytes(out)

    @classmethod
    def from_bytes(cls, params: WangPWParams, data: bytes) -> "Signature":
        """严格解析：拒绝截断、追加、宽度/维数不符。"""
        if not isinstance(params, WangPWParams):
            raise InvalidParameterError("params must be WangPWParams")
        raw = _bytes(data, "signature bytes")
        magic = b"IBM1-WANGPW-SIG"
        if len(raw) < len(magic) + 8 or raw[: len(magic)] != magic:
            raise InvalidParameterError("malformed signature: bad magic")
        n = int.from_bytes(raw[len(magic): len(magic) + 4], "big")
        width = int.from_bytes(raw[len(magic) + 4: len(magic) + 8], "big")
        if n != params.signature_dim:
            raise InvalidParameterError(
                f"signature has {n} coordinates, expected {params.signature_dim}")
        if not 1 <= width <= 8:
            raise InvalidParameterError(f"unsupported coefficient width {width}")
        body = raw[len(magic) + 8:]
        if len(body) != n * width:
            raise InvalidParameterError("malformed signature: length mismatch")
        z = tuple(int.from_bytes(body[i * width:(i + 1) * width], "big", signed=True)
                  for i in range(n))
        result = cls(params, z)
        if result.to_bytes() != raw:
            raise InvalidParameterError("noncanonical signature coefficient width")
        return result


# ---------------------------------------------------------------------------
# 四个算法
# ---------------------------------------------------------------------------


def setup(params: WangPWParams, *, rng=None):
    """``Setup``：采样 ``ā`` 与短陷门 ``R_A``，输出 ``(mpk = A, msk = T_A)``。"""
    if not isinstance(params, WangPWParams):
        raise InvalidParameterError("setup expects WangPWParams")
    rng = SecureRandom() if rng is None else rng
    stream = _Stream(rng)
    a_bar = [[stream.below(params.q) for _ in range(params.m_bar)]
             for _ in range(params.n)]
    sigma_r = params.s0 / math.sqrt(2.0 * math.pi)
    r_a = _sample_gaussian_matrix(stream, params.m_bar, params.w, sigma_r)
    a = public_key_from_trapdoor(a_bar, r_a, params.q)
    return (PublicKey(params, tuple(tuple(r) for r in a)),
            MasterSecretKey(params, tuple(tuple(r) for r in a_bar),
                            tuple(tuple(r) for r in r_a)))


def _trapdoor_kernel_basis(a, r, q):
    """MP12 Lemma 5.3: convert A[R;I]=G to a complete basis of ker_q(A).

    Columns: [R*S; S] followed by [I+R*W; W], where G*W=-Abar.
    Every input relation and the final integer kernel index are checked.
    LLL uses unimodular integer operations and preserves this complete lattice.
    """
    a = _integer_vectors(a, label="A")
    r = _integer_vectors(r, label="trapdoor")
    n, dim = len(a), len(a[0])
    g = gadget_matrix(n, q)
    width = len(g[0])
    prefix = dim - width
    if prefix < 1 or len(r) != prefix or any(len(row) != width for row in r):
        raise InvalidParameterError("G-trapdoor dimensions mismatch")
    t = r + [[int(i == j) for j in range(width)] for i in range(width)]
    if _mat_mul(a, t, q) != g:
        raise InvalidParameterError("A[R;I]=G does not hold")
    sg = integer_kernel_basis(g, q)
    columns = []
    for v in sg:
        columns.append([sum(x*y for x, y in zip(row, v)) for row in r] + list(v))
    for j in range(prefix):
        v = _gf_solve(g, [(-row[j]) % q for row in a], q)
        if v is None:
            raise InvalidParameterError("gadget is not surjective")
        columns.append([int(i == j) + sum(x*y for x, y in zip(row, v))
                        for i, row in enumerate(r)] + v)
    if not verify_kernel_basis_is_complete(columns, a, q):
        raise InvalidParameterError("trapdoor-to-basis completeness check failed")
    basis = lll_reduce(columns)
    if not verify_kernel_basis_is_complete(basis, a, q):
        raise InvalidParameterError("LLL failed to preserve the trapdoor kernel")
    return basis


def key_extract(msk: MasterSecretKey, identity: bytes, *, rng=None):
    """Delegate by GPV preimage sampling using the actual master G-trapdoor."""
    if not isinstance(msk, MasterSecretKey):
        raise InvalidParameterError("key_extract expects MasterSecretKey")
    identity = _bytes(identity, "identity", nonempty=True)
    params = msk.params
    stream = _Stream(SecureRandom() if rng is None else rng)
    a = public_key_from_trapdoor(msk.a_bar(), msk.r_a(), params.q)
    public = PublicKey(params, tuple(map(tuple, a)))
    h1 = hash_identity_matrix(public, identity)
    target = _mat_sub(h1, gadget_matrix(params.n, params.q), params.q)
    basis = _trapdoor_kernel_basis(a, msk.r_a(), params.q)
    # s_del is a research width multiplier; record its meaning explicitly.
    sigma = params.s_del * basis_width(basis) * math.sqrt(params.m)
    columns = []
    for j in range(params.w):
        syndrome = [row[j] for row in target]
        particular = _gf_solve(a, syndrome, params.q)
        if particular is None:
            raise InvalidParameterError("public map is not surjective")
        sampled = sample_coset(stream, basis, particular, sigma)
        if _mat_vec(a, sampled, params.q) != syndrome:
            raise InvalidParameterError("delegation produced an off-coset vector")
        columns.append(sampled)
    return SigningKey(params, identity, hash_identity(identity, 32), public.a_rows,
                      tuple(map(tuple, h1)), tuple(zip(*columns)), params.verify_bound)


def _sample_gadget_block(stream, syndrome, sigma, k, q, *, tail_width=12):
    """Finite-coordinate-box Gaussian on the MODULAR gadget coset.

    Diagnostic reference, not the default signing sampler. Enumerates every
    point in the coordinate box satisfying the congruence, including q-shifts.
    Uses normalized Decimal weights and bounded rejection; not an exact
    infinite Gaussian. q must be supplied explicitly.
    """
    _require_int(k, "k", low=1, high=64)
    if not is_probable_prime(q) or k != (q-1).bit_length():
        raise InvalidParameterError("invalid prime gadget modulus/dimension")
    _require_int(syndrome, "syndrome", low=0, high=q-1)
    _require_int(tail_width, "tail_width", low=1, high=32)
    if isinstance(sigma, bool) or not isinstance(sigma, (int, float)) or not 0 < sigma <= 1_000_000:
        raise InvalidParameterError("invalid gadget Gaussian window")
    radius = max(1, math.ceil(tail_width*sigma))
    if (2*radius+1)**k > 1 << 20:
        raise InvalidParameterError("gadget box exceeds enumeration budget")
    points = [v for v in itertools.product(range(-radius, radius+1), repeat=k)
              if sum((1<<j)*x for j, x in enumerate(v)) % q == syndrome % q]
    if not points:
        raise InvalidParameterError("no point in the finite gadget window")
    norms = [sum(x*x for x in v) for v in points]
    minimum = min(norms)
    with localcontext() as ctx:
        ctx.prec = 80
        den = Decimal.from_float(float(sigma))**2 * 2
        exponents = [Decimal(v-minimum)/den for v in norms]
        thresholds = [0 if x > 128 else int((-x).exp()*Decimal(1<<128)) for x in exponents]
    for _ in range(100_000):
        i = stream.below(len(points))
        if ((stream.word64()<<64) | stream.word64()) < thresholds[i]:
            return list(points[i])
    raise RandomnessError("gadget rejection exceeded its attempt budget")


def sign(sk: SigningKey, message: bytes, *, rng=None, max_attempts=64):
    """Wang SamplePre via a trapdoor-derived basis and GPV sampling.

    The public s'=verify_width is the Gaussian parameter in exp(-pi||z||²/s'²);
    its standard-deviation convention is s'/sqrt(2*pi). No master secret or
    public-kernel shortcut is used. Reject zero/over-norm outputs with a budget.
    """
    if not isinstance(sk, SigningKey):
        raise InvalidParameterError("sign expects SigningKey")
    message = _bytes(message, "message")
    _require_int(max_attempts, "max_attempts", low=1)
    params = sk.params
    public = PublicKey(params, sk.a_rows)
    h2 = hash_message_vector(public, sk.identity, message)
    f_id = sk.identity_matrix()
    particular = _gf_solve(f_id, h2, params.q)
    if particular is None:
        raise InvalidParameterError("identity map is not surjective")
    basis = sk.sampling_basis
    sigma = params.verify_width / math.sqrt(2*math.pi)
    stream = _Stream(SecureRandom() if rng is None else rng)
    bound_sq = Fraction.from_float(params.verify_width)**2 * params.signature_dim
    for _ in range(max_attempts):
        z = sample_coset(stream, basis, particular, sigma)
        if _mat_vec(f_id, z, params.q) != h2:
            raise InvalidParameterError("GPV produced an off-coset signature")
        if any(z) and sum(x*x for x in z) <= bound_sq:
            return Signature(params, tuple(z))
    raise RandomnessError("signing exceeded the zero/norm rejection budget")

def verify(pk: PublicKey, identity: bytes, message: bytes, signature) -> bool:
    """``Ver``：``z ≠ 0``、``F_id·z = h2 (mod q)``、``‖z‖ ≤ B_verify``。"""
    if not isinstance(pk, PublicKey) or not isinstance(signature, Signature):
        return False
    try:
        identity = _bytes(identity, "identity", nonempty=True)
        message = _bytes(message, "message")
    except InvalidParameterError:
        return False
    if signature.params != pk.params:
        return False
    z = list(signature.z)
    if len(z) != pk.params.signature_dim or not any(z):
        return False
    if sum(x*x for x in z) > Fraction.from_float(pk.params.verify_width)**2 * pk.params.signature_dim:
        return False
    f_id = identity_matrix_from_public(pk, bytes(identity))
    h2 = hash_message_vector(pk, bytes(identity), bytes(message))
    return _mat_vec(f_id, z, pk.params.q) == h2


# ---------------------------------------------------------------------------
# Pan–Wagner 外层：单身份单密钥生命周期的缓存服务
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PWSigningKey:
    """Fig.5 output: identity salt r plus the corresponding inner signing key."""
    identity: bytes
    salt: bytes
    inner: SigningKey = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.inner, SigningKey):
            raise InvalidParameterError("inner key must be a SigningKey")
        identity = _bytes(self.identity, "identity", nonempty=True)
        salt = _bytes(self.salt, "salt")
        if len(salt) != self.inner.params.salt_bits // 8:
            raise InvalidParameterError("identity salt length mismatch")
        if j_identity(identity, salt, bits=self.inner.params.internal_id_bits) != self.inner.identity:
            raise InvalidParameterError("identity salt is not bound to the inner key")
        object.__setattr__(self, "identity", identity)
        object.__setattr__(self, "salt", salt)


def key_extract_pw(msk, identity, *, rng=None):
    if not isinstance(msk, MasterSecretKey):
        raise InvalidParameterError("key_extract_pw expects MasterSecretKey")
    identity = _bytes(identity, "identity", nonempty=True)
    rng = SecureRandom() if rng is None else rng
    salt = _read_exact(rng, msk.params.salt_bits // 8)
    internal = j_identity(identity, salt, bits=msk.params.internal_id_bits)
    return PWSigningKey(identity, salt, key_extract(msk, internal, rng=rng))


def sign_pw(key, message, *, rng=None):
    if not isinstance(key, PWSigningKey):
        raise InvalidParameterError("sign_pw expects PWSigningKey")
    message = _bytes(message, "message")
    rng = SecureRandom() if rng is None else rng
    salt = _read_exact(rng, key.inner.params.salt_bits // 8)
    internal = j_message(message, salt, bits=key.inner.params.internal_msg_bits)
    return key.salt, salt, sign(key.inner, internal, rng=rng)


def verify_pw(public, identity, message, r, s, signature):
    if not isinstance(public, PublicKey):
        return False
    try:
        identity = _bytes(identity, "identity", nonempty=True)
        message = _bytes(message, "message")
        r, s = _bytes(r, "r"), _bytes(s, "s")
        if len(r) != public.params.salt_bits//8 or len(s) != public.params.salt_bits//8:
            return False
        internal_id = j_identity(identity, r, bits=public.params.internal_id_bits)
        internal_msg = j_message(message, s, bits=public.params.internal_msg_bits)
        return verify(public, internal_id, internal_msg, signature)
    except InvalidParameterError:
        return False


class WangPWScheme:
    """In-memory fixed-key service around the standalone Fig.5 algorithms.

    A key request reuses the previously issued (r,sk) in this service lifetime.
    Pure key_extract_pw separately implements a fresh Fig.5 extraction.
    """
    __slots__ = ("params", "pk", "_msk", "_cache", "_rng")

    def __init__(self, params: WangPWParams, *, rng=None):
        if not isinstance(params, WangPWParams):
            raise InvalidParameterError("WangPWScheme expects WangPWParams")
        self.params = params
        self._rng = SecureRandom() if rng is None else rng
        self._cache = {}
        self.pk = None
        self._msk = None


    # -- 生命周期 -----------------------------------------------------------

    def setup(self):
        """内层 ``Setup``；结果缓存在实例上（``self.pk`` 为公钥）。"""
        self.pk, self._msk = setup(self.params, rng=self._rng)
        self._cache.clear()
        return self.pk, self._msk

    def key_extract_pw(self, identity: bytes):
        self._require_setup()
        identity = _bytes(identity, "identity", nonempty=True)
        if identity not in self._cache:
            key = key_extract_pw(self._msk, identity, rng=self._rng)
            self._cache[identity] = {
                "key": key, "salt": key.salt, "internal": key.inner.identity, "signed": set()}
        return self._cache[identity]["key"]

    def sign_pw(self, identity: bytes, message: bytes):
        self._require_setup()
        identity = _bytes(identity, "identity", nonempty=True)
        message = _bytes(message, "message")
        key = self.key_extract_pw(identity)
        result = sign_pw(key, message, rng=self._rng)
        self._cache[identity]["signed"].add(message)
        return result

    def verify_pw(self, identity: bytes, message: bytes, r, s, signature) -> bool:
        return verify_pw(self.pk, identity, message, r, s, signature)


    # -- 辅助 ---------------------------------------------------------------

    def cached_identity_salt(self, identity: bytes):
        """缓存中的 ``(r, x)``（未建立缓存返回 ``None``）。"""
        entry = self._cache.get(_bytes(identity, "identity", nonempty=True))
        return None if entry is None else (entry["salt"], entry["internal"])

    def signed_messages(self, identity: bytes):
        """该外部身份已签名过的原始消息集合（复制）。"""
        entry = self._cache.get(_bytes(identity, "identity", nonempty=True))
        return set() if entry is None else set(entry["signed"])

    def _require_setup(self):
        if self._msk is None:
            raise InvalidParameterError("call setup() before extracting keys or signing")
