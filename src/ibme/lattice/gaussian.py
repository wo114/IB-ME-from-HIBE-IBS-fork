"""整数上的离散高斯采样（真离散高斯，禁止均匀冒充）。

采样方法
--------
对整数上的离散高斯分布 ``D_{Z, c, σ}``（质量函数 ∝ exp(-(x-c)²/(2σ²))）
使用**拒绝采样**：

1. 在截断窗口 ``[c - τσ, c + τσ]``（τ 默认 12）内**均匀**取整数候选
   ``x``；窗口内的均匀整数采样本身用"随机字节 + 拒绝"实现，消除模偏差；
2. 以 ``p = exp(-(x-c)²/(2σ²))`` 的概率接受 ``x``：取 64-bit 均匀定点数
   ``u ∈ [0, 1)``，当 ``u < p`` 时接受。

精度
----
- 接受概率 ``p`` 用 float64（``math.exp``）计算，与 64-bit 定点 ``u``
  比较，引入的分布相对误差约 1e-16，远小于统计测试容差；
- 窗口内均匀整数采样无模偏差（拒绝上界为 ``floor(2^{8b}/width)·width``）。

接受率
------
平稳接受率 ≈ √(π/2)/τ ≈ 10.4%（τ = 12 时），即每个样本平均约 9.6 个候选。

尾部截断
--------
默认 ``tail_width = τ = 12``：候选只取自 ``|x - c| <= τσ``，被截断的尾部
质量 ``< 2·exp(-τ²/2) ≈ 2.7e-32``，统计上不可分辨，但对严格的分布声明而言
这是一个已知偏差（见"已知限制"）。

已知限制
--------
- 采样**非常数时间**（拒绝循环依赖候选值），不得用于抗时序侧信道的场景；
- ``σ`` 相对 ``center`` 过小导致候选窗口为空时抛 ``InvalidParameterError``；
- 尾部在 τσ 处截断（见上）。

随机源协议
----------
任何提供 ``read(n: int) -> bytes`` 的对象都可以作为 ``rng`` 注入；
``rng=None`` 时使用 ``os.urandom`` 包装的系统源（生产默认）。
core 层稍后提供的 SecureRandom / DeterministicRandom 具有完全相同的方法
签名，可直接注入。``SeededRandom`` 是本模块提供的最小种子化测试随机源
（SHA-256 计数器模式），**仅限测试**，绝不能用于生产密钥。
"""

from __future__ import annotations

import hashlib
import math
import os

from ibme.core.errors import InvalidParameterError, RandomnessError

__all__ = [
    "DEFAULT_TAIL_WIDTH",
    "SeededRandom",
    "sample_integer_gaussian",
    "sample_vector_gaussian",
    "uniform_integer",
]

DEFAULT_TAIL_WIDTH = 12.0

_SEED_DOMAIN = b"IBME-LATTICE-SEEDED-RNG-V1"


class SeededRandom:
    """Deterministic SHA-256 counter-mode byte source, FOR TESTS ONLY.

    固定种子 → 固定字节流，因此固定随机源下的高斯样本完全可复现。
    绝不能用于生产密钥或任何安全敏感用途；生产代码应注入 core 层的
    SecureRandom（相同 ``read(n)`` 签名）或使用默认系统源。
    """

    def __init__(self, seed) -> None:
        if isinstance(seed, str):
            seed = seed.encode("utf-8")
        elif isinstance(seed, bool):
            raise InvalidParameterError("SeededRandom seed must be bytes, str or int")
        elif isinstance(seed, int):
            seed = seed.to_bytes(max(1, (seed.bit_length() + 7) // 8), "big")
        if not isinstance(seed, (bytes, bytearray, memoryview)):
            raise InvalidParameterError("SeededRandom seed must be bytes, str or int")
        self._seed = bytes(seed)
        self._counter = 0
        self._buffer = b""

    def read(self, n: int) -> bytes:
        if not isinstance(n, int) or isinstance(n, bool) or n < 0:
            raise InvalidParameterError("read() expects a non-negative int")
        while len(self._buffer) < n:
            self._buffer += hashlib.sha256(
                self._seed + _SEED_DOMAIN + self._counter.to_bytes(8, "big")
            ).digest()
            self._counter += 1
        out, self._buffer = self._buffer[:n], self._buffer[n:]
        return out


class _SystemRandomSource:
    """os.urandom wrapper matching the read(n: int) -> bytes protocol."""

    def read(self, n: int) -> bytes:
        return os.urandom(n)


_SYSTEM_RNG = _SystemRandomSource()


def _resolve_rng(rng):
    if rng is None:
        return _SYSTEM_RNG
    if not (hasattr(rng, "read") and callable(rng.read)):
        raise RandomnessError(
            "randomness source must provide a callable read(n: int) -> bytes"
        )
    return rng


def _read_exact(rng, n: int) -> bytes:
    buf = rng.read(n)
    if not isinstance(buf, (bytes, bytearray, memoryview)):
        raise RandomnessError("rng.read() must return bytes")
    if len(buf) != n:
        raise RandomnessError(f"rng.read({n}) returned {len(buf)} bytes")
    return bytes(buf)


def uniform_integer(rng, bound: int) -> int:
    """Uniformly sample an integer in [0, bound) from an injectable rng.

    ``rng`` 遵循 ``read(n: int) -> bytes`` 协议，``None`` 表示系统随机源。
    使用字节拒绝采样消除模偏差。这是均匀采样，与离散高斯无关。
    """
    if not isinstance(bound, int) or isinstance(bound, bool) or bound < 1:
        raise InvalidParameterError(f"bound must be an int >= 1, got {bound!r}")
    rng = _resolve_rng(rng)
    nbytes = max(1, (bound.bit_length() + 7) // 8)
    span = 1 << (8 * nbytes)
    limit = span - (span % bound)
    while True:
        value = int.from_bytes(_read_exact(rng, nbytes), "big")
        if value < limit:
            return value % bound


def _uniform_unit(rng) -> float:
    return int.from_bytes(_read_exact(rng, 8), "big") / float(1 << 64)


def _check_real(value, name: str, *, positive: bool) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidParameterError(
            f"{name} must be a real number, got {type(value).__name__}"
        )
    number = float(value)
    if not math.isfinite(number):
        raise InvalidParameterError(f"{name} must be finite, got {value!r}")
    if positive and number <= 0.0:
        raise InvalidParameterError(f"{name} must be > 0, got {value!r}")
    return number


def sample_integer_gaussian(
    sigma, center=0, *, rng=None, tail_width=DEFAULT_TAIL_WIDTH
) -> int:
    """Sample one integer from the discrete Gaussian D_{Z, center, sigma}.

    冻结接口（IMPLEMENTATION_SPEC.md §3）的位置参数为 ``(sigma, center=0)``；
    随机源通过**关键字参数** ``rng`` 注入（任何 ``read(n: int) -> bytes``
    对象；``None`` 表示系统随机源），不改变冻结的位置签名。固定随机源下
    输出可复现。
    """
    sigma_f = _check_real(sigma, "sigma", positive=True)
    center_f = _check_real(center, "center", positive=False)
    tail_f = _check_real(tail_width, "tail_width", positive=True)
    if tail_f < 1.0:
        raise InvalidParameterError(f"tail_width must be >= 1, got {tail_width}")
    rng = _resolve_rng(rng)
    low = math.ceil(center_f - tail_f * sigma_f)
    high = math.floor(center_f + tail_f * sigma_f)
    width = high - low + 1
    if width < 1:
        raise InvalidParameterError(
            "empty candidate window: sigma is too small for the given center"
        )
    inv_two_sigma_sq = 1.0 / (2.0 * sigma_f * sigma_f)
    while True:
        candidate = low + uniform_integer(rng, width)
        p_accept = math.exp(-((candidate - center_f) ** 2) * inv_two_sigma_sq)
        if _uniform_unit(rng) < p_accept:
            return candidate


def sample_vector_gaussian(
    length, sigma, *, rng=None, center=0, tail_width=DEFAULT_TAIL_WIDTH
) -> list[int]:
    """Sample ``length`` 个 i.i.d. 整数，每个服从 D_{Z, center, sigma}。"""
    if not isinstance(length, int) or isinstance(length, bool) or length < 1:
        raise InvalidParameterError(f"length must be an int >= 1, got {length!r}")
    _check_real(sigma, "sigma", positive=True)
    _check_real(center, "center", positive=False)
    _check_real(tail_width, "tail_width", positive=True)
    rng = _resolve_rng(rng)
    return [
        sample_integer_gaussian(sigma, center, rng=rng, tail_width=tail_width)
        for _ in range(length)
    ]
