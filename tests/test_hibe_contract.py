"""HIBE contract tests：mock 与 ABB10 两个后端在同一接口契约下参数化验证。

对应 DELEGATION_PROMPTS.md 任务 C 与 AI_WORKFLOW.md M2 门槛。覆盖：

* setup→extract→derive→encrypt→decrypt 在 (rcv, phi) 匹配时还原 payload
  （含空 payload 与二进制脏字节）；
* 子身份 / 父身份 / 两者均不匹配 → ``None``（BOTTOM）；
* 密文篡改（单系数、截断、追加）→ 拒绝或解码失败，绝不"错误地成功"；
* 密文序列化字节中不出现身份明文（匿名性抽查）；
* pk/msk/sk1/sk2/ct 序列化往返一致 + 畸形输入拒绝；
* 固定 rng 全流程可复现；
* ABB10 专属：H(rcv) == A·R1 + G、H(rcv,phi) == B_rcv·R2 + G、
  R1/R2 范数有界（代数关系正确性）。

安全声明：本文件使用教学/调试参数（security_claim: none）；测试通过
不构成 LWE、SIS 或 HIBE/IB-ME 安全性证明。
"""

from __future__ import annotations

import math

import pytest

from ibme.core.errors import (
    EncodingError,
    InvalidParameterError,
    SerializationError,
)
from ibme.core.randomness import DeterministicRandom
from ibme.hibe import ABB10HIBE, ABB10_DEBUG_PARAMS, MockHIBE
from ibme.hibe import abb10 as abb10_module
from ibme.lattice import EDUCATION_PARAMS, ModMatrix, gadget_width

# 身份使用字节熵较高的固定值，便于匿名性抽查（原始字节不应出现在密文中）。
RCV = b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa"
PHI = b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba"
OTHER_RCV = b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8"
WRONG_PHI = b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8"

SEED = b"hibe-contract-tests-v1"

_BACKENDS = {
    "mock": lambda: (MockHIBE(), EDUCATION_PARAMS),
    "abb10": lambda: (ABB10HIBE(), ABB10_DEBUG_PARAMS),
}


def _make_env(name: str, seed_suffix: bytes):
    backend, params = _BACKENDS[name]()
    rng = DeterministicRandom(SEED + b":" + name.encode() + seed_suffix)
    pk, msk = backend.setup(params, rng=rng)
    sk1 = backend.extract(msk, RCV, rng=rng)
    sk2 = backend.derive(sk1, PHI, rng=rng)
    return backend, params, pk, msk, sk1, sk2


@pytest.fixture(params=sorted(_BACKENDS), scope="module")
def env(request):
    """每个后端共享一套 setup/extract/derive 结果（abb10 较慢，模块级缓存）。"""
    backend, params, pk, msk, sk1, sk2 = _make_env(request.param, b":main")
    return request.param, backend, params, pk, msk, sk1, sk2


# ---------------------------------------------------------------------------
# 正确性：匹配身份下还原 payload
# ---------------------------------------------------------------------------

PAYLOAD_CASES = [
    b"",
    b"\x00",
    b"\xff" * 8,
    b"\x00\xff\x80\x7f\x01\xfe\x7f\x80",  # 二进制脏字节
    bytes(range(32)),
]


@pytest.mark.parametrize("payload", PAYLOAD_CASES)
def test_roundtrip_matching_identities(env, payload):
    _, backend, params, pk, msk, sk1, sk2 = env
    ct = backend.encrypt(
        pk, RCV, PHI, payload, rng=DeterministicRandom(SEED + b":enc")
    )
    assert backend.decrypt(sk2, ct, rng=DeterministicRandom(SEED + b":dec")) == payload


def test_roundtrip_with_fresh_keys_per_message(env):
    """同一身份对的多条消息（独立随机性）都能还原。"""
    _, backend, params, pk, msk, sk1, sk2 = env
    rng = DeterministicRandom(SEED + b":multi")
    for i in range(3):
        payload = rng.read(8 + 4 * i)
        payload = bytes(payload)
        ct = backend.encrypt(pk, RCV, PHI, payload, rng=rng)
        assert backend.decrypt(sk2, ct, rng=rng) == payload


# ---------------------------------------------------------------------------
# 不匹配场景：三种组合都返回 BOTTOM (None)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ciphertext(env):
    _, backend, params, pk, msk, sk1, sk2 = env
    payload = b"matchmaking-payload"
    ct = backend.encrypt(pk, RCV, PHI, payload, rng=DeterministicRandom(SEED + b":ct"))
    return payload, ct


def _fresh_ciphertext(env, payload=b"roundtrip-ct"):
    """非 fixture 的密文生成 helper（避免直接调用 fixture）。"""
    _, backend, params, pk, msk, sk1, sk2 = env
    return payload, backend.encrypt(
        pk, RCV, PHI, payload, rng=DeterministicRandom(SEED + b":ct2")
    )


def test_child_identity_mismatch_returns_none(env, ciphertext):
    """仅发送者（子身份）不匹配：snd != phi -> None。"""
    _, backend, params, pk, msk, sk1, sk2 = env
    payload, ct = ciphertext
    sk_wrong_child = backend.derive(
        sk1, WRONG_PHI, rng=DeterministicRandom(SEED + b":wrongchild")
    )
    assert sk_wrong_child.child_identity == WRONG_PHI
    assert backend.decrypt(sk_wrong_child, ct, rng=DeterministicRandom(SEED + b":d1")) is None


def test_parent_identity_mismatch_returns_none(env, ciphertext):
    """仅接收者（父身份）不匹配：用别的 rho 的密钥解 -> None。"""
    _, backend, params, pk, msk, sk1, sk2 = env
    payload, ct = ciphertext
    rng = DeterministicRandom(SEED + b":wrongparent")
    sk_other = backend.extract(msk, OTHER_RCV, rng=rng)
    sk_other_child = backend.derive(sk_other, PHI, rng=rng)
    assert sk_other_child.parent_identity == OTHER_RCV
    assert backend.decrypt(sk_other_child, ct, rng=rng) is None


def test_both_identities_mismatch_returns_none(env, ciphertext):
    """两者都不匹配 -> None。"""
    _, backend, params, pk, msk, sk1, sk2 = env
    payload, ct = ciphertext
    rng = DeterministicRandom(SEED + b":wrongboth")
    sk_other = backend.extract(msk, OTHER_RCV, rng=rng)
    sk_other_wrong = backend.derive(sk_other, WRONG_PHI, rng=rng)
    assert backend.decrypt(sk_other_wrong, ct, rng=rng) is None


# ---------------------------------------------------------------------------
# 密文篡改：绝不返回错误地"成功"
# ---------------------------------------------------------------------------


def test_ciphertext_tamper_single_coefficient(env, ciphertext):
    """显著篡改密文尾部系数：解析被拒绝，或解密结果不等于原 payload。

    说明：最低位级别的篡改（±1）落在 LWE 解码噪声容限内，天然不可检
    测——这是 Regev 加密的容错性而非缺陷（CCA 安全不在本任务范围，基
    线协议另由 IBS 验证兜底）。本测试翻转尾部 16 个字节：对 abb10 会
    把 c1 最高字节推到 >= q（序列化层拒绝），对 mock 会破坏认证标签
    （解密返回 None）。
    """
    _, backend, params, pk, msk, sk1, sk2 = env
    payload, ct = ciphertext
    raw = ct.to_bytes()
    tail = bytes(value ^ 0xFF for value in raw[-16:])
    tampered = raw[:-16] + tail
    try:
        ct2 = type(ct).from_bytes(tampered)
    except SerializationError:
        return  # 序列化层拒绝也算通过
    result = backend.decrypt(sk2, ct2, rng=DeterministicRandom(SEED + b":tamper"))
    assert result != payload


def test_ciphertext_tamper_tries_many_positions(env, ciphertext):
    """对密文多个字节位置做大幅篡改：绝不返回与原 payload 相同的结果。

    覆盖"改一个系数"的一般情形：篡改要么被解析拒绝，要么导致解码
    偏离（结果为 None 或不同于原 payload）。LSB 翻转（^0x01）在容错
    范围内可能出现相同结果，故使用 ^0xFF。位置均匀抽样（abb10 的单次
    解密约 20ms，全字节遍历无法保持在秒级）。
    """
    _, backend, params, pk, msk, sk1, sk2 = env
    payload, ct = ciphertext
    raw = ct.to_bytes()
    step = max(1, len(raw) // 24)
    for pos in range(0, len(raw), step):
        tampered = raw[:pos] + bytes([raw[pos] ^ 0xFF]) + raw[pos + 1 :]
        try:
            ct2 = type(ct).from_bytes(tampered)
        except SerializationError:
            continue
        result = backend.decrypt(
            sk2, ct2, rng=DeterministicRandom(SEED + b":tamper-all")
        )
        assert result != payload, f"tampering byte {pos} went undetected"


def test_ciphertext_truncated_rejected(env, ciphertext):
    _, backend, params, pk, msk, sk1, sk2 = env
    payload, ct = ciphertext
    raw = ct.to_bytes()
    with pytest.raises(SerializationError):
        type(ct).from_bytes(raw[:-1])
    with pytest.raises(SerializationError):
        type(ct).from_bytes(raw[: max(1, len(raw) // 2)])


def test_ciphertext_appended_rejected(env, ciphertext):
    _, backend, params, pk, msk, sk1, sk2 = env
    payload, ct = ciphertext
    raw = ct.to_bytes()
    with pytest.raises(SerializationError):
        type(ct).from_bytes(raw + b"\x00")
    with pytest.raises(SerializationError):
        type(ct).from_bytes(raw + b"appended-garbage")


# ---------------------------------------------------------------------------
# 匿名性抽查：密文字节中不出现身份明文
# ---------------------------------------------------------------------------


def test_ciphertext_does_not_contain_identity_plaintext(env, ciphertext):
    _, backend, params, pk, msk, sk1, sk2 = env
    payload, ct = ciphertext
    raw = ct.to_bytes()
    for identity in (RCV, PHI, OTHER_RCV, WRONG_PHI):
        assert identity not in raw, "identity bytes leaked into ciphertext"
    # 编码后的身份（长度前缀形式）同样不应出现。
    from ibme.core.encoding import encode_bytes

    assert encode_bytes(RCV) not in raw
    assert encode_bytes(PHI) not in raw


# ---------------------------------------------------------------------------
# 序列化：往返一致 + 畸形输入拒绝
# ---------------------------------------------------------------------------


def test_serialization_roundtrip(env):
    _, backend, params, pk, msk, sk1, sk2 = env
    for obj in (pk, msk, sk1, sk2):
        clone = type(obj).from_bytes(obj.to_bytes())
        assert clone == obj
    payload, ct = _fresh_ciphertext(env)
    assert type(ct).from_bytes(ct.to_bytes()) == ct


MALFORMED_INPUTS = [b"", b"garbage", b"\x00" * 8]


@pytest.mark.parametrize("bad", MALFORMED_INPUTS)
def test_malformed_serialization_rejected(env, bad):
    _, backend, params, pk, msk, sk1, sk2 = env
    for obj in (pk, msk, sk1, sk2):
        with pytest.raises(SerializationError):
            type(obj).from_bytes(bad)
    with pytest.raises(SerializationError):
        type(pk).from_bytes(bad)


def test_truncated_and_extended_key_serialization_rejected(env):
    _, backend, params, pk, msk, sk1, sk2 = env
    for obj in (pk, msk, sk1, sk2):
        raw = obj.to_bytes()
        with pytest.raises(SerializationError):
            type(obj).from_bytes(raw[:-1])
        with pytest.raises(SerializationError):
            type(obj).from_bytes(raw + b"\x01")


def test_secret_key_identity_binding(env):
    """sk1/sk2 绑定身份（避免调用者误用其他身份）。"""
    _, backend, params, pk, msk, sk1, sk2 = env
    assert sk1.identity == RCV
    assert sk2.parent_identity == RCV
    assert sk2.child_identity == PHI


# ---------------------------------------------------------------------------
# 可复现性：固定 rng 下整套流程字节级一致
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("backend_name", sorted(_BACKENDS))
def test_fixed_rng_full_pipeline_reproducible(backend_name):
    payload = b"reproducible-payload!"

    def run() -> bytes:
        backend, params, pk, msk, sk1, sk2 = _make_env(backend_name, b":repro")
        rng = DeterministicRandom(SEED + b":repro-enc")
        ct = backend.encrypt(pk, RCV, PHI, payload, rng=rng)
        recovered = backend.decrypt(sk2, ct, rng=DeterministicRandom(SEED + b":repro-dec"))
        assert recovered == payload
        return ct.to_bytes()

    assert run() == run()


# ---------------------------------------------------------------------------
# 输入校验
# ---------------------------------------------------------------------------


def test_empty_identity_rejected(env):
    _, backend, params, pk, msk, sk1, sk2 = env
    with pytest.raises(EncodingError):
        backend.extract(msk, b"", rng=DeterministicRandom(SEED + b":v1"))
    with pytest.raises(EncodingError):
        backend.derive(sk1, b"", rng=DeterministicRandom(SEED + b":v2"))
    with pytest.raises(EncodingError):
        backend.encrypt(pk, b"", PHI, b"x", rng=DeterministicRandom(SEED + b":v3"))
    with pytest.raises(EncodingError):
        backend.encrypt(pk, RCV, b"", b"x", rng=DeterministicRandom(SEED + b":v4"))


def test_payload_over_limit_rejected(env):
    _, backend, params, pk, msk, sk1, sk2 = env
    too_long = b"x" * (params.max_message_bytes + 1)
    with pytest.raises(InvalidParameterError):
        backend.encrypt(pk, RCV, PHI, too_long, rng=DeterministicRandom(SEED + b":v5"))


def test_wrong_object_types_rejected(env):
    _, backend, params, pk, msk, sk1, sk2 = env
    with pytest.raises(TypeError):
        backend.extract("not-an-msk", RCV)
    with pytest.raises(TypeError):
        backend.derive("not-an-sk1", PHI)
    with pytest.raises(TypeError):
        backend.encrypt("not-a-pk", RCV, PHI, b"x")
    with pytest.raises(TypeError):
        backend.decrypt("not-an-sk2", "not-a-ct")


def test_string_identity_rejected(env):
    """身份必须是字节串；str 直接进入密码算法是规范禁止的。"""
    _, backend, params, pk, msk, sk1, sk2 = env
    with pytest.raises(EncodingError):
        backend.extract(msk, "alice", rng=DeterministicRandom(SEED + b":v6"))


# ---------------------------------------------------------------------------
# ABB10 专属：代数关系与范数界
# ---------------------------------------------------------------------------


def _skip_unless_abb10(env):
    name = env[0]
    if name != "abb10":
        pytest.skip("algebraic checks only apply to the abb10 backend")


def test_abb10_level1_algebra(env):
    """A·R1 + G == H(rcv) (mod q)：第一层委派的代数关系。"""
    _, backend, params, pk, msk, sk1, sk2 = env
    _skip_unless_abb10(env)
    n, q = params.n, params.q
    a_r1 = sk1.a @ ModMatrix([list(row) for row in sk1.r1], q)
    assert a_r1 + abb10_module.gadget_matrix(n, q) == abb10_module.hash_identity_matrix(
        sk1.identity, n, q
    )
    assert abb10_module.verify_level1_key(sk1)


def test_abb10_level2_algebra(env):
    """B_rcv·R2 + G == H(rcv, phi) (mod q)：第二层委派的代数关系。"""
    _, backend, params, pk, msk, sk1, sk2 = env
    _skip_unless_abb10(env)
    n, q = params.n, params.q
    b_rcv = sk2.a.hstack(
        abb10_module.hash_identity_matrix(sk2.parent_identity, n, q)
    )
    b_r2 = b_rcv @ ModMatrix([list(row) for row in sk2.r2], q)
    assert b_r2 + abb10_module.gadget_matrix(n, q) == abb10_module.hash_pair_matrix(
        sk2.parent_identity, sk2.child_identity, n, q
    )
    assert abb10_module.verify_level2_key(sk2)


def _column_norms(rows):
    return [
        math.sqrt(sum(rows[i][j] ** 2 for i in range(len(rows))))
        for j in range(len(rows[0]))
    ]


def test_abb10_key_norms_bounded(env):
    """R1/R2 的列欧几里得范数有界（理论估计的 8 倍上界；实测约 105/930）。

    理论（中心化分解位方差 1/2，α = sqrt(nk/2)）：
    R1 列 ≈ sqrt(m_bar·((nk/2)·s0² + s_prime²) + nk/2)，
    R2 列 ≈ R1 主导行 std·α 的主导项累积（见 abb10.py 噪声预算）。
    """
    _, backend, params, pk, msk, sk1, sk2 = env
    _skip_unless_abb10(env)
    n, q, s0 = params.n, params.q, params.s0
    k = gadget_width(q)
    nk = n * k
    m_bar = params.m_matrix - nk
    m = params.m_matrix

    r1_bound = 8.0 * math.sqrt(m_bar * ((nk / 2.0) * s0 * s0 + params.s_prime**2) + nk / 2.0)
    for norm in _column_norms(sk1.r1):
        assert norm <= r1_bound, f"R1 column norm {norm:.0f} exceeds bound {r1_bound:.0f}"

    r2_head_std = math.sqrt((nk / 2.0) * s0 * s0 + params.s_prime**2) * math.sqrt(nk / 2.0)
    r2_bound = 8.0 * math.sqrt(m * r2_head_std**2 + nk * 2.0)
    for norm in _column_norms(sk2.r2):
        assert norm <= r2_bound, f"R2 column norm {norm:.0f} exceeds bound {r2_bound:.0f}"


def test_abb10_hash_matrices_deterministic_and_distinct(env):
    """身份哈希矩阵：确定性、层间不碰撞、对输入无拼接歧义。"""
    _, backend, params, pk, msk, sk1, sk2 = env
    _skip_unless_abb10(env)
    n, q = params.n, params.q
    h1 = abb10_module.hash_identity_matrix(RCV, n, q)
    assert h1 == abb10_module.hash_identity_matrix(RCV, n, q)
    assert h1 != abb10_module.hash_identity_matrix(OTHER_RCV, n, q)
    assert h1 != abb10_module.hash_pair_matrix(RCV, PHI, n, q)
    # 长度前缀保证无歧义：("ab", "c") 与 ("a", "bc") 的身份对哈希不同。
    assert abb10_module.hash_pair_matrix(b"ab", b"c", n, q) != abb10_module.hash_pair_matrix(
        b"a", b"bc", n, q
    )
