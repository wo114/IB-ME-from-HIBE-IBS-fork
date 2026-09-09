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
  R1/R2 范数有界（代数关系正确性）；
* P0 整改回归（abb10）：纯密文差分聚类攻击、已知明文单 bit 差分定位
  攻击必须失败（attack-oracle 风格）；密文结构逐比特独立（每 bit 一条
  LWE 样本）；v1 序列化一律拒绝；identity_bytes 作为最大长度强制；
* 主 AI 裁定 pin（mock）：mock 后端不读取也不强制 identity_bytes，
  保持"非空 bytes"语义（BASELINE_MOCK_PARAMS 冲突未解决前）。

安全声明：本文件使用教学/调试参数（security_claim: none）；测试通过
不构成 LWE、SIS 或 HIBE/IB-ME 安全性证明。攻击回归测试的通过同样
只是"该已知攻击在此参数下不可行"的功能性证据，不是 IND-CPA 证明。
"""

from __future__ import annotations

import math

import pytest

from ibme.core.encoding import encode_bytes
from ibme.core.errors import (
    EncodingError,
    InvalidParameterError,
    SerializationError,
)
from ibme.core.randomness import DeterministicRandom
from ibme.hibe import ABB10HIBE, ABB10_DEBUG_PARAMS, MockHIBE
from ibme.hibe import abb10 as abb10_module
from ibme.lattice import EDUCATION_PARAMS, ModMatrix, ModVector, gadget_width

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
    """对密文多个字节位置做大幅篡改（诚实口径，v2 逐比特独立样本）。

    * mock：认证标签覆盖全部密文字节，任何篡改都必须导致 ``None``；
    * abb10 v2：单字节篡改至多落在**单个明文比特**的 LWE 样本上
      （c2^(j) 逐比特独立），解码可能不变（Regev 容限内）、翻转该 bit
      （→ None 或个别 bit 的变体）或被解析层拒绝。HIBE 层不提供完整
      性（CCA 不在范围），协议层由 IBS 签名兜底；本层必须成立的是：
      身份绑定不被篡改击穿——不匹配密钥对任何篡改密文都返回 None。
    位置均匀抽样（abb10 的单次解密约 50ms，全字节遍历无法保持在秒级）。
    """
    name, backend, params, pk, msk, sk1, sk2 = env
    payload, ct = ciphertext
    raw = ct.to_bytes()
    step = max(1, len(raw) // 24)
    sk_wrong = None
    if name == "abb10":
        sk_wrong = backend.derive(
            sk1, WRONG_PHI, rng=DeterministicRandom(SEED + b":tamper-wrong")
        )
    for pos in range(0, len(raw), step):
        tampered = raw[:pos] + bytes([raw[pos] ^ 0xFF]) + raw[pos + 1 :]
        try:
            ct2 = type(ct).from_bytes(tampered)
        except SerializationError:
            continue
        result = backend.decrypt(
            sk2, ct2, rng=DeterministicRandom(SEED + b":tamper-all")
        )
        if name == "mock":
            assert result != payload, f"tampering byte {pos} went undetected"
        else:
            assert result is None or isinstance(result, bytes)
            assert (
                backend.decrypt(
                    sk_wrong, ct2, rng=DeterministicRandom(SEED + b":tamper-w2")
                )
                is None
            ), f"tampering byte {pos} broke identity binding"


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
    # 编码后的身份（长度前缀形式）与 payload 明文同样不应出现。
    assert encode_bytes(RCV) not in raw
    assert encode_bytes(PHI) not in raw
    assert payload not in raw
    # 加强（P0 整改）：身份/payload **内容**的任意 4 字节滑窗都不应字节级
    # 出现在密文里——LWE 系数与明文内容不应有任何逐字节相关性。
    # （长度前缀本身不算"内容"：mock 密文头部合法携带 payload 长度元数据。）
    for chunk in (RCV, PHI, payload):
        for i in range(len(chunk) - 3):
            window = chunk[i : i + 4]
            assert window not in raw, f"plaintext window {window!r} leaked into ciphertext"


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


# ---------------------------------------------------------------------------
# P0 整改回归：纯密文攻击不可行（abb10 后端，attack-oracle 风格）
# ---------------------------------------------------------------------------


def _centered(value: int, q: int) -> int:
    """把 mod-q 值映到 (-q/2, q/2] 的中心化代表元。"""
    residual = value % q
    return residual - q if residual > q // 2 else residual


def _bits_of(data: bytes) -> list[int]:
    """MSB-first 的比特展开（与 abb10.encrypt 的逐 bit 顺序一致）。"""
    return [(byte >> shift) & 1 for byte in data for shift in range(7, -1, -1)]


def test_abb10_ciphertext_structure_is_per_bit(env, ciphertext):
    """结构 pin：每个明文比特恰好一条独立 LWE 样本。

    len(c2) == len(c1) == 明文比特数，各 c2 向量同长 == cols(B_full)。
    任何退回"全部比特共享一条 c2"的实现都会在此直接暴露。
    """
    _, backend, params, pk, msk, sk1, sk2 = env
    _skip_unless_abb10(env)
    payload, ct = ciphertext
    nk = params.n * gadget_width(params.q)
    expected_cols = params.m_matrix + 2 * nk
    expected_bits = 8 * (4 + len(RCV) + 4 + len(PHI) + 4 + len(payload))
    assert len(ct.c1) == len(ct.c2) == expected_bits
    assert {vec.length for vec in ct.c2} == {expected_cols}
    assert ct.c2[0].q == params.q
    # 独立性抽查：不同比特的 c2 向量互不相同（固定 rng 下确定性成立）。
    assert any(vec != ct.c2[0] for vec in ct.c2[1:])


def test_abb10_ciphertext_only_clustering_attack_fails(env):
    """P0 回归（attack-oracle）：审查者的纯密文差分聚类攻击必须失败。

    攻击（对 v1 共享掩码结构成立）：所有 c1 系数共享同一 u·s 掩码时，
    center(c1_j − c1_0) 按明文比特完美双簇聚类（|差| ≈ 0 或 ≈ q/2，
    簇内噪声 ~√2·σ ≪ q/4）；明文首字段是 uint32 长度前缀（高位比特
    恒 0）⇒ bit_0 已知 ⇒ 无密钥恢复全部明文（含身份与消息）。v2 逐比特
    独立 s_j 后，差值含 u·(s_j − s_0) 的均匀分量，任何基于差分阈值的
    重组都必须退化为猜硬币。
    """
    _, backend, params, pk, msk, sk1, sk2 = env
    _skip_unless_abb10(env)
    payload = b"\x00" * 24  # 全零比特 + 零长度前缀：v1 下的完美聚类输入
    ct = backend.encrypt(
        pk, RCV, PHI, payload, rng=DeterministicRandom(SEED + b":atk-cluster")
    )
    q = ct.c2[0].q
    plaintext = encode_bytes(RCV) + encode_bytes(PHI) + encode_bytes(payload)
    true_bits = _bits_of(plaintext)
    assert true_bits[0] == 0  # 长度前缀首字节 0x00 的 MSB：攻击者的已知比特
    diffs = [_centered(value - ct.c1[0], q) for value in ct.c1[1:]]

    # -- 攻击尝试：|差| > q/4 判定 bit_j != bit_0，重组全部明文比特 --
    predicted = [0] + [1 if abs(d) > q // 4 else 0 for d in diffs]
    accuracy = sum(p == t for p, t in zip(predicted, true_bits)) / len(true_bits)
    assert 0.25 <= accuracy <= 0.75, (
        f"clustering attack recovers plaintext bits with accuracy {accuracy:.3f}; "
        "c1 coefficients must not share a common mask"
    )
    recovered = bytes(
        sum(predicted[i * 8 + bit] << (7 - bit) for bit in range(8))
        for i in range(len(predicted) // 8)
    )
    assert recovered != plaintext

    # -- 分布不再双簇：中心化差值的方差必须是均匀量级（~q²/12），
    #    而非共享掩码下的噪声量级（~2σ²）。--
    mean = sum(diffs) / len(diffs)
    variance = sum((d - mean) ** 2 for d in diffs) / len(diffs)
    assert q * q / 24 <= variance <= q * q / 6, (
        f"centered-difference variance {variance:.3e} is not uniform-scale "
        f"(target q^2/12 = {q * q / 12:.3e})"
    )
    # -- |差| <= q/4 的比例应接近均匀值 0.5，不随明文比特模式聚集。--
    within = sum(1 for d in diffs if abs(d) <= q // 4) / len(diffs)
    assert 0.3 <= within <= 0.7
    # 全零 payload 区同样如此（v1 共享掩码下该区域差值全部塌缩到 0 附近）。
    region_start = 8 * (4 + len(RCV) + 4 + len(PHI) + 4)
    region = [_centered(ct.c1[j] - ct.c1[0], q) for j in range(region_start, len(ct.c1))]
    rmean = sum(region) / len(region)
    rvar = sum((d - rmean) ** 2 for d in region) / len(region)
    assert rvar >= q * q / 24, (
        "all-zero plaintext region still clusters; per-bit masks are correlated"
    )


def test_abb10_known_plaintext_single_bit_difference_not_locatable(env):
    """P0 回归（attack-oracle）：两段只差一个 bit 的明文，无法从密文差分
    定位那个 bit。

    v1 下同一 pk 的两条密文各自共享内部掩码：c1'_j − c1_j = 公共偏移
    u·(s' − s) + (bit'_j − bit_j)·q/2 + 噪声，唯一的大差值位置直接暴露
    差异 bit。v2 的逐比特独立 s_j 使每个位置都含独立均匀分量，差异 bit
    被淹没在约一半的"显著"位置里。
    """
    _, backend, params, pk, msk, sk1, sk2 = env
    _skip_unless_abb10(env)
    m0 = b"\x00" * 16
    m1 = m0[:-1] + b"\x80"  # 恰好一个 bit 不同：末字节 MSB
    ct0 = backend.encrypt(pk, RCV, PHI, m0, rng=DeterministicRandom(SEED + b":kp0"))
    ct1 = backend.encrypt(pk, RCV, PHI, m1, rng=DeterministicRandom(SEED + b":kp1"))
    assert (
        backend.decrypt(sk2, ct0, rng=DeterministicRandom(SEED + b":kp-dec0")) == m0
    )
    assert (
        backend.decrypt(sk2, ct1, rng=DeterministicRandom(SEED + b":kp-dec1")) == m1
    )
    q = ct0.c2[0].q
    n_bits = len(ct0.c1)
    assert len(ct1.c1) == n_bits
    true_position = n_bits - 8  # 末字节 MSB 的比特下标
    deltas = [_centered(a - b, q) for a, b in zip(ct1.c1, ct0.c1)]

    # -- 攻击尝试 1：收集所有 |差| > q/4 的"显著"位置，期望只剩差异 bit --
    candidates = [j for j, d in enumerate(deltas) if abs(d) > q // 4]
    assert len(candidates) >= n_bits // 8, (
        f"only {len(candidates)} positions stand out; the differing bit is "
        "locatable, per-bit masks are not independent"
    )
    assert candidates != [true_position]
    # -- 攻击尝试 2：argmax 定位器必须指错位置。--
    top = max(range(n_bits), key=lambda j: abs(deltas[j]))
    assert top != true_position, "argmax locator finds the differing bit"


# ---------------------------------------------------------------------------
# P0 整改回归：v1 序列化拒绝 + identity_bytes 上限强制
# ---------------------------------------------------------------------------


_V1_MAGICS = {
    b"IBME:HIBE-ABB10:PK:v1",
    b"IBME:HIBE-ABB10:MSK:v1",
    b"IBME:HIBE-ABB10:SK1:v1",
    b"IBME:HIBE-ABB10:SK2:v1",
    b"IBME:HIBE-ABB10:CT:v1",
}


def test_abb10_v1_serialization_rejected(env):
    """v2 magic 升级后，v1 对象必须被拒绝，不得静默误解析。

    v1 密文是共享 c2 的旧结构（P0 泄漏形态），v1 密钥快照无
    identity_bytes 字段——两者的字节布局都无法按 v2 正确解释。
    """
    _, backend, params, pk, msk, sk1, sk2 = env
    _skip_unless_abb10(env)
    _, ct = _fresh_ciphertext(env)
    objects = [
        (type(pk), pk.to_bytes(), b"IBME:HIBE-ABB10:PK:v1"),
        (type(msk), msk.to_bytes(), b"IBME:HIBE-ABB10:MSK:v1"),
        (type(sk1), sk1.to_bytes(), b"IBME:HIBE-ABB10:SK1:v1"),
        (type(sk2), sk2.to_bytes(), b"IBME:HIBE-ABB10:SK2:v1"),
        (type(ct), ct.to_bytes(), b"IBME:HIBE-ABB10:CT:v1"),
    ]
    for cls, raw, old_magic in objects:
        assert old_magic in _V1_MAGICS
        magic = raw[: len(old_magic)]
        assert magic.endswith(b":v2"), f"unexpected magic {magic!r}"
        forged = old_magic + raw[len(old_magic):]
        with pytest.raises(SerializationError):
            cls.from_bytes(forged)
    # 按 v1 布局精心构造的"结构合法"旧密文，也必须在 magic 处被拒绝。
    q = params.q
    cols = params.m_matrix + 2 * params.n * gadget_width(params.q)
    elem = (q.bit_length() + 7) // 8
    old_layout_ct = (
        b"IBME:HIBE-ABB10:CT:v1"
        + (8).to_bytes(4, "big")
        + ModVector([0] * cols, q).to_bytes()
        + (0).to_bytes(elem, "big")
    )
    with pytest.raises(SerializationError):
        type(ct).from_bytes(old_layout_ct)


def test_abb10_identity_length_limit_enforced(env):
    """identity_bytes 是最大长度（主 AI 冻结语义，SPEC §2）。

    超上限（identity_bytes+1 字节）→ EncodingError；恰好等于上限 →
    extract/derive/encrypt/decrypt 全链路可用，序列化往返保持绑定。
    mock 后端不在此列（见 test_mock_backend_keeps_nonempty_only_identity_semantics）。
    """
    _, backend, params, pk, msk, sk1, sk2 = env
    _skip_unless_abb10(env)
    limit = params.identity_bytes
    assert limit >= len(RCV) and limit >= len(PHI)
    at_limit = bytes(range(1, limit + 1))
    over_limit = at_limit + b"\xff"
    rng = DeterministicRandom(SEED + b":idlimit")
    with pytest.raises(EncodingError):
        backend.extract(msk, over_limit, rng=rng)
    with pytest.raises(EncodingError):
        backend.derive(sk1, over_limit, rng=rng)
    with pytest.raises(EncodingError):
        backend.encrypt(pk, over_limit, PHI, b"", rng=rng)
    with pytest.raises(EncodingError):
        backend.encrypt(pk, RCV, over_limit, b"", rng=rng)
    # 恰好等于上限：全链路（含解密身份比对）通过。
    sk1_at = backend.extract(msk, at_limit, rng=DeterministicRandom(SEED + b":id-at1"))
    sk2_at = backend.derive(sk1_at, PHI, rng=DeterministicRandom(SEED + b":id-at2"))
    ct_at = backend.encrypt(pk, at_limit, PHI, b"", rng=DeterministicRandom(SEED + b":id-at3"))
    assert (
        backend.decrypt(sk2_at, ct_at, rng=DeterministicRandom(SEED + b":id-at4")) == b""
    )
    # 序列化往返保持身份绑定，且 sk 构造路径同样强制上限。
    clone = type(sk1_at).from_bytes(sk1_at.to_bytes())
    assert clone == sk1_at and clone.identity == at_limit
    with pytest.raises(EncodingError):
        type(sk1_at)(
            meta=sk1_at.meta,
            identity=over_limit,
            a=sk1_at.a,
            u=sk1_at.u,
            r1=sk1_at.r1,
        )


def test_mock_backend_keeps_nonempty_only_identity_semantics(env):
    """主 AI 裁定 pin（2026-09，P0 整改期间）：mock 后端不读取也不强制
    ``params.identity_bytes``，保持 SPEC §1 的"非空 bytes"语义。

    原因：protocol 层 BASELINE_MOCK_PARAMS.identity_bytes=8 小于 baseline
    契约测试的身份长度（9–11B），强制会使禁改的 baseline 测试失败。
    在该规范冲突由主 AI 解决之前，任何"顺手"给 mock 加上限的改动都会
    在此被抓住。
    """
    name, backend, params, pk, msk, sk1, sk2 = env
    if name != "mock":
        pytest.skip("mock-only ruling pin")
    assert params.identity_bytes < len(RCV)  # EDUCATION_PARAMS=8 < 10
    ct = backend.encrypt(
        pk, RCV, PHI, b"ruling", rng=DeterministicRandom(SEED + b":mock-rule")
    )
    assert (
        backend.decrypt(sk2, ct, rng=DeterministicRandom(SEED + b":mock-rule-d"))
        == b"ruling"
    )
