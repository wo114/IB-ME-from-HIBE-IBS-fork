"""IBS contract tests (M2, 任务 D)：MockIBSBackend 与 SisIBSBackend 运行同一契约。

参数化契约（两个后端逐条相同）：setup→key_extract→sign→verify 正确通过
（多字节 UTF-8 身份、二进制消息、空消息）；身份/消息/签名篡改被拒；截断、
追加、重复字段的反序列化被拒；随机伪造签名以概率 1 失败（若干例统计性
检查）；sk 绑定身份摘要；pk/msk/sk/签名序列化往返；固定 rng 可复现。

SIS 专项代数测试：H1 = A·R̂ + G 精确成立、F_id·z = h2 成立、z ≠ 0 且
‖z‖₂ ≤ s'·sqrt(m+n·k)（与 notes §4.3 一致）、超范数界签名在反序列化阶段
即被拒绝、维度不符拒绝。

测试全部使用 DeterministicRandom（测试随机数，与生产 SecureRandom 分离），
结果逐位确定。参数为教学参数（IBS_EDUCATION_PARAMS / EDUCATION_PARAMS，
security_claim: none），不构成任何安全声明。
"""

from __future__ import annotations

import pytest

from ibme.core import (
    DeterministicRandom,
    EncodingError,
    InvalidParameterError,
    SerializationError,
    hash_identity,
)
from ibme.lattice import EDUCATION_PARAMS, Params, gadget_matrix
from ibme.lattice.modmat import ModMatrix, ModVector
from ibme.ibs import (
    IBSError,
    IBS_EDUCATION_PARAMS,
    MockIBSBackend,
    MockMasterSecret,
    MockPublicKey,
    MockSignature,
    MockSigningKey,
    SisIBSBackend,
    SisMasterSecret,
    SisPublicKey,
    SisSignature,
    SisSigningKey,
    f_id_matrix,
    h1_matrix,
    h2_vector,
    signature_bound,
)

# ---------------------------------------------------------------------------
# 后端工厂与公共流水线
# ---------------------------------------------------------------------------


def _make_mock() -> MockIBSBackend:
    return MockIBSBackend(rng=DeterministicRandom(b"ibs-contract-mock"))


def _make_sis() -> SisIBSBackend:
    return SisIBSBackend(rng=DeterministicRandom(b"ibs-contract-sis"))


BACKENDS = [
    pytest.param(_make_mock, EDUCATION_PARAMS, id="mock"),
    pytest.param(_make_sis, IBS_EDUCATION_PARAMS, id="sis"),
]

IDENTITIES = [
    b"alice@example.com",
    "爱丽丝@例子.中国".encode("utf-8"),
    b"\x00\x01\xfe\xff-binary-id",
    "Ψχ==λ/Ω".encode("utf-8"),
]

MESSAGES = [b"payload", b"", bytes(range(64))]


def _pipeline(make_backend, params, identity=b"Alice", message=b"payload"):
    backend = make_backend()
    pk, msk = backend.setup(params)
    sk = backend.key_extract(msk, identity)
    sig = backend.sign(sk, message)
    return backend, pk, msk, sk, sig


def _tamper_signature(sig):
    """对签名做最小篡改（sis：单系数 ±1；mock：单字节翻转），保持对象合法。"""
    if isinstance(sig, SisSignature):
        z = list(sig.z)
        z[0] = z[0] + 1 if z[0] == 0 else z[0] - 1
        return SisSignature(z)
    if isinstance(sig, MockSignature):
        tag = bytearray(sig.tag)
        tag[0] ^= 0x01
        return MockSignature(bytes(tag))
    raise AssertionError(f"unexpected signature type {type(sig).__name__}")


def _parse_signature(raw: bytes, pk):
    if isinstance(pk, SisPublicKey):
        return SisSignature.from_bytes(raw, pk)
    if isinstance(pk, MockPublicKey):
        return MockSignature.from_bytes(raw)
    raise AssertionError(f"unexpected public key type {type(pk).__name__}")


# ---------------------------------------------------------------------------
# 参数化契约测试（mock 与 sis 同一契约）
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("make_backend,params", BACKENDS)
def test_roundtrip_various_identities_and_messages(make_backend, params):
    backend = make_backend()
    pk, msk = backend.setup(params)
    for identity in IDENTITIES:
        sk = backend.key_extract(msk, identity)
        for message in MESSAGES:
            sig = backend.sign(sk, message)
            assert backend.verify(pk, identity, message, sig) is True


@pytest.mark.parametrize("make_backend,params", BACKENDS)
def test_verify_wrong_identity_and_cross_system(make_backend, params):
    backend = make_backend()
    pk, msk = backend.setup(params)
    sk = backend.key_extract(msk, b"Alice")
    sig = backend.sign(sk, b"payload")

    # 身份不对：用 B 的身份验 A 的签名。
    assert backend.verify(pk, b"Bob", b"payload", sig) is False

    # 跨系统：另一套独立 setup 的公钥（不同随机源种子）。
    other = type(backend)(rng=DeterministicRandom(b"ibs-contract-other"))
    pk2, _ = other.setup(params)
    assert backend.verify(pk2, b"Alice", b"payload", sig) is False
    assert other.verify(pk2, b"Alice", b"payload", sig) is False


@pytest.mark.parametrize("make_backend,params", BACKENDS)
def test_verify_rejects_modified_message(make_backend, params):
    backend, pk, msk, sk, sig = _pipeline(make_backend, params)
    message = b"payload"

    flipped = bytearray(message)
    flipped[-1] ^= 0x01
    assert backend.verify(pk, b"Alice", bytes(flipped), sig) is False
    # 追加 / 截断 / 空 ↔ 非空
    assert backend.verify(pk, b"Alice", message + b"\x00", sig) is False
    assert backend.verify(pk, b"Alice", message[:-1], sig) is False
    assert backend.verify(pk, b"Alice", b"", sig) is False

    sig_empty = backend.sign(sk, b"")
    assert backend.verify(pk, b"Alice", b"", sig_empty) is True
    assert backend.verify(pk, b"Alice", b"\x00", sig_empty) is False


@pytest.mark.parametrize("make_backend,params", BACKENDS)
def test_verify_rejects_tampered_signature(make_backend, params):
    backend, pk, _, _, sig = _pipeline(make_backend, params)
    tampered = _tamper_signature(sig)
    assert tampered != sig
    assert backend.verify(pk, b"Alice", b"payload", tampered) is False


@pytest.mark.parametrize("make_backend,params", BACKENDS)
def test_signature_bytes_strict_parse(make_backend, params):
    _, pk, _, _, sig = _pipeline(make_backend, params)
    raw = sig.to_bytes()
    # 往返一致
    assert _parse_signature(raw, pk) == sig
    # 截断 / 追加 / 重复字段
    with pytest.raises(SerializationError):
        _parse_signature(raw[:-1], pk)
    with pytest.raises(SerializationError):
        _parse_signature(raw + b"\x00", pk)
    with pytest.raises(SerializationError):
        _parse_signature(raw + raw, pk)
    with pytest.raises(SerializationError):
        _parse_signature(raw[1:], pk)
    with pytest.raises(SerializationError):
        _parse_signature(b"", pk)


@pytest.mark.parametrize("make_backend,params", BACKENDS)
def test_random_bytes_signature_parse_rejected(make_backend, params):
    _, pk, _, _, sig = _pipeline(make_backend, params)
    rng = DeterministicRandom(b"ibs-contract-random")
    raw_len = len(sig.to_bytes())
    for _ in range(8):
        blob = rng.read(raw_len)
        with pytest.raises(SerializationError):
            _parse_signature(blob, pk)


@pytest.mark.parametrize("make_backend,params", BACKENDS)
def test_random_forgery_verify_false(make_backend, params):
    """随机伪造签名必须验证失败（概率 1 的统计性检查，若干例）。"""
    backend, pk, _, _, sig = _pipeline(make_backend, params)
    rng = DeterministicRandom(b"ibs-contract-forge")
    if isinstance(pk, SisPublicKey):
        # 随机短向量：范数远小于界，但恰好满足 F_id·z = h2 的概率 ~q^{-n}。
        for _ in range(12):
            z = [(b % 13) - 6 for b in rng.read(pk.f_id_cols)]
            if not any(z):
                z[0] = 1
            forged = SisSignature(z)
            assert 0 < forged.norm_squared <= pk.norm_bound_squared
            assert backend.verify(pk, b"Alice", b"payload", forged) is False
        # 随机字节串按签名格式解析必须被拒绝
        with pytest.raises(SerializationError):
            SisSignature.from_bytes(rng.read(len(sig.to_bytes())), pk)
    else:
        for _ in range(12):
            forged = MockSignature(rng.read(32))
            assert backend.verify(pk, b"Alice", b"payload", forged) is False


@pytest.mark.parametrize("make_backend,params", BACKENDS)
def test_sk_binds_identity(make_backend, params):
    backend, pk, msk, sk, sig = _pipeline(make_backend, params, identity=b"Alice")
    assert sk.identity == b"Alice"
    # 规范化身份摘要（hash_identity(identity, 32)）
    assert sk.identity_digest == hash_identity(b"Alice", 32)
    # 用错误身份验签必须失败（sk 只能为绑定身份签名）。
    assert backend.verify(pk, b"Bob", b"payload", sig) is False
    # 摘要篡改在对象构造时被拒绝
    if isinstance(sk, SisSigningKey):
        with pytest.raises(InvalidParameterError):
            SisSigningKey(
                identity=b"Alice",
                r_hat=sk.r_hat,
                public_key=sk.public_key,
                sigma=sk.sigma,
                identity_digest=b"\x00" * 32,
            )
    else:
        with pytest.raises(InvalidParameterError):
            MockSigningKey(
                identity=b"Alice",
                identity_digest=b"\x00" * 32,
                key=sk.key,
            )


@pytest.mark.parametrize("make_backend,params", BACKENDS)
def test_serialization_roundtrip_functional(make_backend, params):
    backend, pk, msk, sk, sig = _pipeline(make_backend, params)
    identity, message = b"Alice", b"payload"

    pk2 = type(pk).from_bytes(pk.to_bytes())
    msk2 = type(msk).from_bytes(msk.to_bytes())
    sk2 = type(sk).from_bytes(sk.to_bytes())
    sig2 = _parse_signature(sig.to_bytes(), pk2)

    assert pk2 == pk and msk2 == msk and sk2 == sk and sig2 == sig
    # 反序列化对象功能等价
    assert backend.verify(pk2, identity, message, sig2) is True
    sig3 = backend.sign(sk2, message)
    assert backend.verify(pk, identity, message, sig3) is True
    sk3 = backend.key_extract(msk2, identity)
    assert backend.verify(pk, identity, message, backend.sign(sk3, message)) is True


@pytest.mark.parametrize("make_backend,params", BACKENDS)
def test_pk_msk_sk_malformed_rejected(make_backend, params):
    _, pk, msk, sk, _ = _pipeline(make_backend, params)
    for obj in (pk, msk, sk):
        raw = obj.to_bytes()
        with pytest.raises(SerializationError):
            type(obj).from_bytes(raw[:-1])
        with pytest.raises(SerializationError):
            type(obj).from_bytes(raw + b"\x00")
        with pytest.raises(SerializationError):
            type(obj).from_bytes(raw[1:])
        with pytest.raises(SerializationError):
            type(obj).from_bytes(b"")


@pytest.mark.parametrize("make_backend,params", BACKENDS)
def test_verify_type_guards(make_backend, params):
    backend, pk, _, _, sig = _pipeline(make_backend, params)
    assert backend.verify(pk, "not-bytes", b"m", sig) is False
    assert backend.verify(pk, b"Alice", "not-bytes", sig) is False
    assert backend.verify(pk, b"Alice", b"m", "not-a-signature") is False
    assert backend.verify(pk, b"Alice", b"m", None) is False
    assert backend.verify(None, b"Alice", b"m", sig) is False
    assert backend.verify("pk", b"Alice", b"m", sig) is False
    assert backend.verify(pk, b"", b"m", sig) is False
    # bytes-like（bytearray/memoryview）合法输入
    assert backend.verify(pk, bytearray(b"Alice"), memoryview(b"payload"), sig) is True


@pytest.mark.parametrize("make_backend,params", BACKENDS)
def test_key_extract_rejects_bad_identity(make_backend, params):
    backend, pk, msk, _, _ = _pipeline(make_backend, params)
    with pytest.raises(EncodingError):
        backend.key_extract(msk, b"")
    with pytest.raises(EncodingError):
        backend.key_extract(msk, "Alice")
    with pytest.raises(TypeError):
        backend.key_extract("not-an-msk", b"Alice")


@pytest.mark.parametrize("make_backend,params", BACKENDS)
def test_setup_rejects_bad_params(make_backend, params):
    backend = make_backend()
    with pytest.raises(InvalidParameterError):
        backend.setup(123)
    with pytest.raises(InvalidParameterError):
        backend.setup("education")


@pytest.mark.parametrize("make_backend,params", BACKENDS)
def test_fixed_rng_reproducible(make_backend, params):
    backend_a, pk_a, msk_a, sk_a, sig_a = _pipeline(make_backend, params)
    backend_b, pk_b, msk_b, sk_b, sig_b = _pipeline(make_backend, params)
    # 同一种子：逐字节一致
    assert pk_a.to_bytes() == pk_b.to_bytes()
    assert msk_a.to_bytes() == msk_b.to_bytes()
    assert sk_a.to_bytes() == sk_b.to_bytes()
    assert sig_a.to_bytes() == sig_b.to_bytes()
    # 不同种子：输出不同
    other = type(backend_a)(rng=DeterministicRandom(b"ibs-contract-different"))
    pk2, msk2 = other.setup(params)
    sk2 = other.key_extract(msk2, b"Alice")
    sig2 = other.sign(sk2, b"payload")
    assert pk2.to_bytes() != pk_a.to_bytes()
    assert sig2.to_bytes() != sig_a.to_bytes()


def test_mock_backend_marked_test_only():
    """mock 组件的类 docstring 必须醒目标注 TEST-ONLY。"""
    for cls in (
        MockIBSBackend,
        MockPublicKey,
        MockMasterSecret,
        MockSigningKey,
        MockSignature,
    ):
        assert "TEST-ONLY" in cls.__doc__, cls.__name__


# ---------------------------------------------------------------------------
# SIS 专项代数与严格性测试
# ---------------------------------------------------------------------------


class TestSisBackend:
    """SIS-IBS 专项：构造 3.4.1 的代数关系与范数界。"""

    def test_construction_h1_relation(self):
        """H1(mpk, id) = A·R̂_id + G (mod q) 精确成立。"""
        _, pk, msk, sk, _ = _pipeline(_make_sis, IBS_EDUCATION_PARAMS)
        assert isinstance(msk, SisMasterSecret)
        h1 = h1_matrix(pk, sk.identity)
        gadget = gadget_matrix(pk.n, pk.q)
        r_hat = ModMatrix([list(row) for row in sk.r_hat], pk.q)
        assert pk.a.mul_matrix(r_hat) + gadget == h1
        # R̂ 维度：m × n·k
        assert len(sk.r_hat) == pk.m
        assert all(len(row) == pk.nk for row in sk.r_hat)

    def test_signature_equation_norm_nonzero(self):
        """F_id·z = h2 (mod q)、z ≠ 0、‖z‖₂ ≤ s'·sqrt(m+n·k)。"""
        backend, pk, _, sk, sig = _pipeline(_make_sis, IBS_EDUCATION_PARAMS)
        h2 = h2_vector(pk, sk.identity, b"payload")
        f_id = f_id_matrix(pk, sk.identity)
        assert f_id.rows == pk.n and f_id.cols == pk.f_id_cols
        assert len(sig.z) == pk.f_id_cols
        assert any(sig.z)
        assert f_id.matvec(ModVector(list(sig.z), pk.q)) == h2
        assert 0 < sig.norm_squared <= pk.norm_bound_squared
        assert signature_bound(pk) == pytest.approx(pk.norm_bound)

    def test_norm_bound_holds_across_signs(self):
        backend, pk, _, sk, _ = _pipeline(_make_sis, IBS_EDUCATION_PARAMS)
        for i in range(5):
            sig = backend.sign(sk, b"message-%d" % i)
            assert 0 < sig.norm_squared <= pk.norm_bound_squared
            assert backend.verify(pk, sk.identity, b"message-%d" % i, sig) is True

    def test_h1_h2_identity_sensitivity(self):
        _, pk, _, _, _ = _pipeline(_make_sis, IBS_EDUCATION_PARAMS)
        assert h1_matrix(pk, b"Alice") != h1_matrix(pk, b"Bob")
        assert h2_vector(pk, b"Alice", b"m") != h2_vector(pk, b"Bob", b"m")
        assert h2_vector(pk, b"Alice", b"m") != h2_vector(pk, b"Alice", b"m2")

    def test_signature_field_tampering_rejected(self):
        _, pk, _, _, sig = _pipeline(_make_sis, IBS_EDUCATION_PARAMS)
        raw = bytearray(sig.to_bytes())
        # 布局：magic(len(b"IBS1-S-SIG")=10) + u32 vec_len + u32 width + 系数
        magic_len = len(b"IBS1-S-SIG")
        # vec_len 字段：维度不符
        raw[magic_len : magic_len + 4] = (pk.f_id_cols + 1).to_bytes(4, "big")
        with pytest.raises(SerializationError):
            SisSignature.from_bytes(bytes(raw), pk)
        # width 字段非法（0 与 9）
        for bad_width in (0, 9):
            raw = bytearray(sig.to_bytes())
            raw[magic_len + 4 : magic_len + 8] = bad_width.to_bytes(4, "big")
            with pytest.raises(SerializationError):
                SisSignature.from_bytes(bytes(raw), pk)

    def test_oversized_norm_signature_rejected(self):
        """超范数界签名：反序列化拒绝，verify 也拒绝。"""
        backend, pk, _, _, sig = _pipeline(_make_sis, IBS_EDUCATION_PARAMS)
        scaled = SisSignature([4 * v for v in sig.z])
        assert scaled.norm_squared > pk.norm_bound_squared
        with pytest.raises(SerializationError):
            SisSignature.from_bytes(scaled.to_bytes(), pk)
        assert backend.verify(pk, b"Alice", b"payload", scaled) is False

    def test_sk_dimension_mismatch_rejected(self):
        _, pk, _, sk, _ = _pipeline(_make_sis, IBS_EDUCATION_PARAMS)
        # 对象构造时拒绝维度不符的 r_hat
        with pytest.raises(InvalidParameterError):
            SisSigningKey(
                identity=b"Alice",
                r_hat=sk.r_hat[:-1],
                public_key=pk,
                sigma=sk.sigma,
            )
        # 序列化后的维度字段被篡改：解析拒绝。
        # 布局：magic(9) + u32+len(id) + digest(32) + u32+pk_blob + f64(8) + 矩阵头
        raw = bytearray(sk.to_bytes())
        sk_magic_len = len(b"IBS1-S-SK")
        matrix_off = sk_magic_len + 4 + len(sk.identity) + 32 + 4 + len(pk.to_bytes()) + 8
        assert raw[matrix_off : matrix_off + 4] == len(sk.r_hat).to_bytes(4, "big")
        raw[matrix_off : matrix_off + 4] = (len(sk.r_hat) + 1).to_bytes(4, "big")
        with pytest.raises(SerializationError):
            SisSigningKey.from_bytes(bytes(raw))

    def test_zero_and_wrong_length_signature_verify_false(self):
        backend, pk, _, _, sig = _pipeline(_make_sis, IBS_EDUCATION_PARAMS)
        assert backend.verify(pk, b"Alice", b"payload", SisSignature([0] * pk.f_id_cols)) is False
        assert backend.verify(pk, b"Alice", b"payload", SisSignature(list(sig.z)[:-1])) is False

    def test_setup_rejects_degenerate_matrix_columns(self):
        backend = _make_sis()
        bad = Params(
            name="bad-matrix",
            security_parameter=8,
            n=8,
            m_matrix=72,  # = n·k，没有 a_bar 列
            q=257,
            s0=4.0,
            s=10.0,
            s_prime=64.0,
            identity_bytes=8,
            max_message_bytes=32,
        )
        with pytest.raises(InvalidParameterError):
            backend.setup(bad)

    def test_education_preset_norm_bound_too_tight(self):
        """文档化行为：lattice 的 EDUCATION_PARAMS（s'=12，界 148）对无扰动
        简化采样链的诚实签名（‖z‖ 实测 ~2.7e2–5.8e2）过紧，sign 重采样
        耗尽后抛 IBSError。这正是 IBS_EDUCATION_PARAMS 把 s_prime 放宽到
        64 的原因（教学放宽，不对应论文渐近参数关系）。"""
        backend = SisIBSBackend(rng=DeterministicRandom(b"ibs-edu-tight"))
        pk, msk = backend.setup(EDUCATION_PARAMS)
        assert pk.norm_bound < 200
        sk = backend.key_extract(msk, b"Alice")
        with pytest.raises(IBSError):
            backend.sign(sk, b"payload")
