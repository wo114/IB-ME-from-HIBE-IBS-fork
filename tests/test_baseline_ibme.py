"""基线 IB-ME 协议契约测试：mock+mock 与 abb10+sis 两种组合跑同一契约。

对应 DELEGATION_PROMPTS.md 任务 E、AI_WORKFLOW.md M3 门槛、
AGENTS.md §5 与 IMPLEMENTATION_SPEC.md §6 的协议测试表。覆盖：

* 双匹配（ρ=rcv 且 snd=φ）→ 原消息（空消息、二进制脏字节）；
* 仅接收者 / 仅发送者 / 两者均不匹配 → BOTTOM；
* 密文篡改（协议组帧、HIBE 密文字节）、截断、追加、重复字段 → BOTTOM；
* 签名篡改（改一个系数）、随机伪造签名、恶意 payload 变体 → BOTTOM；
* 协议对象（PublicKey/MasterSecret/SenderKey/ReceiverKey/ct）序列化
  往返 + 畸形拒绝；
* 固定 rng 全流程逐字节可复现；
* SenderKey 身份绑定、密文不含身份明文、输入校验、BOTTOM 哨兵性质；
* CLI 端到端（真实后端小消息 + mismatch→BOTTOM + 篡改→BOTTOM）。

说明（与 M2 HIBE 契约测试一致的诚实口径）：ABB10 是 Regev 比特加密，
对 c1 低阶字节的微小篡改落在解码容限内，可能解出**原**消息——这是
容错性而非缺陷（CCA 不在范围）。因此对任意位置篡改的断言是
"结果 ∈ {BOTTOM, 原消息}"；能被结构性定位的字节（协议组帧、HIBE
magic、c2 区）则严格断言 BOTTOM。

安全声明：本文件使用教学/调试参数（security_claim: none）；测试通过
不构成 LWE、SIS 或 HIBE/IBS/IB-ME 安全性证明。
"""

from __future__ import annotations

import pickle
import types

import pytest

from ibme.core.encoding import encode_bytes, encode_message
from ibme.core.errors import (
    EncodingError,
    InvalidParameterError,
    SerializationError,
)
from ibme.core.randomness import DeterministicRandom
from ibme.hibe import ABB10HIBE, MockHIBE
from ibme.ibs import MockIBSBackend, SisIBSBackend
from ibme.protocol import (
    BASELINE_DEBUG_IBS_PARAMS,
    BASELINE_DEBUG_PARAMS,
    BASELINE_MOCK_PARAMS,
    BOTTOM,
    BaselineIBME,
    Ciphertext,
    DOMAIN_SIGNATURE,
    MasterSecret,
    MAGIC_CIPHERTEXT,
    PublicKey,
    ReceiverKey,
    SenderKey,
    is_bottom,
    parse_payload,
)

# 高字节熵身份（匿名性抽查用原始字节，不落入密文）。
ALICE = b"alice@ibme\x01"  # 发送者 φ
BOB = b"bob@ibme\x02"      # 接收者 ρ
CAROL = b"carol@ibme\x03"  # 其他身份

SEED = b"baseline-contract-tests-v1"
REF_MSG = b"baseline-message-01!"  # 19B

# ---------------------------------------------------------------------------
# 组合与夹具
# ---------------------------------------------------------------------------

_COMBOS = {
    "mock+mock": {
        "hibe_factory": MockHIBE,
        "ibs_factory": MockIBSBackend,
        "hibe_params": BASELINE_MOCK_PARAMS,
        "ibs_params": BASELINE_MOCK_PARAMS,
    },
    "abb10+sis": {
        "hibe_factory": ABB10HIBE,
        "ibs_factory": SisIBSBackend,
        "hibe_params": BASELINE_DEBUG_PARAMS,
        "ibs_params": BASELINE_DEBUG_IBS_PARAMS,
    },
}


def _rng(env, tag: bytes) -> DeterministicRandom:
    return DeterministicRandom(SEED + b":" + env.combo.encode() + b":" + tag)


@pytest.fixture(params=sorted(_COMBOS), scope="module")
def env(request):
    """每组合一套 setup/密钥（abb10 较慢，模块级共享）。"""
    combo = request.param
    cfg = _COMBOS[combo]
    proto = BaselineIBME(
        cfg["hibe_factory"](),
        cfg["ibs_factory"](rng=DeterministicRandom(SEED + b":" + combo.encode() + b":ibs")),
    )
    pk, msk = proto.setup(
        cfg["hibe_params"],
        ibs_params=cfg["ibs_params"],
        rng=DeterministicRandom(SEED + b":" + combo.encode() + b":setup"),
    )
    return types.SimpleNamespace(
        combo=combo,
        proto=proto,
        pk=pk,
        msk=msk,
        params=cfg["hibe_params"],
        ibs_params=cfg["ibs_params"],
        ek_alice=proto.skgen(msk, ALICE),
        ek_carol=proto.skgen(msk, CAROL),
        dk_bob=proto.rkgen(msk, BOB, rng=DeterministicRandom(SEED + b":" + combo.encode() + b":rk-bob")),
        dk_carol=proto.rkgen(msk, CAROL, rng=DeterministicRandom(SEED + b":" + combo.encode() + b":rk-carol")),
    )


@pytest.fixture(scope="module")
def ref(env):
    """篡改/不匹配测试共用的参考密文（Bob ← Alice，REF_MSG）。"""
    ct = env.proto.encrypt(env.pk, env.ek_alice, BOB, REF_MSG, rng=_rng(env, b"ref-enc"))
    assert env.proto.decrypt(env.pk, env.dk_bob, ALICE, ct, rng=_rng(env, b"ref-dec")) == REF_MSG
    return ct


# ---------------------------------------------------------------------------
# 1. 双匹配：返回原消息
# ---------------------------------------------------------------------------

MESSAGE_CASES = [
    b"",  # 空 message
    b"\x00",  # 单字节
    b"baseline IB-ME!",  # 短 ASCII
    bytes((0x00, 0xFF, 0x80, 0x7F, 0x01, 0xFE, 0x7F, 0x80)) * 4,  # 32B 二进制脏字节
]


@pytest.mark.parametrize("message", MESSAGE_CASES)
def test_both_match_returns_message(env, message):
    ct = env.proto.encrypt(env.pk, env.ek_alice, BOB, message, rng=_rng(env, b"enc"))
    result = env.proto.decrypt(env.pk, env.dk_bob, ALICE, ct, rng=_rng(env, b"dec"))
    assert result == message
    assert not is_bottom(result)


def test_bytes_ciphertext_input_also_decrypts(env, ref):
    """decrypt 接受协议密文的规范字节串（CLI 路径）。"""
    result = env.proto.decrypt(
        env.pk, env.dk_bob, ALICE, ref.to_bytes(), rng=_rng(env, b"dec-bytes")
    )
    assert result == REF_MSG


# ---------------------------------------------------------------------------
# 2-4. 三种不匹配组合 → BOTTOM
# ---------------------------------------------------------------------------


def test_receiver_mismatch_returns_bottom(env, ref):
    """仅接收者不匹配：Carol 的 dk 解 Bob 的密文 → BOTTOM。"""
    result = env.proto.decrypt(
        env.pk, env.dk_carol, ALICE, ref, rng=_rng(env, b"mm-rcv")
    )
    assert result is BOTTOM
    assert not result  # falsy


def test_sender_mismatch_returns_bottom(env, ref):
    """仅发送者不匹配：Bob 的 dk 但 snd=Carol → BOTTOM。"""
    result = env.proto.decrypt(
        env.pk, env.dk_bob, CAROL, ref, rng=_rng(env, b"mm-snd")
    )
    assert result is BOTTOM


def test_both_mismatch_returns_bottom(env, ref):
    """两者都不匹配 → BOTTOM。"""
    result = env.proto.decrypt(
        env.pk, env.dk_carol, CAROL, ref, rng=_rng(env, b"mm-both")
    )
    assert result is BOTTOM


# ---------------------------------------------------------------------------
# 5. 密文篡改 / 截断 / 追加 / 重复字段
# ---------------------------------------------------------------------------

_PROTO_HEADER = len(MAGIC_CIPHERTEXT) + 4  # magic + blob 长度前缀


def test_tamper_protocol_framing_returns_bottom(env, ref):
    """翻转协议组帧字节（magic、blob 长度前缀的每一位）→ BOTTOM。"""
    raw = ref.to_bytes()
    positions = [
        0,  # magic 首字节
        len(MAGIC_CIPHERTEXT) - 1,  # magic 末字节
        len(MAGIC_CIPHERTEXT),  # blob 长度高字节
        _PROTO_HEADER - 1,  # blob 长度低字节
    ]
    for pos in positions:
        for bit in range(8):
            tampered = raw[:pos] + bytes([raw[pos] ^ (1 << bit)]) + raw[pos + 1 :]
            result = env.proto.decrypt(
                env.pk, env.dk_bob, ALICE, tampered, rng=_rng(env, b"tamper-frame")
            )
            assert result is BOTTOM, f"framing tamper pos={pos} bit={bit} undetected"


def test_tamper_whole_byte_in_framing_returns_bottom(env, ref):
    raw = ref.to_bytes()
    for pos in (0, 2, len(MAGIC_CIPHERTEXT), _PROTO_HEADER - 1):
        tampered = raw[:pos] + bytes([raw[pos] ^ 0xFF]) + raw[pos + 1 :]
        assert env.proto.decrypt(
            env.pk, env.dk_bob, ALICE, tampered, rng=_rng(env, b"tamper-byte")
        ) is BOTTOM


def test_truncated_appended_duplicated_ciphertext_returns_bottom(env, ref):
    raw = ref.to_bytes()
    malformed = [
        raw[:-1],  # 截断 1 字节
        raw[: _PROTO_HEADER + 8],  # 只剩组帧 + 少量 blob
        raw + b"\x00",  # 追加 1 字节
        raw + b"appended-garbage",  # 追加垃圾
        raw + raw,  # 重复整个密文
        raw + raw[_PROTO_HEADER:],  # 重复 blob 字段
    ]
    for i, bad in enumerate(malformed):
        result = env.proto.decrypt(
            env.pk, env.dk_bob, ALICE, bad, rng=_rng(env, b"mal-ct")
        )
        assert result is BOTTOM, f"malformed ciphertext variant {i} accepted"


def test_tamper_hibe_magic_returns_bottom(env, ref):
    """翻转 HIBE 密文 magic（blob 首字节）→ 重建被拒 → BOTTOM。"""
    raw = ref.to_bytes()
    pos = _PROTO_HEADER  # blob 第一字节 = HIBE magic 首字节
    tampered = raw[:pos] + bytes([raw[pos] ^ 0xFF]) + raw[pos + 1 :]
    assert env.proto.decrypt(
        env.pk, env.dk_bob, ALICE, tampered, rng=_rng(env, b"tamper-hibe-magic")
    ) is BOTTOM


def test_tamper_inside_hibe_ciphertext(env, ref):
    """HIBE 密文体内的篡改：c2 区（共享向量）→ BOTTOM；c1 区按 Regev
    容错口径断言 ∈ {BOTTOM, 原消息}（见模块 docstring）。"""
    raw = ref.to_bytes()
    blob_len = len(raw) - _PROTO_HEADER
    # blob 偏移 ~30：两后端都落在头部/c2 区（mock 的 masked 长度前缀 /
    # abb10 的 c2 系数），翻转后要么解析被拒要么解码全面偏离。
    pos = _PROTO_HEADER + 30
    tampered = raw[:pos] + bytes([raw[pos] ^ 0xFF]) + raw[pos + 1 :]
    assert env.proto.decrypt(
        env.pk, env.dk_bob, ALICE, tampered, rng=_rng(env, b"tamper-c2")
    ) is BOTTOM
    # 深处（c1 区）：篡改要么被拒/解码失败，要么在容限内解出原消息，
    # 绝不允许解出**不同的**明文。
    for rel in (blob_len // 2, blob_len - 5):
        pos = _PROTO_HEADER + rel
        tampered = raw[:pos] + bytes([raw[pos] ^ 0xFF]) + raw[pos + 1 :]
        result = env.proto.decrypt(
            env.pk, env.dk_bob, ALICE, tampered, rng=_rng(env, b"tamper-c1")
        )
        assert result is BOTTOM or result == REF_MSG


# ---------------------------------------------------------------------------
# 6-8. 签名篡改 / 随机伪造 / 恶意 payload 变体（经 HIBE 公共 API 构造）
# ---------------------------------------------------------------------------


def _encrypt_raw_payload(env, payload: bytes) -> Ciphertext:
    """用 HIBE 后端公共 API 在 (BOB, ALICE) 下加密任意 payload 并包装。"""
    hibe_ct = env.proto.hibe_backend.encrypt(
        env.pk.hpk, BOB, ALICE, payload, rng=_rng(env, b"raw-payload")
    )
    return Ciphertext(hibe_ct=hibe_ct)


def _honest_signature_bytes(env) -> bytes:
    signed = encode_message(BOB, REF_MSG)
    signature = env.proto.ibs_backend.sign(env.ek_alice.signing_key, signed)
    return signature.to_bytes()


def test_signature_tamper_returns_bottom(env):
    """改签名末位系数一个字节 → 验签失败 → BOTTOM。"""
    sig_raw = bytearray(_honest_signature_bytes(env))
    sig_raw[-1] ^= 0x01
    payload = DOMAIN_SIGNATURE + encode_bytes(bytes(sig_raw)) + encode_bytes(REF_MSG)
    ct = _encrypt_raw_payload(env, payload)
    result = env.proto.decrypt(
        env.pk, env.dk_bob, ALICE, ct, rng=_rng(env, b"sig-tamper")
    )
    assert result is BOTTOM


def test_random_forged_signature_returns_bottom(env):
    """payload 放随机字节当签名 → 重建/验签失败 → BOTTOM。"""
    forged = _rng(env, b"forged").read(64)
    payload = DOMAIN_SIGNATURE + encode_bytes(forged) + encode_bytes(REF_MSG)
    ct = _encrypt_raw_payload(env, payload)
    result = env.proto.decrypt(
        env.pk, env.dk_bob, ALICE, ct, rng=_rng(env, b"sig-forged")
    )
    assert result is BOTTOM


def test_malicious_payload_variants_return_bottom(env):
    """无域前缀 / 域错配 / 缺 message 字段 / 双签名字段 / 双 message 字段。

    双签名字段变体使用短假签名（真实 SIS 签名 322B，两份会超出 HIBE 的
    ``max_message_bytes``，在 HIBE 加密处就被拒绝——组帧歧义用短材料
    即可触发，解析在重建签名之前就失败）。
    """
    sig_raw = _honest_signature_bytes(env)
    short_sig = b"short-sig-material"  # 组帧测试不需要合法签名
    variants = [
        encode_bytes(sig_raw) + encode_bytes(REF_MSG),  # 无域前缀
        b"IBME:SIG:v2" + encode_bytes(sig_raw) + encode_bytes(REF_MSG),  # 域错配
        DOMAIN_SIGNATURE + encode_bytes(sig_raw),  # 缺 message 字段
        DOMAIN_SIGNATURE + encode_bytes(short_sig) + encode_bytes(short_sig)
        + encode_bytes(REF_MSG),  # 双签名字段
        DOMAIN_SIGNATURE + encode_bytes(sig_raw) + encode_bytes(REF_MSG)
        + encode_bytes(REF_MSG),  # 双 message 字段（尾部多余）
        b"",  # 空 payload
    ]
    for i, payload in enumerate(variants):
        ct = _encrypt_raw_payload(env, payload)
        result = env.proto.decrypt(
            env.pk, env.dk_bob, ALICE, ct, rng=_rng(env, b"payload-variant")
        )
        assert result is BOTTOM, f"malicious payload variant {i} accepted"


# ---------------------------------------------------------------------------
# 9. 协议对象序列化：往返 + 畸形拒绝
# ---------------------------------------------------------------------------


def test_protocol_objects_serialization_roundtrip(env, ref):
    pk, msk, ek, dk = env.pk, env.msk, env.ek_alice, env.dk_bob
    assert PublicKey.from_bytes(pk.to_bytes(), type(pk.hpk), type(pk.ipk)) == pk
    assert MasterSecret.from_bytes(msk.to_bytes(), type(msk.hmsk), type(msk.imsk)) == msk
    assert SenderKey.from_bytes(ek.to_bytes(), type(ek.signing_key)) == ek
    assert ReceiverKey.from_bytes(dk.to_bytes(), type(dk.level1_key)) == dk
    assert env.proto.load_ciphertext(ref.to_bytes()) == ref
    # 身份字段保持绑定
    assert SenderKey.from_bytes(ek.to_bytes(), type(ek.signing_key)).identity == ALICE
    assert ReceiverKey.from_bytes(dk.to_bytes(), type(dk.level1_key)).identity == BOB


MALFORMED_BLOBS = [b"", b"garbage", b"\x00" * 8, b"IBME:PROTO-PK:v1"]


def test_protocol_objects_malformed_rejected(env):
    pk, msk, ek, dk = env.pk, env.msk, env.ek_alice, env.dk_bob
    for bad in MALFORMED_BLOBS:
        with pytest.raises(SerializationError):
            PublicKey.from_bytes(bad, type(pk.hpk), type(pk.ipk))
        with pytest.raises(SerializationError):
            MasterSecret.from_bytes(bad, type(msk.hmsk), type(msk.imsk))
        with pytest.raises(SerializationError):
            SenderKey.from_bytes(bad, type(ek.signing_key))
        with pytest.raises(SerializationError):
            ReceiverKey.from_bytes(bad, type(dk.level1_key))
        with pytest.raises(SerializationError):
            env.proto.load_ciphertext(bad)


def test_protocol_objects_truncated_appended_rejected(env):
    pk, msk, ek, dk = env.pk, env.msk, env.ek_alice, env.dk_bob
    for obj, loader in (
        (pk, lambda raw: PublicKey.from_bytes(raw, type(pk.hpk), type(pk.ipk))),
        (msk, lambda raw: MasterSecret.from_bytes(raw, type(msk.hmsk), type(msk.imsk))),
        (ek, lambda raw: SenderKey.from_bytes(raw, type(ek.signing_key))),
        (dk, lambda raw: ReceiverKey.from_bytes(raw, type(dk.level1_key))),
    ):
        raw = obj.to_bytes()
        with pytest.raises(SerializationError):
            loader(raw[:-1])
        with pytest.raises(SerializationError):
            loader(raw + b"\x00")


def test_ciphertext_truncated_appended_rejected(env, ref):
    raw = ref.to_bytes()
    with pytest.raises(SerializationError):
        env.proto.load_ciphertext(raw[:-1])
    with pytest.raises(SerializationError):
        env.proto.load_ciphertext(raw + b"\x00")


def test_sender_key_identity_mismatch_in_serialization_rejected(env):
    """SenderKey 序列化中的身份字段与签名密钥绑定身份不一致 → 拒绝。"""
    from ibme.protocol import MAGIC_SENDER_KEY

    ek = env.ek_alice
    raw = ek.to_bytes()
    body = raw[len(MAGIC_SENDER_KEY):]
    # 身份字段是 magic 后第一个长度前缀字段；ALICE 与 CAROL 等长，
    # 替换后结构仍可解析，但身份交叉校验必须拒绝。
    forged = MAGIC_SENDER_KEY + encode_bytes(CAROL) + body[len(encode_bytes(ALICE)):]
    with pytest.raises(SerializationError):
        SenderKey.from_bytes(forged, type(ek.signing_key))


# ---------------------------------------------------------------------------
# 10. 固定 rng 全流程字节级可复现
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("combo", sorted(_COMBOS))
def test_fixed_rng_full_pipeline_reproducible(combo):
    message = b"reproducible-baseline!"

    def run() -> tuple[bytes, bytes]:
        cfg = _COMBOS[combo]
        proto = BaselineIBME(
            cfg["hibe_factory"](),
            cfg["ibs_factory"](rng=DeterministicRandom(SEED + b":repro-ibs")),
        )
        pk, msk = proto.setup(
            cfg["hibe_params"],
            ibs_params=cfg["ibs_params"],
            rng=DeterministicRandom(SEED + b":repro-setup"),
        )
        ek = proto.skgen(msk, ALICE)
        dk = proto.rkgen(msk, BOB, rng=DeterministicRandom(SEED + b":repro-rk"))
        ct = proto.encrypt(pk, ek, BOB, message, rng=DeterministicRandom(SEED + b":repro-enc"))
        out = proto.decrypt(pk, dk, ALICE, ct, rng=DeterministicRandom(SEED + b":repro-dec"))
        assert out == message
        return ct.to_bytes(), ek.to_bytes()

    assert run() == run()


# ---------------------------------------------------------------------------
# 11. 身份绑定 / 匿名性抽查 / 输入校验 / BOTTOM 哨兵
# ---------------------------------------------------------------------------


def test_sender_key_identity_binding(env):
    """ek 绑定 Alice；同一签名以 Carol 身份验证必失败。"""
    assert env.ek_alice.identity == ALICE
    signed = encode_message(BOB, REF_MSG)
    signature = env.proto.ibs_backend.sign(env.ek_alice.signing_key, signed)
    assert env.proto.ibs_backend.verify(env.pk.ipk, ALICE, signed, signature)
    assert not env.proto.ibs_backend.verify(env.pk.ipk, CAROL, signed, signature)


def test_receiver_key_identity_binding(env):
    assert env.dk_bob.identity == BOB
    assert env.dk_carol.identity == CAROL


def test_ciphertext_contains_no_identity_plaintext(env):
    """身份只能以 HIBE 加密形态存在：密文字节不含身份明文或其编码。"""
    ct = env.proto.encrypt(
        env.pk, env.ek_alice, BOB, REF_MSG, rng=_rng(env, b"anon-enc")
    )
    raw = ct.to_bytes()
    for identity in (ALICE, BOB, CAROL):
        assert identity not in raw, "identity bytes leaked into ciphertext"
        assert encode_bytes(identity) not in raw


def test_empty_and_invalid_identities_rejected(env):
    with pytest.raises(EncodingError):
        env.proto.skgen(env.msk, b"")
    with pytest.raises(EncodingError):
        env.proto.rkgen(env.msk, b"", rng=_rng(env, b"v1"))
    with pytest.raises(EncodingError):
        env.proto.encrypt(env.pk, env.ek_alice, b"", REF_MSG, rng=_rng(env, b"v2"))
    with pytest.raises(EncodingError):
        env.proto.decrypt(env.pk, env.dk_bob, b"", None, rng=_rng(env, b"v3"))
    with pytest.raises(EncodingError):
        env.proto.encrypt(env.pk, env.ek_alice, "bob", REF_MSG)  # str 身份


def test_message_over_capacity_rejected(env):
    """消息使 payload 超出 HIBE max_message_bytes → 调用方错误（异常）。"""
    # payload = 11B 域前缀 + 4B + 签名 + 4B + 消息；签名尺寸按后端不同，
    # 取足够大的消息必然超界（400B 容量）。
    with pytest.raises(InvalidParameterError):
        env.proto.encrypt(
            env.pk, env.ek_alice, BOB, b"x" * 400, rng=_rng(env, b"v4")
        )


def test_wrong_object_types_rejected(env):
    with pytest.raises(TypeError):
        env.proto.skgen("not-an-msk", ALICE)
    with pytest.raises(TypeError):
        env.proto.rkgen(env.msk.imsk, BOB)  # 非 MasterSecret
    with pytest.raises(TypeError):
        env.proto.encrypt("not-a-pk", env.ek_alice, BOB, b"m")
    with pytest.raises(TypeError):
        env.proto.encrypt(env.pk, "not-an-ek", BOB, b"m")
    with pytest.raises(TypeError):
        env.proto.decrypt(env.pk, "not-a-dk", ALICE, None)
    with pytest.raises(InvalidParameterError):
        BaselineIBME(object(), object())  # 缺冻结方法的后端
    with pytest.raises(InvalidParameterError):
        BaselineIBME(env.proto.hibe_backend, object())  # IBS 侧缺方法


def test_bottom_sentinel_properties():
    assert BOTTOM is BOTTOM
    assert not BOTTOM
    assert repr(BOTTOM) == "BOTTOM"
    assert is_bottom(BOTTOM)
    assert not is_bottom(b"")
    with pytest.raises(TypeError):
        pickle.dumps(BOTTOM)


def test_parse_payload_unit_cases():
    sig_raw, message = parse_payload(
        DOMAIN_SIGNATURE + encode_bytes(b"sig-bytes") + encode_bytes(b"msg")
    )
    assert sig_raw == b"sig-bytes"
    assert message == b"msg"
    bad_inputs = [
        b"",
        b"IBME:SIG:v2" + encode_bytes(b"s") + encode_bytes(b"m"),
        DOMAIN_SIGNATURE,
        DOMAIN_SIGNATURE + encode_bytes(b"s"),
        DOMAIN_SIGNATURE + encode_bytes(b"s") + encode_bytes(b"m") + b"\x00",
        DOMAIN_SIGNATURE + b"\xff\xff\xff\xff" + b"short",
    ]
    for bad in bad_inputs:
        with pytest.raises(SerializationError):
            parse_payload(bad)


# ---------------------------------------------------------------------------
# CLI 端到端（SPEC §7 场景）
# ---------------------------------------------------------------------------


def _run_cli(argv):
    from ibme.cli import main

    return main(argv)


class TestCLIRealBackends:
    """真实后端（abb10+sis）小消息端到端：成功、不匹配、篡改都过一遍。"""

    def test_full_flow(self, tmp_path):
        state = tmp_path / "state"
        msg_file = tmp_path / "message.bin"
        msg_file.write_bytes(b"cli-e2e-small-message")
        assert _run_cli(["setup", "--params", "education", "--state", str(state)]) == 0
        assert _run_cli(["issue-sender-key", "Alice", "--state", str(state)]) == 0
        assert _run_cli(["issue-receiver-key", "Bob", "--state", str(state)]) == 0
        assert _run_cli(["issue-receiver-key", "Carol", "--state", str(state)]) == 0
        ct_file = tmp_path / "ct.bin"
        assert (
            _run_cli(
                [
                    "encrypt",
                    "--sender", "Alice",
                    "--receiver", "Bob",
                    "--state", str(state),
                    "--in", str(msg_file),
                    "--out", str(ct_file),
                ]
            )
            == 0
        )
        out_file = tmp_path / "recovered.bin"
        assert (
            _run_cli(
                [
                    "decrypt",
                    "--receiver", "Bob",
                    "--sender", "Alice",
                    "--state", str(state),
                    "--in", str(ct_file),
                    "--out", str(out_file),
                ]
            )
            == 0
        )
        assert out_file.read_bytes() == b"cli-e2e-small-message"

    def test_mismatch_sender_bottom_nonzero_exit(self, tmp_path, capsys):
        state = tmp_path / "state"
        msg_file = tmp_path / "message.bin"
        msg_file.write_bytes(b"mismatch-check")
        _run_cli(["setup", "--params", "education", "--state", str(state)])
        _run_cli(["issue-sender-key", "Alice", "--state", str(state)])
        _run_cli(["issue-receiver-key", "Bob", "--state", str(state)])
        ct_file = tmp_path / "ct.bin"
        _run_cli(
            ["encrypt", "--sender", "Alice", "--receiver", "Bob",
             "--state", str(state), "--in", str(msg_file), "--out", str(ct_file)]
        )
        rc = _run_cli(
            ["decrypt", "--receiver", "Bob", "--sender", "Carol",
             "--state", str(state), "--in", str(ct_file)]
        )
        assert rc != 0
        assert "BOTTOM" in capsys.readouterr().out

    def test_mismatch_receiver_bottom(self, tmp_path):
        state = tmp_path / "state"
        msg_file = tmp_path / "message.bin"
        msg_file.write_bytes(b"rcv-mismatch")
        _run_cli(["setup", "--params", "education", "--state", str(state)])
        _run_cli(["issue-sender-key", "Alice", "--state", str(state)])
        _run_cli(["issue-receiver-key", "Bob", "--state", str(state)])
        _run_cli(["issue-receiver-key", "Carol", "--state", str(state)])
        ct_file = tmp_path / "ct.bin"
        _run_cli(
            ["encrypt", "--sender", "Alice", "--receiver", "Bob",
             "--state", str(state), "--in", str(msg_file), "--out", str(ct_file)]
        )
        assert (
            _run_cli(
                ["decrypt", "--receiver", "Carol", "--sender", "Alice",
                 "--state", str(state), "--in", str(ct_file)]
            )
            != 0
        )

    def test_tampered_ciphertext_bottom(self, tmp_path):
        state = tmp_path / "state"
        msg_file = tmp_path / "message.bin"
        msg_file.write_bytes(b"tamper-check")
        _run_cli(["setup", "--params", "education", "--state", str(state)])
        _run_cli(["issue-sender-key", "Alice", "--state", str(state)])
        _run_cli(["issue-receiver-key", "Bob", "--state", str(state)])
        ct_file = tmp_path / "ct.bin"
        _run_cli(
            ["encrypt", "--sender", "Alice", "--receiver", "Bob",
             "--state", str(state), "--in", str(msg_file), "--out", str(ct_file)]
        )
        raw = bytearray(ct_file.read_bytes())
        raw[0] ^= 0xFF  # 协议 magic → 解析被拒
        tampered = tmp_path / "tampered.bin"
        tampered.write_bytes(bytes(raw))
        assert (
            _run_cli(
                ["decrypt", "--receiver", "Bob", "--sender", "Alice",
                 "--state", str(state), "--in", str(tampered)]
            )
            != 0
        )


class TestCLIMockBackends:
    """--mock 开关（TEST-ONLY 后端）全流程 + BOTTOM 用例。"""

    def test_full_flow_and_bottom(self, tmp_path, capsys):
        state = tmp_path / "state"
        msg_file = tmp_path / "message.bin"
        msg_file.write_bytes(b"mock-cli-message")
        assert (
            _run_cli(["setup", "--params", "education", "--state", str(state), "--mock"]) == 0
        )
        assert _run_cli(["issue-sender-key", "Alice", "--state", str(state), "--mock"]) == 0
        assert _run_cli(["issue-receiver-key", "Bob", "--state", str(state), "--mock"]) == 0
        ct_file = tmp_path / "ct.bin"
        assert (
            _run_cli(
                ["encrypt", "--sender", "Alice", "--receiver", "Bob",
                 "--state", str(state), "--in", str(msg_file), "--out", str(ct_file), "--mock"]
            )
            == 0
        )
        out_file = tmp_path / "recovered.bin"
        assert (
            _run_cli(
                ["decrypt", "--receiver", "Bob", "--sender", "Alice",
                 "--state", str(state), "--in", str(ct_file), "--out", str(out_file), "--mock"]
            )
            == 0
        )
        assert out_file.read_bytes() == b"mock-cli-message"
        rc = _run_cli(
            ["decrypt", "--receiver", "Bob", "--sender", "Carol",
             "--state", str(state), "--in", str(ct_file), "--mock"]
        )
        assert rc != 0
        assert "BOTTOM" in capsys.readouterr().out


def test_cli_usage_errors(tmp_path, capsys):
    # 未知参数预设
    assert _run_cli(["setup", "--params", "nosuch", "--state", str(tmp_path)]) == 2
    # 非法身份名（路径分隔符）
    state = tmp_path / "s2"
    assert _run_cli(["setup", "--params", "education", "--state", str(state)]) == 0
    assert _run_cli(["issue-sender-key", "../evil", "--state", str(state)]) == 2
    # 状态目录缺失时签发密钥
    assert (
        _run_cli(["issue-sender-key", "Alice", "--state", str(tmp_path / "missing")]) == 2
    )
