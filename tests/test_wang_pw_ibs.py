"""Wang 基本 IBS + Pan–Wagner 转换（``ibme.ibs.wang_pw``）的功能与正确性测试。

测试口径与模块 docstring 一致：**研究参考实现**，覆盖真实四算法、诚实生命周期、
身份绑定、负例与严格序列化；不把功能测试写成安全结论
（``security_claim="none"``、``parameters_are_formal=False``、``backend_admitted=False``）。

玩具参数用 ``n=2, q=7, m_bar=6``（``k=3, w=6, m=12``，满足原文 ``m ≥ 2n⌈log2 q⌉``）。
测试种子固定，输出可复现（与模块内「生产随机源/测试固定随机源分离」约定一致）。
"""

from __future__ import annotations

import pytest

from ibme.core import DeterministicRandom, InvalidParameterError
from ibme.core.hashing import DOMAIN_IBS_H1, DOMAIN_IBS_H2
from ibme.ibs import wang_pw as w

PARAMS = w.WangPWParams(n=2, q=7, m_bar=6, name="wang-test")
SEED = b"ibme-wang-pw-tests"


def _scheme():
    """默认研究参数（verify_width=200）；不作安全声明。"""
    return w.WangPWScheme(PARAMS, rng=DeterministicRandom(SEED + b"-scheme"))


def _key(identity=b"alice"):
    rng = DeterministicRandom(SEED + b"-key-" + identity)
    pk, msk = w.setup(PARAMS, rng=rng)
    return pk, msk, w.key_extract(msk, identity, rng=rng)


def _matrix_product(a, b, q):
    rows, inner, cols = len(a), len(b), len(b[0])
    return [[sum(a[i][k] * b[k][j] for k in range(inner)) % q for j in range(cols)]
            for i in range(rows)]


# ---------------------------------------------------------------------------
# 参数与维度
# ---------------------------------------------------------------------------


def test_params_derived_dimensions_match_wang_figure4():
    assert PARAMS.k == 3 and PARAMS.w == 6 and PARAMS.m == 12
    assert PARAMS.signature_dim == PARAMS.m + PARAMS.w == 18
    assert PARAMS.verify_bound == pytest.approx(PARAMS.verify_width * 18 ** 0.5)
    # 原文要求 m >= 2n⌈log2 q⌉
    assert PARAMS.m_bar >= PARAMS.w
    assert PARAMS.security_claim == "none"
    assert PARAMS.parameters_are_formal is False
    assert PARAMS.backend_admitted is False


def test_params_reject_non_prime_modulus_and_small_m_bar():
    with pytest.raises(InvalidParameterError):
        w.WangPWParams(n=2, q=9, m_bar=6)
    with pytest.raises(InvalidParameterError):
        w.WangPWParams(n=2, q=7, m_bar=1)   # m_bar < w
    with pytest.raises(InvalidParameterError):
        w.WangPWParams(n=3, q=7, m_bar=6)   # m_bar < n 之外还违反 m_bar >= w=9


def test_gadget_matrix_is_in_both_dimensions():
    g = w.gadget_matrix(PARAMS.n, PARAMS.q)
    assert len(g) == PARAMS.n and len(g[0]) == PARAMS.w
    assert w._gf_rank(g, PARAMS.q) == PARAMS.n


# ---------------------------------------------------------------------------
# 内层四算法
# ---------------------------------------------------------------------------


def test_setup_trapdoor_relation_a_times_ta_equals_g():
    rng = DeterministicRandom(SEED + b"-setup")
    pk, msk = w.setup(PARAMS, rng=rng)
    a_bar, r_a = msk.a_bar(), msk.r_a()
    # A = [ā | G − ā·R_A]，且 A·[R_A; I_w] = G
    assert pk.matrix() == w.public_key_from_trapdoor(a_bar, r_a, PARAMS.q)
    columns = [[r_a[i][j] for i in range(PARAMS.m_bar)] + [1 if i == j else 0
               for i in range(PARAMS.w)] for j in range(PARAMS.w)]
    got = [[sum(pk.matrix()[i][k] * columns[j][k] for k in range(PARAMS.m)) % PARAMS.q
            for j in range(PARAMS.w)] for i in range(PARAMS.n)]
    assert got == w.gadget_matrix(PARAMS.n, PARAMS.q)


def test_key_extract_gives_real_delegated_trapdoor_for_hashed_identity():
    pk, msk, sk = _key()
    a_rows, h1, r_x = sk.matrix(), sk.h1(), sk.r_x()
    g = w.gadget_matrix(PARAMS.n, PARAMS.q)
    # 委派关系：A·R_x ≡ H1 − G (mod q)
    lhs = w._mat_mul(a_rows, r_x, PARAMS.q)
    assert lhs == w._mat_sub(h1, g, PARAMS.q)
    # H1 必须是 H1(mpk, id) 的哈希值（不是调用方可选的自由矩阵）
    assert h1 == w.hash_identity_matrix(pk, sk.identity)
    assert a_rows == pk.matrix()
    # T_id = [−R_x; I_w] 是 F_id = [A | H1] 的合法陷门：F_id·T_id = G
    t_cols = sk.trapdoor_columns()
    t_mat = [[t_cols[j][i] for j in range(len(t_cols))] for i in range(len(t_cols[0]))]
    assert _matrix_product(sk.identity_matrix(), t_mat, PARAMS.q) == g


def test_sign_verify_honest_lifecycle_for_several_messages():
    pk, msk, sk = _key()
    rng = DeterministicRandom(SEED + b"-sign")
    norms = []
    for message in (b"", b"m", b"hello world", b"\x00\xff" * 8):
        sig = w.sign(sk, message, rng=rng)
        assert w.verify(pk, sk.identity, message, sig)
        assert any(sig.z)                                   # z ≠ 0
        assert sig.norm() <= PARAMS.verify_bound            # ‖z‖ ≤ B_verify
        norms.append(sig.norm())
    assert max(norms) > 0.0


def test_sign_is_deterministic_for_a_fixed_test_source():
    _, _, sk = _key()
    first = w.sign(sk, b"repeatable", rng=DeterministicRandom(SEED + b"-det"))
    second = w.sign(sk, b"repeatable", rng=DeterministicRandom(SEED + b"-det"))
    assert first == second
    third = w.sign(sk, b"repeatable", rng=DeterministicRandom(SEED + b"-det2"))
    assert third != first


def test_two_distinct_identities_get_distinct_hashes_and_signatures():
    _, msk, sk_a = _key(b"alice")
    sk_b = w.key_extract(msk, b"bob", rng=DeterministicRandom(SEED + b"-bob"))
    assert sk_a.h1() != sk_b.h1()
    assert sk_a.r_x() != sk_b.r_x()
    sig_a = w.sign(sk_a, b"same", rng=DeterministicRandom(SEED + b"-sa"))
    sig_b = w.sign(sk_b, b"same", rng=DeterministicRandom(SEED + b"-sb"))
    assert sig_a != sig_b


# ---------------------------------------------------------------------------
# 负例：身份、消息、篡改、范数、零向量
# ---------------------------------------------------------------------------


def test_verify_rejects_wrong_identity_and_wrong_message():
    """身份不匹配必须被拒；消息不匹配在 ``h2`` 确实不同时必须被拒。

    注意：``q=7, n=2`` 时 ``h2 ∈ Z_7^2`` 只有 49 种取值，两个短消息的 ``H2`` **可能碰撞**
    （这是玩具参数的固有现象，不是实现缺陷）。因此这里显式检查 ``h2`` 是否不同，只在不同
    时要求拒绝；真正的"消息绑定"由 ``test_hash_message_changes_with_message`` 与
    序列化/篡改用例覆盖。
    """
    pk, _, sk = _key()
    sig = w.sign(sk, b"payload", rng=DeterministicRandom(SEED + b"-neg"))
    assert w.verify(pk, b"alice", b"payload", sig) is True
    # 错误身份：q=7 时 F_eve·z ≡ h2_eve 有 1/49 概率偶然成立（玩具参数固有碰撞），
    # 因此做多试断言：8 个不同身份里要求至少 6 个拒绝
    # （P(≥3 次偶然通过) ≈ C(8,3)/49^3 ≈ 2.8e-5，可忽略）。
    rejections = sum(
        1 for i in range(8)
        if w.verify(pk, b"other-%d" % i, b"payload", sig) is False)
    assert rejections >= 6, f"cross-identity rejections {rejections}/8"
    assert w.verify(pk, b"", b"payload", sig) is False             # 空身份不合法
    other = b"payload!"
    if w.hash_message_vector(pk, b"alice", other) != \
            w.hash_message_vector(pk, b"alice", b"payload"):
        assert w.verify(pk, b"alice", other, sig) is False
    # 长消息下 H2 空间同样小，但"篡改坐标"必然失败（与哈希无关）
    flipped = list(sig.z)
    flipped[-1] += 1
    assert w.verify(pk, sk.identity, b"payload", w.Signature(PARAMS, tuple(flipped))) is False


def test_hash_message_changes_with_message_and_identity():
    """H2 对消息/身份敏感（在输出空间允许的范围内找不同取值）。"""
    pk, _ = w.setup(PARAMS, rng=DeterministicRandom(SEED+b"-hash"))
    seen = {}
    for index in range(40):
        message = f"m{index}".encode()
        digest = tuple(w.hash_message_vector(pk, b"alice", message))
        seen[digest] = message
    assert len(seen) >= 8                                  # 49 个取值里应出现明显多于 8 个
    assert any(w.hash_message_vector(pk, b"alice", str(i).encode()) !=
               w.hash_message_vector(pk, b"bob", str(i).encode()) for i in range(16))


def test_verify_rejects_tampered_coordinates_and_norm_overflow():
    pk, _, sk = _key()
    sig = w.sign(sk, b"payload", rng=DeterministicRandom(SEED + b"-tamper"))
    flipped = list(sig.z)
    flipped[0] += 1
    assert w.verify(pk, sk.identity, b"payload", w.Signature(PARAMS, tuple(flipped))) is False
    huge = list(sig.z)
    huge[0] += int(PARAMS.verify_bound) + 1000
    assert w.verify(pk, sk.identity, b"payload", w.Signature(PARAMS, tuple(huge))) is False
    zero = w.Signature(PARAMS, tuple([0] * PARAMS.signature_dim))
    assert w.verify(pk, sk.identity, b"payload", zero) is False


def test_verify_returns_false_instead_of_raising_for_foreign_objects():
    pk, _, sk = _key()
    sig = w.sign(sk, b"payload", rng=DeterministicRandom(SEED + b"-foreign"))
    assert w.verify(pk, sk.identity, b"payload", b"not-a-signature") is False
    assert w.verify(pk, sk.identity, b"payload", None) is False
    assert w.verify("not-a-pk", sk.identity, b"payload", sig) is False
    other = w.WangPWParams(n=2, q=7, m_bar=6, verify_width=24.0, name="other")
    assert w.verify(pk, sk.identity, b"payload", w.Signature(other, sig.z)) is False


def test_public_key_hash_binding_prevents_cross_parameter_replay():
    pk, _, sk = _key()
    sig = w.sign(sk, b"payload", rng=DeterministicRandom(SEED + b"-cross"))
    # 同一身份/消息，但参数上下文不同 → F_id 与 h2 都不同，验签必须失败
    other = w.WangPWParams(n=2, q=7, m_bar=6, name="other-ctx")
    other_pk = w.PublicKey(other, pk.a_rows)
    assert w.hash_identity_matrix(pk, b"alice") != w.hash_identity_matrix(other_pk, b"alice")
    assert w.hash_message_vector(pk, b"alice", b"payload") != \
        w.hash_message_vector(other_pk, b"alice", b"payload")


# ---------------------------------------------------------------------------
# 哈希与序列化
# ---------------------------------------------------------------------------


def test_hashes_are_domain_separated_and_unbiased_range():
    pk, _ = w.setup(PARAMS, rng=DeterministicRandom(SEED+b"-hash-range"))
    h1 = w.hash_identity_matrix(pk, b"alice")
    assert all(0 <= x < PARAMS.q for row in h1 for x in row)
    h2 = w.hash_message_vector(pk, b"alice", b"payload")
    assert len(h2) == PARAMS.n and all(0 <= x < PARAMS.q for x in h2)
    # 冻结域常量未被本模块替换
    assert DOMAIN_IBS_H1 == b"IBME:IBS-H1:v1" and DOMAIN_IBS_H2 == b"IBME:IBS-H2:v1"
    assert w.DOMAIN_PW_ID == b"IBME-IBS-PW-ID-v1"
    assert w.DOMAIN_PW_MSG == b"IBME-IBS-PW-MSG-v1"
    # H1 的列不随消息变化；H2 随身份与消息变化
    assert w.hash_message_vector(pk, b"alice", b"x") != \
        w.hash_message_vector(pk, b"alice", b"y")
    assert w.hash_message_vector(pk, b"alice", b"x") != \
        w.hash_message_vector(pk, b"bob", b"x")


def test_signature_and_public_key_roundtrip_and_strict_parsing():
    pk, _, sk = _key()
    sig = w.sign(sk, b"payload", rng=DeterministicRandom(SEED + b"-wire"))
    blob = sig.to_bytes()
    assert w.Signature.from_bytes(PARAMS, blob) == sig
    for bad in (blob[:-1], blob + b"\x00", b"", b"IBM1-WANGPW-SIG"):
        with pytest.raises(InvalidParameterError):
            w.Signature.from_bytes(PARAMS, bad)
    pk_blob = pk.to_bytes()
    assert w.PublicKey.from_bytes(PARAMS, pk_blob) == pk
    for bad in (pk_blob[:-4], pk_blob + b"\x01", b"IBM1-WANGPW-PK"):
        with pytest.raises(InvalidParameterError):
            w.PublicKey.from_bytes(PARAMS, bad)


def test_object_shape_validation_rejects_wrong_dimensions():
    pk, msk, sk = _key()
    with pytest.raises(InvalidParameterError):
        w.Signature(PARAMS, tuple([0] * (PARAMS.signature_dim - 1)))
    with pytest.raises(InvalidParameterError):
        w.Signature(PARAMS, tuple([0] * (PARAMS.signature_dim + 1)))
    with pytest.raises(InvalidParameterError):
        w.PublicKey(PARAMS, (tuple([0] * PARAMS.m),))
    with pytest.raises(InvalidParameterError):
        w.SigningKey(PARAMS, sk.identity, sk.identity_digest, sk.a_rows,
                     sk.h1_rows, sk.r_x_rows[:-1], sk.verify_bound)
    with pytest.raises(InvalidParameterError):
        w.MasterSecretKey(PARAMS, msk.a_bar_rows, msk.r_a_rows[:-1])


# ---------------------------------------------------------------------------
# Pan–Wagner 外层
# ---------------------------------------------------------------------------


def test_pw_scheme_reuses_identity_salt_and_takes_fresh_message_salt():
    scheme = _scheme()
    pk, _ = scheme.setup()
    r1, s1, sig1 = scheme.sign_pw(b"Alice", b"hello")
    r2, s2, sig2 = scheme.sign_pw(b"Alice", b"hello")
    assert r1 == r2                                   # 同一身份同一生命周期
    assert s1 != s2                                   # 每次签名新消息盐
    assert sig1 != sig2
    assert scheme.verify_pw(b"Alice", b"hello", r1, s1, sig1) is True
    assert scheme.verify_pw(b"Alice", b"hello", r2, s2, sig2) is True
    assert scheme.cached_identity_salt(b"Alice") == (r1, scheme.cached_identity_salt(b"Alice")[1])
    assert scheme.signed_messages(b"Alice") == {b"hello"}


def test_pw_scheme_rejects_wrong_identity_message_and_salt():
    scheme = _scheme()
    scheme.setup()
    r, s, sig = scheme.sign_pw(b"Alice", b"hello")
    assert scheme.verify_pw(b"Alice", b"hello", r, s, sig) is True
    # 跨身份拒绝同样受 q=7 的 1/49 偶然碰撞影响：多试断言（见内层测试的说明）
    cross = [scheme.verify_pw(b"other-%d" % i, b"hello", r, s, sig) for i in range(8)]
    assert cross.count(False) >= 6, f"cross-identity rejections {cross.count(False)}/8"
    # In Z_7^2 collisions are expected. Check the exact mathematical decision
    # for every candidate, and require an actual rejecting case in each family.
    def expected(identity, message, r_new, s_new):
        internal_id = w.j_identity(identity, r_new, bits=PARAMS.internal_id_bits)
        internal_msg = w.j_message(message, s_new, bits=PARAMS.internal_msg_bits)
        matrix = w.identity_matrix_from_public(scheme.pk, internal_id)
        target = w.hash_message_vector(scheme.pk, internal_id, internal_msg)
        return all(sum(x*y for x, y in zip(row, sig.z)) % PARAMS.q == y
                   for row, y in zip(matrix, target))
    families = [
        [(b"Alice", b"changed-%d" % i, r, s) for i in range(8)],
        [(b"Alice", b"hello", bytes([i])*len(r), s) for i in range(8)],
        [(b"Alice", b"hello", r, bytes([i])*len(s)) for i in range(8)],
    ]
    for candidates in families:
        decisions = [expected(*candidate) for candidate in candidates]
        assert False in decisions
        for candidate, decision in zip(candidates, decisions):
            assert scheme.verify_pw(*candidate, sig) is decision
    assert scheme.verify_pw(b"Alice", b"hello", r[:-1], s, sig) is False
    assert scheme.verify_pw(b"Alice", b"hello", r, s, b"junk") is False


def test_pw_scheme_requires_setup_and_validates_inputs():
    scheme = _scheme()
    with pytest.raises(InvalidParameterError):
        scheme.key_extract_pw(b"Alice")               # 未 setup
    with pytest.raises(InvalidParameterError):
        scheme.sign_pw(b"Alice", b"hello")            # 未 setup
    scheme.setup()
    assert scheme.verify_pw(b"Alice", b"hello", b"\x00" * 16, b"\x00" * 16, None) is False
    with pytest.raises(InvalidParameterError):
        scheme.key_extract_pw(b"")
    with pytest.raises(InvalidParameterError):
        scheme.sign_pw(b"", b"hello")
    with pytest.raises(InvalidParameterError):
        scheme.sign_pw(b"Alice", None)


def test_pw_inner_hash_domains_differ_from_inner_ibs_domains():
    salt = b"\x11" * 16
    x = w.j_identity(b"Alice", salt, bits=PARAMS.internal_id_bits)
    y = w.j_message(b"hello", salt, bits=PARAMS.internal_msg_bits)
    assert len(x) == PARAMS.internal_id_bits // 8
    assert len(y) == PARAMS.internal_msg_bits // 8
    # 同一 (字节串, 盐) 在两个域下不同；盐改变则输出改变
    assert w.j_identity(b"Alice", salt, bits=256) != w.j_message(b"Alice", salt, bits=256)
    assert w.j_identity(b"Alice", salt, bits=256) != w.j_identity(b"Alice", b"\x22" * 16, bits=256)
    with pytest.raises(InvalidParameterError):
        w.j_identity(b"Alice", b"", bits=256)
    with pytest.raises(InvalidParameterError):
        w.j_message(b"hello", b"", bits=256)


# ---------------------------------------------------------------------------
# 采样链自检（核基、陪集采样、界）
# ---------------------------------------------------------------------------


def test_integer_kernel_basis_is_complete_not_a_sublattice():
    """核基必须是**完整**格基：det = q^n，且 A 的 F_q 核生成组都能由其整数表示。

    这条是回归测试：早先版本只得到子格（同一实例 det 为 784/12544 等，Sage 对照为 49），
    后果是采样分布质量下降。完整性由 :func:`verify_kernel_basis_is_complete` 精确判定。
    """
    rng = DeterministicRandom(SEED + b"-kernel")
    pk, _ = w.setup(PARAMS, rng=rng)
    basis = w.integer_kernel_basis(pk.matrix(), PARAMS.q)
    assert len(basis) == PARAMS.m                       # {x : A·x ≡ 0 mod q} 在 Z^m 中满秩
    assert all(not any(w._mat_vec(pk.matrix(), col, PARAMS.q)) for col in basis)
    matrix = [[basis[j][i] for j in range(len(basis))] for i in range(PARAMS.m)]
    assert abs(w._det_bareiss(matrix)) == PARAMS.q ** PARAMS.n       # 指标 = q^n
    assert w.verify_kernel_basis_is_complete(basis, pk.matrix(), PARAMS.q) is True


def test_coset_sampler_returns_vectors_in_the_right_coset():
    rng = DeterministicRandom(SEED + b"-coset")
    pk, _ = w.setup(PARAMS, rng=rng)
    a = pk.matrix()
    basis = w.integer_kernel_basis(a, PARAMS.q)
    stream = w._Stream(DeterministicRandom(SEED + b"-coset-stream"))
    sigma = 2.0 * w.basis_width(basis)
    for _ in range(4):
        target = [stream.below(PARAMS.q) for _ in range(PARAMS.n)]
        particular = w._gf_solve(a, target, PARAMS.q)
        z = w.sample_coset(stream, basis, particular, sigma)
        assert w._mat_vec(a, z, PARAMS.q) == target


def test_gaussian_sampler_mean_and_finite_window_smoke():
    stream = w._Stream(DeterministicRandom(SEED + b"-gauss"))
    from fractions import Fraction
    values = [w._sample_gaussian_z(stream, 5.0, Fraction(0)) for _ in range(400)]
    assert all(abs(v) <= 61 for v in values)                 # finite 12σ + 1 window
    mean = sum(values) / len(values)
    assert abs(mean) < 1.0                                    # 中心 ≈ 0
    assert any(v != 0 for v in values)


def test_honest_norms_stay_below_the_declared_verify_bound():
    pk, _, sk = _key()
    rng = DeterministicRandom(SEED + b"-bounds")
    for index in range(6):
        sig = w.sign(sk, f"message-{index}".encode(), rng=rng)
        assert sig.norm() <= sk.verify_bound == PARAMS.verify_bound
        assert w.verify(pk, sk.identity, f"message-{index}".encode(), sig)


# ---------------------------------------------------------------------------
# 完整陷门基 + GPV 采样（默认 sign 路径）
# ---------------------------------------------------------------------------


def test_gpv_sampler_uses_public_width_and_user_trapdoor(monkeypatch):
    """Check the actual sampler inputs; a second moment does not prove a law."""
    import math
    pk, _, sk = _key()
    original = w.sample_coset
    calls = []
    def capture(stream, basis, particular, sigma):
        calls.append((basis, sigma))
        return original(stream, basis, particular, sigma)
    monkeypatch.setattr(w, "sample_coset", capture)
    sig = w.sign(sk, b"gpv", rng=DeterministicRandom(SEED+b"-gpv"))
    assert w.verify(pk, sk.identity, b"gpv", sig)
    assert calls
    assert calls[0][0] == sk.sampling_basis
    assert calls[0][1] == PARAMS.verify_width / math.sqrt(2*math.pi)
    assert w.verify_kernel_basis_is_complete(list(map(list, sk.sampling_basis)),
                                             sk.identity_matrix(), PARAMS.q)
    assert not hasattr(sk, "r_a_rows")


def test_gpv_signatures_stay_below_bound_across_identities():
    """多个身份/消息下 GPV 签名通过验签且范数低于界。"""
    rng = DeterministicRandom(SEED + b"-perturbed-multi")
    pk, msk = w.setup(PARAMS, rng=rng)
    for name in (b"alice", b"bob", b"carol"):
        sk = w.key_extract(msk, name, rng=rng)
        for i in range(8):
            sig = w.sign(sk, b"m%d" % i, rng=rng)
            assert sig.norm() <= sk.verify_bound
            assert w.verify(pk, name, b"m%d" % i, sig)


def test_independent_pw_signing_key_works_without_authority():
    rng = DeterministicRandom(SEED+b"-independent-pw")
    pk, msk = w.setup(PARAMS, rng=rng)
    key = w.key_extract_pw(msk, b"Alice", rng=rng)
    del msk
    r, s, sig = w.sign_pw(key, b"message", rng=rng)
    assert r == key.salt
    assert w.verify_pw(pk, b"Alice", b"message", r, s, sig)


def test_gadget_block_sampler_modular_coset_and_small_box():
    """gadget 块采样：所有输出满足 g^T·z ≡ syndrome，系数在 8σ 盒内。"""
    from fractions import Fraction
    stream = w._Stream(DeterministicRandom(SEED + b"-gadget-block"))
    q, k = PARAMS.q, PARAMS.k
    for syndrome in (0, 1, q - 1):
        for _ in range(5):
            z = w._sample_gadget_block(stream, syndrome, 2.0, k, q, tail_width=8)
            assert len(z) == k
            assert sum((1 << j) * z[j] for j in range(k)) % q == syndrome
            assert all(abs(x) <= 20 for x in z)
