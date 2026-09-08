"""ibme.lattice 测试：Params、ModMatrix/ModVector、gadget、离散高斯、陷门。

所有统计测试都使用固定种子的 ``SeededRandom``，结果可复现。
参数与安全声明：仅使用教学参数 ``EDUCATION_PARAMS``（security_claim:
none，见 params/education.yaml 与 src/ibme/lattice/params.py）；本文件中
的任何测试都不构成 LWE/SIS 或任何密码安全性的证明。
"""

import math
from dataclasses import FrozenInstanceError, fields, replace

import pytest

from ibme.core.errors import (
    DimensionError,
    InvalidParameterError,
    ModulusMismatchError,
    RandomnessError,
    SerializationError,
)
from ibme.lattice import (
    EDUCATION_PARAMS,
    ModMatrix,
    ModVector,
    Params,
    SeededRandom,
    Trapdoor,
    bit_decompose,
    del_trap,
    get_preset,
    g_vector,
    gadget_matrix,
    gadget_width,
    sample_integer_gaussian,
    sample_pre,
    sample_vector_gaussian,
    trapgen,
    uniform_integer,
)

Q = 257
N = 8

# ---------------------------------------------------------------------------
# Params
# ---------------------------------------------------------------------------


def test_params_fields_match_spec():
    assert [f.name for f in fields(Params)] == [
        "name",
        "security_parameter",
        "n",
        "m_matrix",
        "q",
        "s0",
        "s",
        "s_prime",
        "identity_bytes",
        "max_message_bytes",
    ]


def test_params_is_frozen():
    with pytest.raises(FrozenInstanceError):
        EDUCATION_PARAMS.n = 100


@pytest.mark.parametrize(
    "override",
    [
        {"q": 1},
        {"q": 0},
        {"q": -7},
        {"q": 2**32},
        {"q": 257.0},
        {"n": 0},
        {"n": -1},
        {"m_matrix": 0},
        {"security_parameter": 0},
        {"s0": 0},
        {"s0": -1.0},
        {"s": 0},
        {"s_prime": -3},
        {"identity_bytes": 0},
        {"max_message_bytes": -2},
        {"name": ""},
        {"name": 7},
    ],
)
def test_params_rejects_invalid_values(override):
    base = {
        "name": "t",
        "security_parameter": 4,
        "n": 2,
        "m_matrix": 4,
        "q": 97,
        "s0": 1.0,
        "s": 2.0,
        "s_prime": 3.0,
        "identity_bytes": 4,
        "max_message_bytes": 8,
    }
    base.update(override)
    with pytest.raises(InvalidParameterError):
        Params(**base)


def test_education_preset_is_self_consistent():
    p = EDUCATION_PARAMS
    assert p.n == 8 and p.q == 257
    assert p.m_matrix == p.n + p.n * gadget_width(p.q)
    # q 必须是素数（教学参数的最低要求）
    assert all(p.q % d for d in range(2, int(math.isqrt(p.q)) + 1))


def test_get_preset():
    assert get_preset("education") is EDUCATION_PARAMS
    with pytest.raises(InvalidParameterError):
        get_preset("competition")


# ---------------------------------------------------------------------------
# ModMatrix / ModVector
# ---------------------------------------------------------------------------


def random_matrix(rows, cols, q, tag):
    return ModMatrix.uniform(rows, cols, q, SeededRandom(tag))


def test_matrix_construction_normalizes_entries():
    m = ModMatrix([[-1, Q + 5], [2 * Q, -Q]], Q)
    assert m.to_lists() == [[Q - 1, 5], [0, 0]]
    assert m.rows == 2 and m.cols == 2 and m.q == Q


@pytest.mark.parametrize("bad_q", [1, 0, -5, 2**32, 2.5, True, None])
def test_matrix_rejects_bad_modulus(bad_q):
    with pytest.raises(InvalidParameterError):
        ModMatrix([[1, 2], [3, 4]], bad_q)


@pytest.mark.parametrize(
    "rows",
    [[], [[1, 2], [3]], [[1.5, 2]], [["1", 2]], [[1, True]], [[]], [None]],
)
def test_matrix_rejects_bad_rows(rows):
    with pytest.raises(InvalidParameterError):
        ModMatrix(rows, Q)


@pytest.mark.parametrize("bad_dim", [-1, 0, "2"])
def test_matrix_helpers_reject_bad_dims(bad_dim):
    with pytest.raises(InvalidParameterError):
        ModMatrix.zeros(bad_dim, 2, Q)
    with pytest.raises(InvalidParameterError):
        ModMatrix.zeros(2, bad_dim, Q)
    with pytest.raises(InvalidParameterError):
        ModMatrix.identity(bad_dim, Q)


def test_matrix_add_sub_neg_identities():
    a = random_matrix(4, 5, Q, "add-a")
    b = random_matrix(4, 5, Q, "add-b")
    assert (a + b) - b == a
    assert a + (-a) == ModMatrix.zeros(4, 5, Q)
    assert a - a == ModMatrix.zeros(4, 5, Q)


def test_matrix_mul_distributive_and_associative():
    a = random_matrix(3, 4, Q, "mul-a")
    b = random_matrix(4, 5, Q, "mul-b")
    c = random_matrix(4, 5, Q, "mul-c")
    d = random_matrix(5, 2, Q, "mul-d")
    assert a @ (b + c) == a @ b + a @ c
    assert (a @ b) @ d == a @ (b @ d)
    assert a @ ModMatrix.identity(4, Q) == a


def test_matrix_scale():
    a = random_matrix(3, 3, Q, "scale")
    assert a.scale(0) == ModMatrix.zeros(3, 3, Q)
    assert a.scale(1) == a
    assert a.scale(-1) == -a
    with pytest.raises(InvalidParameterError):
        a.scale(1.5)


def test_matrix_transpose():
    a = random_matrix(3, 5, Q, "tr-a")
    b = random_matrix(5, 2, Q, "tr-b")
    assert a.transpose().transpose() == a
    assert (a @ b).transpose() == b.transpose() @ a.transpose()


def test_matvec_matches_naive():
    a = random_matrix(3, 4, Q, "mv")
    rng = SeededRandom("mv-v")
    v = ModVector([uniform_integer(rng, Q) for _ in range(4)], Q)
    got = a.matvec(v)
    naive = [
        sum(a.to_lists()[i][j] * v.to_list()[j] for j in range(4)) % Q
        for i in range(3)
    ]
    assert got.to_list() == naive
    assert a @ v == got
    with pytest.raises(TypeError):
        a.matvec([1, 2, 3, 4])


def test_mismatched_modulus_raises():
    a = random_matrix(2, 3, Q, "mm-a")
    b = ModMatrix.uniform(2, 3, 101, SeededRandom("mm-b"))
    v101 = ModVector([1, 2, 3], 101)
    with pytest.raises(ModulusMismatchError):
        a + b
    with pytest.raises(ModulusMismatchError):
        a - b
    with pytest.raises(ModulusMismatchError):
        a @ b
    with pytest.raises(ModulusMismatchError):
        a.matvec(v101)
    with pytest.raises(ModulusMismatchError):
        a.hstack(b)


def test_mismatched_dimensions_raise():
    a = random_matrix(2, 3, Q, "dm-a")
    b = random_matrix(3, 2, Q, "dm-b")
    c = random_matrix(4, 5, Q, "dm-c")
    v_short = ModVector([1, 2], Q)
    with pytest.raises(DimensionError):
        a + b
    with pytest.raises(DimensionError):
        a - b
    with pytest.raises(DimensionError):
        a @ c
    with pytest.raises(DimensionError):
        a.matvec(v_short)
    with pytest.raises(DimensionError):
        a.hstack(c)
    with pytest.raises(TypeError):
        a @ 5


def test_hstack():
    a = random_matrix(2, 3, Q, "hs-a")
    b = random_matrix(2, 4, Q, "hs-b")
    joined = a.hstack(b)
    assert joined.rows == 2 and joined.cols == 7
    la, lb = a.to_lists(), b.to_lists()
    assert joined.to_lists() == [la[i] + lb[i] for i in range(2)]


def test_uniform_matrix_range_and_reproducibility():
    a = ModMatrix.uniform(3, 4, Q, SeededRandom("uni"))
    b = ModMatrix.uniform(3, 4, Q, SeededRandom("uni"))
    c = ModMatrix.uniform(3, 4, Q, SeededRandom("other"))
    assert a == b
    assert a != c
    for row in a.to_lists():
        for value in row:
            assert 0 <= value < Q
    with pytest.raises(InvalidParameterError):
        ModMatrix.uniform(0, 3, Q, SeededRandom("uni"))


def test_bad_rng_rejected():
    with pytest.raises(RandomnessError):
        ModMatrix.uniform(2, 2, Q, object())
    with pytest.raises(RandomnessError):
        sample_integer_gaussian(3.0, rng=object())


def test_matrix_serialization_roundtrip():
    a = random_matrix(4, 6, Q, "ser")
    restored = ModMatrix.from_bytes(a.to_bytes())
    assert restored == a
    assert restored.to_bytes() == a.to_bytes()


def test_vector_serialization_roundtrip():
    v = ModVector([0, 1, Q - 1, 128, 256], Q)
    assert ModVector.from_bytes(v.to_bytes()) == v
    assert ModVector.from_bytes(v.to_bytes()).to_bytes() == v.to_bytes()


def test_matrix_serialization_rejects_malformed():
    data = random_matrix(3, 5, Q, "mal").to_bytes()
    with pytest.raises(SerializationError):
        ModMatrix.from_bytes(data[:-1])  # 截断
    with pytest.raises(SerializationError):
        ModMatrix.from_bytes(data + b"\x00")  # 尾随垃圾
    with pytest.raises(SerializationError):
        ModMatrix.from_bytes(data[:11])  # 头部不完整
    with pytest.raises(SerializationError):
        ModMatrix.from_bytes(b"")  # 空输入
    tampered = bytearray(data)
    tampered[0:4] = (4).to_bytes(4, "big")  # 声称 4 行，与数据长度不符
    with pytest.raises(SerializationError):
        ModMatrix.from_bytes(bytes(tampered))


def test_matrix_serialization_rejects_out_of_range_entry():
    blob = (
        (1).to_bytes(4, "big")
        + (1).to_bytes(4, "big")
        + Q.to_bytes(4, "big")
        + (Q).to_bytes(2, "big")  # 元素等于 q，越界
    )
    with pytest.raises(SerializationError):
        ModMatrix.from_bytes(blob)


def test_matrix_serialization_rejects_bad_header_values():
    for rows, cols in [(0, 3), (3, 0)]:
        blob = (
            rows.to_bytes(4, "big") + cols.to_bytes(4, "big") + Q.to_bytes(4, "big")
        )
        with pytest.raises(SerializationError):
            ModMatrix.from_bytes(blob)
    for q in [0, 1, 2**32 - 1]:
        blob = (1).to_bytes(4, "big") + (1).to_bytes(4, "big") + q.to_bytes(4, "big") + b"\x00"
        with pytest.raises(SerializationError):
            ModMatrix.from_bytes(blob)


def test_vector_serialization_rejects_malformed():
    v = ModVector([1, 2, 3], Q)
    data = v.to_bytes()
    with pytest.raises(SerializationError):
        ModVector.from_bytes(data[:-1])
    with pytest.raises(SerializationError):
        ModVector.from_bytes(data + b"\x01")
    with pytest.raises(SerializationError):
        ModVector.from_bytes(data[:4])


def test_vector_ops_and_norms():
    v = ModVector([1, 2, Q - 1], Q)
    w = ModVector([3, 4, 5], Q)
    assert (v + w).to_list() == [4, 6, 4]
    assert (v - w).to_list() == [Q - 2, Q - 2, Q - 6]
    assert (-v).to_list() == [Q - 1, Q - 2, 1]
    assert v.scale(3).to_list() == [3, 6, Q - 3]
    assert v.dot(w) == (1 * 3 + 2 * 4 + (Q - 1) * 5) % Q
    assert v.centered() == [1, 2, -1]
    assert v.norm2_squared() == 6
    assert v.norm_inf() == 2
    assert len(v) == 3 and v[0] == 1 and list(v) == [1, 2, Q - 1]


def test_vector_mismatch_errors():
    v = ModVector([1, 2], Q)
    w = ModVector([1, 2, 3], Q)
    u = ModVector([1, 2], 101)
    with pytest.raises(DimensionError):
        v + w
    with pytest.raises(DimensionError):
        v.dot(w)
    with pytest.raises(ModulusMismatchError):
        v + u
    with pytest.raises(ModulusMismatchError):
        v.dot(u)
    with pytest.raises(TypeError):
        v + [1, 2]


# ---------------------------------------------------------------------------
# Gadget
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "q,expected_k",
    [(2, 1), (3, 2), (4, 2), (5, 3), (255, 8), (256, 8), (257, 9), (1024, 10)],
)
def test_gadget_width(q, expected_k):
    assert gadget_width(q) == expected_k
    assert gadget_width(q) == math.ceil(math.log2(q))


def test_g_vector_is_powers_of_two():
    assert g_vector(257).to_list() == [1, 2, 4, 8, 16, 32, 64, 128, 256]


def test_gadget_matrix_shape_and_block_diagonal():
    n, q = 4, 257
    k = gadget_width(q)
    g_mat = gadget_matrix(n, q)
    assert g_mat.rows == n and g_mat.cols == n * k
    rows = g_mat.to_lists()
    for i in range(n):
        for j in range(n * k):
            if i * k <= j < (i + 1) * k:
                assert rows[i][j] == (1 << (j - i * k)) % q
            else:
                assert rows[i][j] == 0


def test_bit_decompose_roundtrip():
    n, q = 5, 257
    rng = SeededRandom("bd")
    v = ModVector([uniform_integer(rng, q) for _ in range(n)], q)
    bits = bit_decompose(v)
    assert bits.length == n * gadget_width(q)
    assert set(bits.to_list()) <= {0, 1}
    assert (gadget_matrix(n, q) @ bits) == v


# ---------------------------------------------------------------------------
# Discrete gaussian
# ---------------------------------------------------------------------------


def test_gaussian_reproducible_with_same_seed():
    a = sample_vector_gaussian(32, 3.0, rng=SeededRandom("g1"))
    b = sample_vector_gaussian(32, 3.0, rng=SeededRandom("g1"))
    c = sample_vector_gaussian(32, 3.0, rng=SeededRandom("g2"))
    assert a == b
    assert a != c


def test_gaussian_rejects_bad_arguments():
    with pytest.raises(InvalidParameterError):
        sample_integer_gaussian(0)
    with pytest.raises(InvalidParameterError):
        sample_integer_gaussian(-2.0)
    with pytest.raises(InvalidParameterError):
        sample_vector_gaussian(0, 3.0)
    with pytest.raises(InvalidParameterError):
        sample_vector_gaussian(3, 3.0, center=float("nan"))


def _mean_variance(samples):
    count = len(samples)
    mean = sum(samples) / count
    var = sum((x - mean) ** 2 for x in samples) / (count - 1)
    return mean, var


def test_gaussian_mean_and_variance():
    sigma = 3.0
    rng = SeededRandom("stat-1")
    samples = [sample_integer_gaussian(sigma, rng=rng) for _ in range(5000)]
    mean, var = _mean_variance(samples)
    assert abs(mean) <= 0.25  # σ/√n ≈ 0.042，容差约 6 个标准差
    assert 0.8 * sigma**2 <= var <= 1.2 * sigma**2


def test_gaussian_nonzero_center():
    sigma, center = 2.0, 2.5
    rng = SeededRandom("stat-2")
    samples = [sample_integer_gaussian(sigma, center, rng=rng) for _ in range(4000)]
    mean, _ = _mean_variance(samples)
    assert abs(mean - center) <= 0.2


def test_gaussian_tail_counts():
    sigma = 3.0
    rng = SeededRandom("stat-3")
    samples = [sample_integer_gaussian(sigma, rng=rng) for _ in range(6000)]
    beyond_3 = sum(1 for x in samples if abs(x) > 3 * sigma)
    beyond_5 = sum(1 for x in samples if abs(x) > 5 * sigma)
    # P(|x|>3σ) ≈ 0.27% → 期望 16.2，标准差约 4
    assert 5 <= beyond_3 <= 30
    # P(|x|>5σ) ≈ 5.7e-7 → 期望 0.003（均匀冒充会给出 ~0%，可被此组测试区分）
    assert beyond_5 <= 2
    # 尾部截断：|x| <= τσ（τ=12）加取整余量
    assert max(abs(x) for x in samples) <= 12 * sigma + 1


def test_vector_gaussian_statistics():
    sigma = 2.5
    rng = SeededRandom("stat-4")
    samples = [x for _ in range(240) for x in sample_vector_gaussian(16, sigma, rng=rng)]
    assert len(samples) == 3840
    mean, var = _mean_variance(samples)
    assert abs(mean) <= 0.25
    assert 0.75 * sigma**2 <= var <= 1.25 * sigma**2


def test_uniform_integer_distribution_and_reproducibility():
    rng = SeededRandom("uni-int")
    draws = [uniform_integer(rng, 7) for _ in range(7000)]
    assert set(draws) <= set(range(7))
    counts = [draws.count(value) for value in range(7)]
    for count in counts:
        assert 700 <= count <= 1300  # 期望 1000，±30%
    first = [uniform_integer(SeededRandom("u1"), 97) for _ in range(50)]
    second = [uniform_integer(SeededRandom("u1"), 97) for _ in range(50)]
    assert first == second
    with pytest.raises(InvalidParameterError):
        uniform_integer(rng, 0)


# ---------------------------------------------------------------------------
# Trapdoor
# ---------------------------------------------------------------------------

EDU = EDUCATION_PARAMS
NK = EDU.n * gadget_width(EDU.q)


@pytest.fixture()
def fresh_rng():
    return SeededRandom("trapdoor")


def identity_rows(nk):
    return [[1 if i == j else 0 for j in range(nk)] for i in range(nk)]


def random_target(rng):
    return ModVector([uniform_integer(rng, EDU.q) for _ in range(EDU.n)], EDU.q)


def test_trapgen_relation(fresh_rng):
    td = trapgen(EDU, fresh_rng)
    a = td.public_matrix()
    assert a.rows == EDU.n
    assert a.cols == EDU.m_matrix
    # 分块关系：A == [Ā | G - Ā·R mod q]
    g = gadget_matrix(EDU.n, EDU.q)
    r_mod = ModMatrix([list(row) for row in td.r], EDU.q)
    assert a == td.a_bar.hstack(g - td.a_bar @ r_mod)
    # 等价的 MP12 不变式：A · [R ; I] == G (mod q)
    stacked = [list(row) for row in td.r] + identity_rows(NK)
    assert (a @ ModMatrix(stacked, EDU.q)) == gadget_matrix(EDU.n, EDU.q)


def test_trapgen_r_is_short(fresh_rng):
    td = trapgen(EDU, fresh_rng)
    assert td.m_bar == EDU.m_matrix - NK == 8
    assert len(td.r) == td.m_bar
    assert all(len(row) == NK for row in td.r)
    bound = 6 * EDU.s0  # P(|x| > 6σ) ≈ 2e-9
    assert max(abs(x) for row in td.r for x in row) <= bound


def test_trapgen_rejects_bad_params():
    broken = replace(EDU, m_matrix=NK)  # m_bar = 0
    with pytest.raises(InvalidParameterError):
        trapgen(broken, SeededRandom("x"))
    with pytest.raises(InvalidParameterError):
        trapgen(EDU, SeededRandom("x"), m_bar=0)
    with pytest.raises(InvalidParameterError):
        trapgen("not-params", SeededRandom("x"))


def test_trapdoor_validates_shape():
    td = trapgen(EDU, SeededRandom("shape"))
    with pytest.raises(DimensionError):
        Trapdoor(td.a_bar, td.r[:-1])
    with pytest.raises(DimensionError):
        Trapdoor(td.a_bar, [row[:-1] for row in td.r])
    with pytest.raises(InvalidParameterError):
        Trapdoor(td.a_bar, [[1.5] * NK for _ in range(td.m_bar)])
    with pytest.raises(InvalidParameterError):
        Trapdoor("nope", td.r)


def test_sample_pre_equation_and_norm(fresh_rng):
    td = trapgen(EDU, fresh_rng)
    a = td.public_matrix()
    for _ in range(3):
        u = random_target(fresh_rng)
        z = sample_pre(td, u, fresh_rng, sigma_e=10.0)
        assert len(z) == EDU.m_matrix
        assert any(x != 0 for x in z)
        assert (a @ ModVector(z, EDU.q)) == u  # A·z = u (mod q)
        # 范数界：z = (R·bits + e, bits)，Var(z_i) <= nk·s0² + σe²
        bound = 6.0 * math.sqrt(td.m_bar * (NK * EDU.s0**2 + 10.0**2) + NK)
        assert sum(x * x for x in z) <= bound**2


def test_sample_pre_rejects_bad_target(fresh_rng):
    td = trapgen(EDU, fresh_rng)
    with pytest.raises(TypeError):
        sample_pre(td, [0] * EDU.n, fresh_rng)
    with pytest.raises(DimensionError):
        sample_pre(td, ModVector([0] * (EDU.n + 1), EDU.q), fresh_rng)
    with pytest.raises(ModulusMismatchError):
        sample_pre(td, ModVector([0] * EDU.n, 101), fresh_rng)


def test_del_trap_relation_and_delegation(fresh_rng):
    td1 = trapgen(EDU, fresh_rng)
    a1 = td1.public_matrix()
    td2 = del_trap(td1, fresh_rng, extra_cols=8, sigma_r=4.0)
    assert td2.m_bar == td1.m_bar + 8
    a2 = td2.public_matrix()
    assert a2.rows == EDU.n
    assert a2.cols == td1.m_bar + 8 + NK
    # 前 m_bar 列继承自父矩阵
    for j in range(td1.m_bar):
        assert a2.col(j) == a1.col(j)
    # 委派后的 MP12 不变式：A2 · [R1 ; R2 ; I] == G (mod q)
    stacked = [list(row) for row in td2.r] + identity_rows(NK)
    assert (a2 @ ModMatrix(stacked, EDU.q)) == gadget_matrix(EDU.n, EDU.q)
    # 委派陷门上 sample_pre 仍然满足方程
    u = random_target(fresh_rng)
    z = sample_pre(td2, u, fresh_rng, sigma_e=10.0)
    assert (a2 @ ModVector(z, EDU.q)) == u


def test_del_trap_validates_arguments(fresh_rng):
    td = trapgen(EDU, fresh_rng)
    with pytest.raises(TypeError):
        del_trap(td, fresh_rng)  # 缺少必需关键字参数
    with pytest.raises(InvalidParameterError):
        del_trap(td, fresh_rng, extra_cols=0, sigma_r=4.0)
    with pytest.raises(InvalidParameterError):
        del_trap(td, fresh_rng, extra_cols=4, sigma_r=0.0)
