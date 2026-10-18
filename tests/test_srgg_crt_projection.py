"""Exact independent CRT probability checks, with optional actual Sage rings."""
from fractions import Fraction as F
from itertools import product
import json

import pytest

from experiments.research.candidates.srgg.crt_projection import (
    build_report, enumerate_block_law, project_block, project_polynomial, projection_certificate,
)


def unpack(record):
    return F(int(record["numerator_hex"], 16), int(record["denominator_hex"], 16))


@pytest.mark.parametrize("sign", [-1, 1])
def test_weighted_81_input_enumeration_has_the_stated_pair_law(sign):
    # Independent polynomial long division; integer multiplicities are the
    # two-bit CBD1 sampler's weights, not weights fetched from the module.
    counts = {(a, b): 0 for a, b in product(range(3), repeat=2)}
    for a, b, c, d in product((-1, 0, 1), repeat=4):
        poly = [a, b, c, d]
        for power in (3, 2):
            coefficient = poly[power]
            poly[power] = 0
            poly[power-2] += coefficient
            poly[power-1] -= sign*coefficient
        weight = 2**sum(x == 0 for x in (a, b, c, d))
        counts[(poly[0] % 3, poly[1] % 3)] += weight
    assert sum(counts.values()) == 256
    assert counts[(0, 0)] == 32
    assert all(value == 28 for point, value in counts.items() if point != (0, 0))
    law = {point: F(count, 256) for point, count in counts.items()}
    assert enumerate_block_law(sign=sign) == law
    assert sum(value*value for value in law.values()) == F(57, 512)


def test_small_F9_public_Ahat_full_joint_enumeration_matches_chi_square():
    # F9=F3[t]/(t²+t-1). Enumerate all A,S,E and form the complete joint
    # distribution of public A and noisy V; this is ONE CRT factor.
    field = tuple(product(range(3), repeat=2))
    probability = {x: F(1, 8) if x == (0, 0) else F(7, 64) for x in field}

    def multiply(a, b):
        return ((a[0]*b[0]+a[1]*b[1]) % 3,
            (a[0]*b[1]+a[1]*b[0]-a[1]*b[1]) % 3)

    joint = {(a, v): F(0) for a, v in product(field, repeat=2)}
    for a, s, e in product(field, repeat=3):
        z = multiply(a, s)
        v = ((z[0]+e[0]) % 3, (z[1]+e[1]) % 3)
        joint[a, v] += probability[s]*probability[e]/9
    assert sum(joint.values()) == 1
    exact_chi_square = sum((mass-F(1, 81))**2/F(1, 81) for mass in joint.values())
    exact_tv = sum(abs(mass-F(1, 81)) for mass in joint.values())/2
    certificate = projection_certificate(degree=4, rank=1)
    assert exact_chi_square == F(57, 262144)
    assert unpack(certificate["average_conditional_chi_square_exact"]) == exact_chi_square
    assert exact_tv**2 <= unpack(certificate["one_factor_public_Ahat_noisy_column_tv_squared_upper_exact"])
    # A=0 leaves the unmodified error: the claimed average cannot be replaced
    # with a pointwise bound for every public matrix.
    zero_A_tv = sum(abs(9*joint[(0, 0), v]-F(1, 9)) for v in field)/2
    assert zero_A_tv**2 > unpack(certificate["one_factor_public_Ahat_noisy_column_tv_squared_upper_exact"])


def test_full_mod3_n4_public_Ahat_joint_enumeration_matches_exact_chi_square():
    # This uses only the original negacyclic coefficient ring, without the
    # projection functions, factor laws, CRT isomorphism or sampling.
    ring = tuple(product(range(3), repeat=4))
    index = {value: i for i, value in enumerate(ring)}
    weights = {value: 2**value.count(0) for value in ring}
    assert sum(weights.values()) == 256

    def multiply(a, s):
        result = [0]*4
        for i in range(4):
            for j in range(4):
                if i+j < 4:
                    result[i+j] += a[i]*s[j]
                else:
                    result[i+j-4] -= a[i]*s[j]
        return tuple(value % 3 for value in result)

    total_squares = 0
    total_absolute_uniform_difference = 0
    for a in ring:
        counts = [0]*81
        for s in ring:
            z = multiply(a, s)
            for e in ring:
                v = tuple((z[i]+e[i]) % 3 for i in range(4))
                counts[index[v]] += weights[s]*weights[e]
        assert sum(counts) == 256**2
        total_squares += sum(count*count for count in counts)
        total_absolute_uniform_difference += sum(abs(81*count-256**2) for count in counts)
    # Joint denominator 81*256²; reference uniform mass 1/81².
    exact_chi_square = F(total_squares, 256**4)-1
    exact_tv = F(total_absolute_uniform_difference, 2*81**2*256**2)
    certificate = projection_certificate(degree=4, rank=1)
    assert exact_chi_square == F(205665, 16777216)
    assert unpack(certificate["full_mod3_average_conditional_chi_square_exact"]) == exact_chi_square
    assert exact_tv**2 <= unpack(certificate["full_mod3_public_Ahat_noisy_column_tv_squared_upper_exact"])


def test_two_columns_share_public_Ahat_and_fixed_shift_preserves_exact_tv():
    # Actual F9 joint distributions, conditional products at the SAME A.
    field = tuple(product(range(3), repeat=2))
    weights = {value: 8 if value == (0, 0) else 7 for value in field}
    exact_tv = F(0)
    shifted_tv = F(0)
    shift = (1, 2)
    for a in field:
        counts = {value: 0 for value in field}
        for s, e in product(field, repeat=2):
            z = ((a[0]*s[0]+a[1]*s[1]) % 3,
                (a[0]*s[1]+a[1]*s[0]-a[1]*s[1]) % 3)
            v = ((z[0]+e[0]) % 3, (z[1]+e[1]) % 3)
            counts[v] += weights[s]*weights[e]
        assert sum(counts.values()) == 64**2
        shifted = {((shift[0]-v[0]) % 3, (shift[1]-v[1]) % 3): count
            for v, count in counts.items()}
        for v, w in product(field, repeat=2):
            exact_tv += abs(F(counts[v]*counts[w], 9*64**4)-F(1, 9**3))/2
            shifted_tv += abs(F(shifted[v]*shifted[w], 9*64**4)-F(1, 9**3))/2
    assert exact_tv == shifted_tv
    certificate = projection_certificate(degree=4, rank=1, columns=2)
    assert exact_tv**2 <= unpack(certificate["one_factor_public_Ahat_shared_columns_tv_squared_upper_exact"])


@pytest.mark.parametrize("degree", [4, 8])
def test_actual_sage_quotients_match_all_block_values_and_basis_images(degree):
    sage = pytest.importorskip("sage.all", reason="actual quotient rings require specified WSL Sage")
    ring = sage.PolynomialRing(sage.GF(3), "x")
    x = ring.gen()
    k = degree//4
    for sign in (-1, 1):
        factor = x**(2*k)+sign*x**k-1
        other = x**(2*k)-sign*x**k-1
        assert factor*other == x**degree+1
        assert factor.is_irreducible()
        quotient = ring.quotient(factor, "a")
        inputs = []
        for j in range(degree):
            inputs.append(tuple(1 if i == j else 0 for i in range(degree)))
        for j in range(k):
            for block in product((-1, 0, 1), repeat=4):
                inputs.append(tuple(block[(i-j)//k] if i % k == j else 0 for i in range(degree)))
        for coefficients in inputs:
            actual = quotient(ring(coefficients)).lift()
            expected = tuple(int(actual[i]) for i in range(degree//2))
            assert project_polynomial(coefficients, sign=sign) == expected


@pytest.mark.parametrize("degree,rank", [(4, 1), (8, 3), (512, 2), (2048, 3)])
def test_exact_collision_tensor_product_and_conservative_optimal_dyadic_upper(degree, rank):
    certificate = projection_certificate(degree=degree, rank=rank)
    c = unpack(certificate["projected_secret_collision_probability_exact"])
    expected_c = F(57, 512)**(degree*rank//4)
    assert c == expected_c
    K = 3**(degree*rank//2)
    assert unpack(certificate["average_conditional_chi_square_exact"]) == c*(K*c-1)
    square = unpack(certificate["one_factor_public_Ahat_noisy_column_tv_squared_upper_exact"])
    upper = unpack(certificate["one_factor_public_Ahat_noisy_column_tv_dyadic_upper_exact"])
    assert square <= upper**2
    assert square > (upper/2)**2
    assert upper == F(1, 2**certificate["one_factor_tv_dyadic_bits_lower"])
    full_c = F(3, 8)**(degree*rank)
    assert unpack(certificate["full_mod3_secret_collision_probability_exact"]) == full_c
    # Enumerate the four delta-support cases symbolically, independently of
    # the expanded chi-square expression implemented in the certificate.
    support_masses = [full_c, c-full_c, c-full_c, 1-2*c+full_c]
    assert all(mass >= 0 for mass in support_masses)
    assert sum(support_masses) == 1
    conditional_collision = (support_masses[0]*full_c
        + (support_masses[1]+support_masses[2])*c/K+support_masses[3]/K**2)
    assert unpack(certificate["full_mod3_average_conditional_chi_square_exact"]) == K**2*conditional_collision-1
    square = unpack(certificate["full_mod3_public_Ahat_noisy_column_tv_squared_upper_exact"])
    upper = unpack(certificate["full_mod3_public_Ahat_noisy_column_tv_dyadic_upper_exact"])
    assert square <= upper**2
    assert square > (upper/2)**2
    assert upper == F(1, 2**certificate["full_mod3_tv_dyadic_bits_lower"])


@pytest.mark.parametrize("degree,rank,columns,expected_single_bits", [
    (4, 1, 1, 4), (512, 2, 16, 406), (512, 8, 1, 1620), (2048, 3, 66, 2430)])
def test_full_mod3_single_and_shared_column_exact_dyadic_bounds(degree, rank, columns, expected_single_bits):
    certificate = projection_certificate(degree=degree, rank=rank, columns=columns)
    assert certificate["full_mod3_tv_dyadic_bits_lower"] == expected_single_bits
    for prefix in ("one_factor", "full_mod3"):
        single_square = unpack(certificate[f"{prefix}_public_Ahat_noisy_column_tv_squared_upper_exact"])
        multi_square = unpack(certificate[f"{prefix}_public_Ahat_shared_columns_tv_squared_upper_exact"])
        upper = unpack(certificate[f"{prefix}_public_Ahat_shared_columns_tv_dyadic_upper_exact"])
        assert multi_square == min(1, columns**2*single_square)
        assert multi_square <= upper**2
        assert multi_square > (upper/2)**2
        assert upper == F(1, 2**certificate[f"{prefix}_shared_columns_tv_dyadic_bits_lower"])


def test_column_hybrid_caps_at_trivial_tv_one():
    certificate = projection_certificate(degree=4, rank=1, columns=2**16)
    for prefix in ("one_factor", "full_mod3"):
        assert unpack(certificate[f"{prefix}_public_Ahat_shared_columns_tv_squared_upper_exact"]) == 1
        assert certificate[f"{prefix}_shared_columns_tv_dyadic_bits_lower"] == 0


@pytest.mark.parametrize("columns", [True, 0, -1, 2**16+1, 2.0, "2", None])
def test_bad_column_count_rejected_before_large_arithmetic(columns):
    with pytest.raises(ValueError):
        projection_certificate(degree=4, rank=1, columns=columns)


@pytest.mark.parametrize("degree,rank", [(True, 1), (2, 1), (12, 1), (2**17, 1),
    (4, True), (4, 0), (4, 33), (4, 1.0)])
def test_bad_parameters_reject_before_large_arithmetic(degree, rank):
    with pytest.raises(ValueError):
        projection_certificate(degree=degree, rank=rank)


@pytest.mark.parametrize("values,sign", [((0, 0, 0, True), 1), ((0, 0, 0), 1),
    ((0, 0, 0, 2), 1), ((0, 0, 0, 0), True), ((0, 0, 0, 0), 0)])
def test_block_domain_is_exact_and_strict(values, sign):
    with pytest.raises(ValueError):
        project_block(values, sign=sign)


def test_report_is_zero_entropy_and_cannot_upgrade_the_mod3_projection():
    report = build_report()
    json.loads(json.dumps(report))
    assert report["actual_entropy_bytes"] == 0 and report["draw_performed"] is False
    for profile in report["profiles"]:
        assert profile["both_CRT_factors_jointly_covered"] is True
        assert profile["shared_Ahat_columns_hybrid_covered"] is True
        assert profile["both_CRT_factor_Ahat_projections_independent"] is True
        assert profile["both_CRT_factor_CBD1_projections_independent"] is False
        assert profile["requires_only_3_divides_original_modulus_not_base_3"] is True
        assert profile["prime_power_3_to_w_covered"] is False
        assert profile["other_prime_factors_covered"] is False
        assert profile["tv_bound_pointwise_for_every_Ahat"] is False
        assert profile["whole_MLWE_or_IBS_security_established"] is False
        assert profile["security_claim"] == "none"
        assert profile["backend_admitted"] is profile["parameters_are_formal"] is False
        assert profile["nist_security_category"] is None
    assert [profile["columns"] for profile in report["profiles"]] == [16, 66]
