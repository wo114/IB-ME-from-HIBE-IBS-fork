"""Independent checks of the public prime-square CRT certificate."""
import json

import pytest

from experiments.research.candidates.srgg.paper_ring_crt_lift import prime_square_crt


def test_small_cyclotomic_ring_has_two_genuinely_lifted_components():
    # ord_8(3)=2, so X^4+1 splits as exactly two degree-2 factors over F_3.
    report = prime_square_crt(prime=3, degree=4)
    assert report["modulus"] == 9
    assert report["factor_count"] == 2
    assert [item["factor_degree"] for item in report["factors"]] == [2, 2]
    assert len({item["factor_coefficients_sha256"] for item in report["factors"]}) == 2
    assert len({item["idempotent_coefficients_sha256"] for item in report["factors"]}) == 2
    assert all(item["centered_idempotent_norm_squared"] > 1 for item in report["factors"])
    assert report["all_lifted_factors_product_equals_Xn_plus_1"]
    assert report["idempotents_pairwise_project_and_sum_to_one"]
    assert report["public_polynomial_crt_reconstruction"]
    assert report["actual_attack_cost"] is None


def test_original_prime_square_component_is_constructed_not_inferred():
    # This is the 31^2 factor of the paper's Q=3*31^2*43*127.
    report = prime_square_crt(prime=31, degree=512)
    assert report["modulus"] == 961
    assert report["factor_count"] == 16
    assert {item["factor_degree"] for item in report["factors"]} == {32}
    assert len({item["factor_coefficients_sha256"] for item in report["factors"]}) == 16
    assert report["public_polynomial_crt_reconstruction"]
    assert report["actual_entropy_bytes"] == report["sampler_draws"] == 0
    assert report["CBD1_projection_law"] is None
    assert report["actual_attack_cost"] is None
    assert report["security_claim"] == "none"
    assert report["parameters_are_formal"] is False
    json.dumps(report)


@pytest.mark.parametrize("prime,degree", [(2, 4), (9, 4), (31, 3), (31, 1024), (True, 4)])
def test_invalid_or_unbounded_ring_is_rejected(prime, degree):
    with pytest.raises(ValueError):
        prime_square_crt(prime=prime, degree=degree)
