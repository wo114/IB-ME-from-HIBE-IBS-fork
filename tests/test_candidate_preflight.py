"""Independent lattice volume checks for public teaching prerequisites only."""

import pytest

pytest.importorskip("sage.all")
from sage.all import GF, QQ, ZZ, matrix

from experiments.research.candidate_preflight import (
    abb_fixed_dimension_algebra, chkp_algebra, complete_kernel_basis, extend_basis, ring_algebra,
)


def test_chkp_two_extensions_preserve_full_kernel_volume():
    result = chkp_algebra()
    assert [row["columns"] for row in result["rows"]] == [4, 8, 12]
    assert all(row["determinant"] == 17**2 and row["kernel_equation"] for row in result["rows"])
    assert not result["randbasis_implemented"] and not result["gaussian_sampling_implemented"]
    assert result["security_claim"] == "none"


def test_fixed_dimension_multiplication_is_not_complete_delegation():
    result = abb_fixed_dimension_algebra()
    assert [row["multiply_only_sublattice_index"] for row in result["rows"]] == [2, 6]
    assert all(row["columns"] == 4 and row["complete_basis_determinant"] == 17**2
               and not row["multiply_only_is_complete_basis"] for row in result["rows"])
    assert not result["short_basis_completion_implemented"]


def test_nonleading_pivots_are_unpermuted_correctly():
    a = matrix(ZZ, [[0, 2, 1, 3], [0, 0, 1, 4]])
    s = complete_kernel_basis(a, 17)
    assert matrix(GF(17), a * s) == 0 and abs(s.det()) == 17**2
    # A full integer basis with this determinant gives exactly the full
    # modular-kernel lattice, rather than only a set of kernel vectors.
    assert s.base_ring() == ZZ


@pytest.mark.parametrize("q", [True, 2, 9, 259])
def test_no_prime_field_substitution_for_composite_or_unbounded_modulus(q):
    with pytest.raises(ValueError): complete_kernel_basis(matrix(ZZ, [[1, 0]]), q)


def test_rank_and_integer_lattice_type_required():
    for a in (matrix(ZZ, [[0, 0]]), matrix(QQ, [[1, 0]])):
        with pytest.raises(ValueError): complete_kernel_basis(a, 17)


@pytest.mark.parametrize("mutation", ["proper-sublattice", "wrong-shape", "noninteger", "suffix-rows"])
def test_extension_rejects_bad_parent_and_suffix(mutation):
    a = matrix(ZZ, [[1, 0, 2], [0, 1, 3]])
    s, c = complete_kernel_basis(a, 17), matrix(ZZ, [[1], [2]])
    if mutation == "proper-sublattice": s[:, 0] = 2 * s[:, 0]
    elif mutation == "wrong-shape": s = matrix(ZZ, [[1]])
    elif mutation == "noninteger": s = matrix(QQ, s)
    else: c = matrix(ZZ, [[1]])
    with pytest.raises(ValueError): extend_basis(a, s, c, 17)


def test_ring_probe_covers_composite_modulus_without_claiming_keygen():
    result = ring_algebra()
    assert result["moduli"] == [17, 81] and result["negacyclic_product_matches_sage"]
    assert result["toy_NTRU_integer_identity"] and not result["actual_NTRU_keygen"]
    assert not result["ring_sampler_implemented"] and result["security_claim"] == "none"
