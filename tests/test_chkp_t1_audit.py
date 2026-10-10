"""Independent exact-algebra checks and negative controls for CHKP T1."""

import pytest

pytest.importorskip("sage.all", reason="Use the prescribed WSL Sage environment")
from sage.all import GF, QQ, ZZ, matrix

from experiments.research.chkp_basis import (
    CHKPAlgebraParams, KernelBasis, ModMatrixReference, complete_kernel_basis,
    ext_basis, gram_schmidt_squared_lengths,
)
from experiments.research.chkp_t1_audit import (
    exhaustive_audit, gram_determinant_lengths, integer_kernel_hnf,
    permutation_regression, public_example, seeded_audit,
)


def test_all_small_full_rank_roots_and_extension_blocks():
    result = exhaustive_audit()
    assert result["roots"] == 60
    assert result["extensions"] == 224
    assert result["membership_checks"] == 3584


def test_seeded_two_extensions_with_unimodular_parent_bases():
    result = seeded_audit()
    assert result["cases"] == 36
    assert result["bases"] == 108
    assert result["extensions"] == 72
    assert result["fractional_gs_seen"]
    assert result["negative_determinant_seen"]


def test_integer_kernel_oracle_rejects_proper_sublattice():
    public = ModMatrixReference([[1, 2]], 3)
    s = matrix(ZZ, complete_kernel_basis(public).basis_rows)
    sublattice = 2 * s
    assert all(x % 3 == 0 for x in (matrix(ZZ, public.rows) * sublattice).list())
    assert s.transpose().hermite_form() == integer_kernel_hnf(public)
    assert sublattice.transpose().hermite_form() != integer_kernel_hnf(public)


def test_rational_nullspace_denominator_clearing_is_not_integer_kernel():
    public = ModMatrixReference([[1, 2]], 3)
    # These are valid rational-kernel vectors of [1,2,-3], independently
    # denominator-cleared. Their projections span 3 Z^2, not the full kernel.
    cleared = matrix(ZZ, [[3, 0, 1], [0, 3, 2]])
    assert matrix(ZZ, [[1, 2, -3]]) * cleared.transpose() == 0
    projected = cleared.matrix_from_columns([0, 1])
    assert abs(projected.det()) == 9
    assert projected.hermite_form() != integer_kernel_hnf(public)


def test_wrong_sign_in_extension_is_detected():
    parent = complete_kernel_basis(ModMatrixReference([[1, 2]], 5))
    child = ext_basis(parent, ModMatrixReference([[1]], 5))
    corrupted = matrix(ZZ, child.basis_rows)
    corrupted[:2, 2:] = -corrupted[:2, 2:]
    with pytest.raises(ValueError, match="do not satisfy"):
        KernelBasis(child.public, corrupted)


def test_gs_can_have_lengths_below_one():
    # Only max(GS) >= 1 follows from an integer full basis; not every GS length.
    s = matrix(ZZ, [[2, 1], [1, 1]])
    assert abs(s.det()) == 1
    assert gram_determinant_lengths(s) == (QQ(5), QQ(1) / 5)


def test_parent_change_really_changes_gs_before_extension():
    public = ModMatrixReference([[1, 2]], 5)
    original = complete_kernel_basis(public)
    s = matrix(ZZ, original.basis_rows)
    changed = KernelBasis(public, s * matrix(ZZ, [[1, 0], [1, 1]]))
    before = gram_determinant_lengths(changed.basis_rows)
    assert before == (QQ(10), QQ(5) / 2)
    assert before != gram_determinant_lengths(original.basis_rows)
    child = ext_basis(changed, ModMatrixReference([[3, 1]], 5))
    assert gram_determinant_lengths(child.basis_rows) == before + (1, 1)


def test_non_involutive_coordinate_permutation_uses_inverse():
    result = permutation_regression()
    assert result["correct_residue"] == [[0, 0, 0]]
    assert result["wrong_residue"] == [[0, 0, 1]]


def test_public_three_level_evidence_is_replayable():
    first, second = public_example(), public_example()
    assert first == second
    assert [entry["rank"] for entry in first["levels"]] == [4, 8, 12]
    assert [entry["determinant"] for entry in first["levels"]] == ["289"] * 3
    assert first["security_claim"] == "none" and not first["is_randomized"]


@pytest.mark.parametrize("rows", [matrix(GF(7), [[-1]]), [[GF(7)(-1)]],
                                  matrix(GF(25, "a"), [[1]])])
def test_modular_inputs_must_match_the_declared_prime_field(rows):
    with pytest.raises(ValueError, match="finite-ring"):
        ModMatrixReference(rows, 5)


def test_matching_field_and_explicit_integer_lifts_are_distinguished():
    assert ModMatrixReference(matrix(GF(5), [[-1, 2]]), 5).rows == ((4, 2),)
    assert ModMatrixReference([[GF(5)(-1), GF(5)(2)]], 5).rows == ((4, 2),)
    # A caller may explicitly choose integer representatives and reduce again.
    assert ModMatrixReference([[int(GF(7)(-1))]], 5).rows == ((1,),)


def test_integer_basis_gs_and_dimensions_do_not_silently_lift_finite_fields():
    # This finite-field matrix happens to lift to a valid determinant-3 basis;
    # still require the caller to supply its unreduced integer representation.
    reduced = matrix(GF(3), [[2, 1], [1, 2]])
    public = ModMatrixReference([[1, 1]], 3)
    with pytest.raises(ValueError, match="finite-ring"):
        KernelBasis(public, reduced)
    with pytest.raises(ValueError, match="finite-ring"):
        gram_schmidt_squared_lengths(reduced)
    with pytest.raises(ValueError, match="finite-ring"):
        CHKPAlgebraParams(GF(5)(1), 2, 3)
    assert KernelBasis(public, matrix(ZZ, reduced)).basis_rows == ((2, 1), (1, 2))
