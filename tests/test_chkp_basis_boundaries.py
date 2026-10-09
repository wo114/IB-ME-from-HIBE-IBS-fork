"""T1 input contracts and boundaries, using explicit educational algebra cases.

These tests make no shortness, sampling, HIBE, or security claim. Independent
integer-kernel, HNF, and Gram-Schmidt audits belong to the separate T1 audit.
"""

from dataclasses import FrozenInstanceError
from fractions import Fraction

import pytest

pytest.importorskip("sage.all", reason="Use the prescribed WSL Sage environment")
from sage.all import GF, QQ, ZZ, identity_matrix, matrix, vector

from experiments.research.chkp_basis import (
    CHKPAlgebraParams, KernelBasis, ModMatrixReference, complete_kernel_basis,
    ext_basis, gram_schmidt_squared_lengths, two_level_matrices,
)


@pytest.mark.parametrize("rows,q", [([[1]], 2),
                                    ([[0, 1], [1, 1]], 2),
                                    ([[2, 1], [1, 1]], 5)])
def test_square_full_rank_root_has_no_free_coordinates(rows, q):
    params = CHKPAlgebraParams(n=len(rows), m=len(rows), q=q)
    public = ModMatrixReference(rows, q)
    basis = complete_kernel_basis(public)
    assert matrix(ZZ, basis.basis_rows) == q * identity_matrix(ZZ, params.m)
    assert params.security_claim == basis.security_claim == "none"
    assert not basis.is_randomized


@pytest.mark.parametrize("q,width", [(2, 1), (2, 3), (5, 1), (5, 4)])
def test_zero_valued_extension_accepts_rank_zero_block(q, width):
    parent = KernelBasis(ModMatrixReference([[1]], q), [[-q]])
    block = ModMatrixReference([[0] * width], q)
    child = ext_basis(parent, block)
    expected = identity_matrix(ZZ, width + 1)
    expected[0, 0] = -q
    assert child.public.rows == ((1,) + (0,) * width,)
    assert matrix(ZZ, child.basis_rows) == expected
    assert parent.basis_rows == ((-q,),)
    assert block.rows == ((0,) * width,)


def test_binary_extension_keeps_integer_basis_coefficients():
    parent = KernelBasis(ModMatrixReference([[1]], 2), [[-2]])
    child = ext_basis(parent, ModMatrixReference([[1, 0, -1]], 2))
    assert child.public.rows == ((1, 1, 0, 1),)
    # At q=2, -1 and +1 coincide publicly; the integer lift is +1.
    assert child.basis_rows == ((-2, 1, 0, 1), (0, 1, 0, 0),
                                (0, 0, 1, 0), (0, 0, 0, 1))


@pytest.mark.parametrize("n,m,q", [(1, 1, 2), (2, 2, 2), (2, 3, 5)])
def test_two_levels_preserve_rectangular_blocks_and_identity_order(n, m, q):
    params = CHKPAlgebraParams(n, m, q)
    root_rows = [[int(i == j) for j in range(m)] for i in range(n)]
    parent_rows = [[i + 2 * j + 1 for j in range(m)] for i in range(n)]
    child_rows = [[2 * i + j + 2 for j in range(m)] for i in range(n)]
    root, parent, child = two_level_matrices(params, root_rows, parent_rows, child_rows)
    blocks = [ModMatrixReference(rows, q) for rows in
              (root_rows, parent_rows, child_rows)]
    assert [(a.nrows, a.ncols) for a in (root, parent, child)] == [
        (n, m), (n, 2 * m), (n, 3 * m),
    ]
    assert root == blocks[0]
    assert parent.rows == tuple(a + b for a, b in zip(blocks[0].rows, blocks[1].rows))
    assert child.rows == tuple(a + b + c for a, b, c in zip(
        blocks[0].rows, blocks[1].rows, blocks[2].rows))
    assert two_level_matrices(params, root_rows, child_rows, parent_rows)[2] != child
    basis = complete_kernel_basis(root)
    for block, expected_public in zip(blocks[1:], (parent, child)):
        previous = matrix(ZZ, basis.basis_rows)
        basis = ext_basis(basis, block)
        extended = matrix(ZZ, basis.basis_rows)
        assert basis.public == expected_public
        assert extended.dimensions() == (expected_public.ncols, expected_public.ncols)
        assert extended[:previous.nrows(), :previous.ncols()] == previous


@pytest.mark.parametrize("slot", [0, 1, 2], ids=["root", "parent", "child"])
@pytest.mark.parametrize("bad_rows", [
    [[1, 0, 0]],                           # Wrong row count.
    [[1, 0], [0, 1]],                      # Wrong column count.
    [[1, 0], [0, 1], [0, 0]],              # Transposed n by m.
    [[1, 0, 0, 1], [0, 1, 0, 1]],          # Extra column.
])
def test_two_levels_validate_each_block_shape(slot, bad_rows):
    blocks = [[[1, 0, 0], [0, 1, 0]] for _ in range(3)]
    blocks[slot] = bad_rows
    with pytest.raises(ValueError, match="shape n by m"):
        two_level_matrices(CHKPAlgebraParams(2, 3, 5), *blocks)


@pytest.mark.parametrize("bad", [True, False, 2.0, QQ(3) / 2, "2", None])
@pytest.mark.parametrize("field", ["n", "m", "q", "depth"])
def test_parameters_require_exact_integer_types(field, bad):
    values = dict(n=2, m=3, q=5, depth=2)
    values[field] = bad
    with pytest.raises(ValueError, match="integer"):
        CHKPAlgebraParams(**values)


@pytest.mark.parametrize("n,m,depth", [(0, 1, 2), (-1, 1, 2), (1, 0, 2),
                                        (2, 1, 2), (1, 1, 0), (1, 1, 1),
                                        (1, 1, 3)])
def test_parameter_dimension_and_depth_boundaries(n, m, depth):
    with pytest.raises(ValueError, match="n >= 1, m >= n, and fixed depth 2"):
        CHKPAlgebraParams(n, m, 2, depth)


@pytest.mark.parametrize("q", [-7, 0, 1, 4, 9, 25])
def test_nonprime_moduli_are_rejected_even_with_unit_pivot(q):
    with pytest.raises(ValueError, match="proven prime modulus"):
        CHKPAlgebraParams(1, 1, q)
    with pytest.raises(ValueError, match="proven prime modulus"):
        ModMatrixReference([[1]], q)


def test_sage_integers_and_matrices_are_snapshotted_as_python_integers():
    params = CHKPAlgebraParams(ZZ(1), ZZ(2), ZZ(5), ZZ(2))
    source = matrix(ZZ, [[-1, 7]])
    public = ModMatrixReference(source, ZZ(5))
    source[0, 0] = 0
    basis_source = matrix(ZZ, [[5, 2], [0, 1]])
    basis = KernelBasis(public, basis_source)
    basis_source[0, 1] = 999
    assert all(type(x) is int for x in (params.n, params.m, params.q, params.depth))
    assert public.rows == ((4, 2),)
    assert basis.basis_rows == ((5, 2), (0, 1))
    assert all(type(x) is int for rows in (public.rows, basis.basis_rows)
               for row in rows for x in row)


@pytest.mark.parametrize("representation", ["list", "tuple", "iterator", "ZZ", "QQ"])
def test_exact_integral_matrix_representations_have_identical_meaning(representation):
    public_rows = [[-4, 7]]
    basis_rows = [[5, -2], [0, 1]]
    if representation == "tuple":
        public_rows = tuple(tuple(row) for row in public_rows)
        basis_rows = tuple(tuple(row) for row in basis_rows)
    elif representation == "iterator":
        public_rows = (iter(row) for row in public_rows)
        basis_rows = (iter(row) for row in basis_rows)
    elif representation in ("ZZ", "QQ"):
        ring = ZZ if representation == "ZZ" else QQ
        public_rows = matrix(ring, public_rows)
        basis_rows = matrix(ring, basis_rows)
    public = ModMatrixReference(public_rows, 5)
    basis = KernelBasis(public, basis_rows)
    assert public.rows == ((1, 2),)
    assert basis.basis_rows == ((5, -2), (0, 1))


def test_integral_sage_rationals_support_the_exact_integer_index_contract():
    params = CHKPAlgebraParams(QQ(1), QQ(2), QQ(5), QQ(2))
    assert (params.n, params.m, params.q, params.depth) == (1, 2, 5, 2)
    assert all(type(x) is int for x in (params.n, params.m, params.q, params.depth))


@pytest.mark.parametrize("rows", [None, 1, [1, 2], [], [[]],
                                  [[1, 2], [3]], [[1], []]])
def test_modular_matrix_rejects_empty_ragged_and_nonmatrix_input(rows):
    with pytest.raises(ValueError):
        ModMatrixReference(rows, 5)


@pytest.mark.parametrize("bad", [True, False, 1.0, QQ(1) / 2, "1", None])
def test_matrix_and_basis_entries_cannot_be_coerced_to_integers(bad):
    with pytest.raises(ValueError, match="integer"):
        ModMatrixReference([[bad]], 5)
    with pytest.raises(ValueError, match="integer"):
        KernelBasis(ModMatrixReference([[1]], 5), [[bad]])
    with pytest.raises(ValueError, match="integer"):
        gram_schmidt_squared_lengths([[bad]])


@pytest.mark.parametrize("q", [True, False, 5.0, QQ(5) / 2, "5", None, Fraction(5)])
def test_modular_matrix_uses_the_same_exact_modulus_type_contract(q):
    with pytest.raises(ValueError, match="integer"):
        ModMatrixReference([[1]], q)


def test_fractional_sage_matrices_are_rejected_without_rounding():
    rows = matrix(QQ, [[5, -QQ(3) / 2], [0, 1]])
    with pytest.raises(ValueError, match="exact integer"):
        ModMatrixReference(rows, 5)
    with pytest.raises(ValueError, match="exact integer"):
        KernelBasis(ModMatrixReference([[1, 2]], 5), rows)
    with pytest.raises(ValueError, match="exact integer"):
        gram_schmidt_squared_lengths(rows)


def test_one_dimensional_sage_vector_is_not_a_matrix():
    rows = vector(ZZ, [1, 2])
    with pytest.raises(ValueError, match="two-dimensional integer matrix"):
        ModMatrixReference(rows, 5)
    with pytest.raises(ValueError, match="two-dimensional integer matrix"):
        KernelBasis(ModMatrixReference([[1, 2]], 5), rows)
    with pytest.raises(ValueError, match="two-dimensional integer matrix"):
        gram_schmidt_squared_lengths(rows)


@pytest.mark.parametrize("rows", [matrix(ZZ, 0, 2), matrix(ZZ, 2, 0)])
def test_zero_sized_sage_matrices_are_not_zero_valued_blocks(rows):
    with pytest.raises(ValueError, match="nonempty and rectangular"):
        ModMatrixReference(rows, 2)


@pytest.mark.parametrize("bad", [None, [[1]], {"rows": ((1,),), "q": 5}])
def test_public_entry_points_reject_unvalidated_object_types(bad):
    public = ModMatrixReference([[1]], 5)
    basis = KernelBasis(public, [[5]])
    with pytest.raises(ValueError, match="modular reference matrix"):
        complete_kernel_basis(bad)
    with pytest.raises(ValueError, match="modular reference matrix"):
        KernelBasis(bad, [[5]])
    with pytest.raises(ValueError, match="modular matrix block"):
        public.append(bad)
    with pytest.raises(ValueError, match="validated basis and a modular block"):
        ext_basis(bad, public)
    with pytest.raises(ValueError, match="validated basis and a modular block"):
        ext_basis(basis, bad)
    with pytest.raises(ValueError, match="CHKPAlgebraParams"):
        two_level_matrices(bad, [[1]], [[1]], [[1]])


def test_extension_rejects_valid_objects_in_the_wrong_argument_roles():
    public = ModMatrixReference([[1]], 5)
    basis = KernelBasis(public, [[5]])
    with pytest.raises(ValueError, match="validated basis and a modular block"):
        ext_basis(public, public)
    with pytest.raises(ValueError, match="validated basis and a modular block"):
        ext_basis(basis, basis)
    with pytest.raises(ValueError, match="modular matrix block"):
        public.append(basis)


@pytest.mark.parametrize("block", [ModMatrixReference([[1]], 3),
                                   ModMatrixReference([[1], [0]], 5)])
def test_append_and_extension_reject_modulus_or_row_mismatch(block):
    public = ModMatrixReference([[1]], 5)
    basis = KernelBasis(public, [[5]])
    with pytest.raises(ValueError, match="same modulus and row count"):
        public.append(block)
    with pytest.raises(ValueError, match="same modulus and row count"):
        ext_basis(basis, block)
    assert public.rows == ((1,),)
    assert basis.basis_rows == ((5,),)


@pytest.mark.parametrize("rows", [[[0, 0]], [[1], [0]],
                                  [[1, 1], [1, 6]], [[5, 0], [0, 1]]])
def test_kernel_operations_require_full_row_rank_modulo_q(rows):
    public = ModMatrixReference(rows, 5)
    with pytest.raises(ValueError, match="full row rank modulo q"):
        complete_kernel_basis(public)
    with pytest.raises(ValueError, match="full row rank modulo q"):
        KernelBasis(public, 5 * identity_matrix(ZZ, public.ncols))


@pytest.mark.parametrize("rows", [[[5]], [[5, 0]], [[5], [0]],
                                  [[5, 0, 0], [0, 1, 0]],
                                  [[5, 0], [0, 1], [0, 0]]])
def test_kernel_basis_must_match_public_column_count(rows):
    with pytest.raises(ValueError, match="m by m integer matrix"):
        KernelBasis(ModMatrixReference([[1, 2]], 5), rows)


@pytest.mark.parametrize("factor", [2, 5])
def test_scaling_one_basis_column_creates_rejected_proper_sublattice(factor):
    public = ModMatrixReference([[1, 2]], 5)
    rows = [[5 * factor, -2], [0, 1]]
    candidate = matrix(ZZ, rows)
    assert matrix(GF(5), public.rows) * matrix(GF(5), candidate) == 0
    assert abs(candidate.det()) == factor * 5
    with pytest.raises(ValueError, match="complete kernel index"):
        KernelBasis(public, rows)


@pytest.mark.parametrize("rows", [[[1, 0], [0, 5]], [[5, 0], [-2, 1]]],
                         ids=["same-index-wrong-kernel", "row-basis-transposed"])
def test_correct_determinant_does_not_certify_kernel_columns(rows):
    public = ModMatrixReference([[1, 2]], 5)
    assert abs(matrix(ZZ, rows).det()) == 5
    assert matrix(GF(5), public.rows) * matrix(GF(5), rows) != 0
    with pytest.raises(ValueError, match="basis columns"):
        KernelBasis(public, rows)


def test_singular_kernel_columns_are_not_a_basis():
    with pytest.raises(ValueError, match="complete kernel index"):
        KernelBasis(ModMatrixReference([[1, 2]], 5), [[5, 0], [0, 0]])


@pytest.mark.parametrize("rows,match", [
    ([[1, 0, 0], [0, 1, 0]], "square full-rank"),
    ([[1, 0], [0, 1], [0, 0]], "square full-rank"),
    ([[0]], "deficient integer rank"),
    ([[1, 2], [2, 4]], "deficient integer rank"),
])
def test_gram_schmidt_rejects_invalid_input_shapes_and_integer_rank(rows, match):
    with pytest.raises(ValueError, match=match):
        gram_schmidt_squared_lengths(rows)


def test_modular_representative_changes_do_not_change_public_or_basis():
    q = 5
    rows = [[1, 0, 2], [0, 1, 1]]
    block_rows = [[2, 4], [1, 3]]
    large = 2**100 + 1
    shifted_rows = [[x + (-1)**(i + j) * large * q for j, x in enumerate(row)]
                    for i, row in enumerate(rows)]
    shifted_block = [[x - large * q for x in row] for row in block_rows]
    first = complete_kernel_basis(ModMatrixReference(rows, q))
    second = complete_kernel_basis(ModMatrixReference(shifted_rows, q))
    assert first == second
    assert ext_basis(first, ModMatrixReference(block_rows, q)) == ext_basis(
        second, ModMatrixReference(shifted_block, q))


def test_extension_preserves_swapped_sheared_parent_basis_without_reduction():
    public = ModMatrixReference([[1, 0, 2], [0, 1, 1]], 5)
    original = matrix(ZZ, [[5, 0, -2], [0, 5, -1], [0, 0, 1]])
    large = 2**80 + 1
    transform = matrix(ZZ, [[0, 1, 0], [1, 0, -large], [0, 0, 1]])
    assert transform.det() == -1
    changed = original * transform
    assert changed.det() == -25
    parent = KernelBasis(public, changed)
    child = ext_basis(parent, ModMatrixReference([[4, 2], [1, 3]], 5))
    extended = matrix(ZZ, child.basis_rows)
    assert matrix(ZZ, parent.basis_rows) == changed
    assert extended[:3, :3] == changed
    assert extended[3:, :3] == matrix(ZZ, 2, 3)
    assert extended[3:, 3:] == identity_matrix(ZZ, 2)
    assert matrix(GF(5), child.public.rows) * matrix(GF(5), extended) == 0
    assert max(abs(x) for x in extended.list()) > 2**80
    assert child.security_claim == "none"
    assert not child.is_randomized


def test_two_level_and_basis_objects_retain_snapshots_of_mutable_inputs():
    source = [[[1, 0]], [[2, 3]], [[4, 1]]]
    matrices = two_level_matrices(CHKPAlgebraParams(1, 2, 5), *source)
    saved = tuple(a.rows for a in matrices)
    for rows in source:
        rows[0][0] = 99
        rows[0].append(99)
        rows.append([99])
    assert tuple(a.rows for a in matrices) == saved

    rows = [[5, 0], [0, 1]]
    parent = KernelBasis(matrices[0], rows)
    block_rows = [[2, 3, 4]]
    block = ModMatrixReference(block_rows, 5)
    child = ext_basis(parent, block)
    saved_child = child.basis_rows
    rows[0][0] = 0
    rows.append([0, 0])
    block_rows[0][0] = 0
    block_rows.clear()
    assert parent.basis_rows == ((5, 0), (0, 1))
    assert block.rows == ((2, 3, 4),)
    assert child.basis_rows == saved_child
    assert child.public.rows == ((1, 0, 2, 3, 4),)


def test_validated_objects_and_security_markers_cannot_be_reassigned():
    params = CHKPAlgebraParams(1, 1, 5)
    public = ModMatrixReference([[1]], 5)
    basis = KernelBasis(public, [[5]])
    for obj, field, value in [
        (params, "n", 0), (params, "depth", 3), (params, "security_claim", "secure"),
        (public, "q", 4), (public, "rows", ((0,),)),
        (basis, "public", ModMatrixReference([[0]], 5)),
        (basis, "basis_rows", ((1,),)), (basis, "security_claim", "secure"),
        (basis, "is_randomized", True),
    ]:
        with pytest.raises(FrozenInstanceError):
            setattr(obj, field, value)
    assert params.security_claim == basis.security_claim == "none"
    assert basis.public == public
    assert basis.basis_rows == ((5,),)
    assert not basis.is_randomized
