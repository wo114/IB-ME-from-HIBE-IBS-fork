"""Exact cached GSO equivalence using public deterministic algebra fixtures.

No private state, Gaussian samples or actual key generation is used. For a
bounded timing diagnostic in prescribed Sage, run this file with --benchmark;
timing is not a unit-test assertion or a prediction for the full CHKP pipeline.
"""

from copy import copy
from hashlib import sha256
import json
import platform
from statistics import median
from time import perf_counter

import pytest

pytest.importorskip("sage.all")
from sage.all import QQ, ZZ, matrix
from sage.version import version as sage_version

from ibme.lattice.chkp import basis_reduce
from ibme.lattice.chkp.basis import KernelBasis, ModMatrixReference, complete_kernel_basis


def public_dense(dimension):
    # Strict diagonal dominance supplies an elementary nonsingularity
    # certificate. Hashes specify public integer entries, not random sampling.
    return matrix(ZZ, dimension, dimension, lambda i, j:
        (dimension*256 if i == j else 0)
        + sha256(f"PUBLIC-LLL-GSO/{dimension}/{i}/{j}".encode()).digest()[0] - 128)


def sage_geometry(basis):
    star, _ = basis.transpose().change_ring(QQ).gram_schmidt()
    return star, tuple(row.dot_product(row) for row in star.rows())


@pytest.mark.parametrize("dimension", [1, 2, 4, 8, 16, 32])
def test_cached_exact_gso_matches_every_sage_entry(dimension):
    basis = public_dense(dimension)
    before = copy(basis)
    actual = basis_reduce._exact_column_gso(basis)
    expected = sage_geometry(basis)
    assert actual == expected
    assert basis == before
    assert actual[0].base_ring() is QQ
    assert all(length.parent() is QQ for length in actual[1])


@pytest.mark.parametrize("rows", [
    [[0, 0], [0, 0], [0, 0]],
    [[1, 2, 0], [2, 4, 0]],
    [[1, 2, 3], [4, 5, 6], [7, 8, 9], [2, -3, 1]],
    [[QQ(1)/3, QQ(2)/7], [QQ(11)/5, QQ(-19)/23], [QQ(5)/17, QQ(29)/31]],
    [[2**257+1, 2**513-1, 2], [3, 2**129, -17], [7, 11, 13]],
])
def test_rational_rectangular_dependent_and_large_entries_match_sage(rows):
    basis = matrix(QQ, rows)
    assert basis_reduce._exact_column_gso(basis) == sage_geometry(basis)


@pytest.mark.parametrize("dimension", [2, 5, 9])
def test_checked_lll_output_is_identical_with_old_or_cached_gso(monkeypatch, dimension):
    base = complete_kernel_basis(ModMatrixReference([[1] + [2]*(dimension-1)], 17))
    mixed = matrix(ZZ, base.basis_rows)
    for j in range(1, dimension):
        mixed.add_multiple_of_column(j, j-1, (j+1)**3)
    base = KernelBasis(base.public, mixed)
    bound = 17**2*dimension
    actual = basis_reduce.checked_lll(base, bound)
    monkeypatch.setattr(basis_reduce, "_exact_column_gso", sage_geometry)
    expected = basis_reduce.checked_lll(base, bound)
    assert actual == expected
    assert actual.public == base.public


def benchmark():
    """Fixed public fixtures, three alternated pairs per dimension, no secrets."""
    results = []
    for dimension in (24, 40, 64):
        basis = public_dense(dimension)
        old_times, new_times = [], []
        for repetition in range(3):
            methods = (("old", sage_geometry), ("new", basis_reduce._exact_column_gso))
            if repetition % 2:
                methods = tuple(reversed(methods))
            values = {}
            for name, method in methods:
                started = perf_counter()
                values[name] = method(basis)
                (old_times if name == "old" else new_times).append(perf_counter() - started)
            assert values["old"] == values["new"]
        results.append(dict(dimension=dimension, repetitions=3, exact_equal=True,
                            original_seconds=old_times, cached_seconds=new_times,
                            median_speedup=median(old_times)/median(new_times)))
    return dict(public_fixtures_only=True, private_input_read=False,
                environment=dict(python=platform.python_version(), sage=sage_version,
                                 platform=platform.platform(), processor=platform.processor()),
                security_claim="none", parameters_are_formal=False,
                algorithm="same QQ original-column recurrence with cached norms",
                limitation="local contended timings; not whole-pipeline prediction", results=results)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", action="store_true", required=True)
    parser.parse_args()
    print(json.dumps(benchmark(), indent=2))
