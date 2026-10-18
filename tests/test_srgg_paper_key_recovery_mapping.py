"""Check the Table 4 column equation and printed BKZ-input sensitivity."""
from math import sqrt

import pytest

from experiments.research.candidates.srgg.paper_algebra import PaperRing, public_matrix
from experiments.research.candidates.srgg.paper_key_recovery_mapping import report
from experiments.research.candidates.srgg.paper_parameters import PaperParams


@pytest.mark.parametrize("name,dimension,columns", [
    ("PARAM-I", 2049, 4), ("PARAM-II", 3073, 6), ("PARAM-III", 4097, 8),
])
def test_every_public_gadget_column_has_exact_cbd1_witness(name, dimension, columns):
    params = PaperParams(name)
    ring = PaperRing(params)
    n, rank, q = params.degree, params.rank, params.modulus
    a_hat = public_matrix(params, bytes(range(32)))
    # Sparse CBD1-support algebra fixture, not a sample from Setup's accepted law.
    witness = tuple(tuple(
        tuple(1 if k == (7*i+11*j) % n else
              -1 if k == (7*i+11*j+1) % n else 0 for k in range(n))
        for j in range(columns)) for i in range(2*rank))
    b = ring.build_public(a_hat, witness)
    gadget = ring.gadget()
    assert len(b) == rank and len(witness) == 2*rank
    for j in range(columns):
        s = tuple(witness[rank+i][j] for i in range(rank))
        e = tuple(witness[i][j] for i in range(rank))
        a_s = ring.matvec(a_hat, s, q)
        for i in range(rank):
            target = ring.add(gadget[i][j], ring.scale(b[i][j], -1), q)
            assert ring.add(a_s[i], e[i], q) == target
    assert (2*rank*n + 1, len(b[0])) == (dimension, columns)


def test_author_beta_threshold_changes_with_secret_norm_input():
    rows = report()["rows"]
    assert [row["q_ary_kernel_dimension_D"] for row in rows] == [2049, 3073, 4097]
    assert [row["first_beta_using_rms_surrogate_approx"] for row in rows] == [360, 614, 882]
    assert [row["first_beta_using_support_upper_approx"] for row in rows] == [380, 645, 925]
    for row in rows:
        assert row["squared_norm_expectation_before_setup_filter"] == row["coefficient_rows_m"]+1
        assert row["full_support_norm_upper"] == sqrt(row["q_ary_kernel_dimension_D"])
        assert row["max_witness_norm_at_author_beta_approx"] < row["unfiltered_rms_norm_surrogate"]
        assert row["accepted_root_norm_distribution_known"] is False
