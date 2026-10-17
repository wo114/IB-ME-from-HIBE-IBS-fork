"""Exact public-only normal form; no Gaussian/security claim from algebra QA."""

import pytest

from experiments.research.structured_identity_view import identity_noise_view


@pytest.fixture
def case():
    q = 101
    root = ((1, 0, 7), (0, 1, 9))
    leaf = ((1, 0, 7, 11, 12, 13, 14, 15, 16),
            (0, 1, 9, 21, 22, 23, 24, 25, 26))
    secret = (37, 85)
    error = (2, -3, 4, -1, 0, 1, 2, -2, 3)
    preamble = tuple((sum(leaf[i][j]*secret[i] for i in range(2))+error[j]) % q
                     for j in range(9))
    return root, leaf, preamble, error, q


def test_canceling_public_identity_uses_only_two_H_blocks(case):
    root, leaf, preamble, error, q = case
    h, b = identity_noise_view(root, leaf, preamble, q)
    assert h == tuple(row[3:] for row in leaf) and len(b) == 6
    z = tuple(-x for x in error[:2])
    assert b == tuple((sum(h[i][j]*z[i] for i in range(2))+error[3+j]) % q for j in range(6))
    assert tuple((preamble[i]+z[i]) % q for i in range(2)) == (37, 85)


@pytest.mark.parametrize("which", ["not_identity", "different_root", "short_preamble",
    "foreign_residue", "boolean_residue", "wrong_leaf_dimension"])
def test_view_does_not_silently_normalize_a_different_public_layout(case, which):
    root, leaf, preamble, error, q = case
    if which == "not_identity": root = ((2, 0, 7), root[1])
    elif which == "different_root": root = ((1, 0, 8), root[1])
    elif which == "short_preamble": preamble = preamble[:-1]
    elif which == "foreign_residue": preamble = (q,)+preamble[1:]
    elif which == "boolean_residue": preamble = (True,)+preamble[1:]
    elif which == "wrong_leaf_dimension": leaf = tuple(row[:-1] for row in leaf)
    with pytest.raises(ValueError): identity_noise_view(root, leaf, preamble, q)
