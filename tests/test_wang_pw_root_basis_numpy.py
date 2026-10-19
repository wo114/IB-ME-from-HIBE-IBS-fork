"""Numpy MP12 root-basis formula test (q32, n=16)."""
import numpy as np
import pytest

pytest.importorskip("sage.all")

from experiments.research.wang_pw_numeric.numeric_gpv_ibs import numeric_gs
from experiments.research.wang_pw_numeric.root_basis_numpy import root_basis_numpy


def test_root_basis_matches_sage_width_n16():
    n, q = 16, 4294967291
    k = (q - 1).bit_length()
    w = n * k
    rng = np.random.default_rng(0)
    a_bar = rng.integers(0, q, size=(n, w), dtype=np.int64)
    R = np.rint(rng.normal(0, 4, size=(w, w))).astype(np.int64)
    A, T = root_basis_numpy(a_bar, R, q)
    assert T.shape == (2 * w, 2 * w)
    star, norms = numeric_gs(T)
    assert abs(float(np.sqrt(norms.max())) - 204.206) < 1e-2
    obj = A.astype(object)
    for j in range(0, T.shape[1], max(1, T.shape[1] // 8)):
        assert all(int(x) % q == 0 for x in (obj @ T[:, j].astype(object)))
