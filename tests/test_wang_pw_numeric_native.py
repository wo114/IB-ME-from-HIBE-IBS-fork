"""Reject unsafe native ABI inputs before entering the experimental C kernel."""
import os
import subprocess
import sys
from types import SimpleNamespace

import numpy as np
import pytest

pytest.importorskip("sage.all")


@pytest.mark.parametrize("case", [
    "basis_dtype", "particular_dtype", "star_dtype", "norms_dtype", "short_norms",
    "strided_norms", "zero_norm", "nan_norm", "nan_star", "zero_sigma", "nan_sigma",
    "bool_sigma", "zero_threads", "bool_threads", "too_many_threads", "basis_shape",
    "empty_targets", "vector_targets",
])
def test_invalid_native_input_does_not_enter_c(monkeypatch, case):
    from experiments.research.wang_pw_numeric import gpv_kernel as kernel

    called = []
    monkeypatch.setattr(kernel, "_LIB", SimpleNamespace(sample_x=lambda *args: called.append(True)))
    args = dict(B=np.eye(2, dtype=np.int64), star=np.eye(2, dtype=np.float64),
                norms=np.ones(2, dtype=np.float64), P=np.zeros((2, 1), dtype=np.int64),
                sigma=2.0, threads=1)
    changes = {
        "basis_dtype": dict(B=args["B"].astype(np.float32)),
        "particular_dtype": dict(P=args["P"].astype(np.float64)),
        "star_dtype": dict(star=args["star"].astype(np.float32)),
        "norms_dtype": dict(norms=args["norms"].astype(np.float32)),
        "short_norms": dict(norms=np.ones(1, dtype=np.float64)),
        "strided_norms": dict(norms=np.array([1., 0., 1., 0.])[::2]),
        "zero_norm": dict(norms=np.array([1., 0.])),
        "nan_norm": dict(norms=np.array([1., np.nan])),
        "nan_star": dict(star=np.full((2, 2), np.nan)),
        "zero_sigma": dict(sigma=0.0), "nan_sigma": dict(sigma=float("nan")),
        "bool_sigma": dict(sigma=True), "zero_threads": dict(threads=0),
        "bool_threads": dict(threads=True), "too_many_threads": dict(threads=257),
        "basis_shape": dict(B=np.eye(1, dtype=np.int64)),
        "empty_targets": dict(P=np.zeros((2, 0), dtype=np.int64)),
        "vector_targets": dict(P=np.zeros(2, dtype=np.int64)),
    }
    args.update(changes[case])
    with pytest.raises((TypeError, ValueError)):
        kernel.sample_x_c(**args)
    assert not called


def test_native_shape_guard_survives_optimized_python():
    code = """
import numpy as np
from types import SimpleNamespace
from experiments.research.wang_pw_numeric import gpv_kernel as k
called = []
k._LIB = SimpleNamespace(sample_x=lambda *args: called.append(True))
try:
    k.sample_x_c(np.eye(1, dtype=np.int64), np.eye(2), np.ones(2),
                 np.zeros((2, 1), dtype=np.int64), 2., threads=1)
except ValueError:
    if called:
        raise RuntimeError('invalid input entered C')
else:
    raise RuntimeError('shape validation was optimized away')
print('rejected before native')
"""
    env = dict(os.environ, OPENBLAS_NUM_THREADS="1", OMP_NUM_THREADS="1")
    result = subprocess.run([sys.executable, "-O", "-c", code], env=env,
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "rejected before native"
