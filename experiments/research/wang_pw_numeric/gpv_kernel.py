"""ctypes wrapper for the OpenMP GPV X kernel (Fortran-order arrays)."""
import ctypes
import subprocess
from pathlib import Path

import numpy as np

_HERE = Path(__file__).parent
_SO = _HERE / "libgpv_kernel.so"
if not _SO.exists():
    subprocess.run(
        ["gcc", "-O3", "-fopenmp", "-shared", "-fPIC",
         str(_HERE / "gpv_kernel.c"), "-o", str(_SO)],
        check=True,
    )
_LIB = ctypes.CDLL(str(_SO))
_LIB.sample_x.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_double, ctypes.c_int,
]
_LIB.sample_x.restype = None


def sample_x_c(B, star, norms, P, sigma, threads=16):
    B = np.asfortranarray(B)
    star = np.asfortranarray(star)
    P = np.asfortranarray(P)
    m, w = P.shape
    assert B.shape == (m, m) and star.shape == (m, m)
    X = np.empty((m, w), order="F", dtype=np.int64)
    _LIB.sample_x(B.ctypes.data, star.ctypes.data, norms.ctypes.data,
                  P.ctypes.data, X.ctypes.data, m, w, float(sigma), int(threads))
    return X
