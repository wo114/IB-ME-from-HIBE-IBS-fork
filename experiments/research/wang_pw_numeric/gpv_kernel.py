"""ctypes wrapper for the OpenMP GPV X kernel (Fortran-order arrays)."""
import ctypes
import hashlib
import math
from numbers import Real
import subprocess
from pathlib import Path

import numpy as np

_HERE = Path(__file__).parent
_SOURCE = _HERE / "gpv_kernel.c"
_SOURCE_ID = hashlib.sha256(_SOURCE.read_bytes()).hexdigest()[:16]
_SO = _HERE / ("libgpv_kernel-" + _SOURCE_ID + ".so")
if not _SO.exists():
    subprocess.run(
        ["gcc", "-O3", "-fopenmp", "-shared", "-fPIC",
         str(_SOURCE), "-o", str(_SO)],
        check=True,
    )
_LIB = ctypes.CDLL(str(_SO))
_LIB.sample_x.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_double, ctypes.c_int,
]
_LIB.sample_x.restype = None


def sample_x_c(B, star, norms, P, sigma, threads=16):
    """Sample with the numeric test kernel after checking its native ABI.

    This validates buffers and scalar arguments, not the distribution law or
    a general arithmetic error bound for arbitrary integer inputs.
    """
    B, star, norms, P = (np.asarray(value) for value in (B, star, norms, P))
    for label, value, dtype in (("B", B, np.int64), ("P", P, np.int64),
                                ("star", star, np.float64), ("norms", norms, np.float64)):
        if value.dtype != np.dtype(dtype):
            raise TypeError(label + " has the wrong native dtype")
    if P.ndim != 2:
        raise ValueError("P must be a matrix")
    m, w = P.shape
    if not (0 < m <= 2**31 - 1 and 0 < w <= 2**31 - 1):
        raise ValueError("P dimensions exceed the native integer domain")
    if B.shape != (m, m) or star.shape != (m, m):
        raise ValueError("basis and Gram-Schmidt shapes must match P")
    if norms.shape != (m,) or not norms.flags.c_contiguous:
        raise ValueError("norms must be a contiguous vector of length m")
    if not np.isfinite(star).all() or not np.isfinite(norms).all() or not (norms > 0).all():
        raise ValueError("Gram-Schmidt data must be finite with positive norms")
    if isinstance(sigma, (bool, np.bool_)) or not isinstance(sigma, Real):
        raise TypeError("sigma must be a real number")
    sigma = float(sigma)
    if not math.isfinite(sigma) or sigma <= 0:
        raise ValueError("sigma must be positive and finite")
    if isinstance(threads, (bool, np.bool_)) or not isinstance(threads, (int, np.integer)):
        raise TypeError("threads must be an integer")
    if not 1 <= int(threads) <= 256:
        raise ValueError("threads must be in the research limit 1..256")
    B = np.asfortranarray(B)
    star = np.asfortranarray(star)
    P = np.asfortranarray(P)
    X = np.empty((m, w), order="F", dtype=np.int64)
    _LIB.sample_x(B.ctypes.data, star.ctypes.data, norms.ctypes.data,
                  P.ctypes.data, X.ctypes.data, m, w, float(sigma), int(threads))
    return X
