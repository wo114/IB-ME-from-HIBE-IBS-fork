"""Exact FLINT fraction-free Gram geometry through an explicit local tool.

For G=B^t B, unpivoted Bareiss gives principal minors D_i, norms D_{i+1}/D_i
and mu_ij=F_ij/F_ii. Augmenting G by B^t also gives the exact GPV projection
weights F_i,n+j/F_ii. No approximate arithmetic or native RNG is involved.
The executable is a trusted local dependency, never a suite-selected path.
Private matrices, geometry and native diagnostics are excluded from receipts.
"""

import os
from pathlib import Path
import re
import subprocess
import tempfile

from sage.all import QQ, ZZ, matrix

VERSION = b"IBME-EXACT-GRAM/1 "
MAX_CONTENT_BYTES = 2**30


def require_provider(executable=None):
    selected = executable if executable is not None else os.environ.get("IBME_EXACT_GRAM_EXECUTABLE")
    if not selected or not Path(selected).is_file():
        raise ValueError("explicit local exact Gram executable required")
    path = Path(selected).resolve()
    result = subprocess.run([str(path), "--version"], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=10, check=False)
    if result.returncode or not result.stdout.startswith(VERSION) or len(result.stdout) > 256:
        raise ValueError("incompatible local exact Gram executable")
    return path


def _rational(token):
    if len(token) > 40000:
        raise ValueError("exact Gram rational text budget exceeded")
    if re.fullmatch(rb"-?[0-9]+(?:/[1-9][0-9]*)?", token) is None:
        raise ArithmeticError("invalid exact rational geometry")
    value = QQ(token.decode("ascii"))
    if max(abs(int(value.numerator())).bit_length(), int(value.denominator()).bit_length()) > 65536:
        raise ValueError("exact Gram rational bit budget exceeded")
    return value


def gram_geometry(columns_matrix, *, executable=None, projection_weights=False, norms_only=False):
    path = require_provider(executable)
    b = matrix(ZZ, columns_matrix)
    d = b.ncols()
    if b.nrows() != d or not 1 <= d <= 1536:
        raise ValueError("bounded square integer basis required")
    if projection_weights and norms_only:
        raise ValueError("projection weights require complete geometry")
    if any(abs(int(v)).bit_length() > 65536 for v in b.list()):
        raise ValueError("exact Gram input integer budget exceeded")
    encoded = (str(d) + " " + " ".join(str(v) for v in b.list()) + "\n").encode("ascii")
    if len(encoded) > MAX_CONTENT_BYTES:
        raise ValueError("exact Gram input content budget exceeded")
    command = [str(path)]
    if projection_weights:
        command.append("--projections")
    elif norms_only:
        command.append("--norms-only")
    # Keep large private output off the Python heap and never expose stderr.
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(command, input=encoded, stdout=output,
                                stderr=subprocess.DEVNULL, check=False)
        if result.returncode:
            raise ArithmeticError("exact Gram provider rejected the input")
        if output.tell() > MAX_CONTENT_BYTES:
            raise ValueError("exact Gram returned content budget exceeded")
        output.seek(0)
        lengths = tuple(_rational(output.readline().strip()) for _ in range(d))
        if any(value <= 0 for value in lengths):
            raise ArithmeticError("positive definite exact Gram required")
        if norms_only:
            if output.read(1):
                raise ArithmeticError("invalid exact Gram geometry format")
            return lengths
        if output.readline().strip() != b"MU":
            raise ArithmeticError("invalid exact Gram geometry format")
        mu = matrix(QQ, d, d)
        for i in range(d):
            for j in range(i + 1, d):
                mu[i, j] = _rational(output.readline().strip())
        if projection_weights:
            if output.readline().strip() != b"WEIGHTS":
                raise ArithmeticError("invalid exact Gram projection format")
            weights = tuple(tuple(_rational(output.readline().strip()) for _ in range(d)) for _ in range(d))
        if output.read(1):
            raise ArithmeticError("invalid exact Gram trailing content")
    return (lengths, mu, weights) if projection_weights else (lengths, mu)


def size_reduce_and_check(basis_columns, upper, *, executable=None):
    b = matrix(ZZ, basis_columns)
    lengths, mu = gram_geometry(b, executable=executable)
    for j in range(b.ncols()):
        for i in reversed(range(j)):
            nearest = ZZ((mu[i, j] + QQ(1)/2).floor())
            if nearest:
                b.add_multiple_of_column(j, i, -nearest)
                for k in range(i):
                    mu[k, j] -= nearest * mu[k, i]
                mu[i, j] -= nearest
    if max(lengths) > upper:
        raise ArithmeticError("LLL public GS bound failed")
    for j in range(b.ncols()):
        for i in range(j):
            if abs(mu[i, j]) > QQ(1)/2:
                raise ArithmeticError("LLL exact size reduction failed")
            if i == j - 1 and lengths[j] + mu[i, j]**2 * lengths[i] < QQ(74)/100 * lengths[i]:
                raise ArithmeticError("LLL exact Lovasz condition failed")
    return b
