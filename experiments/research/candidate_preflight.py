"""Exact public algebra prerequisites, NOT TrapGen/DelTrap or secure backends.

All examples are deterministic teaching inputs. Complete kernel bases below
are public and deliberately have no shortness or Gaussian distribution claim.
"""

import argparse
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import platform
import sys


def _prime_matrix(matrix_value, q):
    from sage.all import ZZ
    if isinstance(q, bool) or not isinstance(q, int) or not 3 <= q <= 257 or not ZZ(q).is_prime(proof=True):
        raise ValueError("prime teaching modulus 3..257 required")
    if matrix_value.base_ring() != ZZ or not 1 <= matrix_value.nrows() <= 4 or not matrix_value.nrows() < matrix_value.ncols() <= 16:
        raise ValueError("bounded wide public matrix required")


def complete_kernel_basis(public, q):
    """A PUBLIC full kernel basis from modular elimination, not a trapdoor."""
    from sage.all import GF, ZZ, identity_matrix, matrix, zero_matrix, block_matrix
    _prime_matrix(public, q)
    a = matrix(GF(q), public)
    pivots = list(a.pivots())
    if len(pivots) != public.nrows(): raise ValueError("public matrix must have full modular row rank")
    rest = [i for i in range(public.ncols()) if i not in pivots]
    n, r = public.nrows(), len(rest)
    d = a.matrix_from_columns(pivots).inverse() * a.matrix_from_columns(rest)
    d = matrix(ZZ, n, r, [ZZ(x) for x in d.list()])
    base = block_matrix(ZZ, [[q * identity_matrix(ZZ, n), -d],
                             [zero_matrix(ZZ, r, n), identity_matrix(ZZ, r)]])
    result = zero_matrix(ZZ, public.ncols())
    for i, original in enumerate(pivots + rest): result[original, :] = base[i, :]
    if matrix(GF(q), public * result) != 0 or abs(result.det()) != q**n:
        raise RuntimeError("public complete kernel construction failed")
    return result


def extend_basis(public, basis, suffix, q):
    """CHKP's ExtBasis algebra only; child exposes parent basis until RandBasis."""
    from sage.all import GF, ZZ, identity_matrix, matrix, zero_matrix, block_matrix
    _prime_matrix(public, q)
    if (basis.base_ring() != ZZ or suffix.base_ring() != ZZ
            or basis.nrows() != public.ncols() or basis.ncols() != public.ncols()
            or suffix.nrows() != public.nrows() or not 1 <= suffix.ncols() <= 8
            or public.ncols() + suffix.ncols() > 16
            or matrix(GF(q), public * basis) != 0 or abs(basis.det()) != q**public.nrows()):
        raise ValueError("invalid full parent basis or extension dimensions")
    a = matrix(GF(q), public)
    if a.rank() != public.nrows(): raise ValueError("full modular row rank required")
    preimage = a.solve_right(matrix(GF(q), suffix))
    x = matrix(ZZ, preimage.nrows(), preimage.ncols(), [ZZ(t) for t in preimage.list()])
    r = suffix.ncols()
    result = block_matrix(ZZ, [[basis, -x], [zero_matrix(ZZ, r, public.ncols()), identity_matrix(ZZ, r)]])
    expanded = public.augment(suffix)
    if matrix(GF(q), expanded * result) != 0 or abs(result.det()) != q**public.nrows():
        raise RuntimeError("ExtBasis exact kernel/determinant failed")
    return expanded, result


def chkp_algebra():
    from sage.all import ZZ, matrix
    q, n, m = 17, 2, 4
    public = matrix(ZZ, [[1, 0, 3, 5], [0, 1, 7, 2]])
    basis, rows = complete_kernel_basis(public, q), []
    for level in range(3):
        rows.append(dict(level=level, columns=public.ncols(), basis_shape=list(basis.dimensions()),
                         kernel_equation=True, determinant=int(abs(basis.det()))))
        if level < 2:
            suffix = matrix(ZZ, n, m, lambda i, j: (5 * i + 3 * j + level + 1) % q)
            public, basis = extend_basis(public, basis, suffix, q)
    return dict(n=n, base_columns=m, q=q, rows=rows, security_claim="none", backend_admitted=False,
                randbasis_implemented=False, gaussian_sampling_implemented=False,
                note="Public long bases and ExtBasis only. Parent basis remains visible: these objects MUST NOT be issued as user keys.")


def abb_fixed_dimension_algebra():
    from sage.all import GF, ZZ, matrix, diagonal_matrix
    q = 17
    original = matrix(ZZ, [[1, 0, 3, 5], [0, 1, 7, 2]])
    basis = complete_kernel_basis(original, q)
    public, transformed, rows = matrix(GF(q), original), basis, []
    for level, diagonal in enumerate(([2, 1, 1, 1], [1, 3, 1, 1]), start=1):
        change = diagonal_matrix(ZZ, diagonal)
        public = public * matrix(GF(q), change).inverse()
        transformed = change * transformed
        lifted = matrix(ZZ, public.nrows(), public.ncols(), [ZZ(x) for x in public.list()])
        full = complete_kernel_basis(lifted, q)
        if public * matrix(GF(q), transformed) != 0: raise RuntimeError("fixed-dimension transformed kernel failed")
        rows.append(dict(level=level, columns=public.ncols(), complete_basis_determinant=int(abs(full.det())),
                         multiply_only_determinant=int(abs(transformed.det())),
                         multiply_only_sublattice_index=int(abs(transformed.det()) // abs(full.det())),
                         multiply_only_is_complete_basis=abs(transformed.det()) == abs(full.det())))
    return dict(q=q, n=2, m=4, rows=rows, security_claim="none", backend_admitted=False,
                sampler_R_implemented=False, short_basis_completion_implemented=False,
                note="Multiplication alone yields a proper sublattice (indices 2,6). Public elimination completes only a long basis; it is NOT ABB BasisDel.")


def ring_algebra():
    from sage.all import ZZ, PolynomialRing
    from ibme.ibs.luo_module_math import negacyclic_schoolbook
    degree = 8
    polynomials = PolynomialRing(ZZ, "X")
    x = polynomials.gen()
    ring = polynomials.quotient(x**degree + 1, "a")
    values = tuple(i - 4 for i in range(degree)), tuple((-1)**i * (i + 1) for i in range(degree))
    product = (ring(polynomials(values[0])) * ring(polynomials(values[1]))).lift()
    exact = tuple(int(product[i]) for i in range(degree))
    for q in (17, 81):
        if tuple(t % q for t in negacyclic_schoolbook(*values)) != tuple(t % q for t in exact):
            raise RuntimeError("ring convolution/modulus mismatch")
    f, g, F, G = ring(1), ring(x), ring(x**2), ring(17 + x**3)
    if f * G - g * F != ring(17): raise RuntimeError("toy NTRU integer identity failed")
    return dict(degree=degree, moduli=[17, 81], negacyclic_product_matches_sage=True,
                composite_modulus_tested=True, toy_NTRU_integer_identity=True, security_claim="none",
                actual_NTRU_keygen=False, ring_sampler_implemented=False,
                note="Only ring arithmetic and a public trivial NTRU identity. No LATTE, Zhang or Sageloli signature/encryption is implemented here.")


def ibs_smoke():
    from ibme.core.randomness import DeterministicRandom
    from ibme.ibs.luo import LuoIBSBackend, LuoMatrixParams
    from ibme.ibs.luo_module import LuoModuleIBSBackend, LuoModuleParams
    from ibme.ibs.luo_module_codec import encode_compact, decode_compact
    rows = []
    for name, backend_type, params in (("luo-matrix", LuoIBSBackend, LuoMatrixParams()),
                                     ("luo-module", LuoModuleIBSBackend, LuoModuleParams())):
        backend = backend_type(rng=DeterministicRandom(b"candidate-preflight:" + name.encode()))
        public, master = backend.setup(params)
        key = backend.key_extract(master, b"Alice")
        signature = backend.sign(key, b"foundation")
        loaded = backend.load_signature(public, signature.to_bytes())
        if not (backend.verify(public, b"Alice", b"foundation", loaded)
                and not backend.verify(public, b"Other", b"foundation", loaded)
                and not backend.verify(public, b"Alice", b"changed", loaded)):
            raise RuntimeError("existing IBS primitive smoke failed")
        row = dict(candidate_id=name, setup_extract_sign_verify=True, signature_bytes=len(signature.to_bytes()),
                   identity_bytes=5, message_bytes=10, repeats=1, parameters=asdict(params),
                   security_claim="none", backend_admitted=False)
        if name == "luo-module":
            compact = encode_compact(signature)
            if decode_compact(compact, public).to_bytes() != signature.to_bytes(): raise RuntimeError("lossless smoke failed")
            row["compact_signature_bytes"] = len(compact)
        rows.append(row)
    return rows


def audit():
    from sage.version import version
    root = Path(__file__).resolve().parents[2]
    source = "experiments/research/candidate_preflight.py"
    return dict(security_claim="none", backend_admitted=False, parameter_admission=False,
                python=sys.version, sage=version, platform=platform.platform(), processor=platform.processor(),
                entropy="Deterministic public examples and test-only IBS random streams", repeats=1,
                rom="Existing Luo hash interpretation only; algebra examples have no security-model claim",
                chkp=chkp_algebra(), abb=abb_fixed_dimension_algebra(), ring=ring_algebra(), ibs=ibs_smoke(),
                source_sha256_lf={source: sha256((root / source).read_bytes().replace(b"\r\n", b"\n")).hexdigest()},
                limits="No new full HIBE/IBS backend, secure parameter, timing comparison or proof follows from these prerequisites.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(dict(algebra_probes=3, existing_ibs_smokes=2, security_claim="none")))


if __name__ == "__main__": main()
