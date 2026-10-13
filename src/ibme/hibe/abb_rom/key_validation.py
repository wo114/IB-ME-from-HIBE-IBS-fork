"""Primitive-internal public path and complete secret-basis validation."""

from functools import lru_cache

from sage.all import ZZ, matrix

from ibme.lattice.research import KernelBasis, ModMatrixReference
from experiments.research.chkp_basis import gram_schmidt_squared_lengths
from ibme.lattice.matrix_sampling.modular import modular_inverse
from .params import ABBROMParams
from .identity import prefix_matrix


@lru_cache(maxsize=8)
def _expected_matrix(params_bytes, a, u0, path):
    from .objects import ABBPublicKey
    params = ABBROMParams.from_bytes(params_bytes)
    public = ABBPublicKey(params,a,u0)
    result = matrix(ZZ,a)
    for level in range(1,len(path)+1):
        transform = prefix_matrix(public.context,path[:level],params)
        result = (result*modular_inverse(transform,params.q)).apply_map(lambda x:x%params.q)
    return ModMatrixReference(tuple(tuple(int(x) for x in row) for row in result.rows()),params.q)


def expected_matrix(public,path):
    if not isinstance(path,tuple) or len(path)>2:
        raise ValueError("ABB path depth")
    return _expected_matrix(public.params.to_bytes(),public.a,public.u0,path)


def validate_basis(public,path,rows):
    p = public.params
    basis = KernelBasis(expected_matrix(public,path),rows)
    if not path:
        from .trapgen import ABBTrapGenParams
        upper = ABBTrapGenParams(p.n,p.q,p.random_rows,p.root_m1,p.root_m2,
            hadamard_scale=p.hadamard_scale,uniform_trials=p.uniform_trials).gs_squared_bound
        if p.normalized_root_gs_squared_bound is not None:
            upper = p.normalized_root_gs_squared_bound
    else:
        upper = (p.sigma1_squared if len(path)==1 else p.sigma2_squared)*p.dimension
    # Public bound and private algebra only; this cannot certify provenance.
    columns = matrix(ZZ,rows).columns()
    if max(sum(int(x)**2 for x in col) for col in columns)>upper:
        if max(gram_schmidt_squared_lengths(rows))>upper:
            raise ValueError("ABB private basis fails declared GS limit")
    return basis
