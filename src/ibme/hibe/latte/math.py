"""Independent coefficient-ring checks; no FFT, native RNG or sampling calls."""
from fractions import Fraction
from functools import lru_cache
from .params import N, Q, SIGMA


@lru_cache(maxsize=1)
def rings():
    try:
        from sage.all import ZZ, PolynomialRing, Integers
    except ImportError:
        from ibme.core.errors import InvalidParameterError
        raise InvalidParameterError("LATTE private math requires WSL ~/miniconda3/envs/sage") from None
    p = PolynomialRing(ZZ, "x")
    pmod = PolynomialRing(Integers(Q), "x")
    return p.quotient(p.gen()**N+1), pmod.quotient(pmod.gen()**N+1)


def element(ring, coefficients):
    return ring(ring.cover_ring()(coefficients))


def vector_hash(public, parent, child=None):
    """Separate classical-ROM hash domains, injective context framing, uniform Rq."""
    from hashlib import shake_256
    from ibme.core.encoding import encode_bytes
    domain = b"IBME:LATTE3:H:DELEGATE:v1" if child is None else b"IBME:LATTE3:H:EXTRACT:v1"
    context = encode_bytes(public.to_bytes()) + encode_bytes(parent)
    if child is not None:
        context += encode_bytes(child)
    # A bounded public XOF rejection stream; not private Gaussian randomness.
    raw = shake_256(domain + context).digest(5 * 2048)
    result = []
    for i in range(0, len(raw), 5):
        v = int.from_bytes(raw[i:i+5], "big") & ((1 << 36)-1)
        if v < Q:
            result.append(v)
            if len(result) == N:
                return tuple(result)
    raise RuntimeError("LATTE public hash rejection budget exhausted")


def check_basis(public, basis, identity=None):
    ring, mod = rings()
    from sage.all import matrix
    dim = 2 if identity is None else 3
    b = [element(ring, row) for row in basis]
    a = [mod(1), element(mod, public.h)]
    if identity is not None:
        a.append(element(mod, vector_hash(public, identity)))
    for i in range(dim):
        if sum(mod(b[i*dim+j].lift())*a[j] for j in range(dim)) != 0:
            raise ValueError("LATTE basis/public/path kernel binding")
    # Exact ring determinant +/-q implies complete coefficient lattice index q^N.
    if matrix(ring, dim, dim, b).det() not in (ring(Q), ring(-Q)):
        raise ValueError("LATTE incomplete or altered ring basis")


def check_leaf(public, parent, child, secret):
    _, mod = rings()
    a1 = element(mod, vector_hash(public, parent))
    a2 = element(mod, vector_hash(public, parent, child))
    t = [element(mod, p) for p in secret]
    residual = (a2-element(mod, public.h)*t[0]-a1*t[1]).lift().list()
    residual += [0]*(N-len(residual))
    centred = [int(v) if int(v) <= Q//2 else int(v)-Q for v in residual]
    norm = sum(v*v for v in centred) + sum(v*v for p in secret for v in p)
    # Public, conservative import/issuance norm event, independent of observed keys.
    # This is a finite research guard, not a closed sampler/security failure bound.
    limit = 4*3*N*Fraction(SIGMA[2])**2
    if norm > limit:
        raise ValueError("LATTE leaf/path/public short-preimage binding")
