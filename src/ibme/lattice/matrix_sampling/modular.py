"""Exact wide-modulus matrix arithmetic through the bundled PARI library.

No entropy, floating coefficients, approximate inverse or native key generation.
Results are independently checked over ZZ modulo q. Matrix input sizes/entries
are gated before PARI; its internal stack usage is a separate runtime resource.
"""

from itertools import islice

from sage.all import ZZ, matrix, identity_matrix
from cypari2.handle_error import PariError

from .scalar import exact_integer


def integer_square(rows):
    if hasattr(rows,"rows") and callable(rows.rows):
        if rows.nrows()!=rows.ncols() or not 1<=rows.nrows()<=1536:
            raise ValueError("bounded exact square matrix required")
        rows=rows.rows()
    try:
        rows=tuple(islice(iter(rows),1537))
        if not 1<=len(rows)<=1536:raise ValueError("matrix dimension outside resource domain")
        rows=tuple(tuple(islice(iter(row),len(rows)+1)) for row in rows)
    except TypeError as exc:raise ValueError("exact square matrix required") from exc
    if any(len(row)!=len(rows) for row in rows):raise ValueError("square matrix dimension mismatch")
    if any(isinstance(x,bool) or not isinstance(x,(int,type(ZZ(0)))) or abs(int(x)).bit_length()>4096
           for row in rows for x in row):raise ValueError("exact bounded signed matrix entries required")
    return matrix(ZZ,rows)


def proven_prime(q):
    q=exact_integer(q,"q",minimum=3,maximum=2**256-1)
    if q%2==0 or not ZZ(q).is_prime(proof=True):raise ValueError("proven odd prime required")
    return q


def modular_determinant(rows,q):
    a=integer_square(rows);q=proven_prime(q)
    try:
        value=int(a.__pari__().matdetmod(q))
    except PariError as exc:
        raise ArithmeticError("native modular determinant failed; no fallback") from exc
    if not 0<=value<q:raise ArithmeticError("native modular determinant is noncanonical")
    return value


def modular_inverse(rows,q):
    a=integer_square(rows);q=proven_prime(q)
    try:
        inverse=matrix(ZZ,a.__pari__().matinvmod(q))
    except PariError as exc:
        raise ArithmeticError("native modular inverse failed; no fallback") from exc
    if inverse.dimensions()!=a.dimensions():raise ArithmeticError("native inverse dimension mismatch")
    if any(not 0<=x<q for x in inverse.list()):raise ArithmeticError("native inverse residues are noncanonical")
    unit=identity_matrix(ZZ,a.nrows())
    if any(x%q for x in (a*inverse-unit).list()) or any(x%q for x in (inverse*a-unit).list()):
        raise ArithmeticError("native inverse failed exact left/right equations")
    inverse.set_immutable()
    return inverse
