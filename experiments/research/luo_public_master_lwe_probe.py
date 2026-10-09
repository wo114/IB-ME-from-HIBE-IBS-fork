"""Reproducible public-only recovery of one toy Luo master column.

Run only in the repository's designated Sage environment. This is a research
negative control for the hand-selected n=128, m=256, q=2^61-1, eta=1 input;
it is not a full-key recovery or a demonstrated forgery against a legal
parameter set.
"""

from __future__ import annotations

import hashlib
from time import perf_counter

from sage.all import GF, ZZ, matrix, set_random_seed, vector


SEED = 2026100916
N, M, Q, ETA, EQUATIONS = 128, 256, 2**61 - 1, 1, 16


def _matrix_digest(value, q: int) -> str:
    width = (q.bit_length() + 7) // 8
    digest = hashlib.sha256()
    digest.update(value.nrows().to_bytes(4, "big"))
    digest.update(value.ncols().to_bytes(4, "big"))
    for item in value.list():
        digest.update(int(item).to_bytes(width, "big"))
    return digest.hexdigest()


def recover_public_column(public_a, public_t, *, q: int, eta: int, equations: int) -> dict:
    """Attempt one-column recovery using only public A,T and public bounds."""
    n, m = public_a.nrows(), public_a.ncols()
    if n != N or m != M or q != Q or eta != ETA or equations != EQUATIONS:
        raise ValueError("probe is deliberately pinned to its reproducible research input")
    field = GF(q)
    if public_a.base_ring() != field or public_t.base_ring() != field or public_t.length() != n:
        raise ValueError("public input field or dimensions do not match the pinned probe")

    a0_inverse = public_a[:, :n].inverse()
    c = -a0_inverse * public_a[:, n:]
    a = a0_inverse * public_t
    free = m - n

    # Standard embedding for a partial set of the transformed LWE equations.
    basis = matrix(ZZ, equations + free + 1, equations + free + 1)
    for i in range(equations):
        basis[i, i] = q
    for j in range(free):
        for i in range(equations):
            residue = int(c[i, j])
            basis[equations + j, i] = residue if residue <= q // 2 else residue - q
        basis[equations + j, equations + j] = 1
    for i in range(equations):
        residue = int(a[i])
        basis[equations + free, i] = residue if residue <= q // 2 else residue - q
    basis[equations + free, equations + free] = 1

    start = perf_counter()
    reduced = basis.LLL(algorithm="fpLLL:heuristic")
    elapsed = perf_counter() - start
    recovered = False
    for row in reduced.rows():
        if abs(row[-1]) != 1:
            continue
        s1 = vector(field, [int(row[equations + j] * row[-1]) for j in range(free)])
        s0 = a + c * s1
        candidate = [int(x) if int(x) <= q // 2 else int(x) - q for x in list(s0) + list(s1)]
        if max(abs(x) for x in candidate) <= eta and public_a * vector(field, candidate) == public_t:
            recovered = True
            break

    return dict(
        input_a_sha256=_matrix_digest(public_a, q),
        input_t_sha256=_matrix_digest(matrix(public_a.base_ring(), n, 1, list(public_t)), q),
        a0_invertible=True,
        equation_count=equations,
        embedding_dimension=basis.nrows(),
        recovered_one_full_bounded_master_column=recovered,
        attacker_inputs="public A,T and public n,m,q,eta only",
        original_secret_given_to_recovery_routine=False,
        victim_oracle_queries=0,
        lll_algorithm="fpLLL:heuristic",
        lll_seconds=elapsed,
        full_master_recovery=False,
        full_scheme_forgery_tested=False,
        security_claim="none",
    )


def run_control() -> dict:
    """Create a deterministic toy instance, then expose only A,T to recovery."""
    set_random_seed(SEED)
    field = GF(Q)
    public_a = matrix(field, N, M, lambda _i, _j: field.random_element())
    setup_secret = vector(ZZ, [ZZ.random_element(-ETA, ETA + 1) for _ in range(M)])
    public_t = public_a * vector(field, setup_secret)
    del setup_secret

    result = recover_public_column(
        public_a, public_t,
        q=Q, eta=ETA, equations=EQUATIONS,
    )
    return dict(
        profile="screen-n128-q61",
        seed=SEED,
        n=N,
        m=M,
        q=Q,
        eta=ETA,
        result=result,
        private_secret_saved=False,
        scope="single synthetic column recovery; it does not establish a full IBS break",
    )
