"""Candidate RandBasis bridge; legacy rank helper retained only for diagnostics."""
from sage.all import GF, QQ, ZZ, matrix, vector
from ibme.lattice.matrix_sampling.scalar import exact_integer
from ibme.lattice.matrix_sampling.chkp_profiles import (CHKPFiniteRandBasis as FirstFiniteRandBasis, CHKPFiniteRandResult as FirstFiniteRandResult)
class _ExactIncrementalRank:
    """One-sided modular independence witness with exact rational fallback.

    A full-rank modular image of the retained rows plus the candidate proves
    independence over Q. If the retained rows already lost rank modulo the
    prime, a modular rank INCREASE alone proves nothing; that case and every
    modular dependence trigger the original exact check. Retained vectors and
    order are identical for every input sequence. No random bytes are used.
    """

    def __init__(self, dimension, *, witness_prime=2147483647):
        self.dimension = exact_integer(dimension, "rank dimension", minimum=1, maximum=512)
        prime = exact_integer(witness_prime, "rank witness prime", minimum=2, maximum=2**61-1)
        if not ZZ(prime).is_prime(proof=True):
            raise ValueError("rank witness requires a prime field")
        self.field = GF(prime)
        self.echelon = []
        self.chosen = []
        self.exact_fallbacks = 0

    def add(self, candidate):
        candidate = vector(ZZ, candidate)
        if len(candidate) != self.dimension:
            raise ValueError("rank candidate dimension mismatch")
        residual = vector(self.field, candidate)
        for pivot, row in self.echelon:
            if residual[pivot]:
                residual -= residual[pivot] * row
        pivot = next((i for i, value in enumerate(residual) if value), None)
        def retain():
            if pivot is not None:
                normalized = residual / residual[pivot]
                normalized.set_immutable()
                self.echelon.append((pivot, normalized))
                self.echelon.sort(key=lambda pair: pair[0])
            self.chosen.append(candidate)
            return True

        if pivot is not None and len(self.echelon) == len(self.chosen):
            return retain()
        self.exact_fallbacks += 1
        if matrix(ZZ, self.chosen + [candidate]).rank() > len(self.chosen):
            # An accepted but modularly dependent row leaves a rank deficit.
            # Keep using exact checks whenever that deficit is present.
            return retain()
        return False
