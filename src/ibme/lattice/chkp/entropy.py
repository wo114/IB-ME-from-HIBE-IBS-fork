"""Frozen byte RNG checks and finite consumption; never a seeded native RNG."""

from ibme.core.errors import RandomnessError
from ibme.lattice.chkp.gaussian import SamplingAbort


class CheckedEntropy:
    def __init__(self, source, budget):
        if not callable(getattr(source, "read", None)):
            raise RandomnessError("finite sampler source must provide read(n)")
        if type(budget) is not int or not 1 <= budget <= 2**48:
            raise RandomnessError("invalid finite entropy byte budget")
        self.source, self.budget, self.bytes_used = source, budget, 0

    def read(self, count):
        if type(count) is not int or count < 0:
            raise RandomnessError("finite sampler read length must be nonnegative integer")
        if self.bytes_used + count > self.budget:
            raise SamplingAbort("finite entropy budget exhausted; no fallback")
        data = self.source.read(count)
        if not isinstance(data, bytes) or len(data) != count:
            raise RandomnessError("finite sampler source returned wrong byte type or length")
        self.bytes_used += count
        return data
