"""Bounded, fixed-target leaf preimages; NOT a HIBE key/backend or cache.

CHKP (2011-06-14), section 5.2, PDF p.20 permits omitting the basis at
maximum depth. Sample with the EXTENDED PARENT basis, not a randomized
leaf basis. No sampler, width rule, retry policy or existing cap is changed.
The caller must later supply fixed identity/bit targets and persistent state.
"""

from dataclasses import dataclass, field

from sage.all import ZZ, matrix, vector

from ibme.core.randomness import SecureRandom
from .chkp_basis import ModMatrixReference
from .chkp_gpv import CHKPGPVSampler
from .online_gaussian_reference import exact_integer


MAX_LEAF_TARGETS = 32  # independent research batch cap, NOT a payload capacity
MAX_LEAF_TAPE_BYTES = 256 * 1024 * 1024


class LeafAdmissionError(ValueError):
    """Invalid fixed-target batch, rejected before any entropy consumption."""


@dataclass(frozen=True)
class LeafPreimages:
    public: ModMatrixReference
    targets: tuple
    preimages: tuple = field(repr=False)
    security_claim: str = field(default="none", init=False)
    backend_admitted: bool = field(default=False, init=False)


def sample_leaf_preimages(sampler, targets, *, rng=None):
    """Return only public context, targets and vectors; never retain a basis.

    This is a one-shot fixed-target experiment, not repeat-identity Extract.
    Repeated targets are allowed and get independent draws; they DO NOT model
    repeated requests for the same identity/bit address. ABORT/RNG failures
    propagate without retry or a partial return. No new norm/zero rejection.
    """
    if not isinstance(sampler, CHKPGPVSampler):
        raise LeafAdmissionError("Leaf sampling needs an admitted research GPV sampler")
    if not isinstance(targets, (tuple, list)) or not 1 <= len(targets) <= MAX_LEAF_TARGETS:
        raise LeafAdmissionError("Leaf targets must be a bounded nonempty sequence")
    public = sampler.basis.public
    checked = []
    for target in targets:
        if not isinstance(target, (tuple, list)) or len(target) != public.nrows:
            raise LeafAdmissionError("Wrong leaf target dimension")
        try:
            checked.append(tuple(exact_integer(x, "leaf target", maximum=public.q-1)
                                 for x in target))
        except ValueError as exc:
            raise LeafAdmissionError(str(exc)) from exc
    if len(checked) * sampler.random_tape_bytes > MAX_LEAF_TAPE_BYTES:
        raise LeafAdmissionError("Whole leaf batch tape exceeds the resource budget")
    source = SecureRandom() if rng is None else rng
    a = matrix(ZZ, public.rows)
    samples = []
    for target in checked:
        sample = sampler.sample(target, rng=source)
        if (len(sample) != public.ncols or
                tuple(int(x) % public.q for x in a * vector(ZZ, sample)) != target):
            raise ArithmeticError("Leaf preimage equation failed")
        samples.append(sample)
    return LeafPreimages(public, tuple(checked), tuple(samples))
