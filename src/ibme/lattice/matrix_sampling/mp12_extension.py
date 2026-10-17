"""MP12 structured Gaussian sampling on full CHKP H/G extensions.

The gadget still occupies the last w=n*ceil(log2(q)) columns. To sample
over [A | E], put E before that gadget, pad R with zero *rows*, sample
with Algorithm 3, then undo the column permutation. Every output coordinate
is sampled; zero-padding R does not mean zero-padding a preimage.

Algorithm 4 accepts a tail of exactly w columns. A larger extension is split
into a prefix for the above sampler and its final w columns for Algorithm 4.
No H block is shortened and no full kernel basis is expanded. This module
is mathematical machinery; fixed issuance/pending persistence is a caller
responsibility, as are all finite-distribution and security admission gaps
of mp12_structured.
"""

from .mp12_structured import (
    StructuredTrapdoor, StructuredPreimageSampler, MAX_PREFIX, MAX_COLUMNS,
    MAX_R_ENTRIES, _rows, _syndrome,
)
from experiments.research.first_suite.entropy import CheckedEntropy
from experiments.research.gaussian_reference import SamplingAbort
from ibme.core.randomness import SecureRandom


class StructuredLeftSampler:
    """A coordinate permutation of actual structured SampleD on [A | E]."""

    def __init__(self, trapdoor, extension, **sampler_options):
        if not isinstance(trapdoor, StructuredTrapdoor):
            raise ValueError("structured SampleLeft needs its own trapdoor")
        if (not isinstance(extension, (tuple, list)) or len(extension) != trapdoor.n
                or not isinstance(extension[0], (tuple, list))):
            raise ValueError("structured SampleLeft needs an n-row extension")
        count = len(extension[0])
        prefix = trapdoor.prefix + count
        if (prefix > MAX_PREFIX or prefix+trapdoor.w > MAX_COLUMNS
                or prefix*trapdoor.w > MAX_R_ENTRIES):
            raise ValueError("structured SampleLeft extension resource limit")
        extension = _rows(extension, trapdoor.n, count, q=trapdoor.q)
        padded = StructuredTrapdoor(trapdoor.n, trapdoor.q,
            tuple(a+e for a, e in zip(trapdoor.a_bar, extension)),
            trapdoor.r+((0,)*trapdoor.w,)*count,
            trapdoor.frobenius_squared_bound)
        self.original = trapdoor
        self.extension = extension
        self.public_rows = tuple(a+e for a, e in zip(trapdoor.public.rows, extension))
        self.inner = StructuredPreimageSampler(padded, **sampler_options)
        self.output_squared = self.inner.output_squared
        self.random_tape_bytes = self.inner.random_tape_bytes
        self.dimension = padded.dimension
        self.options = self.inner.options

    def sample(self, syndrome, *, rng=None):
        syndrome = _syndrome(syndrome, self.original.n, self.original.q)
        values = self.inner.sample(syndrome, rng=rng)
        p, count = self.original.prefix, len(self.extension[0])
        result = values[:p]+values[p+count:]+values[p:p+count]
        # The inner sampler already checks its equation. Check the public
        # permutation independently to catch ordering mistakes at this boundary.
        if any(sum(a*x for a, x in zip(row, result)) % self.original.q != int(u)
               for row, u in zip(self.public_rows, syndrome)):
            raise ArithmeticError("structured SampleLeft column permutation failed")
        return result

    def public_certificate(self):
        return dict(self.inner.public_certificate(),
            extension_columns=len(self.extension[0]),
            coordinate_order="original-A followed by complete extension",
            zero_padded_output_coordinates=False)


def delegate_extension(trapdoor, extension, *, rng=None, epsilon_bits=128, options=None):
    """MP12 Algorithm 4 for an extension with at least w columns.

    A single attempt; any norm/entropy/precision failure aborts the operation.
    This stateless helper never retries. A service must mark its address
    pending *before* invoking it, and preserve that marker on every failure.
    """
    if not isinstance(trapdoor, StructuredTrapdoor):
        raise ValueError("structured delegation needs its own trapdoor")
    t = trapdoor
    if (not isinstance(extension, (tuple, list)) or len(extension) != t.n
            or not isinstance(extension[0], (tuple, list))):
        raise ValueError("structured delegation needs an n-row extension")
    width = len(extension[0])
    new_prefix = t.dimension+width-t.w
    if width < t.w or new_prefix > MAX_PREFIX or new_prefix*t.w > MAX_R_ENTRIES:
        raise ValueError("structured full-extension delegation resource limit")
    extension = _rows(extension, t.n, width, q=t.q)
    extras, tail = tuple(row[:-t.w] for row in extension), tuple(row[-t.w:] for row in extension)
    sampler = StructuredLeftSampler(t, extras, epsilon_bits=epsilon_bits, options=options)
    if t.w*sampler.random_tape_bytes > sampler.options.max_tape_bytes:
        raise ValueError("structured whole-extension delegation tape limit")
    source = CheckedEntropy(SecureRandom() if rng is None else rng, sampler.options.max_tape_bytes)
    columns = []
    k = (t.q-1).bit_length()
    for j in range(t.w):
        target = tuple((int(i == j//k)*2**(j % k)-tail[i][j]) % t.q for i in range(t.n))
        sample = sampler.sample(target, rng=source)
        if sum(x*x for x in sample) > sampler.dimension*sampler.output_squared:
            raise SamplingAbort("structured extension column norm event; no retry")
        columns.append(sample)
    result = StructuredTrapdoor(t.n, t.q,
        tuple(a+e for a, e in zip(t.public.rows, extras)),
        tuple(tuple(columns[j][i] for j in range(t.w)) for i in range(sampler.dimension)),
        sampler.dimension*t.w*sampler.output_squared)
    if result.public.rows != tuple(a+e for a, e in zip(t.public.rows, extension)):
        raise ArithmeticError("structured full-H Algorithm 4 equation failed")
    result.to_bytes()
    return result
