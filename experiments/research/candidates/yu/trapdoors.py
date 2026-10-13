"""Yu--Liu--Li (2026), PDF pp. 5--6 Lemmas 1--4 / p. 12 Fig. 5.

Research bridge: AP09 full-basis TrapGen; ExtBasis -> finite RandBasis;
ExtBasis -> finite GPV SamplePre at zero. Columns are lattice vectors.
Each extension is ONE n by w block, w = n*ceil(log2(q)), not n by m.
The caller supplies the evaluated identity/message blocks; this module does
not implement PRFs, identity binding, or the complete IBS verifier.

gamma_squared and delta_squared are FIXED PUBLIC squared Gaussian widths in
exp(-pi*||x||^2/s^2), not variances. Admission may reject a secret basis, but
never chooses a new width, retries, substitutes a public kernel basis, or
relaxes the shared sampler's caps. Callers must retain failed invocations.

postprocess=True applies the shared deterministic bounded exact LLL map to
the RandBasis output. This is an explicit finite implementation extension,
NOT a step in Yu Fig. 5. Applying the same map (including ABORT) to both
distributions cannot increase their TV distance; it does not prove the
original ideal RandBasis distribution, success probability, secrecy, or a
security level, nor justify conditioning away aborts. postprocess=False
returns the raw RandBasis output, which may fail subsequent GPV admission.

KernelBasis certifies containment AND determinant q^n, not provenance or
randomization. Its historical is_randomized=False is deliberately unchanged.
Keep returned bases, RNG state and sampler geometry private: no certificates,
logs, serialization or basis-dependent diagnostics are emitted here.
Variable time, small research parameters only; security_claim='none'.
"""

from __future__ import annotations

from experiments.research.chkp_basis import KernelBasis, ModMatrixReference, ext_basis
from experiments.research.chkp_basis_reduce import MAX_DIMENSION as LLL_MAX_DIMENSION
from experiments.research.chkp_basis_reduce import reduce_basis
from experiments.research.chkp_genbasis import AP09Parameters, gen_basis
from experiments.research.chkp_gpv import (
    MAX_DIMENSION, MAX_INPUT_BITS, CHKPGPVSampler, _bounded_basis, _bounded_rational,
)
from experiments.research.chkp_randbasis import CHKPRandBasis
from experiments.research.gaussian_reference import SamplingAbort
from experiments.research.online_gaussian_reference import OnlineOptions, exact_integer


security_claim = "none"
backend_admitted = False
parameters_are_formal = False

__all__ = ["generate_root", "issue_basis", "sample_zero"]


def _rng(source):
    if source is not None and not callable(getattr(source, "read", None)):
        raise ValueError("rng must implement read(n)->bytes or be None")
    return source


def _basis(value):
    # Reuse the shared cheap resource gate BEFORE determinant/field arithmetic.
    checked = _bounded_basis(value, MAX_DIMENSION, MAX_INPUT_BITS)
    if checked.public.q < 3:
        raise ValueError("Yu requires an odd prime q >= 3")
    return checked


def _extension(parent, block):
    parent = _basis(parent)
    if not isinstance(block, ModMatrixReference):
        raise ValueError("Yu block must be a ModMatrixReference")
    public = parent.public
    w = public.nrows * (public.q - 1).bit_length()
    q = exact_integer(block.q, "block modulus", minimum=3, maximum=(1 << MAX_INPUT_BITS) - 1)
    if (q != public.q or not isinstance(block.rows, (tuple, list))
            or len(block.rows) != public.nrows
            or any(not isinstance(row, (tuple, list)) or len(row) != w for row in block.rows)):
        raise ValueError("Yu block must have matching q and shape n by w")
    if public.ncols + w > MAX_DIMENSION:
        raise ValueError("Yu extension exceeds the shared dimension resource limit")
    # Constructors normally enforce this. Recheck forged/deserialized objects
    # without silently reducing noncanonical public residues.
    for row in block.rows:
        for value in row:
            exact_integer(value, "block residue", minimum=0, maximum=public.q - 1)
    block = ModMatrixReference(block.rows, public.q)
    return ext_basis(parent, block)


def _configuration(width, name, options, epsilon_bits, rng):
    if options is not None and not isinstance(options, OnlineOptions):
        raise ValueError("options must be OnlineOptions or None")
    bits = min(MAX_INPUT_BITS, options.rational_bits) if options else MAX_INPUT_BITS
    width = _bounded_rational(width, name, bits)
    if width <= 0:
        raise ValueError(f"{name} must be positive")
    epsilon_bits = exact_integer(epsilon_bits, "epsilon_bits", minimum=2, maximum=4096)
    _rng(rng)
    return width, epsilon_bits


def _output_basis(value, expected_public):
    checked = _basis(value)
    if checked.public != expected_public:
        raise ArithmeticError("Yu trapdoor output changed the public matrix")
    return checked


def generate_root(ap09_params: AP09Parameters, rng=None) -> KernelBasis:
    """One AP09 attempt; rank/entropy failures propagate without retry.

    None uses SecureRandom in the shared generator. Deterministic sources
    are allowed only for tests. AP09's finite-domain checks still apply;
    near-uniformity and security are not certified by a successful call.
    """
    if not isinstance(ap09_params, AP09Parameters):
        raise ValueError("generate_root requires AP09Parameters")
    params = AP09Parameters(**{name: getattr(ap09_params, name) for name in (
        "n", "q", "random_rows", "m1", "m2", "hadamard_scale", "max_uniform_trials",
    )})
    if params.q < 3:
        raise ValueError("Yu requires an odd prime q >= 3")
    _rng(rng)
    root = _basis(gen_basis(params, rng=rng).basis)
    if (root.public.q, root.public.nrows, root.public.ncols) != (
        params.q, params.n, params.m1 + params.m2,
    ):
        raise ArithmeticError("AP09 output does not match the requested dimensions/modulus")
    return root


def issue_basis(root: KernelBasis, block: ModMatrixReference, gamma_squared,
                max_vectors, *, rng, options=None, epsilon_bits=16,
                postprocess=True) -> KernelBasis:
    """Extend by w, randomize at public gamma, optionally apply fixed LLL.

    max_vectors is the TOTAL RandBasis draw budget (<=4096), not a retry
    count. LLL retains its existing <=64-dimension/100000-step caps. A raw
    or reduced result is rechecked for the SAME complete integer lattice.
    """
    gamma_squared, epsilon_bits = _configuration(
        gamma_squared, "gamma_squared", options, epsilon_bits, rng,
    )
    if type(postprocess) is not bool:
        raise ValueError("postprocess must be a bool")
    max_vectors = exact_integer(max_vectors, "max_vectors", minimum=1, maximum=4096)
    extended = _extension(root, block)
    dimension = extended.public.ncols
    if max_vectors < dimension:
        raise ValueError("max_vectors must cover the extended dimension")
    if postprocess and dimension > LLL_MAX_DIMENSION:
        raise ValueError("Yu postprocessing exceeds the shared LLL dimension cap")
    sampler = CHKPGPVSampler(extended, gamma_squared, epsilon_bits=epsilon_bits,
                             options=options)
    result = CHKPRandBasis(sampler, max_vectors=max_vectors).sample(rng=rng)
    randomized = _output_basis(result.basis, extended.public)
    if postprocess:
        randomized = _output_basis(reduce_basis(randomized).basis, extended.public)
    return randomized


def sample_zero(parent: KernelBasis, block: ModMatrixReference, delta_squared,
                *, rng, options=None, epsilon_bits=16) -> tuple[int, ...]:
    """One zero-syndrome SamplePre, with Fig. 5's exact verification gates.

    Returns signed INTEGER coordinates, never residues mod q. Zero and norm
    outliers cause SamplingAbort, with no resampling. A wrong modular
    equation or malformed sampler output is an implementation error.
    """
    delta_squared, epsilon_bits = _configuration(
        delta_squared, "delta_squared", options, epsilon_bits, rng,
    )
    extended = _extension(parent, block)
    sampler = CHKPGPVSampler(extended, delta_squared, epsilon_bits=epsilon_bits,
                             options=options)
    sampled = sampler.sample((0,) * extended.public.nrows, rng=rng)
    if not isinstance(sampled, tuple) or len(sampled) != extended.public.ncols:
        raise ArithmeticError("Yu sampler returned an invalid vector dimension/type")
    try:
        entries = tuple(exact_integer(x, "signature coordinate",
                                     minimum=-(1 << MAX_INPUT_BITS) + 1,
                                     maximum=(1 << MAX_INPUT_BITS) - 1) for x in sampled)
    except ValueError:
        raise ArithmeticError("Yu sampler returned an invalid integer coordinate") from None
    if any(sum(a * x for a, x in zip(row, entries)) % extended.public.q
           for row in extended.public.rows):
        raise ArithmeticError("Yu SamplePre zero-syndrome equation failed")
    norm_squared = sum(x * x for x in entries)
    if norm_squared == 0:
        raise SamplingAbort("Yu SamplePre returned zero; call aborted without retry")
    if norm_squared > delta_squared * extended.public.ncols:
        raise SamplingAbort("Yu signature norm budget exceeded; call aborted without retry")
    return entries
