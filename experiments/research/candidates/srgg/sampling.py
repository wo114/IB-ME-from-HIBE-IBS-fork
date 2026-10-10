"""Finite-error SRGG gadget sampling; no perturbation or IBS backend.

The digit density is exp(-pi*z^2/digit_width_squared) on bZ+v.
Table 3's sigma=b*r recipe means digit_width_squared=b^2*r^2;
Algorithm 6's literal width r instead means digit_width_squared=r^2.
Callers must select that width explicitly. Use the specified WSL Sage.
"""

from dataclasses import dataclass, field
from typing import ClassVar

from sage.all import QQ

from ibme.core.randomness import SecureRandom
from experiments.research.gaussian_reference import (
    SamplingAbort, build_gaussian_table_squared, interval_bounds,
)
from .algebra import (
    ExtractionTrace, Params, add, identity, integer, matrix,
    matvec, scale, trapdoor_relation, vector,
)
from .geometry import rational


class GadgetSamplingAbort(SamplingAbort):
    """A digit sampler exhausted its budget; no partial vector is returned."""


@dataclass(frozen=True)
class TableOptions:
    tail_bits: int = 80
    mass_bits: int = 128
    precision_bits: int = 192
    max_trials: int = 128
    max_radius: int = 128

    def __post_init__(self):
        limits = {
            "tail_bits": (8, 128), "mass_bits": (32, 256),
            "precision_bits": (96, 512), "max_trials": (1, 256),
            "max_radius": (0, 128),
        }
        for name, (low, high) in limits.items():
            integer(getattr(self, name), low, high, name)
        if self.precision_bits < self.mass_bits + 32:
            raise ValueError("interval precision must exceed mass precision by 32 bits")


@dataclass(frozen=True)
class GadgetSampler:
    params: Params
    digit_width_squared: object
    options: TableOptions = field(default_factory=TableOptions)
    tables: tuple = field(init=False, repr=False)
    security_claim: ClassVar[str] = "none"
    backend_admitted: ClassVar[bool] = False

    def __post_init__(self):
        if not isinstance(self.params, Params) or not isinstance(self.options, TableOptions):
            raise TypeError("SRGG Params/TableOptions required")
        width = rational(self.digit_width_squared)
        if not QQ(1)/4096 <= QQ(width)/self.params.base**2 <= 64:
            raise ValueError("digit squared width/base^2 outside research range")
        object.__setattr__(self, "digit_width_squared", width)
        object.__setattr__(self, "tables", tuple(
            build_gaussian_table_squared(width, step=self.params.base, residue=residue,
                                         **self.options.__dict__)
            for residue in range(self.params.base)
        ))

    def sample_scalar(self, target, *, rng=None):
        p = self.params
        target = integer(target, 0, p.modulus - 1, "canonical scalar target")
        source = SecureRandom() if rng is None else rng
        error, state = target % p.p, target // p.p
        result = []
        try:
            for _ in range(p.digits):
                value = self.tables[state % p.base].sample(rng=source)
                if (state - value) % p.base:
                    raise RuntimeError("digit coset relation failed")
                result.append(value)
                state = (state - value) // p.base
        except SamplingAbort as exc:
            raise GadgetSamplingAbort("SRGG digit rejection budget exhausted") from exc
        if (p.p * sum(p.base**i * x for i, x in enumerate(result)) - target + error) % p.modulus:
            raise RuntimeError("approximate gadget relation failed")
        return tuple(result), error

    def sample_module(self, target, *, rng=None):
        p = self.params
        target = vector(p, target, p.rank, p.modulus)
        source = SecureRandom() if rng is None else rng
        result, errors = [], []
        for polynomial in target:
            coefficients = [self.sample_scalar(value, rng=source) for value in polynomial]
            result.extend(tuple(row[0][i] for row in coefficients) for i in range(p.digits))
            errors.append(tuple(row[1] for row in coefficients))
        return vector(p, tuple(result), p.rank * p.digits), tuple(errors)

    def finite_scalar_distribution(self, target, *, max_states=100000):
        """Exact ideal-ticket finite CDF law; not the law conditional on no abort."""
        p = self.params
        target = integer(target, 0, p.modulus - 1, "canonical scalar target")
        integer(max_states, 1, 200000, "enumeration budget")
        if max(len(t.support) for t in self.tables)**p.digits > max_states:
            raise ValueError("finite recurrence enumeration exceeds state budget")
        current = {((), target // p.p): QQ(1)}
        for _ in range(p.digits):
            following = {}
            for (prefix, state), mass in current.items():
                table = self.tables[state % p.base]
                for value, weight in zip(table.support, table.masses):
                    if weight:
                        following[prefix + (value,), (state-value)//p.base] = mass * QQ(weight)/table.total_mass
            current = following
        return {prefix: mass for (prefix, _), mass in current.items()}

    def certificate(self, *, blocks=1):
        """Uniform-in-target bound including finite error, abort and coset bias.

        Each recurrence digit contributes a coset partition function. Their
        maximum/minimum ratio to the power of the draw count bounds the
        ideal recurrence's deviation from the infinite spherical fiber law.
        This does not certify extraction convolution or the reconstructed key.
        """
        p = self.params
        integer(blocks, 1, p.rank * p.degree, "coefficient blocks")
        draws = blocks * p.digits
        low = min(interval_bounds(t.normalizer)[0] for t in self.tables)
        high = max(interval_bounds(t.normalizer)[1] for t in self.tables)
        if low <= 0:
            raise ValueError("coset partition lower bound must be positive")
        ratio = high / low
        bias = min(QQ(1), (ratio**draws - 1)/2)
        finite = min(QQ(1), draws * max(t.tv_upper for t in self.tables))
        abort = min(QQ(1), draws * max(t.abort_upper for t in self.tables))
        return {
            "security_claim": "none", "backend_admitted": False, "constant_time": False,
            "density": "exp(-pi*z^2/digit_width_squared) on bZ+v",
            "digit_width_squared": str(self.digit_width_squared),
            "SampleZ_recipe_width_squared": str(self.digit_width_squared / p.base**2),
            "blocks": blocks, "scalar_draws": draws,
            "partition_ratio_upper": str(ratio),
            "ideal_recurrence_to_spherical_fiber_tv_upper": str(bias),
            "finite_sampling_tv_upper_including_abort": str(finite),
            "abort_upper": str(abort),
            "total_fiber_tv_upper_including_abort": str(min(QQ(1), bias + finite)),
            "uniform_in_canonical_target": True,
            "scalar_certificates": [t.certificate() for t in self.tables],
            "limits": "width^2/base^2 in [1/4096,64]; Params and TableOptions resource bounds",
            "assumptions": "independent uniform bytes; correctly rounded MPFR/MPFI intervals",
            "scope": "gadget fiber law only; no perturbation, key or signature distribution claim",
        }


def extract_with_gadget(public, r, target, perturbation, sampler, *, rng=None):
    """Algorithm 2 algebra with actual gadget draws and a supplied perturbation."""
    p = public.params
    if not isinstance(sampler, GadgetSampler) or sampler.params != p:
        raise ValueError("sampler/public parameter mismatch")
    r = matrix(p, r, 2 * p.rank, p.rank * p.digits)
    if not trapdoor_relation(public, r):
        raise ValueError("master relation mismatch")
    target = vector(p, target, p.rank, p.modulus)
    perturbation = vector(p, perturbation, p.columns)
    residual = tuple(add(h, scale(v, -1), p.modulus)
                     for h, v in zip(target, matvec(p, public.a, perturbation, p.modulus)))
    x, errors = sampler.sample_module(residual, rng=rng)
    raw = vector(p, tuple(add(a, b) for a, b in zip(
        perturbation, matvec(p, r + identity(p, p.rank * p.digits), x))), p.columns)
    expected = tuple(add(h, scale(e, -1), p.modulus) for h, e in zip(target, errors))
    if matvec(p, public.a, raw, p.modulus) != expected:
        raise RuntimeError("randomized approximate extraction relation failed")
    return ExtractionTrace(raw, raw[p.rank:], errors)
