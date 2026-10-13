"""Correlated SRGG master perturbations using a finite coefficient-GPV law.

The target is the complete Table 3 / Algorithms 1 and 3 shape
Sigma_p = Sigma - b^2*r^2*[R; I]*[R; I]^T, with center zero.
This distributional reference substitutes the existing finite GPV sampler;
it does NOT implement Algorithm 4's continuous Gaussian and rounding steps.
No extraction convolution, HNF key distribution or full IBS claim is made.
Run in WSL conda ~/miniconda3/envs/sage. Variable time; research only.
"""

from copy import deepcopy
from dataclasses import dataclass

from sage.all import QQ

from ibme.core.randomness import SecureRandom
from experiments.research.online_gaussian_reference import OnlineScalarGaussian, interval_upper
from experiments.research.online_mp12_reference import OnlineNonSphericalSampler, nearest_plane_bound

from .algebra import (
    ExtractionTrace, MAX_COEFFICIENT_BITS, Params, PublicRelation, matrix,
    reconstruct_vector, trapdoor_relation, vector,
)
from .geometry import Widths, master_geometry
from .sampling import GadgetSampler, extract_with_gadget


class MasterPerturbation:
    """Private complete-shape sampler, admitted against an explicit public class.

    The default [64,512] class covers every CBD1 witness in the independent
    degree-2/rank-1/digits-1 profile with Widths(512,128,4). Other shapes must
    pass the same exact floor, Loewner, arithmetic and entropy-budget gates.
    Never export the underlying sampler's full certificate: its covariance
    cross block reveals R. The public certificate below is a strict whitelist.
    """

    __slots__ = ("_params", "_witness", "_sampler", "_certificate")

    def __init__(self, params, witness, widths, *, width_min_squared=64,
                 width_max_squared=512, options=None):
        if not isinstance(params, Params) or not isinstance(widths, Widths):
            raise TypeError("SRGG Params and Widths required")
        witness = matrix(params, witness, 2 * params.rank, params.rank * params.digits)
        geometry = master_geometry(params, witness, widths)
        scalar = OnlineScalarGaussian(width_min_squared, width_max_squared, options=options)
        sampler = OnlineNonSphericalSampler(geometry.perturbation, scalar)
        if any(int(bound).bit_length() > MAX_COEFFICIENT_BITS
               for bound in sampler.resources["integer_coefficient_absolute_bounds"]):
            raise ValueError("all-path perturbation coefficient resource bound exceeded")
        dimension = sampler.dimension
        # This total depends only on the supplied public class and dimension.
        # It never calls the private sampler's covariance-bearing certificate.
        nearest = nearest_plane_bound(scalar, dimension)
        finite = min(QQ(1), dimension * scalar.tv_upper)
        total = min(QQ(1), interval_upper(scalar.field(nearest + finite)))
        self._params, self._witness, self._sampler = params, witness, sampler
        self._certificate = {
            "algorithm": "complete SRGG master shape via finite coefficient GPV",
            "density": "exp(-pi*x^T*Sigma_p^-1*x)",
            "dimension": dimension,
            "public_width_class_squared": [str(scalar.v_min), str(scalar.v_max)],
            "public_tape_bytes": sampler.random_tape_bytes,
            "target_tv_upper_including_abort": str(total),
            "paper_noise_squared": str(geometry.noise_squared),
            "smoothing_floor_squared": str(geometry.floor_squared),
            "literal_SampleF_implemented": False,
            "full_IBS_implemented": False,
            "constant_time": False,
            "security_claim": "none",
            "backend_admitted": False,
        }

    @property
    def params(self):
        return self._params

    def __repr__(self):
        return "MasterPerturbation(private_shape=<redacted>, literal_SampleF=False)"

    def public_certificate(self):
        return deepcopy(self._certificate)

    def sample(self, *, rng=None):
        """Return a complete signed module vector, or propagate explicit abort.

        The scalar implementation uses fresh rational-center conditional draws
        for the full shape; it does not replace correlation by diagonal noise.
        """
        source = SecureRandom() if rng is None else rng
        coefficients = self._sampler.sample(rng=source)
        p = self._params
        polynomials = tuple(tuple(coefficients[i * p.degree:(i + 1) * p.degree])
                            for i in range(p.columns))
        return vector(p, polynomials, p.columns)


@dataclass(frozen=True, repr=False)
class SampledExtraction:
    """Private results of two different operations, with distinct claims."""

    raw: ExtractionTrace
    reconstructed: tuple

    def __repr__(self):
        return "SampledExtraction(raw_and_HNF_vectors=<redacted>, Gaussian_key_claim=False)"


def extract_with_perturbation(public, target, perturbation, gadget, *,
                             perturbation_rng=None, gadget_rng=None):
    """Real perturbation + Table 3 gadget recipe, followed by HNF correction.

    raw satisfies A*y_raw=target-error (mod Q). Reconstructed satisfies
    A*y=target (mod Q). Neither result receives a full-key Gaussian claim.
    The two random sources are independently injectable and defaults are OS
    sources. Invalid context/target/recipe is rejected before either draw.
    """
    if not isinstance(public, PublicRelation) or not isinstance(perturbation, MasterPerturbation):
        raise TypeError("SRGG public relation and private perturbation sampler required")
    p = public.params
    if perturbation.params != p or not isinstance(gadget, GadgetSampler) or gadget.params != p:
        raise ValueError("perturbation/gadget/public parameter mismatch")
    target = vector(p, target, p.rank, p.modulus)
    if not trapdoor_relation(public, perturbation._witness):
        raise ValueError("master public relation does not match the private perturbation witness")
    if str(gadget.digit_width_squared) != perturbation._certificate["paper_noise_squared"]:
        raise ValueError("Table 3 recipe requires gadget digit width squared b^2*r^2")
    draw = perturbation.sample(rng=perturbation_rng)
    raw = extract_with_gadget(public, perturbation._witness, target, draw, gadget, rng=gadget_rng)
    reconstructed = reconstruct_vector(public, target, raw.tail)
    return SampledExtraction(raw, reconstructed)
