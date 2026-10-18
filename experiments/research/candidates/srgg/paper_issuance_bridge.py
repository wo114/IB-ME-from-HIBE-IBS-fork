"""Fixed-root original-parameter SRGG issuance law, with explicit premises.

The reference is a centered-HNF pushforward of an anisotropic Gaussian on
the approximate-preimage union S_h. It is trapdoor independent at fixed A,h,
but is NOT an exact-preimage Gaussian or a full IBS security theorem.
No sampling, root selection, cryptographic parameter or backend change occurs.
"""
from __future__ import annotations

from fractions import Fraction

from sage.all import ComplexIntervalField, QQ

from .paper_backend import PaperGadget
from .paper_parameters import PaperParams
from .paper_rounding_budget import theta_certificate
from .paper_samplef import PaperSampleF, _ldl_status, _negacyclic_spectrum
from .structured_geometry import StructuredGeometry


SCHEMA = "IBME/SRGG-PAPER-FIXED-ROOT-ISSUANCE-LAW/1"


def _fraction(value):
    if type(value) not in (int, Fraction):
        raise ValueError("bounded exact int or Fraction required")
    value = Fraction(value)
    if max(abs(value.numerator).bit_length(), value.denominator.bit_length()) > 32768:
        raise ValueError("rational resource bound exceeded")
    return value


def _probability(value):
    value = _fraction(value)
    if not 0 <= value <= 1:
        raise ValueError("probability outside [0,1]")
    return value


def fixed_root_c_gate(geometry, *, lower_bound=64, precision_bits=192):
    """Certify C>lambda I by directed small-module Fourier LDL.

    C=nu I-nu^2 T*Sigma^-1 T, T=[R;I]. Only the selected public coarse
    lambda and the overall result are returned; private spectra stay local.
    Failure means this gate did not certify its bound, never root rejection.
    """
    if type(geometry) is not StructuredGeometry:
        raise ValueError("validated exact StructuredGeometry required")
    bound = _fraction(lower_bound)
    if not 0 < bound <= 1024:
        raise ValueError("coarse lower bound outside (0,1024]")
    if type(precision_bits) is not int or not 128 <= precision_bits <= 2048:
        raise ValueError("precision_bits must lie in [128,2048]")
    g = geometry
    if (g.upper_polynomials+g.lower_polynomials)*g.degree > 32768:
        raise ValueError("issuance coefficient dimension resource gate exceeded")
    nu = g.noise_squared
    threshold = 1-QQ(bound.numerator)/bound.denominator/nu
    result = {
        "coarse_lower_bound_exact": str(bound), "precision_bits": precision_bits,
        "dimension": g.lower_polynomials*g.degree,
        "certified": False, "all_fourier_blocks_checked": False,
        "method": "directed interval FFT and Hermitian LDL of (1-lambda/nu)I-nu*T*Sigma^-1*T",
        "private_spectra_and_witness_exported": False,
        "sampler_draws": 0, "root_redraws": 0,
        "scope": "this fixed root only; no setup-output-distribution guarantee",
    }
    if threshold <= 0:
        result["status"] = "coarse-bound-not-certified"
        return result
    field = ComplexIntervalField(precision_bits)
    spectra = [[_negacyclic_spectrum(poly, g.degree, field) for poly in row]
               for row in g.witness]
    columns = g.lower_polynomials
    for k in range(g.degree//2):
        gram = [[field(0) for _ in range(columns)] for _ in range(columns)]
        for i in range(columns):
            for j in range(i+1):
                value = sum((row[i][k].conjugate()*row[j][k]/g.top_squared[t]
                             for t, row in enumerate(spectra)), field(0))
                if i == j:
                    value += 1/g.lower_squared
                gram[i][j] = nu*value
                gram[j][i] = gram[i][j].conjugate()
        if _ldl_status(gram, threshold, field) != "positive":
            result["status"] = "coarse-bound-not-certified"
            return result
    result.update(certified=True, all_fourier_blocks_checked=True, status="certified")
    return result


def combine_issuance_tv(*, perturbation_tv, gadget_scalar_tv,
                        digit_relative_sum, center_relative_error):
    """Abort-preserving triangle bound; no duplicated gadget-fiber term.

    The digit normalizer product lies in [1-x,1/(1-x)]. Its sharp range TV
    is x/(2-x). The remaining completed-square tilt costs eps/(1-eps).
    An inconclusive prerequisite returns no nontrivial bound.
    """
    delta_f, delta_g = map(_probability, (perturbation_tv, gadget_scalar_tv))
    x = _fraction(digit_relative_sum)
    if x < 0:
        raise ValueError("nonnegative digit normalizer sum required")
    epsilon = None if center_relative_error is None else _fraction(center_relative_error)
    if epsilon is not None and epsilon < 0:
        raise ValueError("nonnegative center error required")
    if x >= 1 or epsilon is None or epsilon >= 1:
        return {"certified": False, "complete_law_tv_upper_including_abort": None,
                "denominator_removal_tv_upper": None,
                "completed_square_center_tilt_tv_upper": None}
    denominator, center = x/(2-x), epsilon/(1-epsilon)
    total = min(Fraction(1), delta_f+delta_g+denominator+center)
    return {"certified": True, "complete_law_tv_upper_including_abort": str(total),
            "denominator_removal_tv_upper": str(denominator),
            "completed_square_center_tilt_tv_upper": str(center)}


def issuance_certificate(params, plan, gadget, *, c_lower_bound=64, precision_bits=192):
    """Bind fresh finite plan, centered paper gadget and exact master shape.

    The resulting bound concerns mathematical raw/tail/HNF vectors, including
    sampler aborts. Applying it to key_extract additionally requires valid
    identity/state/capacity and proof that finite-output object guards cannot
    fail. Disk faults, histories, wire distributions and signatures are outside.
    """
    if type(params) is not PaperParams or type(plan) is not PaperSampleF or type(gadget) is not PaperGadget:
        raise ValueError("actual paper params, prepared sampler and centered gadget required")
    g = plan.geometry
    def exact_shape(value):
        return QQ(value.numerator)/value.denominator
    if (g.degree != params.degree or g.upper_polynomials != 2*params.rank
            or g.lower_polynomials != params.rank*params.digits
            or g.top_squared != (exact_shape(params.master_first_squared),)*(2*params.rank)
            or g.lower_squared != exact_shape(params.master_second_squared)
            or g.noise_squared != params.base**2*exact_shape(params.r_squared)
            or g.rounding_squared != exact_shape(params.r_squared)
            or any(plan.center) or gadget.params != params):
        raise ValueError("fixed plan/gadget differs from zero-centered original master shape")
    c_gate = fixed_root_c_gate(g, lower_bound=c_lower_bound, precision_bits=precision_bits)
    rounding = theta_certificate(dimension=plan.dimension,
        density_shape=Fraction(int(g.rounding_squared.numerator()),
                               int(g.rounding_squared.denominator())), precision_bits=precision_bits)
    finite = plan.public_certificate()
    delta_f = min(Fraction(1), Fraction(finite["finite_center_numerical_tv_upper"])
        + Fraction(finite["scalar_batch"]["scalar_kernel_tv_including_aggregate_exact"])
        + Fraction(rounding["rounding_tv_upper"]))
    delta_g = Fraction(gadget.batch["scalar_kernel_tv_including_aggregate_exact"])
    draws = params.degree*params.rank*params.digits
    digit = theta_certificate(dimension=draws, density_shape=Fraction(params.r_squared),
                             precision_bits=precision_bits)
    x = Fraction(digit["dimension_times_scalar_theta_upper_exact"])
    center = (theta_certificate(dimension=draws, density_shape=_fraction(c_lower_bound),
                               precision_bits=precision_bits) if c_gate["certified"] else None)
    epsilon = None if center is None else center["relative_normalizer_error_upper_exact"]
    combined = combine_issuance_tv(perturbation_tv=delta_f, gadget_scalar_tv=delta_g,
        digit_relative_sum=x, center_relative_error=None if epsilon is None else Fraction(epsilon))
    return {"schema": SCHEMA, "parameter_record": params.record(),
        "c_gate": c_gate, "perturbation_sampler": finite,
        "tight_rounding_theta": rounding, "digit_theta": digit,
        "completed_square_theta": center,
        "perturbation_tv_upper_including_abort": str(delta_f),
        "gadget_scalar_tv_upper_including_aggregate_abort": str(delta_g),
        "digit_normalizer_relative_sum_exact": str(x), **combined,
        "reference": "centered-HNF pushforward of D_(Z^N,Sigma,0) conditioned on S_h",
        "support": "S_h={u: h-Au mod Q has a representative in centered E_c}",
        "equivalent_mixed_domain_reference": "C_Q(U+JE) conditioned on A*C_Q(U+JE)=h; E uniform centered E_c",
        "center_formula": "mu(u)=nu*T*Sigma^-1*u; generally nonzero",
        "conditional_on_success_tv_upper_if_finite_object_guards_cannot_fail": combined["complete_law_tv_upper_including_abort"],
        "finite_object_guards_verified_by_this_function": False,
        "trapdoor_public_relation_verified_by_this_function": False,
        "requires_valid_fixed_public_root_relation": True,
        "law_space": "mathematical_vectors_plus_abort",
        "no_extra_hnf_or_tail_tv_cost": True, "gadget_fiber_bias_counted_once": True,
        "sampler_draws": 0, "root_redraws": 0,
        "all_setup_roots_certified": False, "full_signature_law_certified": False,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None}
