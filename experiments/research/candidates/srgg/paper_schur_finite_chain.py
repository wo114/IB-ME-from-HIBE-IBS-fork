"""Fixed-root finite source-Schur sampler versus mathematical Algorithms 3--4.

This is a *local*, all-ticket numerical/discrete-kernel coupling.  It starts
from an independently replayed ``SchurNumericalAudit`` on one accepted root;
no root-selection probability, lattice smoothing, HNF, signature history, or
hardness claim follows from it.  An independent uniform byte stream and
correctly rounded, exception-free MPFR operations are explicit premises.

The conservative constants below are for B=512, P=768, dyadic bits <=384,
n<=512, not empirical error estimates. Put u=2^-768, h=2^-512, tau=2^-170.

* Couple each B-bit midpoint ticket to the continuous uniform in its cell.
  Outside U<tau, |U-midpoint|<=h/2 and min(U,midpoint)>tau/2.  Thus the
  Box--Muller radius changes by at most sqrt(2h/tau); the angle changes by
  at most pi*h.  The radius on this event is <sqrt(2log(2/tau))<16, hence
  both normal coordinates change by less than 2^-168.  There is one bad-U
  event of probability tau per pair, not a TV comparison of continuous laws.
* Every midpoint is an exact P-bit MPFR input.  Its log has magnitude <2^9;
  correct rounding introduces absolute error <2^9u.  The smallest exact
  -2log(U) is >2^-512.  Propagating a <2^10u input error through sqrt costs
  <2^267u.  Pi, angle, sin/cos, and final multiplication add <2^100u.
  Therefore each computed normal differs from its exact midpoint normal by
  <2^-490 and has magnitude <32, for *every* ticket.
* In a length-n negacyclic forward/factor/inverse FFT, each exact and finite
  intermediate has complex magnitude <2^64: unit-modulus twiddles (finite
  powers differ by <2^20u) give a <2^17 forward envelope; the stored
  factor is <2^32; inverse butterflies and twists remain <2^64.  There are
  <2^20 rounded real/complex operations.  Each local error, including a
  twiddle error times an operand, is <2^132u; the remaining butterflies,
  factor and twists amplify it by <2^128.  The coordinate error is thus
  <2^(20+132+128)u=2^-488; we use the weaker 2^-400 gate.  This is an
  all-input arithmetic bound, not a replay of selected vectors.
  More explicitly, a primitive unit has error <2^10u; for <=512 repeated
  products the recurrence e_(j+1)<=(1+2^10u)e_j+2^11u gives e_j<2^20u.
  A butterfly has amplification <2+2^-700; 18 layers, one <2^32 factor,
  and two twist stages amplify an injected error by <2^128.  A complex
  multiply is four correctly rounded *real* products and additions, not a
  single correctly rounded complex primitive.
* A stored factor >2 and covariance-square error <=2^-128 imply a factor
  error <2^-128 against the ideal Schur square root.  For any normal vector
  with coordinates <=32, the resulting coefficient shift changes by at most
  n*32*2^-128.  The same-successful-history center error is <=2^-96 from
  the independent numerical audit.
* For 1<=v<=16, the exact scalar D_Z,v,c kernel is 4096-Lipschitz in TV as
  a function of c.  Indeed Z(c)>1/3, and at most two integers lie in each
  shell j<=|k-c|<j+1.  Since exp(-pi*j*j/16)<=(7/8)^j, the unnormalized
  first absolute moment is <=2*sum(j+1)*(7/8)^j=128.  Hence the normalized
  moment is <384 and its TV derivative is <=(2pi/v)*384<4096.

An 8192-bit scalar rational-input gate needs separate treatment: a nonzero
P-bit shift of absolute value >=2^-6000 has dyadic denominator at most
2^(P+6000).  For the admitted integer witness, the initial center
denominator divides the checked public noise/lower ratio; later centers are
directly rounded onto the checked 2^-D grid, D<=384.
With center magnitude <2^240 these two denominators leave both numerator
and denominator below 8192 bits.  A bit-gate abort therefore requires a
finite shift smaller than 2^-6000.  Under the good-ticket coupling this is
within ``delta_stored`` of one coordinate of a stored-factor Gaussian whose
factor spectrum is >2; that coordinate has variance >4 and density <1/4.
The union probability is bounded by 2*n*(2^-6000+delta_stored) per leaf.
"""

from __future__ import annotations

from fractions import Fraction

from sage.all import ComplexField, ComplexIntervalField

from .aggregate_budget import batch_certificate
from .paper_samplef import PaperSeriesOptions
from .paper_schur_fourier import FourierSchurPlan
from .paper_schur_numerical import SchurNumericalAudit
from .paper_schur_samplef import PaperSchurSampleF, RingSampleF
from .structured_samplef import SeriesOptions
from .wide_scalar import WideScalarGaussian, WideScalarOptions


SCHEMA = "IBME/SRGG-SCHUR-FIXED-ROOT-FINITE-CHAIN/1"
TICKET_BITS = 512
PRECISION_BITS = 768
MAX_DYADIC_BITS = 384
RATIONAL_BITS = 8192
MAX_DEGREE = 512
MAX_LEAVES = 16
FACTOR_MAX = 2**32
FACTOR_MIN = 2
CENTER_MAX = 2**240


def _fraction(value):
    """Sage rationals are not reliably accepted by Fraction on Python 3.13."""
    if isinstance(value, bool):
        raise ValueError("exact rational required")
    if isinstance(value, Fraction):
        return value
    if callable(getattr(value, "numerator", None)):
        return Fraction(int(value.numerator()), int(value.denominator()))
    if type(value) in (int, str):
        return Fraction(value)
    raise ValueError("exact rational required")


def _dyadic_bits(value):
    """Largest b with nonzero 0<value<=2^-b, using integer comparisons."""
    value = _fraction(value)
    if not 0 < value < 1:
        raise ValueError("positive subunit bound required")
    numerator, denominator = value.numerator, value.denominator
    bits = max(0, denominator.bit_length()-numerator.bit_length())
    while bits and numerator << bits > denominator:
        bits -= 1
    while numerator << (bits+1) <= denominator:
        bits += 1
    return bits


def _bit_length(value):
    """Bit length of ceil(nonnegative exact rational)."""
    value = _fraction(value)
    if value < 0:
        raise ValueError("nonnegative bound required")
    return ((value.numerator+value.denominator-1)//value.denominator).bit_length()


def _source_gates(audit):
    if type(audit) is not SchurNumericalAudit:
        raise TypeError("independent fixed-root SchurNumericalAudit required")
    sampler, g, public = audit.sampler, audit.geometry, audit.public_certificate()
    n, leaves = g.degree, g.upper_polynomials
    opt = sampler.options
    if (type(sampler) is not PaperSchurSampleF or
            type(opt) not in (SeriesOptions, PaperSeriesOptions) or
            sampler.geometry is not g or type(sampler.plan) is not FourierSchurPlan or
            sampler.plan.geometry is not g or sampler.plan.degree != n or
            sampler.plan.precision_bits != opt.precision_bits or
            sampler.plan.dyadic_bits != opt.vector_dyadic_bits or
            sampler.plan.field is not ComplexIntervalField(opt.precision_bits)):
        raise ValueError("parent sampler/Schur plan parameters are not bound")
    if (n < 2 or n > MAX_DEGREE or n & (n-1) or
            leaves < 1 or leaves > MAX_LEAVES or
            (opt.ticket_bits, opt.precision_bits) !=
            (TICKET_BITS, PRECISION_BITS) or
            not 64 <= opt.vector_dyadic_bits <= MAX_DYADIC_BITS):
        raise ValueError("fixed B512/P768/dyadic<=384 power-of-two profile required")
    scalar_groups = ((sampler.lower_scalar, g.lower_scalar, sampler.lower_batch,
                      g.lower_polynomials*n),
                     (sampler.rounding_scalar, g.rounding_squared, sampler.rounding_batch,
                      leaves*n))
    for scalar, width, recorded_batch, count in scalar_groups:
        if (type(scalar) is not WideScalarGaussian or
                type(scalar.options) is not WideScalarOptions or
                scalar.options.rational_bits != RATIONAL_BITS or
                _fraction(scalar.v_min) != _fraction(width) or
                _fraction(scalar.v_max) != _fraction(width)):
            raise ValueError("scalar parameter/field class is not bound")
        reference = WideScalarGaussian(width, width, options=scalar.options)
        if scalar.field is not reference.field:
            raise ValueError("scalar parameter/field class is not bound")
        if (scalar.certificate() != reference.certificate() or
                scalar.cap_bits != reference.cap_bits or
                recorded_batch != batch_certificate(reference, count,
                    error_bits=opt.aggregate_abort_bits,
                    max_bytes=opt.max_entropy_bytes)):
            raise ValueError("scalar implementation or aggregate batch changed after preparation")
    ticket_bytes = leaves*n*((opt.ticket_bits+7)//8)
    if (sampler.ticket_bytes != ticket_bytes or
            sampler.byte_cap != ticket_bytes+sampler.lower_batch["selected_cap_bytes"]+
            sampler.rounding_batch["selected_cap_bytes"] or
            sampler.byte_cap > opt.max_entropy_bytes):
        raise ValueError("parent sampler entropy caps are not bound")
    if not Fraction(1) <= _fraction(g.rounding_squared) <= Fraction(16):
        raise ValueError("rounding density shape outside the proved [1,16] class")
    if (not public["all_ideal_schur_pivot_eigenvalues_at_least_64"] or
            public["gain_coefficient_error_upper"] != "1/"+str(2**128) or
            public["stored_factor_ideal_covariance_operator_error_upper"] != "1/"+str(2**128) or
            public["adaptive_center_coefficient_error_upper_on_same_successful_history"] !=
            "1/"+str(2**96) or
            not public["center_recurrence_covers_all_successful_residuals_within_prepared_envelopes"]):
        raise ValueError("fixed-root numerical audit does not meet local gates")
    if len(audit._stored_factor_rationals) != leaves or len(sampler.leaves) != leaves:
        raise ValueError("audited factor stages do not match prepared leaves")
    for factors, leaf in zip(audit._stored_factor_rationals, sampler.leaves):
        if (type(leaf) is not RingSampleF or leaf.geometry is not g or
                leaf.options is not opt or leaf.scalar is not sampler.rounding_scalar or
                leaf.field is not ComplexField(opt.precision_bits) or
                leaf.field(0).real().parent().prec() != opt.precision_bits or
                leaf.field(0).real().parent().rounding_mode() != "RNDN"):
            raise ValueError("leaf field/options/geometry/scalar are not bound")
        if len(factors) != n//2 or len(leaf.factors) != n//2:
            raise ValueError("audited factor dimension mismatch")
        for recorded, current in zip(factors, leaf.factors):
            if current.imag() != 0 or _fraction(recorded) != _fraction(current.real().exact_rational()):
                raise ValueError("stored factor changed after the independent audit")
            if not FACTOR_MIN < _fraction(recorded) < FACTOR_MAX:
                raise ValueError("positive stored factor outside the proved envelope")

    ratio = _fraction(g.noise_squared/g.lower_scalar)
    dyadic_bits = opt.vector_dyadic_bits
    if ratio.denominator.bit_length() > dyadic_bits:
        raise ValueError("initial exact-center denominator exceeds dyadic reserve")
    if any(_fraction(c).denominator != 1 for row in g.witness
           for poly in row for c in poly.list()):
        raise ValueError("integer witness required for the initial-center denominator proof")
    # Recompute the public all-history magnitude envelope independently of
    # PaperSchurSampleF's constructor.  Witness coefficients stay process-local.
    lower_cap = sampler.lower_scalar.radius+1
    bounds = [abs(ratio)*sum(sum(abs(_fraction(c)) for c in poly.list())
                             for poly in row)*lower_cap for row in g.witness]
    if len(bounds) != leaves or not all(bound < CENTER_MAX for bound in bounds):
        raise ValueError("initial adaptive centers exceed the proved envelope")
    for stage, leaf in zip(sampler.plan.stages, sampler.leaves):
        if stage.index != len(bounds)-1 or len(stage.gains) != len(bounds)-1:
            raise ValueError("source-Schur stage/center order mismatch")
        if any((2**dyadic_bits) % _fraction(c).denominator for gain in stage.gains
               for c in gain.list()):
            raise ValueError("stored gain is not on the certified dyadic grid")
        factor_max = max(_fraction(f) for f in audit._stored_factor_rationals[leaves-1-stage.index])
        shift_max = n*32*factor_max+Fraction(1, 2**400)
        if (shift_max+sampler.rounding_scalar.radius+1 > _fraction(leaf.noise_cap) or
                _bit_length(bounds[-1]+shift_max+sampler.rounding_scalar.radius+1) >
                sampler.rounding_scalar.options.max_output_bits or
                _bit_length(bounds[-1]+shift_max+sampler.rounding_scalar.radius+1) > 256):
            raise ValueError("leaf numerical/noise/object output guard not proved")
        bounds = [bound+sum(abs(_fraction(c)) for c in gain.list())*_fraction(leaf.noise_cap)
                  +Fraction(1, 2**dyadic_bits)
                  for bound, gain in zip(bounds[:-1], stage.gains)]
        if not all(bound < CENTER_MAX for bound in bounds):
            raise ValueError("updated adaptive centers exceed the proved envelope")
    return n, leaves, sampler


def fixed_root_finite_chain_certificate(audit):
    """Bound finite ``PaperSchurSampleF`` vs exact mathematical Algorithm 3--4.

    The comparator samples the same ideal lower D_Z block, then descends the
    *same* ring-Schur geometry with independent exact continuous Gaussians
    and exact D_Z,r conditional rounding at each adaptive center.  Abort is
    an extra output symbol.  A failed gate raises rather than returning a
    misleading security-admission certificate.
    """
    if type(audit) is not SchurNumericalAudit:
        raise TypeError("independent fixed-root SchurNumericalAudit required")
    # A caller may have changed the mutable plan after constructing `audit`.
    # Replay the *whole* independent Schur check on its current sampler; a
    # public metadata or dyadic-grid check alone cannot bind stored gains.
    audit = SchurNumericalAudit(audit.sampler)
    n, leaves, sampler = _source_gates(audit)
    lower_tv = _fraction(sampler.lower_batch["scalar_kernel_tv_including_aggregate_exact"])
    rounding_tv = _fraction(sampler.rounding_batch["scalar_kernel_tv_including_aggregate_exact"])
    ticket_bad = leaves*(n//2)*Fraction(1, 2**170)
    # Coupling continuous U,V to midpoint tickets; computed Box--Muller;
    # then exact Fourier application of the *stored* factors.
    delta_stored = n*FACTOR_MAX*(Fraction(1, 2**168)+Fraction(1, 2**490))+Fraction(1, 2**400)
    # Independent directed fixed-root covariance-square audit supplies the
    # ideal-factor difference, with both positive factors >2.
    delta_ideal = delta_stored+n*32*Fraction(1, 2**128)
    bit_gate = leaves*2*n*(Fraction(1, 2**6000)+delta_stored)
    adaptive_centers = leaves*4096*n*(Fraction(1, 2**96)+delta_ideal)
    total = lower_tv+rounding_tv+ticket_bad+bit_gate+adaptive_centers
    if not 0 < total < 1:
        raise ValueError("finite fixed-root total-TV bound is not nontrivial")
    bits = _dyadic_bits(total)
    components = {
        "lower_scalar_and_aggregate": lower_tv,
        "rounding_scalar_and_aggregate": rounding_tv,
        "bad_continuous_ticket_cells": ticket_bad,
        "rational_input_bit_gate": bit_gate,
        "adaptive_center_and_shift_kernel": adaptive_centers,
    }
    return {"schema": SCHEMA, "degree": n, "upper_leaf_count": leaves,
        "reference": "fixed-root mathematical Algorithms 3-4 sequential continuous-then-discrete chain, with abort as an extra symbol",
        "density_shape_scope": "the current PaperParams exact rational interpretation, including the table-standard-deviation pi-endpoint approximation where selected; not a unique author-exact r/pi claim",
        "finite_vs_exact_algorithm34_tv_dyadic_upper": "2^-"+str(bits),
        "finite_vs_exact_algorithm34_tv_dyadic_bits": bits,
        "component_dyadic_uppers": {key: "2^-"+str(_dyadic_bits(value))
                                     for key, value in components.items()},
        "bound_formula": "lower_batch_tv + rounding_batch_tv + leaves*(n/2)*2^-170 + leaves*2*n*(2^-6000+delta_stored) + leaves*4096*n*(2^-96+delta_ideal)",
        "delta_stored_formula": "n*2^32*(2^-168+2^-490)+2^-400",
        "delta_ideal_formula": "delta_stored+n*32*2^-128",
        "mpfr_arithmetic_premise": "exception-free P768 complex arithmetic built from correctly rounded MPFR real primitives (including pi, log, sqrt, sin, cos); no external runtime faults",
        "randomness_premise": "independent uniform bytes; deterministic test seeds do not establish this",
        "all_midpoint_tickets_covered": True,
        "normal_ticket_invariant_abort_upper": "0",
        "leaf_noise_and_output_invariant_abort_upper": "0",
        "scalar_magnitude_checked_inputs_abort_upper": "0",
        "scalar_rational_bit_abort_upper": "2^-"+str(_dyadic_bits(bit_gate)),
        "aggregate_and_scalar_abort_included_in_batch_tv": True,
        "fixed_root_only": True, "accepted_setup_root_distribution_bound": None,
        "finite_vs_joint_integer_gaussian_tv_upper": None,
        "HNF_key_or_signature_law_certified": False,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None}
