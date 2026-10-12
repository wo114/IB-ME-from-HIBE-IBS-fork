"""Same-input sufficient widths/resources, not ABB's hidden omega constants.

All quantities below are public. The conservative transformation bound uses
the actual finite SampleR support, not observed private geometry. Rejected
domains are reported; nothing generates a key, retries a sample, or drops a
guard. Bit correctness and LWE/ROM conditions are independent.
"""

from fractions import Fraction

from ibme.core.errors import InvalidParameterError
from ibme.lattice.research import FirstFiniteGaussian, FirstFiniteOptions
from .trapgen import ABBTrapGenParams, ceil_sqrt, bounded_integer


def abb_parameter_screen(root, *, epsilon_bits=128, error_bits=128,
                         seed_bytes=32, encapsulations=2**20, options=None):
    if not isinstance(root, ABBTrapGenParams):
        raise InvalidParameterError("explicit AP09 root profile required")
    epsilon_bits = bounded_integer(epsilon_bits, "epsilon_bits", 2, 4096)
    error_bits = bounded_integer(error_bits, "error_bits", 8, 4096)
    seed_bytes = bounded_integer(seed_bytes, "seed_bytes", 1, 32)
    encapsulations = bounded_integer(encapsulations, "encapsulations", 1, 2**32)
    opts = FirstFiniteOptions() if options is None else options
    m = root.dimension
    factor = (2 * m * (1 + 2**epsilon_bits) - 1).bit_length()
    root_gs = root.gs_squared_bound
    r_squared = 4 * root_gs * factor
    scalar = FirstFiniteGaussian(r_squared, r_squared, options=opts)
    r_operator_squared = m**2 * scalar.radius**2  # deterministic Frobenius >= spectral
    sigma1_squared = 4 * root_gs * r_operator_squared * factor
    parent_gs_squared = sigma1_squared * m  # bounded RandBasis norm event
    sigma2_squared = 4 * parent_gs_squared * r_operator_squared * factor
    leaf_gs_squared = sigma2_squared * m
    tau_squared = 4 * leaf_gs_squared * factor
    d_squared = tau_squared * m
    q_alpha = 4
    # ln(2/eps)/pi < error_bits+1, and two upward integer square roots.
    error_upper = (q_alpha * ceil_sqrt(1 + d_squared) * ceil_sqrt(error_bits + 1)
                   + Fraction(1 + ceil_sqrt(m * d_squared), 2))
    bits = 8 * seed_bytes
    sufficient = error_upper < Fraction(root.q, 5) and root.q >= 23
    blockers = []
    if m > 192:
        blockers.append("BasisDel/ToBasis existing hard dimension 192")
    if m > 256:
        blockers.append("public finite GPV existing hard dimension 256")
    if root.q > 2**61 - 1:
        blockers.append("existing SampleR hard modulus 2^61-1")
    if sigma2_squared > 2**80:
        # Coordinate variance can be even larger if a GS length is <1. This
        # is a necessary support obstacle for any lattice of determinant q^n:
        # min GS^2 <= (q^(2n))^(1/m), handled explicitly below.
        if sigma2_squared**m > (2**80)**m * root.q**(2 * root.n):
            blockers.append("at least one leaf GPV scalar exceeds squared width 2^80")
    if not sufficient:
        blockers.append("conditional ABB phase-noise sufficient bound fails")
    certificate = root.certificate()
    return {
        "profile": "ABB-ROM-SAME-INPUT-SCREEN/1", "measured": False,
        "root": certificate, "epsilon_bits": epsilon_bits, "error_bits": error_bits,
        "matrix_gaussian_squared_width": str(r_squared), "finite_R_support_radius": scalar.radius,
        "transformation_operator_squared_sufficient_bound": str(r_operator_squared),
        "sigma1_squared": str(sigma1_squared), "parent_gs_squared_on_success": str(parent_gs_squared),
        "sigma2_squared": str(sigma2_squared), "leaf_gs_squared_on_success": str(leaf_gs_squared),
        "decryption_tau_squared": str(tau_squared), "preimage_norm_squared_event": str(d_squared),
        "q_alpha": q_alpha, "alpha": str(Fraction(q_alpha, root.q)),
        "conditional_phase_error_upper": str(error_upper),
        "conditional_noise_sufficient": sufficient,
        "conditional_ideal_noise_lifetime_upper": (str(Fraction(bits * encapsulations, 2**error_bits))
                                                   if sufficient else None),
        "seed_bytes": seed_bytes, "independently_encrypted_bits": bits,
        "encapsulations": encapsulations,
        "raw_seed_coefficient_wire_lower_bound_bytes": bits * (m + 1) * ((root.log_q_ceiling + 7) // 8),
        "root_parent_leaf_basis_entry_counts": [m * m] * 3,
        "root_parent_leaf_dimensions": [m] * 3,
        "finite_R_scalar_certificate": scalar.certificate(), "blockers": blockers,
        "available_complete_execution": False,
        "paper_Theorem3_omega_constants_verified": False,
        "matrix_RO_indifferentiability_verified": False, "LWE_hardness_verified": False,
        "disclosure": "public sufficient bounds only; no private basis/GS or sampled outputs",
        "not_covered": ["bad norm events", "root/SampleR/GPV TV and ABORT", "BasisDel completion resources",
                        "ROM instantiation and security reductions", "hardware process RSS/time"],
        "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False,
    }
