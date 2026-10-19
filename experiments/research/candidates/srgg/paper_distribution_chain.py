r"""Mathematical thresholds and conditional SRGG distribution bounds.

The original three Table 4 rows and both Gaussian interpretations are fixed.
For the mathematical set G_C={C>64I}, exact algebra gives G_C subset A and
the ideal master Schur floor L2>64. The trace-moment calculation bounds
mu(G_C^c), TV(mu(.|A),mu(.|G_C)), and exhaustion for an ideal mathematical
G_C retry model. None of these numbers is a measured or certified budget
for the implemented interval guard.

B_legacy denotes the historical unguarded backend's one-attempt success set.
H_setup and H_sign denote the current complete implemented audit predicates.
Interval soundness prevents false acceptance; it does not establish numerical
completeness on G_C. The uniform preparation-error envelope, the 192-bit C-gate
inconclusive shell, actual accepted-root law and actual Setup abort budget
remain null. In particular G_C subset B_legacy is an additional unverified
premise, not a consequence asserted by this module.

Conditional issuance/signing bounds apply on plans that actually pass all
required gates. Applying the same key guard and abort atom to actual and
reference laws gives TV <= delta_issue+s*epsilon_good. Logical API outputs
and deterministic persistent state are the history scope; timing, internal
sampler/runtime traces and unmodeled faults are excluded. No security claim,
formal parameter admission, NIST category or HIBE result is added.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
from hashlib import sha256
import json
import platform
from pathlib import Path
from time import perf_counter

from sage.version import version as sage_version

from ibme.core.randomness import DeterministicRandom

from .paper_issuance_bridge import combine_issuance_tv, fixed_root_c_gate
from .paper_parameters import PaperParams, pi_enclosure
from .paper_profiles import SOURCE_PDF, SOURCE_SHA256, profiles
from .paper_rounding_budget import theta_certificate
from .paper_samplef import WitnessGeometryError
from .paper_schur_backend import SourceSchurBackend
from .paper_schur_convolution import chain_convolution_certificate
from .paper_schur_finite_chain import (
    _fraction, _dyadic_bits, fixed_root_finite_chain_certificate,
)
from .paper_schur_literal_moment import moment_chain_certificate
from .paper_schur_normalizer import fixed_root_normalizer_certificate
from .paper_schur_numerical import SchurNumericalAudit
from .paper_setup_acceptance import wishart_trace_moment
from .paper_setup_conditioning import residual_threshold_squared
from .paper_source_issuance_bridge import _source_key_guard_envelope


SCHEMA = "IBME/SRGG-PAPER-DISTRIBUTION-CHAIN/1"
PROFILES = ("PARAM-I", "PARAM-II", "PARAM-III")
INTERPRETATIONS = ("table-standard-deviation", "literal-density-width")
GATE_FLOOR = Fraction(64)
HISTORY_SCOPE = "logical_api_outputs_and_deterministic_persistent_state"
MOMENT_ORDERS = {"PARAM-I": 17, "PARAM-II": 22, "PARAM-III": 28}
SECURITY_FIELDS = {
    "security_claim": "none",
    "backend_admitted": False,
    "parameters_are_formal": False,
    "nist_security_category": None,
}


class ChainCertificateError(ValueError):
    """A distribution-chain premise or exact comparison failed."""


def _dyadic_probability(text):
    if type(text) is not str or not text.startswith("2^-"):
        raise ChainCertificateError("dyadic upper required")
    bits = text[3:]
    if not bits.isdecimal() or len(bits) > 5 or int(bits) > 16384:
        raise ChainCertificateError("bounded dyadic exponent required")
    return Fraction(1, 2**int(bits))


def _dyadic_upper(value):
    """Readable outward power-of-two upper bound for a probability."""
    value = Fraction(value)
    if not 0 <= value <= 1:
        raise ChainCertificateError("probability required")
    if value == 0:
        return "0"
    if value == 1:
        return "1"
    bits = _dyadic_bits(value)
    return "2^-" + str(bits) if bits else "1"


def _fraction_text(value):
    return str(Fraction(value))


def good_root_constants(profile, interpretation):
    """Exact G_C => A/Schur comparisons and candidate envelope constants.

    Rational comparisons below are exact. Constants assigned for numerical
    error/output envelopes are not a proof that every G_C root passes the
    finite implementation's preparation gates.
    """
    if type(profile) is not str or profile not in PROFILES:
        raise ChainCertificateError("one original Table 4 profile required")
    if type(interpretation) is not str or interpretation not in INTERPRETATIONS:
        raise ChainCertificateError("one explicit Gaussian interpretation required")
    params = PaperParams(profile, interpretation)
    a1 = Fraction(params.master_first_squared)
    a2 = Fraction(params.master_second_squared)
    r2 = Fraction(params.r_squared)
    nu = Fraction(params.base**2) * r2
    scale = nu * a2 / (a2 - nu)
    threshold_a = residual_threshold_squared(a1, a2, r2, params.base)
    threshold_c = a1 * (nu - GATE_FLOOR - nu * nu / a2) / (nu * nu)
    threshold_schur = (a1 - GATE_FLOOR) / scale
    lower_schur = a1 - scale * threshold_c
    if not threshold_c < threshold_a:
        raise ChainCertificateError("C-gate threshold does not imply A")
    if not threshold_c < threshold_schur:
        raise ChainCertificateError("C gate does not imply the Schur pivot floor")
    if not lower_schur > GATE_FLOOR:
        raise ChainCertificateError("uniform Schur lower bound does not exceed 64")
    gain_bound = (a1 + scale * threshold_c) / lower_schur
    pi_low, pi_high = pi_enclosure()
    factor_low_squared = (lower_schur - r2) / (2 * pi_high)
    factor_high_squared = (2 * a1 - r2) / (2 * pi_low)
    if not factor_low_squared > 250**2:
        raise ChainCertificateError("uniform factor lower bound below 250")
    if not factor_high_squared < 8192**2:
        raise ChainCertificateError("uniform factor upper bound above 8192")
    if not gain_bound < 512:
        raise ChainCertificateError("uniform gain coefficient bound above 512")
    # Conservative audit/cap constants used by the proof.
    noise_cap_upper = Fraction(2**35)
    # The stored gain is rounded to the 2^-256 dyadic grid; the directed
    # interval error is far below that.  Cauchy--Schwarz on the length-512
    # coefficient vector and Plancherel give ||gain||_1 <= sqrt(n)*max|gain|
    # <= sqrt(512)*512 < 2^14.
    gain_error_upper = Fraction(1, 2**256)
    gain_l1_upper = Fraction(2**14)
    center_error_upper = Fraction(1, 2**96)
    error = Fraction(0)
    for _ in range(2 * params.rank):
        error = (params.degree * gain_error_upper * noise_cap_upper
                 + gain_l1_upper * error + Fraction(1, 2**257))
    if not error < center_error_upper:
        raise ChainCertificateError("uniform adaptive-center error exceeds 2^-96")
    object_cap_bits = 64
    if object_cap_bits > 255:
        raise ChainCertificateError("uniform object envelope exceeds 256 bits")
    return {
        "profile": profile,
        "interpretation": interpretation,
        "good_root_set": "C > 64 I",
        "C_definition": "C = nu I - nu^2 T^* Sigma^-1 T, T=[R;I]",
        "A_definition": "Sigma_p - r^2 I > 0",
        "threshold_A_squared_exact": str(threshold_a),
        "threshold_C_gate_squared_exact": str(threshold_c),
        "threshold_schur_gate_squared_exact": str(threshold_schur),
        "uniform_schur_lower_bound_exact": str(lower_schur),
        "uniform_schur_lower_bound_decimal": float(lower_schur),
        "uniform_schur_lower_bound_gt_64": lower_schur > GATE_FLOOR,
        "C_gate_implies_A": threshold_c < threshold_a,
        "C_gate_implies_schur_floor": threshold_c < threshold_schur,
        "uniform_gain_coefficient_upper_exact": str(gain_bound),
        "uniform_gain_coefficient_upper_lt_512": gain_bound < 512,
        "uniform_factor_squared_lower_exact": str(factor_low_squared),
        "uniform_factor_squared_upper_exact": str(factor_high_squared),
        "uniform_factor_in_250_8192": True,
        "uniform_noise_cap_upper_exact": str(noise_cap_upper),
        "uniform_gain_error_upper_exact": str(gain_error_upper),
        "uniform_gain_l1_upper_exact": str(gain_l1_upper),
        "uniform_center_error_upper_exact": str(center_error_upper),
        "uniform_center_error_below_2_minus_96": error < center_error_upper,
        "uniform_object_cap_bits": object_cap_bits,
        "scope": "mathematical G_C algebra plus candidate envelope constants",
        "uniform_implementation_preparation_error_upper": None,
        "G_C_implies_legacy_backend_acceptance": None,
        "implemented_C_gate_inconclusive_shell_mass_upper": None,
        "parameters_unchanged": True,
        "bit_lengths": {
            "threshold_A": max(threshold_a.numerator.bit_length(),
                               threshold_a.denominator.bit_length()),
            "threshold_C": max(threshold_c.numerator.bit_length(),
                               threshold_c.denominator.bit_length()),
            "lower_schur": max(lower_schur.numerator.bit_length(),
                               lower_schur.denominator.bit_length()),
        },
    }


def moment_bound(threshold, rows, columns, order, degree):
    """Exact complex-Wishart trace-moment bound at an arbitrary threshold."""
    if not isinstance(threshold, Fraction) or threshold <= 0:
        raise ChainCertificateError("positive exact threshold required")
    if type(rows) is not int or type(columns) is not int or type(order) is not int:
        raise ChainCertificateError("integer moment dimensions required")
    if type(degree) is not int:
        raise ChainCertificateError("integer degree required")
    moment = wishart_trace_moment(rows, columns, order, Fraction(degree, 2))
    return Fraction(degree, 2) * moment / threshold**order


def bad_root_certificate(profile, interpretation):
    """Exact q_A/q_C for mathematical events, not implemented acceptance."""
    constants = good_root_constants(profile, interpretation)
    params = PaperParams(profile, interpretation)
    threshold_a = Fraction(constants["threshold_A_squared_exact"])
    threshold_c = Fraction(constants["threshold_C_gate_squared_exact"])
    order = MOMENT_ORDERS[profile]
    rows, columns = 2 * params.rank, params.digits * params.rank
    q_a = moment_bound(threshold_a, rows, columns, order, params.degree)
    q_c = moment_bound(threshold_c, rows, columns, order, params.degree)
    if not (0 < q_a < 1 and 0 < q_c < 1):
        raise ChainCertificateError("moment bound is not a probability upper bound")
    ratio = q_c / (1 - q_a)
    if not ratio < 1:
        raise ChainCertificateError("accepted-root TV bound is trivial")
    abort = q_c**64
    return {
        "profile": profile,
        "interpretation": interpretation,
        "moment_order": order,
        "wishart_shape": [rows, columns],
        "entry_second_moment": str(Fraction(params.degree, 2)),
        "A_rejection_one_attempt_upper_exact": str(q_a),
        "A_rejection_one_attempt_upper_decimal": float(q_a),
        "C_gate_rejection_one_attempt_upper_exact": str(q_c),
        "C_gate_rejection_one_attempt_upper_decimal": float(q_c),
        "A_minus_G_unconditional_upper_decimal": float(q_c),
        "mathematical_mu_A_mu_G_tv_upper_exact": str(ratio),
        "mathematical_mu_A_mu_G_tv_upper_decimal": float(ratio),
        "mathematical_mu_A_mu_G_tv_upper_dyadic": _dyadic_upper(ratio),
        "mathematical_G_64_retry_abort_upper_dyadic": _dyadic_upper(abort),
        "mathematical_G_64_retry_abort_below_2_minus_64": abort < Fraction(1, 2**64),
        "scope": "ideal mathematical G_C predicate; all G_C failures retried",
        "implemented_guard_retry_abort_upper": None,
        "moment_method": "negacyclic Fourier direct sum; CBD1 moment dominance; "
                         "exact complex Wishart hook moment; Markov union over n/2 blocks",
    }


def _root_seed(profile, interpretation):
    return ("paper-baseline-" + profile + "-" + interpretation).encode("ascii")


def require_gates(plan, *, params=None, gadget=None, root_phase=False):
    """Run the complete audit gate set on a prepared plan.

    This is a check, not a new sampler. It defines an implemented predicate;
    no completeness claim over the mathematical G_C set is inferred from
    the deterministic frozen/boundary witnesses.
    """
    try:
        audit = SchurNumericalAudit(plan)
        from .paper_schur_finite_chain import _source_gates
        _n, _leaves, sampler = _source_gates(audit)
    except (ValueError, ArithmeticError, TypeError) as error:
        raise ChainCertificateError("audit/plan gates failed: " + str(error)) from error
    if sampler is not plan:
        raise ChainCertificateError("audit sampler is not the prepared plan")
    extras = {}
    if root_phase:
        if params is None or gadget is None:
            raise ChainCertificateError("root gate requires params and gadget")
        c_gate = fixed_root_c_gate(plan.geometry, lower_bound=64, precision_bits=192)
        if not c_gate.get("certified"):
            raise ChainCertificateError("issuance C gate is not certified")
        object_guard = _source_key_guard_envelope(params, plan, gadget)
        if not object_guard.get("raw_and_key_within_256bit_object_guard"):
            raise ChainCertificateError("finite-key object envelope failed")
        extras = {"c_gate": c_gate, "object_guard": object_guard}
    return audit, extras


def phase_bound(plan, interpretation):
    """Uniform finite + mathematical + normalizer bound on a gated plan.

    Every numerical ingredient is a gate-floor constant or a root-independent
    parameter; the actual pivots enter only through the gate booleans.
    """
    if interpretation not in INTERPRETATIONS:
        raise ChainCertificateError("explicit interpretation required")
    audit = SchurNumericalAudit(plan)
    degree, leaves = audit.geometry.degree, audit.geometry.upper_polynomials
    try:
        finite = fixed_root_finite_chain_certificate(audit)
        finite_upper = _dyadic_probability(
            finite["finite_vs_exact_algorithm34_tv_dyadic_upper"])
    except (ValueError, ArithmeticError) as error:
        return {
            "closed": False,
            "blocker": "finite-chain total is trivial or not certified: " + str(error),
            "finite_upper": None,
            "middle": None,
            "normalizer": None,
            "joint_tv_exact": None,
        }
    if interpretation == "literal-density-width":
        convolution = moment_chain_certificate(
            degree=degree, upper_polynomials=leaves,
            rounding_squared=_fraction(plan.geometry.rounding_squared),
            ideal_pivot_lower=GATE_FLOOR)
    else:
        convolution = chain_convolution_certificate(
            degree=degree, upper_polynomials=leaves,
            rounding_squared=_fraction(plan.geometry.rounding_squared),
            ideal_pivot_lower=GATE_FLOOR)
    middle = convolution[
        "mathematical_algorithm34_to_ideal_sequential_discrete_tv_upper_exact"]
    normalizer = fixed_root_normalizer_certificate(audit)
    normalizer_upper = _dyadic_probability(
        normalizer["ideal_sequential_vs_joint_integer_tv_dyadic_upper"])
    if middle is None:
        return {
            "closed": False,
            "blocker": convolution.get("blocker", "middle mathematical bound is null"),
            "finite_upper": _dyadic_upper(finite_upper),
            "middle": None,
            "normalizer": _dyadic_upper(normalizer_upper),
            "joint_tv_exact": None,
        }
    total = finite_upper + Fraction(middle) + normalizer_upper
    if not 0 <= total < 1:
        return {
            "closed": False,
            "blocker": "combined phase bound is trivial (>=1)",
            "finite_upper": _dyadic_upper(finite_upper),
            "middle": str(Fraction(middle)),
            "normalizer": _dyadic_upper(normalizer_upper),
            "joint_tv_exact": None,
        }
    return {
        "closed": True,
        "blocker": None,
        "finite_upper": _dyadic_upper(finite_upper),
        "middle": str(Fraction(middle)),
        "normalizer": _dyadic_upper(normalizer_upper),
        "joint_tv_exact": str(total),
        "joint_tv_dyadic_upper": _dyadic_upper(total),
        "gate_floor": "64",
        "comparison": "finite Algorithm 3-4 + mathematical convolution + ideal sequential/joint",
    }


def issuance_bound(params, backend, master_plan, interpretation, extras):
    """Uniform first-issuance TV on every root passing the complete gate set."""
    phase = phase_bound(master_plan, interpretation)
    if not phase["closed"]:
        return {"closed": False, "blocker": phase["blocker"],
                "master_perturbation": None,
                "complete_law_tv_upper_including_abort": None}
    if not extras.get("c_gate", {}).get("certified"):
        return {"closed": False,
                "blocker": "issuance centered-gadget C gate is not certified",
                "master_perturbation": phase["joint_tv_dyadic_upper"],
                "complete_law_tv_upper_including_abort": None}
    object_guard = extras.get("object_guard", {})
    if not object_guard.get("raw_and_key_within_256bit_object_guard"):
        return {"closed": False,
                "blocker": "finite-key object/service envelope is not certified",
                "master_perturbation": phase["joint_tv_dyadic_upper"],
                "complete_law_tv_upper_including_abort": None}
    gadget, _scalar = backend._components(params)
    draws = params.rank * params.digits * params.degree
    digit = theta_certificate(dimension=draws,
                              density_shape=Fraction(params.r_squared),
                              precision_bits=192)
    center = theta_certificate(dimension=draws, density_shape=GATE_FLOOR,
                               precision_bits=192)
    digit_sum = digit["dimension_times_scalar_theta_upper_exact"]
    center_error = center["relative_normalizer_error_upper_exact"]
    if digit_sum is None or center_error is None:
        return {"closed": False,
                "blocker": "gadget digit normalizer or completed-square center gate is inconclusive",
                "master_perturbation": phase["joint_tv_dyadic_upper"],
                "complete_law_tv_upper_including_abort": None}
    combined = combine_issuance_tv(
        perturbation_tv=Fraction(phase["joint_tv_exact"]),
        gadget_scalar_tv=Fraction(gadget.batch["scalar_kernel_tv_including_aggregate_exact"]),
        digit_relative_sum=Fraction(digit_sum),
        center_relative_error=Fraction(center_error))
    if not combined.get("certified"):
        return {"closed": False,
                "blocker": "gadget/denominator/center combination not certified",
                "master_perturbation": phase["joint_tv_dyadic_upper"],
                "complete_law_tv_upper_including_abort": None}
    total = Fraction(combined["complete_law_tv_upper_including_abort"])
    return {
        "closed": 0 <= total < 1,
        "blocker": None if total < 1 else "issuance bound is trivial",
        "master_perturbation": phase["joint_tv_dyadic_upper"],
        "c_gate_certified": True,
        "finite_key_object_guard": True,
        "key_coordinate_abs_upper": object_guard.get(
            "centered_hnf_full_key_coordinate_abs_upper"),
        "gadget_scalar_tv": _dyadic_upper(
            Fraction(gadget.batch["scalar_kernel_tv_including_aggregate_exact"])),
        "gadget_digit_relative_sum": str(Fraction(digit_sum)),
        "completed_square_center_relative_error": str(Fraction(center_error)),
        "complete_law_tv_upper_including_abort": str(total),
        "complete_law_tv_dyadic_upper": _dyadic_upper(total),
    }


def sign_call_bound(params, backend, key, interpretation):
    """Uniform one-sign-call TV on every key passing the signing audit gates."""
    plan = backend._sign_plan(key)
    phase = phase_bound(plan, interpretation)
    if not phase["closed"]:
        return {"closed": False, "blocker": phase["blocker"],
                "sign_perturbation": None, "one_sign_call_tv_upper": None}
    _gadget, scalar = backend._components(params)
    backend._sign_attempt_source(params, plan, scalar)
    budget = backend.last_sign_attempt_certificate
    if not budget.get("admitted"):
        return {"closed": False,
                "blocker": "whole-attempt entropy budget not admitted",
                "sign_perturbation": phase["joint_tv_dyadic_upper"],
                "one_sign_call_tv_upper": None}
    perturbation = Fraction(phase["joint_tv_exact"])
    delta_u = Fraction(budget["u_scalar_kernel_tv_including_aggregate_exact"])
    delta = min(Fraction(1), perturbation + delta_u)
    one_call = min(Fraction(1), delta * backend.sign_max_attempts)
    return {
        "closed": one_call < 1,
        "blocker": None if one_call < 1 else "one-call bound is trivial",
        "sign_perturbation": phase["joint_tv_dyadic_upper"],
        "u_batch_tv": _dyadic_upper(delta_u),
        "one_attempt_tv": _dyadic_upper(delta),
        "sign_attempts_per_call": backend.sign_max_attempts,
        "one_sign_call_tv_upper": str(one_call),
        "one_sign_call_tv_dyadic_upper": _dyadic_upper(one_call),
    }


def lifecycle_probe(profile, interpretation):
    """Replay one frozen root through Setup/Extract/Sign and the full gates."""
    params = PaperParams(profile, interpretation)
    seed = _root_seed(profile, interpretation)
    backend = SourceSchurBackend(rng=DeterministicRandom(seed))
    started = perf_counter()
    public, master = backend.setup(params)
    master_plan = backend._master_plan(params, master.witness)
    gadget, _scalar = backend._components(params)
    audit, extras = require_gates(master_plan, params=params,
                                  gadget=gadget, root_phase=True)
    master_phase = phase_bound(master_plan, interpretation)
    issuance = issuance_bound(params, backend, master_plan, interpretation, extras)
    key = backend.key_extract(master, b"Alice")
    sign_plan = backend._sign_plan(key)
    sign_audit, _sign_extras = require_gates(sign_plan)
    sign_phase = phase_bound(sign_plan, interpretation)
    sign_call = sign_call_bound(params, backend, key, interpretation)
    message = b"SRGG distribution chain 32B!!!!"
    signature = backend.sign(key, message)
    verified = backend.verify(public, b"Alice", message, signature)
    elapsed = perf_counter() - started
    return {
        "profile": profile,
        "interpretation": interpretation,
        "seed_sha256": sha256(seed).hexdigest(),
        "public_context_sha256": public.context.hex(),
        "setup_attempts": backend.setup_attempts,
        "extract_calls": backend.extract_calls,
        "sign_attempts": backend.sign_attempts,
        "functional_verified": bool(verified),
        "master_audit_certified": audit.public_certificate()[
            "all_ideal_schur_pivot_eigenvalues_at_least_64"],
        "sign_audit_certified": sign_audit.public_certificate()[
            "all_ideal_schur_pivot_eigenvalues_at_least_64"],
        "c_gate_certified": extras["c_gate"]["certified"],
        "object_envelope_certified": extras["object_guard"][
            "raw_and_key_within_256bit_object_guard"],
        "master_phase": master_phase,
        "issuance": issuance,
        "sign_phase": sign_phase,
        "sign_call": sign_call,
        "elapsed_seconds": elapsed,
    }


def _guarded_tv(delta_issue, epsilon_sign, signs):
    if delta_issue is None or epsilon_sign is None:
        return None
    return min(Fraction(1), Fraction(delta_issue) + signs * Fraction(epsilon_sign))


def build_row(profile, interpretation, *, lifecycle=False):
    params = PaperParams(profile, interpretation)
    constants = good_root_constants(profile, interpretation)
    bad = bad_root_certificate(profile, interpretation)
    row = {
        "profile": profile,
        "interpretation": interpretation,
        "parameters": {
            "n": params.degree, "p": params.p, "b": params.base,
            "w": params.digits, "Q": params.modulus, "d": params.rank,
        },
        "good_root_constants": constants,
        "bad_root_mass": bad,
        "good_root_gate_implication":
            "G_C={C>64I} => A and ideal C_schur>L2 I with L2>64; "
            "acceptance by every finite preparation gate is not established.",
        "accepted_root_distribution": {
            "legacy_backend_set_B":
                "B_legacy: historical unguarded one-attempt preparation success",
            "implemented_guard_set_H":
                "H_setup: current complete implemented root/audit/C/object gates",
            "soundness_inclusion": "H_setup subset G_C subset A; B_legacy subset A",
            "G_C_subset_B_legacy_certified": None,
            "uniform_implementation_preparation_error_upper": None,
            "implemented_C_gate_inconclusive_shell_mass_upper": None,
            "A_minus_B_upper_exact": None,
            "TV_mu_A_mu_B_upper_exact": None,
            "TV_mu_A_mu_B_upper_dyadic": None,
            "TV_mu_A_mu_H_upper_exact": None,
            "original_backend_64_retry_abort_upper": None,
            "original_backend_reason":
                "legacy non-geometric failures did not retry; current retries "
                "do not supply a probability bound for all implemented gates",
            "guarded_64_retry_abort_dyadic": None,
            "reason":
                "mathematical q_C excludes preparation completeness and the "
                "implemented C-gate inconclusive shell; no actual-service "
                "acceptance or abort bound is inferred",
        },
        "guarded_composition": {
            "scope": "conditional on H_setup, common signing guard and abort semantics",
            "history_scope": HISTORY_SCOPE,
            "unguarded_key_TV_delta_issue": None,
            "good_key_one_call_TV_epsilon_good": None,
            "guarded_issue_plus_1_sign_TV": None,
            "guarded_issue_plus_2_signs_TV": None,
            "conditional_logical_no_fault_history_TV": None,
            "implemented_full_history_TV": None,
            "beta_bad_unguarded": None,
            "beta_bad_strictly_positive": True,
            "beta_bad_reason":
                "the canonical large-tail key is in the ideal reference support "
                "and has a strictly negative signature Schur diagonal; its mass "
                "is not quantified.  The guarded theorem applies the same key "
                "guard to actual and reference, so data processing absorbs the "
                "bad-key mass into delta_issue and beta_bad is not needed.",
            "formula":
                "TV(guarded issue + s signs) <= min(1, delta_issue + s*epsilon_good)",
        },
        "fault_history": {
            "TV": None,
            "reason": "no disk/process/lock/rollback fault probability model; an "
                      "injected read fault of probability p gives TV=p, so a "
                      "faulty bound cannot be inferred from the fault-free one",
        },
        "security": dict(SECURITY_FIELDS),
    }
    if lifecycle:
        probe = lifecycle_probe(profile, interpretation)
        row["lifecycle_probe"] = probe
        issuance = probe["issuance"]
        sign_call = probe["sign_call"]
        delta_issue = (Fraction(issuance["complete_law_tv_upper_including_abort"])
                       if issuance["closed"] else None)
        epsilon_sign = (Fraction(sign_call["one_sign_call_tv_upper"])
                        if sign_call["closed"] else None)
        composition = row["guarded_composition"]
        composition["unguarded_key_TV_delta_issue"] = (
            str(delta_issue) if delta_issue is not None else None)
        composition["good_key_one_call_TV_epsilon_good"] = (
            str(epsilon_sign) if epsilon_sign is not None else None)
        composition["guarded_issue_plus_1_sign_TV"] = (
            str(_guarded_tv(delta_issue, epsilon_sign, 1))
            if _guarded_tv(delta_issue, epsilon_sign, 1) is not None else None)
        composition["guarded_issue_plus_2_signs_TV"] = (
            str(_guarded_tv(delta_issue, epsilon_sign, 2))
            if _guarded_tv(delta_issue, epsilon_sign, 2) is not None else None)
        composition["conditional_logical_no_fault_history_TV"] = (
            str(_guarded_tv(delta_issue, epsilon_sign, 2))
            if _guarded_tv(delta_issue, epsilon_sign, 2) is not None else None)
        if delta_issue is not None:
            composition["guarded_issue_plus_1_sign_dyadic"] = _dyadic_upper(
                _guarded_tv(delta_issue, epsilon_sign, 1))
            composition["guarded_issue_plus_2_signs_dyadic"] = _dyadic_upper(
                _guarded_tv(delta_issue, epsilon_sign, 2))
    return row


def build_report(*, lifecycle=False):
    root = Path(__file__).resolve().parents[4]
    if sha256((root / SOURCE_PDF).read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ChainCertificateError("frozen original paper checksum differs")
    if tuple(p.name for p in profiles) != PROFILES:
        raise ChainCertificateError("frozen Table 4 profile set/order differs")
    source_files = [
        "experiments/research/candidates/srgg/paper_schur_finite_chain.py",
        "experiments/research/candidates/srgg/paper_source_issuance_bridge.py",
        "experiments/research/candidates/srgg/paper_schur_numerical.py",
        "experiments/research/candidates/srgg/paper_schur_backend.py",
        "experiments/research/candidates/srgg/paper_setup_acceptance.py",
        "experiments/research/candidates/srgg/paper_issuance_bridge.py",
    ]
    return {
        "schema": SCHEMA,
        "source_pdf": SOURCE_PDF,
        "source_sha256": SOURCE_SHA256,
        "paper_locations":
            "Table 3 p.6; Table 4 pp.9-10; Algorithm 1 p.7; Algorithms 3-8 pp.7-8",
        "scope": "independent SRGG IBS distribution chain; no HIBE",
        "scope_version": "mathematical_events_and_conditional_implemented_gates_v2",
        "good_root_set": "G_C = {C > 64 I} (mathematical)",
        "implemented_guard_set": "H_setup / H_sign: actual complete implemented gates",
        "history_scope": {
            "included": HISTORY_SCOPE,
            "excluded": ["wall_clock_timing", "internal_sampler_or_runtime_traces",
                         "unmodeled_disk_process_lock_rollback_or_power_faults"],
            "matching_setup_or_conditioned_success_required": True,
            "actual_service_full_history_TV": None,
        },
        "main_results": [
            "G_C implies A; threshold gaps are about 0.79% (std) / 4.96% (literal)",
            "G_C implies the ideal master Schur floor L2 = 4.0e5/5.7e5/7.4e5",
            "mu(G_C^c) <= q_C; mathematical TV(mu(.|A),mu(.|G_C)) <= q_C/(1-q_A)",
            "q_C^64 applies only to an ideal mathematical G_C retry model",
            "conditional common-guard logical issue+sign TV <= delta_issue+s*epsilon_good",
        ],
        "source_parameters_unchanged": True,
        "independent_uniform_bytes_assumed": True,
        "mpfr_premise":
            "exception-free P768 complex arithmetic built from correctly rounded "
            "MPFR real primitives; deterministic seeds do not establish this",
        "guard_is_service_change": True,
        "unguarded_original_backend": {
            "A_minus_B_upper_exact": None,
            "accepted_root_distribution_TV_upper_exact": None,
            "reason":
                "G_C subset B_legacy requires a uniform finite-preparation "
                "enclosure not supplied here; interval soundness alone is "
                "insufficient. Historical B_legacy is not the current H_setup.",
        },
        "rows": [build_row(p, i, lifecycle=lifecycle)
                 for p in PROFILES for i in INTERPRETATIONS],
        "null_ledger": [
            "unguarded beta_bad mass: null (guarded data-processing theorem does not need it)",
            "legacy B_legacy acceptance law and all-B finite-chain/issuance TV: null",
            "G_C subset B_legacy and uniform finite-preparation enclosure: null",
            "implemented C-gate inconclusive-shell mass: null",
            "implemented H_setup accepted-root law and 64-attempt abort: null",
            "actual-service full history including Setup budget: null; logical conditional bounds only",
            "wall-clock timing and internal sampler/runtime trace TV: null (outside logical API scope)",
            "literal-density first issuance: null (gadget digit-normalizer gate fails)",
            "literal-density one sign call: trivial 1",
            "original backend 64-attempt abort: null (non-retryable failures)",
            "exact author sampler / C program correspondence: null",
            "exact ring Schur acceptance certifier: failed at the 16384-bit "
            "rational cap on a Table 4 root; not used",
            "native strong, structural hardness, NIST category: null",
            "fault history: null (no fault probability model)",
        ],
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "sage": sage_version,
        },
        "dependency_sha256": {
            path: sha256((root / path).read_bytes()).hexdigest()
            for path in source_files
        },
        **SECURITY_FIELDS,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--lifecycle", action="store_true",
                        help="run the six deterministic Setup/Extract/Sign probes")
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("output path already exists")
    report = build_report(lifecycle=args.lifecycle)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                           encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "rows": len(report["rows"]),
        "lifecycle": args.lifecycle,
        "security_claim": report["security_claim"],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
