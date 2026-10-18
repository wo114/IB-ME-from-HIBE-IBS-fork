"""Distribution-chain guard for the standalone SRGG paper backend.

This module does not change the paper parameters, the source sampler or the
signature equations.  It makes one structural fact explicit: every numerical
bound in the fixed-root finite/convolution/normalizer chain uses the *audit gate
floor* 64 and root-independent constants, never the actual pivot values.  Hence
the six-root receipts are witnesses, not the theorem's domain.  The theorem is
uniform over every root and key that passes the same audit gates.

The original backend does not run ``SchurNumericalAudit`` during Setup or before
signing.  ``GuardedSourceSchurBackend`` adds that audit as an explicit accept
condition: Setup retries a gate failure (as a root rejection), while signing
aborts for a key that fails the signing gate.  The probabilities of those
rejections are *not* bounded here; they remain explicit null fields.  The
guard closes the distributional bridge conditional on the gate set, not the
gate-set mass.

Security fields remain: security_claim=none, backend_admitted=false,
parameters_are_formal=false, nist_security_category=None.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
from hashlib import sha256
import json
import platform
from pathlib import Path

from sage.version import version as sage_version

from ibme.core.randomness import DeterministicRandom

from .paper_issuance_bridge import combine_issuance_tv, fixed_root_c_gate
from .paper_parameters import PaperParams
from .paper_rounding_budget import theta_certificate
from .paper_samplef import WitnessGeometryError
from .paper_schur_backend import SourceSchurBackend
from .paper_schur_convolution import chain_convolution_certificate
from .paper_schur_finite_chain import (
    _fraction, _source_gates, fixed_root_finite_chain_certificate,
)
from .paper_schur_literal_moment import moment_chain_certificate
from .paper_schur_normalizer import fixed_root_normalizer_certificate
from .paper_schur_numerical import SchurNumericalAudit
from .paper_source_issuance_bridge import _source_key_guard_envelope


SCHEMA = "IBME/SRGG-PAPER-DISTRIBUTION-GUARD/1"
PROFILES = ("PARAM-I", "PARAM-II", "PARAM-III")
INTERPRETATIONS = ("table-standard-deviation", "literal-density-width")
GATE_FLOOR = Fraction(64)


class GateFailure(ValueError):
    """The independent audit gates do not cover this sampler plan."""


class RootGateRejection(WitnessGeometryError):
    """A Setup attempt passes the backend but fails the audit gates.

    It subclasses the original geometry rejection so the unchanged Setup retry
    loop treats it as another rejected root.  It is *not* a claim about the
    paper's mathematical positivity event A.
    """


class SigningKeyGateRejection(Exception):
    """A fixed signing key fails the signing audit gates; the service aborts.

    No retry is attempted: the key and its Schur plan are deterministic, so a
    redraw cannot repair the key.  The coupling charges this event once.
    """


def _dyadic_probability(text):
    if type(text) is not str or not text.startswith("2^-"):
        raise ValueError("dyadic upper required")
    bits = text[3:]
    if not bits.isdecimal() or len(bits) > 5 or int(bits) > 16384:
        raise ValueError("bounded dyadic exponent required")
    return Fraction(1, 2**int(bits))


def _dyadic_upper(value):
    """Readable outward power-of-two upper bound for a positive probability."""
    value = Fraction(value)
    if not 0 <= value <= 1:
        raise ValueError("probability required")
    if value == 0:
        return "0"
    if value == 1:
        return "1"
    bits = value.denominator.bit_length() - value.numerator.bit_length()
    bits = max(0, bits)
    while bits and value > Fraction(1, 2**bits):
        bits -= 1
    while value <= Fraction(1, 2**(bits + 1)):
        bits += 1
    return ("2^-" + str(bits)) if bits else "1"


def require_gates(plan, *, params=None, gadget=None, root_phase=False):
    """Run the complete gate set for a prepared plan.

    The Schur/audit layer checks the pivot floor 64, gain and stored-factor
    covariance errors, the adaptive-center recurrence, the factor and center
    envelopes, the scalar/entropy batches and the finite output/object bit
    guards.  A Setup/root plan additionally checks the issuance ``C`` gate
    (centered gadget completion ``C > 64 I``) and the successful finite-key
    object/service byte envelope.

    Returns ``(audit, n, leaves, extras)``.  Raises ``GateFailure`` for any
    audit, gate or envelope mismatch; the caller decides whether that is a root
    rejection or a signing-key abort.
    """
    try:
        audit = SchurNumericalAudit(plan)
        n, leaves, sampler = _source_gates(audit)
    except (ValueError, ArithmeticError, TypeError) as error:
        raise GateFailure(str(error)) from error
    if sampler is not plan:
        raise GateFailure("audit sampler is not the prepared plan")
    extras = {}
    if root_phase:
        if params is None or gadget is None:
            raise GateFailure("root gate requires the prepared parameters and gadget")
        c_gate = fixed_root_c_gate(plan.geometry, lower_bound=64, precision_bits=192)
        if not c_gate.get("certified"):
            raise GateFailure("issuance C gate is not certified")
        try:
            object_guard = _source_key_guard_envelope(params, plan, gadget)
        except (ValueError, ArithmeticError, TypeError) as error:
            raise GateFailure("finite-key object/service envelope failed: " + str(error)) from error
        extras = {"c_gate": c_gate, "object_guard": object_guard}
    return audit, n, leaves, extras


class GuardedSourceSchurBackend(SourceSchurBackend):
    """The unchanged paper backend plus an explicit full-gate accept set."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.gate_rejections = 0
        self.last_master_gate_audit = None
        self.last_sign_gate_audit = None
        self.last_master_gate_extras = None
        self.last_sign_gate_extras = None

    def _master_plan(self, params, witness):
        plan = super()._master_plan(params, witness)
        try:
            gadget, _scalar = self._components(params)
            audit, _degree, _leaves, extras = require_gates(
                plan, params=params, gadget=gadget, root_phase=True)
        except GateFailure as error:
            self.gate_rejections += 1
            raise RootGateRejection("Setup audit gate rejected root: " + str(error)) from error
        self.last_master_gate_audit = audit
        self.last_master_gate_extras = extras
        return plan

    def _sign_plan(self, key):
        plan = super()._sign_plan(key)
        try:
            audit, _degree, _leaves, extras = require_gates(plan)
        except GateFailure as error:
            raise SigningKeyGateRejection("signing-key audit gate failed: " + str(error)) from error
        self.last_sign_gate_audit = audit
        self.last_sign_gate_extras = extras
        return plan


def uniform_phase_bound(plan, interpretation):
    """Uniform finite+mathematical+ideal-normalizer bound on a gated plan.

    Every numerical input below is either a gate constant (pivot floor 64) or a
    root/leaf-independent parameter.  The only root-specific objects are the
    gate booleans checked by ``require_gates``.  Therefore two roots that pass
    the same gates get exactly the same bound.
    """
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
            "mathematical_algorithm34_vs_ideal_sequential": None,
            "ideal_sequential_vs_joint": None,
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
            "mathematical_algorithm34_vs_ideal_sequential": None,
            "ideal_sequential_vs_joint": _dyadic_upper(normalizer_upper),
            "joint_tv_exact": None,
        }
    total = finite_upper + Fraction(middle) + normalizer_upper
    if not 0 <= total < 1:
        return {
            "closed": False,
            "blocker": "combined phase bound is trivial (>=1)",
            "finite_upper": _dyadic_upper(finite_upper),
            "mathematical_algorithm34_vs_ideal_sequential": str(Fraction(middle)),
            "ideal_sequential_vs_joint": _dyadic_upper(normalizer_upper),
            "joint_tv_exact": None,
        }
    return {
        "closed": True,
        "blocker": None,
        "finite_upper": _dyadic_upper(finite_upper),
        "mathematical_algorithm34_vs_ideal_sequential": str(Fraction(middle)),
        "ideal_sequential_vs_joint": _dyadic_upper(normalizer_upper),
        "joint_tv_exact": str(total),
        "joint_tv_dyadic_upper": _dyadic_upper(total),
        "gate_floor": "64",
        "comparison": "finite Algorithm 3-4 + mathematical convolution + ideal sequential/joint",
    }


def uniform_issuance_bound(params, backend, master_plan, interpretation, *, extras=None):
    """Uniform first-issuance TV for every root passing the complete gate set.

    ``extras`` is the root-phase gate record (issuance C gate and finite-key
    object/service envelope) produced by ``require_gates``.  If omitted it is
    recomputed.  A non-certified C gate or object envelope keeps the bound null.
    """
    phase = uniform_phase_bound(master_plan, interpretation)
    if not phase["closed"]:
        return {"closed": False, "blocker": phase["blocker"],
                "master_perturbation": None, "complete_law_tv_upper_including_abort": None}
    if extras is None:
        gadget, _scalar = backend._components(params)
        _audit, _n, _l, extras = require_gates(
            master_plan, params=params, gadget=gadget, root_phase=True)
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
    digit = theta_certificate(dimension=draws, density_shape=Fraction(params.r_squared),
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
        "key_coordinate_abs_upper": object_guard.get("centered_hnf_full_key_coordinate_abs_upper"),
        "gadget_scalar_tv": _dyadic_upper(
            Fraction(gadget.batch["scalar_kernel_tv_including_aggregate_exact"])),
        "gadget_digit_relative_sum": str(Fraction(digit_sum)),
        "completed_square_center_relative_error": str(Fraction(center_error)),
        "complete_law_tv_upper_including_abort": str(total),
        "complete_law_tv_dyadic_upper": _dyadic_upper(total),
    }


def uniform_sign_call_bound(params, backend, key, interpretation):
    """Uniform one-sign-call TV for every key passing the signing gates."""
    plan = backend._sign_plan(key)
    phase = uniform_phase_bound(plan, interpretation)
    if not phase["closed"]:
        return {"closed": False, "blocker": phase["blocker"],
                "sign_perturbation": None, "one_sign_call_tv_upper": None}
    _gadget, scalar = backend._components(params)
    backend._sign_attempt_source(params, plan, scalar)
    budget = backend.last_sign_attempt_certificate
    if not budget.get("admitted"):
        return {"closed": False, "blocker": "whole-attempt entropy budget not admitted",
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


def _root_seed(profile, interpretation):
    return ("paper-baseline-" + profile + "-" + interpretation).encode("ascii")


def build_row(profile, interpretation, *, seed=None, check_uniformity=True):
    params = PaperParams(profile, interpretation)
    seed = _root_seed(profile, interpretation) if seed is None else seed
    backend = GuardedSourceSchurBackend(rng=DeterministicRandom(seed))
    public, master = backend.setup(params)
    master_plan = backend._master_plan(params, master.witness)
    master_phase = uniform_phase_bound(master_plan, interpretation)
    issuance = uniform_issuance_bound(
        params, backend, master_plan, interpretation, extras=backend.last_master_gate_extras)
    key = backend.key_extract(master, b"Alice")
    sign_phase = uniform_phase_bound(backend._sign_plan(key), interpretation)
    sign_call = uniform_sign_call_bound(params, backend, key, interpretation)

    uniformity = None
    if check_uniformity:
        other_seed = ("uniformity-" + profile + "-" + interpretation).encode("ascii")
        other = GuardedSourceSchurBackend(rng=DeterministicRandom(other_seed))
        other_public, other_master = other.setup(params)
        other_phase = uniform_phase_bound(other._master_plan(params, other_master.witness),
                                          interpretation)
        other_key = other.key_extract(other_master, b"Alice")
        try:
            other_sign = uniform_phase_bound(other._sign_plan(other_key), interpretation)
            other_sign_gate_passed, other_sign_total = True, other_sign.get("joint_tv_exact")
        except SigningKeyGateRejection as error:
            other_sign_gate_passed, other_sign_total = False, None
            other_sign_error = str(error)
        else:
            other_sign_error = None
        uniformity = {
            "second_root_seed_sha256": sha256(other_seed).hexdigest(),
            "second_root_context_sha256": other_public.context.hex(),
            "same_gate_floor": "64",
            "master_joint_tv_identical": (
                master_phase.get("joint_tv_exact") == other_phase.get("joint_tv_exact")),
            "second_root_master_joint_tv": other_phase.get("joint_tv_dyadic_upper"),
            "second_root_sign_gate_passed": other_sign_gate_passed,
            "second_root_sign_joint_tv": None if other_sign_total is None else
                _dyadic_upper(Fraction(other_sign_total)),
            "sign_joint_tv_identical": (
                other_sign_total is not None and
                other_sign_total == sign_phase.get("joint_tv_exact")),
            "second_root_sign_gate_error": other_sign_error,
        }

    return {
        "profile": profile,
        "interpretation": interpretation,
        "paper_parameters": params.record(),
        "rng": "DeterministicRandom TEST FIXTURE ONLY",
        "seed_sha256": sha256(seed).hexdigest(),
        "public_context_sha256": public.context.hex(),
        "setup_attempts": backend.setup_attempts,
        "setup_gate_rejections": backend.gate_rejections,
        "extraction_calls": backend.extract_calls,
        "identity_bytes": 5,
        "guarded_backend_ran_audit_at_setup_and_sign": True,
        "original_backend_runs_audit": False,
        "gate_floor": "64",
        "issuance_c_gate": None if backend.last_master_gate_extras is None else
            backend.last_master_gate_extras.get("c_gate"),
        "finite_key_object_guard": None if backend.last_master_gate_extras is None else
            backend.last_master_gate_extras.get("object_guard"),
        "master_phase": master_phase,
        "issuance": issuance,
        "signature_phase": sign_phase,
        "sign_call": sign_call,
        "second_root_uniformity": uniformity,
        "root_gate_mass_under_actual_setup": None,
        "root_gate_mass_reason":
            "requires mu(Setup accepts but audit gates fail); no bound under the paper's density "
            "and finite backend acceptance set",
        "a_minus_b_event_mass": None,
        "a_minus_b_reason":
            "requires a uniform numeric/interval/leaf/center acceptance bound on the mathematical "
            "positivity event A; the moment bound only controls A itself",
        "bad_issued_key_mass_beta": None,
        "bad_key_mass_reason":
            "the conditional HNF reference needs a target-uniform lower bound for P_D(S_h) and an "
            "upper bound with HNF wrapping; not available at the paper's widths",
        "bad_key_mass_strictly_positive": True,
        "bad_key_mass_positive_witness":
            "canonical large-tail key has a strictly negative Fourier diagonal and lies in the "
            "mathematical reference support; its mass is positive but not quantified",
        "full_history_tv": None,
        "full_history_formula":
            "min(1, alpha_root + delta_issue + beta_bad + s*epsilon_sign_call)",
        "fault_history_tv": None,
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
        "nist_security_category": None,
        "private_material_exported": False,
    }


def probe_unguarded_gate_gap(profile, interpretation, count=6):
    """Search for a root the original backend accepts but the audit rejects.

    The result is an empirical witness search, not a probability.  A found
    witness proves B is not contained in the audit-gate set G.
    """
    params = PaperParams(profile, interpretation)
    for index in range(count):
        seed = ("unguarded-gap-" + profile + "-" + interpretation + "-" + str(index)).encode("ascii")
        backend = SourceSchurBackend(rng=DeterministicRandom(seed))
        try:
            public, master = backend.setup(params)
        except Exception as error:  # noqa: BLE001 - fixture search records every failure
            continue
        try:
            gadget, _scalar = backend._components(params)
            require_gates(backend._master_plan(params, master.witness),
                          params=params, gadget=gadget, root_phase=True)
        except GateFailure as error:
            return {
                "witness_found": True,
                "seed_index": index,
                "seed_sha256": sha256(seed).hexdigest(),
                "public_context_sha256": public.context.hex(),
                "gate_failure": str(error),
                "scope": "one unguarded Setup root accepted by the original backend and rejected by the complete gate set",
            }
    return {
        "witness_found": False,
        "seeds_tried": count,
        "note": "no witness in this deterministic search; the logical gap remains because the original "
                "backend does not execute the audit gates",
    }


def probe_sign_gate_mass(profile, interpretation, count=3):
    """Empirical gate-failure count for issued keys; not a probability bound."""
    params = PaperParams(profile, interpretation)
    accepted = rejected = 0
    for index in range(count):
        seed = ("sign-gate-mass-" + profile + "-" + interpretation + "-" + str(index)).encode("ascii")
        backend = GuardedSourceSchurBackend(rng=DeterministicRandom(seed))
        try:
            _public, master = backend.setup(params)
            key = backend.key_extract(master, b"Alice")
            backend._sign_plan(key)
        except SigningKeyGateRejection:
            rejected += 1
        except Exception:
            continue
        else:
            accepted += 1
    return {
        "roots_attempted": count,
        "sign_gate_accepts": accepted,
        "sign_gate_rejections": rejected,
        "note": "empirical fixture count only; it does not bound beta_bad under the ideal issuance law",
    }


def build_report():
    rows = [build_row(profile, interpretation)
            for profile in PROFILES for interpretation in INTERPRETATIONS]
    return {
        "schema": SCHEMA + "/REPORT",
        "paper": {
            "path": "papers/2025_efficient_ibs_jia.pdf",
            "sha256": rows[0]["paper_parameters"]["source_sha256"],
        },
        "environment": {
            "python": platform.python_version(),
            "sage": sage_version,
            "platform": platform.platform(),
        },
        "scope": "six original Table 4 roots; complete guarded accept set; uniform conditional bounds; gate-set masses remain null",
        "core_correction":
            "The fixed-root finite/convolution/normalizer chain is already uniform over every root that "
            "passes the complete gate set: its numerical inputs are the gate floor 64 and root-independent "
            "constants, not the actual pivots. The six receipts are witnesses of a nonempty gate set, not "
            "the domain of the theorem.",
        "complete_gate_set": [
            "all ideal Schur pivots at least 64",
            "gain coefficient error at most 2^-128",
            "stored-factor ideal-covariance error at most 2^-128",
            "adaptive-center recurrence error at most 2^-96 on the same successful history",
            "stored factors in (2, 2^32)",
            "adaptive centers below 2^240",
            "scalar/entropy aggregate caps and whole-attempt entropy budgets",
            "finite leaf/output 256-bit object guard",
            "issuance centered-gadget C gate (C > 64 I)",
            "successful finite-key object/service byte envelope (raw and HNF key within 256 bits)",
        ],
        "guard_construction":
            "GuardedSourceSchurBackend runs SchurNumericalAudit, the finite-chain source gates, the "
            "issuance C gate and the finite-key object/service envelope at Setup, and the Schur/audit "
            "gates before signing. Setup treats a gate failure as a root rejection/retry; signing treats "
            "it as a fixed-key abort. The original backend runs none of these execute-time gates.",
        "scope_warning":
            "This is a statement about the modified protected accept set. The original unguarded paper "
            "backend has not been shown to satisfy the same gate set, so this does not directly certify "
            "the original unmodified algorithm.",
        "closed": [
            "uniform finite-vs-mathematical Algorithm 3-4 bound on every plan passing the complete gate set",
            "uniform mathematical Algorithm 3-4 vs ideal sequential bound using pivot floor 64",
            "uniform ideal sequential vs joint discrete Gaussian normalizer bound",
            "uniform first-issuance TV on every root passing the C gate and object envelope (table-standard-deviation rows)",
            "uniform one-sign-call TV on every signing key passing the Schur/audit gates (table-standard-deviation rows)",
        ],
        "still_null": [
            "P(A minus B): mathematical positivity vs finite backend acceptance",
            "P(B minus G): backend accepts but complete gates fail",
            "mass of roots/keys rejected by the guard, and the accepted-root distribution relative to mu_A",
            "beta_bad: key gate failure mass under the ideal issuance reference",
            "full random-issuance/signature/fault history TV",
            "norm-exhaustion probability, native strong security, structural hardness, NIST category",
        ],
        "rows": rows,
        "gate_mass_note":
            "The guard converts distributional uniformity into an accept-set/gate-mass question. It "
            "does not bound the gate-mass probabilities; those are operational abort masses, not "
            "cryptographic bounds.",
        "probes": {
            "unguarded_gate_gap": probe_unguarded_gate_gap("PARAM-I", "table-standard-deviation", 6),
            "sign_gate_mass": probe_sign_gate_mass("PARAM-I", "table-standard-deviation", 3),
            "scope": "deterministic fixture searches only; not probabilities and not security evidence",
        },
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
        "nist_security_category": None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("--output already exists")
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({
        "rows": len(report["rows"]),
        "closed_master": sum(row["master_phase"].get("closed", False) for row in report["rows"]),
        "closed_issuance": sum(row["issuance"].get("closed", False) for row in report["rows"]),
        "closed_sign_call": sum(row["sign_call"].get("closed", False) for row in report["rows"]),
        "full_history_tv": None,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
