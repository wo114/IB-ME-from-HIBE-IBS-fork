"""One source-Schur signature-attempt entropy cap, including Algorithm 7 u.

No sampler width, trial count or finite scalar law is changed. A caller must
wrap BOTH perturbation and all u draws in one AggregateByteSource. This is a
per-attempt/per-sign-call engineering budget, not a service-lifetime bound.
"""
from __future__ import annotations

from fractions import Fraction


SCHEMA = "IBME/SRGG-SOURCE-SCHUR-SIGNATURE-ATTEMPT-BUDGET/1"
MAX_BYTES = 256 * 1024 * 1024


def _integer(value, name, low=1, high=MAX_BYTES):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded exact integer required: " + name)
    return value


def _fraction(value):
    if callable(getattr(value, "numerator", None)):
        return Fraction(int(value.numerator()), int(value.denominator()))
    return Fraction(value)


def signature_attempt_certificate(params, perturbation_cap, scalar, *,
                                  error_bits=192, max_bytes=MAX_BYTES):
    """Return a public cap; installing its AggregateByteSource is the caller's job.

    Perturbation consumption P<=Pcap is an explicit existing hard-cap premise.
    Then P+U>Pcap+Ucap implies U>Ucap, pointwise for every perturbation and
    challenge history. The existing adaptive-center batch proof therefore
    bounds the new cap's additional abort by the u batch's aggregate term.
    Perturbation/scalar internal aborts are already charged in their own laws.
    """
    _integer(perturbation_cap, "perturbation hard cap")
    _integer(max_bytes, "whole attempt byte budget")
    _integer(error_bits, "aggregate error bits", low=8, high=512)

    from .aggregate_budget import batch_certificate
    from .paper_parameters import PaperParams
    from .wide_scalar import WideScalarGaussian

    if type(params) is not PaperParams or type(scalar) is not WideScalarGaussian:
        raise ValueError("actual paper params and unchanged wide scalar required")
    width = params.r_squared
    if not _fraction(scalar.v_min) <= width <= _fraction(scalar.v_max):
        raise ValueError("Algorithm 7 squared width outside the supplied scalar class")
    # zeta*=1-X^(n/2), binary challenge; negacyclic wrap gives exactly this set.
    centers = (Fraction(-1), Fraction(-1, 2), Fraction(0), Fraction(1, 2))
    for center in centers:
        scalar.checked_inputs(width, center)
    batch = batch_certificate(scalar, params.degree, error_bits=error_bits, max_bytes=max_bytes)
    total = perturbation_cap + batch["selected_cap_bytes"]
    extra = Fraction(batch["aggregate_budget_abort_upper_exact"])
    return {"schema": SCHEMA, "parameter_record": params.record(),
        "perturbation_hard_cap_bytes": perturbation_cap,
        "perturbation_hard_cap_is_an_external_premise": True,
        "u_scalar_count": params.degree, "u_squared_width_exact": str(width),
        "u_reachable_centers_exact": list(map(str, centers)),
        "u_batch": batch, "u_selected_cap_bytes": batch["selected_cap_bytes"],
        "selected_cap_bytes": total, "whole_attempt_budget_bytes": max_bytes,
        "admitted": batch["admitted"] and total <= max_bytes,
        "extra_attempt_cap_abort_upper_exact": str(extra),
        "u_scalar_kernel_tv_including_aggregate_exact": batch["scalar_kernel_tv_including_aggregate_exact"],
        "u_internal_abort_upper_including_aggregate_exact": batch["abort_upper_including_aggregate_exact"],
        "all_widths_and_scalar_trial_limits_retained": True,
        "coupling": "P<=Pcap implies {P+U>Pcap+Ucap} subset {U>Ucap}; batch bound is uniform over the actual adaptive centers/history",
        "runtime_requirement": "one AggregateByteSource(selected_cap_bytes) wraps plan.sample and all Algorithm 7 u scalar draws for this attempt",
        "cap_installed_by_this_function": False,
        "extra_abort_term_is_not_charged_twice": True,
        "requires_independent_uniform_bytes": True,
        "global_service_lifetime_entropy_cap_bytes": None,
        "norm_retry_failure_and_infrastructure_faults_bounded": False,
        "actual_entropy_bytes": 0, "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None}


def signature_call_envelope(certificate, *, max_attempts=64):
    """Union/envelope for at most this many attempts of ONE sign call."""
    _integer(max_attempts, "sign attempt count", high=1024)
    if (type(certificate) is not dict or certificate.get("schema") != SCHEMA
            or certificate.get("admitted") is not True):
        raise ValueError("admitted signature-attempt certificate required")
    cap = _integer(certificate.get("selected_cap_bytes"), "admitted attempt cap")
    values = {}
    for name in ("extra_attempt_cap_abort_upper_exact", "u_internal_abort_upper_including_aggregate_exact"):
        text = certificate.get(name)
        if type(text) is not str or not 1 <= len(text) <= 8192:
            raise ValueError("bounded exact probability text required")
        try:
            value = Fraction(text)
        except (ValueError, ZeroDivisionError):
            raise ValueError("bounded exact probability required") from None
        if not 0 <= value <= 1:
            raise ValueError("probability outside [0,1]")
        values[name] = value
    return {"schema": SCHEMA + "/CALL", "max_attempts": max_attempts,
        "one_attempt_cap_bytes": cap, "one_sign_call_hard_cap_bytes": max_attempts * cap,
        "extra_attempt_cap_abort_union_upper_exact": str(min(Fraction(1),
            max_attempts * values["extra_attempt_cap_abort_upper_exact"])),
        "u_internal_abort_union_upper_exact": str(min(Fraction(1),
            max_attempts * values["u_internal_abort_upper_including_aggregate_exact"])),
        "adaptive_norm_retries_covered": True,
        "scope": "one sign call only; excludes norm-retry exhaustion and infrastructure failures",
        "global_service_lifetime_entropy_cap_bytes": None,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None}
