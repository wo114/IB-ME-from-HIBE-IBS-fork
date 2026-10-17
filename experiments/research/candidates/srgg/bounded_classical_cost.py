"""Exact conditional costs of the actual adaptive-owner classical extractor.

All security-game correspondence premises are explicit caller hypotheses.
This pure arithmetic module samples nothing and proves no hardness assumption,
production-game correspondence, QROM claim or parameter admission.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from fractions import Fraction
import re


SCHEMA = "IBME/SRGG-BOUNDED-CLASSICAL-COST/1"
MAX_RATIONAL_BITS = 262144
MAX_TEXT_COMPONENT_DIGITS = 4096
MAX_TEXT_CHARACTERS = 2*MAX_TEXT_COMPONENT_DIGITS+2
_RATIONAL_TEXT = re.compile(r"([+-]?)(0|[1-9][0-9]*)(?:/([1-9][0-9]*))?", re.ASCII)


def _prob(value, name):
    if type(value) not in (int, Fraction, str):
        raise ValueError("exact rational probability required: " + name)
    if type(value) is str:
        # Fraction accepts scientific notation. Reject it before construction:
        # e.g. "1e-1000000000" must never allocate 10**1000000000 first.
        if len(value) > MAX_TEXT_CHARACTERS:
            raise ValueError("rational text length limit violated: " + name)
        match = _RATIONAL_TEXT.fullmatch(value)
        if match is None:
            raise ValueError("bounded integer or numerator/positive-denominator text required: " + name)
        for component in (match[2], match[3]):
            if component is not None and (len(component) > MAX_TEXT_COMPONENT_DIGITS
                    or 4*len(component) > MAX_RATIONAL_BITS):
                raise ValueError("rational text component resource limit violated: " + name)
    elif type(value) is Fraction and max(value.numerator.bit_length(), value.denominator.bit_length()) > MAX_RATIONAL_BITS:
        raise ValueError("rational resource limit violated: " + name)
    elif type(value) is int and value.bit_length() > MAX_RATIONAL_BITS:
        raise ValueError("rational resource limit violated: " + name)
    try:
        value = Fraction(value)
    except (ValueError, ZeroDivisionError) as exc:
        raise ValueError("exact rational probability required: " + name) from exc
    if (not 0 <= value <= 1 or
            max(value.numerator.bit_length(), value.denominator.bit_length()) > MAX_RATIONAL_BITS):
        raise ValueError("probability range or resource limit violated: " + name)
    return value


def _count(value, name, minimum=0):
    if type(value) is not int or not minimum <= value <= 2**64:
        raise ValueError("bounded exact integer required: " + name)
    return value


def _parameters(free_queries, degree):
    q = _count(free_queries, "free H2 entries", 1)
    if type(degree) is not int or not 2 <= degree <= 4096 or degree & (degree-1):
        raise ValueError("bounded power-of-two degree required")
    return q, Fraction(1, 2**(degree//2))


def owner_split_lower(*, sign_success, free_success, free_queries, degree):
    """a + max(0,b²/q-b*2^(-n/2)); no independent owner-choice coin.

    a,b are unconditional, disjoint success masses of this same replayable
    bounded Run. Full returned-signature witnesses and ideal free H2 replies
    are premises, not verified by evaluating this arithmetic expression.
    """
    a, b = _prob(sign_success, "sign-owner mass"), _prob(free_success, "free-owner mass")
    q, kappa = _parameters(free_queries, degree)
    if a+b > 1:
        raise ValueError("disjoint owner success masses exceed one")
    return a+max(Fraction(0), b*b/q-b*kappa)


def residual_owner_lower(*, residual_success, free_queries, degree):
    """Exact infimum of the owner bound over a+b >= residual_success.

    q=1 may reach the linear segment; using max(0,t²/q-kappa*t)
    everywhere would overstate that case. The resulting envelope is convex
    and nondecreasing on [0,1], permitting averaging over public instances.
    """
    t = _prob(residual_success, "residual owner success")
    q, kappa = _parameters(free_queries, degree)
    pivot = q*(1+kappa)/2
    if t <= pivot:
        return max(Fraction(0), t*t/q-t*kappa)
    return t-q*(1+kappa)**2/4


def run_success_lower(*, success, free_queries, degree):
    """From full target-strong Run success p, subtract unseen full-c guessing.

    Finite-sampler failures already present in this Run's law are not charged
    a second time for replay. A separate ideal-to-finite two-run simulation
    would require its own joint-law argument instead.
    """
    p = _prob(success, "target-strong Run success")
    _parameters(free_queries, degree)
    t = max(Fraction(0), p-Fraction(1, 2**degree))
    return residual_owner_lower(residual_success=t, free_queries=free_queries, degree=degree)


@dataclass(frozen=True)
class IBSLedger:
    """Every Eq.(7) term is required; None keeps a missing bound unresolved.

    delta0, issue, bad, alias and overlay are whole-game costs. image/pub
    are per-first-identity; the remaining five are per-sign-attempt costs.
    No term is defaulted to zero and repeated endpoints remain distinct.
    """
    delta0: object
    delta_issue: object
    delta_bad: object
    delta_alias: object
    epsilon_image: object
    delta_pub: object
    commitment_collision: object
    delta_zk: object
    eta_sign: object
    delta_sim: object
    delta_known: object
    delta_overlay: object

    def __post_init__(self):
        for field in fields(self):
            value = getattr(self, field.name)
            if value is not None:
                object.__setattr__(self, field.name, _prob(value, field.name))


@dataclass(frozen=True)
class Premises:
    """Explicit assumptions, never a certificate that those assumptions hold."""
    complete_honest_reference: object
    hidden_index_independent_common_space: object
    uniform_reachable_history_bounds: object
    canonical_native_strong_log: object
    independent_uniform_target: object
    ideal_classical_free_h2: object
    raw_first_touch_consistent: object
    replayable_nonfree_and_callback: object
    two_run_source_byte_envelope: object
    same_bounded_game_and_failure_interfaces: object
    specified_source_and_arithmetic_model: object

    def __post_init__(self):
        for field in fields(self):
            value = getattr(self, field.name)
            if value is not None and type(value) is not bool:
                raise ValueError("explicit bool or unresolved None premise required: " + field.name)


def _rational_record(value):
    # 2^-36351 and large image denominators exceed Python's decimal-string
    # safety limit. Hex is exact; no process-wide digit limit is changed.
    if value is None:
        return None
    return {"numerator_hex": hex(value.numerator), "denominator_hex": hex(value.denominator)}


def ibs_ledger_bound(*, advantage, identity_queries, sign_attempts, free_queries,
                     degree, ledger, premises):
    """Conditional Eq.(7) -> actual-owner E bound; unknown terms stay null.

    No production parameters or security facts are inferred from numeric
    values or True flags supplied by a caller. Raw, source-fault, state and
    bounded-adversary correspondence costs belong in the explicit ledger.
    """
    epsilon = _prob(advantage, "assumed IBS success")
    qi = _count(identity_queries, "all first-touch identities", 1)
    ns = _count(sign_attempts, "all signing attempts")
    q, _ = _parameters(free_queries, degree)
    if type(ledger) is not IBSLedger or type(premises) is not Premises:
        raise TypeError("explicit complete ledger and premises objects required")
    missing = tuple(field.name for field in fields(ledger) if getattr(ledger, field.name) is None)
    unassumed = tuple(field.name for field in fields(premises) if getattr(premises, field.name) is not True)
    loss = None
    if not missing:
        loss = (ledger.delta0+ledger.delta_issue+ledger.delta_bad+ledger.delta_alias
            +qi*(ledger.epsilon_image+ledger.delta_pub)
            +ns*(ledger.commitment_collision+ledger.delta_zk+ledger.eta_sign
                +ledger.delta_sim+ledger.delta_known)+ledger.delta_overlay)
    p0 = None if loss is None or unassumed else max(Fraction(0), (epsilon-loss)/qi)
    extraction = None if p0 is None else run_success_lower(success=p0, free_queries=q, degree=degree)
    return {"schema": SCHEMA,
        "assumed_IBS_success": _rational_record(epsilon),
        "identity_first_touch_bound": qi, "sign_attempt_bound": ns,
        "free_H2_entry_bound": q, "degree": degree,
        "numerator_loss_upper": _rational_record(loss),
        "target_Run_success_lower": _rational_record(p0),
        "actual_owner_extraction_success_lower": _rational_record(extraction),
        "unresolved_ledger_terms": missing, "unassumed_premises": unassumed,
        "ledger": {field.name: _rational_record(getattr(ledger, field.name)) for field in fields(ledger)},
        "premises": {field.name: getattr(premises, field.name) for field in fields(premises)},
        "premises_are_explicit_caller_hypotheses": True,
        "meaning": "conditional extraction probability lower bound, not a security-level estimate",
        "actual_entropy_bytes": 0, "draw_performed": False,
        "complete_production_game_correspondence_proved": False,
        "matrix_hardness_proved": False, "QROM_reduction_proved": False,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None}
