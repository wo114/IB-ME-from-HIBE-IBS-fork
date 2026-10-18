"""Conditional finite-history TV lemma for the original-parameter SRGG route.

This is a *generic* lemma, not an SRGG distribution certificate.  Let the two
experiments start with complete joint states (root, issued keys, durable image,
adversary state/view) at TV at most ``initial_joint_tv``.  At every common
reachable full history, the next adaptively chosen API transition -- including
its complete next state, response, distinct abort/fault labels and any exposed
observation -- must have TV at most ``full_step_kernel_tv``.  The adversary and
the stopping rule are the same causal maps in both experiments.  At most
``query_cap`` transitions are made; early stops can be padded with identical
dummy transitions.

Maximally couple the initial states, then each pair of transition kernels
while the full histories still agree.  The first-divergence union bound is

    TV(full histories) <= min(1, initial_joint_tv + query_cap * step_tv).

Any common projection to a public transcript contracts TV.  If a *common*
success event has probability at least s>0 in both full laws, conditioning
costs at most min(1, TV/s).  The latter follows by applying the overlap
identity to the success and failure restrictions; it does not set any abort or
fault probability to zero.

The existing fixed-root issuance bound concerns the old joint sampler and a
single mathematical issuance vector.  The new source-Schur chain has no
complete per-call TV certificate, accepted Setup roots have no uniform joint
law, and disk/runtime fault kernels are unquantified.  Accordingly the
current source-Schur application has null inputs and null history bounds.
Passing numbers to this arithmetic helper asserts, but does not prove, its
premises.  It does not prove signing, ROM/QROM, native strong, or security.
"""
from __future__ import annotations

from fractions import Fraction


SCHEMA = "IBME/SRGG-PAPER-CONDITIONAL-HISTORY-HYBRID/1"
MAX_QUERY_CAP = 1 << 40
_MAX_RATIONAL_BITS = 32768


def _probability(value: int | Fraction | None, name: str) -> Fraction | None:
    if value is None:
        return None
    if type(value) not in (int, Fraction):
        raise ValueError(f"{name} must be an exact int or Fraction")
    result = Fraction(value)
    if not 0 <= result <= 1:
        raise ValueError(f"{name} must lie in [0,1]")
    if max(result.numerator.bit_length(), result.denominator.bit_length()) > _MAX_RATIONAL_BITS:
        raise ValueError(f"{name} exceeds rational resource bound")
    return result


def conditional_history_bound(
    *,
    query_cap: int,
    initial_joint_tv: int | Fraction | None,
    full_step_kernel_tv: int | Fraction | None,
    success_probability_lower: int | Fraction | None = None,
) -> dict:
    """Compute the exact union bound, only when its numerical premises exist.

    ``initial_joint_tv`` is over the *complete* initial state and earlier
    adversary view, not just the public root or one key marginal.
    ``full_step_kernel_tv`` must hold uniformly over every common reachable
    history, including adaptively selected requests, all later-used private
    state and every distinguishable abort/fault outcome.  An unmodeled fault
    cannot be supplied as zero.  ``query_cap`` counts complete transitions,
    including a sign request that internally issues a previously unseen key.

    ``success_probability_lower`` must hold for both complete history laws and
    for the same success event.  Zero or absent information leaves the
    conditioned result null.  These are conditional mathematical formulas;
    no input certificate or SRGG backend is checked here.
    """
    if type(query_cap) is not int or not 0 <= query_cap <= MAX_QUERY_CAP:
        raise ValueError(f"query_cap must be an integer in [0,{MAX_QUERY_CAP}]")
    initial = _probability(initial_joint_tv, "initial_joint_tv")
    step = _probability(full_step_kernel_tv, "full_step_kernel_tv")
    success = _probability(success_probability_lower, "success_probability_lower")

    available = initial is not None and (query_cap == 0 or step is not None)
    full = min(Fraction(1), initial + query_cap * (step or 0)) if available else None
    conditioned = min(Fraction(1), full / success) if full is not None and success else None
    return {
        "schema": SCHEMA,
        "query_cap": query_cap,
        "initial_complete_joint_tv_upper": None if initial is None else str(initial),
        "uniform_complete_transition_tv_upper": None if step is None else str(step),
        "full_history_tv_upper_including_abort_fault": None if full is None else str(full),
        "both_success_probabilities_lower": None if success is None else str(success),
        "conditioned_success_history_tv_upper": None if conditioned is None else str(conditioned),
        "mathematical_bound_given_premises": available,
        "premises_verified_by_this_function": False,
        "source_schur_application_certified": False,
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
        "nist_security_category": None,
    }


def current_source_schur_history_status(*, query_cap: int = MAX_QUERY_CAP) -> dict:
    """Record the presently missing source-Schur/Setup/fault premises.

    The deliberately null result must not borrow the old joint-sampler's
    fixed-root issuance certificate or infer zero faults from passing tests.
    """
    result = conditional_history_bound(
        query_cap=query_cap,
        initial_joint_tv=None,
        full_step_kernel_tv=None,
        success_probability_lower=None,
    )
    result["missing_inputs"] = [
        "accepted-Setup joint law including earlier adversary view and state",
        "uniform source-Schur full issuance/signature transition TV at each reachable history",
        "complete abort/fault transition kernel and success probability",
    ]
    return result
