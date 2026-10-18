"""Public backend-random-source and storage envelope for one Table-4 issuer.

This is a control-flow/byte-cap audit of SourceSchurBackend and FixedIssuer,
not a finite-sampler distribution theorem, RAM bound, or author C benchmark.
Bytes count only ``backend.rng.read``. Python/OS randomness used for temporary
filenames or other infrastructure is unmetered. The full service has no
lifetime backend-random-source cap while sign calls are unbounded.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path

from .aggregate_budget import batch_certificate
from .paper_parameters import PaperParams
from .paper_profiles import SOURCE_PDF, SOURCE_SHA256, profiles
from .paper_schur_backend import SourceSchurBackend
from .paper_sign_budget import signature_attempt_certificate, signature_call_envelope
from .wide_scalar import WideScalarGaussian


SCHEMA = "IBME/SRGG-PAPER-SERVICE-RESOURCE-ENVELOPE/1"
ROOT = Path(__file__).resolve().parents[4]
SOURCE_FILES = (
    "experiments/research/candidates/srgg/paper_service_resource_envelope.py",
    "experiments/research/candidates/srgg/paper_backend.py",
    "experiments/research/candidates/srgg/paper_schur_backend.py",
    "experiments/research/candidates/srgg/paper_schur_samplef.py",
    "experiments/research/candidates/srgg/paper_sign_budget.py",
    "experiments/research/candidates/srgg/aggregate_budget.py",
    "experiments/research/candidates/srgg/structured_execution.py",
    "experiments/research/candidates/srgg/structured_geometry.py",
    "experiments/research/candidates/srgg/paper_objects.py",
    "src/ibme/ibs/srgg_paper_service.py",
    "src/ibme/ibs/srgg_service.py",
)


def _probability(value):
    result = Fraction(value)
    if not 0 <= result <= 1:
        raise ValueError("probability outside [0,1]")
    return result


def _integer(value, name, *, maximum=2**40, allow_zero=False):
    if type(value) is not int or not (0 if allow_zero else 1) <= value <= maximum:
        raise ValueError("bounded exact integer required: " + name)
    return value


def _scalar_batch(width, count, options, series):
    sampler = WideScalarGaussian(width, width, options=options)
    batch = batch_certificate(sampler, count,
        error_bits=series.aggregate_abort_bits, max_bytes=series.max_entropy_bytes)
    if not batch["admitted"]:
        raise ValueError("original-parameter scalar batch exceeds its configured cap")
    return sampler, batch


def _service_capacity(params):
    """Actual FixedIssuer._preflight capacity, without creating a state path."""
    from ibme.ibs.srgg_paper_service import _preflight, IssuerCapacityError
    from .paper_objects import MAX_USERS

    low, high = 0, MAX_USERS + 1
    while high - low > 1:
        mid = (low + high) // 2
        try:
            envelope = _preflight(params, mid)
        except IssuerCapacityError:
            high = mid
        else:
            low = mid
    if low == 0:
        raise ValueError("even one user fails the current service preflight")
    return {"maximum_admitted_new_identities": low,
            "state_bytes_upper_at_maximum": _preflight(params, low),
            "first_rejected_capacity": high if high <= MAX_USERS else None}


def row_envelope(profile_name, interpretation="table-standard-deviation",
                 *, setup_max_attempts=64, sign_max_attempts=64):
    """Recompute live public caps; no root, user key or entropy is created."""
    params = PaperParams(profile_name, interpretation)
    backend = SourceSchurBackend(setup_max_attempts=setup_max_attempts,
                                 sign_max_attempts=sign_max_attempts)
    p, series, scalar_options = params, backend.series_options, backend.scalar_options
    n, d, w = p.degree, p.rank, p.digits
    if (n, w, p.base, p.p, p.modulus) != (512, 2, 31, 16383, 15744063):
        raise ValueError("Table 4 common inputs changed")

    master_lower_width = p.master_second_squared - p.base**2*p.r_squared
    sign_lower_width = p.signature_second_squared - p.r_squared
    _unused, master_lower = _scalar_batch(master_lower_width, d*w*n,
                                           scalar_options, series)
    rounding_scalar, master_rounding = _scalar_batch(p.r_squared, 2*d*n,
                                                     scalar_options, series)
    _unused, sign_lower = _scalar_batch(sign_lower_width, n,
                                         scalar_options, series)
    _unused, sign_rounding = _scalar_batch(p.r_squared, p.columns*n,
                                            scalar_options, series)
    _unused, gadget = _scalar_batch(p.r_squared, d*w*n,
                                     scalar_options, series)
    ticket_size = (series.ticket_bits+7)//8
    master_tickets = 2*d*n*ticket_size
    sign_tickets = p.columns*n*ticket_size
    master_sample_cap = (master_tickets + master_lower["selected_cap_bytes"]
                         + master_rounding["selected_cap_bytes"])
    sign_sample_cap = (sign_tickets + sign_lower["selected_cap_bytes"]
                       + sign_rounding["selected_cap_bytes"])
    if max(master_sample_cap, sign_sample_cap) > series.max_entropy_bytes:
        raise ValueError("source-Schur SampleF cap exceeds its configured budget")
    first_issue_cap = master_sample_cap + gadget["selected_cap_bytes"]
    sign_attempt = signature_attempt_certificate(p, sign_sample_cap,
        rounding_scalar, error_bits=series.aggregate_abort_bits)
    if not sign_attempt["admitted"]:
        raise ValueError("current full Algorithm 7 attempt exceeds its budget")
    sign_call = signature_call_envelope(sign_attempt,
        max_attempts=backend.sign_max_attempts)
    setup_attempt_bytes = 2*d*d*w*n
    setup_cap = 32 + backend.setup_max_attempts*setup_attempt_bytes
    service = _service_capacity(p)

    issue_abort = min(Fraction(1), sum((
        _probability(batch["abort_upper_including_aggregate_exact"])
        for batch in (master_lower, master_rounding, gadget)), Fraction(0)))
    sign_scalar_abort = min(Fraction(1), sum((
        _probability(batch["abort_upper_including_aggregate_exact"])
        for batch in (sign_lower, sign_rounding, sign_attempt["u_batch"])), Fraction(0)))
    # The whole-attempt extra-cap event is a subset of the u-batch aggregate
    # event when P<=Pcap; counting it again would double-charge the same abort.
    if _probability(sign_attempt["extra_attempt_cap_abort_upper_exact"]) > _probability(
            sign_attempt["u_batch"]["aggregate_budget_abort_upper_exact"]):
        raise AssertionError("whole-attempt cap is not covered by u aggregate abort")
    return {
        "profile": profile_name, "interpretation": interpretation,
        "parameter_record": p.record(),
        "setup": {"seed_bytes": 32, "witness_bytes_per_attempt": setup_attempt_bytes,
                  "max_attempts": backend.setup_max_attempts,
                  "one_setup_hard_entropy_cap_bytes": setup_cap,
                  "actual_setup_retry_failure_upper": None},
        "first_issuance": {
            "master_lower_scalar_count": d*w*n,
            "master_rounding_scalar_count": 2*d*n,
            "master_fixed_ticket_bytes": master_tickets,
            "master_lower_batch_cap_bytes": master_lower["selected_cap_bytes"],
            "master_rounding_batch_cap_bytes": master_rounding["selected_cap_bytes"],
            "master_samplef_hard_cap_bytes": master_sample_cap,
            "gadget_scalar_count": d*w*n,
            "gadget_batch_cap_bytes": gadget["selected_cap_bytes"],
            "one_new_identity_hard_entropy_cap_bytes": first_issue_cap,
            "scalar_abort_union_upper_including_aggregate_exact": str(issue_abort),
            "complete_issuance_failure_upper": None,
            "cached_or_rejected_identity_additional_entropy_bytes": 0},
        "signing": {
            "sign_lower_scalar_count_per_attempt": n,
            "sign_rounding_scalar_count_per_attempt": p.columns*n,
            "u_scalar_count_per_attempt": n,
            "sign_fixed_ticket_bytes_per_attempt": sign_tickets,
            "sign_lower_batch_cap_bytes": sign_lower["selected_cap_bytes"],
            "sign_rounding_batch_cap_bytes": sign_rounding["selected_cap_bytes"],
            "sign_samplef_hard_cap_bytes": sign_sample_cap,
            "u_batch_cap_bytes": sign_attempt["u_selected_cap_bytes"],
            "one_attempt_hard_entropy_cap_bytes": sign_attempt["selected_cap_bytes"],
            "max_attempts_per_call": backend.sign_max_attempts,
            "one_call_hard_entropy_cap_bytes": sign_call["one_sign_call_hard_cap_bytes"],
            "per_attempt_scalar_abort_union_upper_including_aggregate_exact": str(sign_scalar_abort),
            "one_call_scalar_abort_union_upper_exact": str(min(Fraction(1),
                backend.sign_max_attempts*sign_scalar_abort)),
            "whole_attempt_extra_cap_charged_once": True,
            "actual_norm_retry_exhaustion_upper": None,
            "complete_signature_failure_upper": None},
        "fixed_issuer": {**service, "default_max_users": 1,
                         "state_file_hard_cap_bytes": 2*1024*1024,
                         "setup_count_per_fixed_issuer": 1,
                         "SourceSchurBackend_requires_explicit_injection": True,
                         "cached_identity_reused_after_restart": True,
                         "failed_or_pending_identity_auto_retry": False,
                         "trusted_cooperating_storage_premise": True,
                         "external_fault_probability_upper": None},
        "formula": {
            "bounded_single_root_entropy_bytes": "E_setup + U*E_first_issue + S*E_sign_call",
            "U_range": "0..FixedIssuer.maximum_admitted_new_identities; counts first issuance attempts, including failed attempts",
            "S_range": "nonnegative integer when externally limited; current backend has no sign-call quota",
            "bounded_arithmetic_helper_max_S": 2**40,
            "global_service_lifetime_entropy_cap_bytes": None,
            "global_service_lifetime_failure_upper": None,
            "reason": "a restored or issued SigningKey can be signed repeatedly; each call may consume fresh bytes and no service counter limits S",
            "also_unbounded_if_new_issuer_roots_are_created_without_an_external_root_quota": True},
        "output_wire_and_state_caps_are_not_peak_ram_or_time": True,
        "metered_randomness": "only bytes returned by backend.rng.read; tempfile.mkstemp and other process/OS randomness excluded",
        "whole_process_randomness_upper_bytes": None,
        "author_C_ANS_or_1000_run_performance_reproduced": False,
        "requires_independent_uniform_bytes_for_scalar_abort_bounds": True,
        "actual_entropy_bytes_measured": False,
        "source_sampler_full_TV_upper": None,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
    }


def bounded_single_root(row, *, new_identities, sign_calls):
    """A backend.rng.read cap for an explicitly bounded, trusted single root."""
    if type(row) is not dict or row.get("profile") not in {p.name for p in profiles}:
        raise ValueError("Table 4 row envelope required")
    capacity = row["fixed_issuer"]["maximum_admitted_new_identities"]
    u = _integer(new_identities, "new identity attempts", maximum=capacity, allow_zero=True)
    s = _integer(sign_calls, "sign calls", allow_zero=True)
    value = (row["setup"]["one_setup_hard_entropy_cap_bytes"]
             + u*row["first_issuance"]["one_new_identity_hard_entropy_cap_bytes"]
             + s*row["signing"]["one_call_hard_entropy_cap_bytes"])
    return {"new_identity_attempts": u, "sign_calls": s,
            "single_root_hard_entropy_cap_bytes": value,
            "assumptions": "one initialized trusted FixedIssuer with explicit SourceSchurBackend injection, no state rollback, U and S externally limited; backend.rng.read bytes only",
            "complete_lifetime_failure_upper": None}


def report():
    pdf = ROOT / SOURCE_PDF
    if sha256(pdf.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("frozen SRGG paper checksum changed")
    rows = [row_envelope(p.name, interpretation) for p in profiles
            for interpretation in ("table-standard-deviation", "literal-density-width")]
    return {"schema": SCHEMA, "paper_sha256": SOURCE_SHA256,
        "source_sha256": {name: sha256((ROOT/name).read_bytes()).hexdigest()
                          for name in SOURCE_FILES},
        "rows": rows, "scope": "current SourceSchurBackend plus trusted FixedIssuer; six unmodified original Table 4 parameter interpretations",
        "backend_rng_bytes_read_during_report": 0,
        "metered_randomness": "backend.rng.read only; excludes tempfile.mkstemp and other process/OS randomness",
        "whole_process_randomness_upper_bytes": None,
        "global_service_lifetime_entropy_cap_bytes": None,
        "global_service_lifetime_failure_upper": None,
        "peak_ram_upper_bytes": None, "end_to_end_time_upper_seconds": None,
        "author_C_ANS_or_1000_run_performance_reproduced": False,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(report(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(result, end="")
    else:
        if args.output.exists():
            parser.error("--output already exists; choose a fresh receipt path")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8", newline="\n") as output:
            output.write(result)
        print(json.dumps({"schema": SCHEMA, "rows": 6, "output": str(args.output)}))


if __name__ == "__main__":
    main()
