"""Public, zero-entropy resource preflight for SRGG paper and old candidates.

Unlike resource_probe's small dense SPD measurements, this audits the actual
paper/structured execution paths, public constructors, scalar budgets and JSON
service envelopes.  It never creates a trapdoor, key, signature or issuer path.
Witness-dependent preparation and lifetime/history-dependent budgets remain
unknown.  A failed class-wide sufficient bound does not reject a measured key.
Run the report with the prescribed WSL Sage environment.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from fractions import Fraction
from hashlib import sha256
import json
from math import gcd, isqrt
from pathlib import Path
import platform

from .formal_candidates import Candidate
from .paper_profiles import SOURCE_PDF, SOURCE_SHA256, profiles


SCHEMA = "IBME/SRGG-PUBLIC-RESOURCE-PREFLIGHT/1"
ROOT = Path(__file__).resolve().parents[4]
BASE = Path("docs/research/team-b-delivery")
HARDNESS = BASE / "2026-10-16-srgg-hardness"
PAPER_EVIDENCE = BASE / "2026-10-16-srgg-paper-baseline"
BRIDGE_EVIDENCE = BASE / "2026-10-16-srgg-bridge"
SOURCES = (
    "experiments/research/candidates/srgg/paper_resource_audit.py",
    "experiments/research/candidates/srgg/paper_parameters.py",
    "experiments/research/candidates/srgg/paper_backend.py",
    "experiments/research/candidates/srgg/paper_samplef.py",
    "experiments/research/candidates/srgg/paper_objects.py",
    "experiments/research/candidates/srgg/paper_algebra.py",
    "experiments/research/candidates/srgg/structured_geometry.py",
    "experiments/research/candidates/srgg/structured_execution.py",
    "experiments/research/candidates/srgg/structured_samplef.py",
    "experiments/research/candidates/srgg/structured_backend.py",
    "experiments/research/candidates/srgg/wide_scalar.py",
    "experiments/research/candidates/srgg/aggregate_budget.py",
    "experiments/research/online_gaussian_reference.py",
    "src/ibme/lattice/chkp/gaussian.py",
    "src/ibme/ibs/srgg_paper_service.py",
    "src/ibme/ibs/srgg_structured_service.py",
    "src/ibme/ibs/srgg_service.py",
    "experiments/research/candidates/wang_pw/hashing.py",
)


def _read(path):
    path = ROOT / path
    if not path.is_file() or not 2 <= path.stat().st_size <= 32 * 1024 * 1024:
        raise ValueError("missing or oversized public receipt")
    return json.loads(path.read_text(encoding="utf-8"))


def _integer(value, name, low=1, high=2**32):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded exact integer required: " + name)
    return value


def _fraction(value):
    if callable(getattr(value, "numerator", None)):
        return Fraction(int(value.numerator()), int(value.denominator()))
    if isinstance(value, bool) or not isinstance(value, (int, Fraction)):
        raise ValueError("exact rational required")
    return Fraction(value)


def _length(value):
    return len(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii"))


def repeat_array_length(element_bytes, count):
    """Exact JSON array size when every element has the declared byte length."""
    _integer(element_bytes, "element bytes", high=2**64)
    _integer(count, "element count", low=0)
    return 2 + count * element_bytes + max(0, count - 1)


def nested_array_length(coordinate_bytes, *dimensions):
    value = coordinate_bytes
    for count in reversed(dimensions):
        value = repeat_array_length(value, count)
    return value


def dimensions(degree, rank, digits):
    for name, value in (("degree", degree), ("rank", rank), ("digits", digits)):
        _integer(value, name)
    columns = (2 + digits) * rank
    return {
        "degree": degree, "rank": rank, "digits": digits, "columns": columns,
        "master": {"rows": 2 * rank, "lower_columns": rank * digits,
                   "dimension": columns * degree,
                   "witness_coefficients": 2 * rank * rank * digits * degree},
        "signature": {"rows": columns, "lower_columns": 1,
                      "dimension": (columns + 1) * degree,
                      "witness_coefficients": columns * degree},
        "gadget_draws": rank * digits * degree, "u_draws": degree,
    }


def wire_envelope(*, degree, rank, digits, modulus, parameters, record,
                  max_wire, max_state_bytes, max_users, tail_coordinate_cap,
                  signature_norm_cap):
    """Conservative class envelope using actual canonical JSON/hex nesting.

    Coordinates simultaneously attaining these maxima need not be reachable;
    that makes the envelope conservative. No large vectors are allocated.
    """
    shape = dimensions(degree, rank, digits)
    public_matrix = nested_array_length(len(str(modulus - 1)), rank, rank * digits, degree)
    public_empty = {**parameters, "seed": bytes(32).hex(), "b": []}
    public_bytes = _length(public_empty) + public_matrix - 2
    tail = nested_array_length(len(str(-tail_coordinate_cap)), (1 + digits) * rank, degree)
    witness = nested_array_length(2, 2 * rank, rank * digits, degree)  # -1 is the longest CBD1 value.
    key = _length(record("key", public="", identity="", tail=[])) + 2 * public_bytes + 8192 + tail - 2
    master_empty = _length(record("master", public="", witness=[], entries=[])) + 2 * public_bytes + witness - 2
    entry = _length(["", "issued", []]) + 8192 + tail - 2
    counts = []
    envelopes = {}
    for count in range(1, max_users + 1):
        master = master_empty + count * entry + count - 1
        issuer = _length(record("issuer", status="failed", max_users=count, master="")) + 2 * master
        fits = master <= max_wire and issuer <= max_wire and issuer <= max_state_bytes
        if fits:
            counts.append(count)
        if count in (1, 2, max_users):
            envelopes[str(count)] = {"master_bytes_upper": master, "issuer_bytes_upper": issuer,
                                     "service_envelope_fits": fits}
    accepted_coordinate = isqrt(signature_norm_cap)
    signature_coordinates = nested_array_length(len(str(-accepted_coordinate)), shape["columns"] + 1, degree)
    unbound_coordinates = nested_array_length(len(str(-(2**256 - 1))), shape["columns"] + 1, degree)
    signature_base = _length(record("signature", context=bytes(32).hex(), response=[], challenge=[]))
    challenge = repeat_array_length(1, degree)
    accepted_signature = signature_base + signature_coordinates + challenge - 4
    unbound_signature = signature_base + unbound_coordinates + challenge - 4
    return {
        "method": "canonical ASCII JSON lengths plus repeated-array arithmetic; nested public/master hex counted",
        "identity_capacity_bytes": 4096, "coordinate_input_bits": 256,
        "public_bytes_upper": public_bytes, "key_bytes_upper": key,
        "master_no_cache_bytes_upper": master_empty,
        "accepted_signature_bytes_upper": accepted_signature,
        "unbound_256bit_signature_bytes_upper": unbound_signature,
        "accepted_signature_fits_wire": accepted_signature <= max_wire,
        "unbound_256bit_signature_class_fits_wire": unbound_signature <= max_wire,
        "public_fits_wire": public_bytes <= max_wire, "key_class_fits_wire": key <= max_wire,
        "wire_cap_bytes": max_wire, "state_cap_bytes": max_state_bytes,
        "declared_object_max_users": max_users, "service_capacities_passing_envelope": counts,
        "service_capacity_envelopes": envelopes, "actual_object_sizes_are_measured_separately": True,
    }


def _candidates():
    receipt = _read(HARDNESS / "finite-search.json")
    validation = _read(HARDNESS / "validation.json")
    digest = sha256((ROOT / HARDNESS / "finite-search.json").read_bytes()).hexdigest()
    if validation.get("artifacts_sha256", {}).get("finite-search.json") != digest:
        raise ValueError("hardness receipt differs from its public manifest")
    small = Candidate(**receipt["current_research_point"]["parameters"])
    rows = [Candidate(**item["parameters"]) for item in receipt["selected_candidates"]]
    large = next(item for item in rows if (item.degree, item.rank, item.base, item.digits) == (2048, 3, 3, 22))
    if (small.degree, small.rank, small.base, small.digits) != (512, 2, 31, 8):
        raise ValueError("unexpected executed research point")
    return small, large


def _attempt(action):
    try:
        value = action()
        return {"passes": True, "error_type": None, "value": value}
    except Exception as error:
        return {"passes": False, "error_type": type(error).__name__, "value": None}


def _execution_guards(candidate, execution_params):
    checks = {
        "degree_power_of_two_in_2_to_512": 2 <= candidate.degree <= 512 and candidate.degree & (candidate.degree - 1) == 0,
        "rank_in_1_to_4": 1 <= candidate.rank <= 4,
        "p_le_65535": 1 <= candidate.p <= 65535,
        "base_le_63": 1 <= candidate.base <= 63,
        "digits_le_8": 1 <= candidate.digits <= 8,
        "r_squared_le_4096": 1 <= candidate.r_squared <= 4096,
        "sign_attempts_le_16": 1 <= candidate.sign_max_attempts <= 16,
        "odd_coprime_p_and_base_at_least_three": min(candidate.p, candidate.base) >= 3 and candidate.p % 2 == candidate.base % 2 == 1 and gcd(candidate.p, candidate.base) == 1,
        "isotropic_master_and_signature": candidate.master_first_squared == candidate.master_second_squared and candidate.signature_first_squared == candidate.signature_second_squared,
        "widths_and_caps_le_2pow96": all(1 <= value <= 2**96 for value in (
            candidate.master_first_squared, candidate.signature_first_squared,
            candidate.raw_norm_squared_cap, candidate.user_norm_squared_cap, candidate.signature_norm_squared_cap)),
        "master_dimension_le_32768": candidate.columns * candidate.degree <= 32768,
        "modulus_bits_le_128": candidate.modulus.bit_length() <= 128,
        "user_cap_covers_raw_and_hnf_correction": candidate.user_norm_squared_cap >= 2 * candidate.raw_norm_squared_cap + 2 * candidate.rank * candidate.degree * (candidate.p - 1)**2,
        "conditional_Q_squared_gt_4_signature_cap": candidate.modulus**2 > 4 * candidate.signature_norm_squared_cap,
    }
    actual = _attempt(lambda: execution_params.from_candidate(candidate))
    if actual["passes"] != all(checks.values()):
        raise ValueError("resource guard ledger differs from actual ExecutionParams validator")
    actual.pop("value")
    return {"actual_constructor": actual, "checks": checks,
            "scope": "complete public ExecutionParams.from_candidate gates; excludes preparation and security admission"}


def _sampling_resource(*, shape, target, noise_squared, rounding_squared, series, scalar,
                       class_beta, paper, batch_certificate, interval_field, series_certificate):
    """Use public class bounds; never evaluate a private witness or center."""
    dimension = shape["dimension"]
    width = _fraction(rounding_squared)
    residual = min(target) - width
    rho = _fraction(noise_squared) * class_beta / residual if residual > 0 else None
    geometry_pass = residual > 0 and rho is not None and 0 < rho < 1
    per_term = 2 * (shape["rows"] * shape["lower_columns"] + shape["lower_columns"])
    interval = interval_field(series.precision_bits)
    rational = lambda value: interval(value.numerator) / value.denominator
    scale_interval = 1 / (2 * interval.pi()).sqrt()
    low, high = map(lambda endpoint: endpoint.exact_rational(), scale_interval.endpoints())
    scale_mid = (low + high) / 2
    grid = 2**series.vector_dyadic_bits
    largest_residual = max(target) - width
    diagonal = (rational(largest_residual).sqrt().upper().exact_rational() * grid).ceil() / grid
    # For every admitted outward 32-bit rho<1, 1/(1-rho)<=2^32.
    operator_rounding = Fraction(dimension * 2**32, grid)
    if paper:
        scale_upper = 2 * _fraction(diagonal * high)
        scale_error = _fraction(diagonal * (high - low))
        noise_cap = scale_upper * (4 * dimension * (series.ticket_bits + 1) + operator_rounding)
        diagonal_denominator_bits = 2 * series.vector_dyadic_bits + 1
    else:
        exact_scale = (rational(largest_residual) / (2 * interval.pi())).sqrt()
        sl, sh = (endpoint.exact_rational() for endpoint in exact_scale.endpoints())
        scale_mid = (sl + sh) / 2
        scale_upper, scale_error = _fraction(sh), _fraction((sh - sl) / 2)
        noise_cap = scale_upper * (4 * dimension * (series.ticket_bits + 1) + operator_rounding)
        diagonal_denominator_bits = 0
    magnitude_bits = ((noise_cap.numerator + noise_cap.denominator - 1) // noise_cap.denominator + 1).bit_length()
    reserve_overhead = (1 + int(scale_mid.denominator()).bit_length() + diagonal_denominator_bits
                        + series.vector_dyadic_bits + magnitude_bits + 2)
    sufficient_terms = max(-1, (scalar.options.rational_bits - reserve_overhead) // 2)
    public_series = None
    if geometry_pass:
        public_series = _attempt(lambda: series_certificate(dimension=dimension, rho=rho,
            scale_upper=scale_upper, scale_error=scale_error, options=series))
        if public_series["passes"]:
            public_series["value"] = {
                "terms_for_public_class_bound": public_series["value"]["terms"],
                "ring_products_for_public_class_bound": public_series["value"]["terms"] * per_term,
                "ring_budget_passes": public_series["value"]["terms"] * per_term <= series.max_ring_products,
                "zero_center_reserve_sufficient": public_series["value"]["terms"] <= sufficient_terms,
            }
    batch = batch_certificate(scalar, dimension, error_bits=series.aggregate_abort_bits,
                              max_bytes=series.max_entropy_bytes)
    fixed = 2 * ((dimension + 1) // 2) * ((series.ticket_bits + 7) // 8)
    coefficient_cap = (noise_cap.numerator + noise_cap.denominator - 1) // noise_cap.denominator + scalar.radius + 1
    noise_integer_cap = (noise_cap.numerator + noise_cap.denominator - 1) // noise_cap.denominator
    return {
        "dimension": dimension, "dimension_cap": series.max_dimension,
        "dimension_guard_passes": dimension <= series.max_dimension,
        "class_spectral_squared_upper": str(class_beta),
        "class_sufficient_contraction_bound": None if rho is None else str(rho),
        "class_sufficient_contraction_passes": geometry_pass,
        "class_bound_failure_is_not_an_actual_witness_failure": True,
        "actual_witness_contraction_passes": None, "actual_private_terms": None,
        "public_class_series_preflight": public_series,
        "terms_option_cap": series.max_terms, "ring_products_per_series_term": per_term,
        "ring_product_cap": series.max_ring_products,
        "max_terms_permitted_by_ring_budget": series.max_ring_products // per_term,
        "configured_max_terms_always_fits_ring_budget": series.max_terms * per_term <= series.max_ring_products,
        "ring_cap_scope": "sqrt-series H products only; excludes Fourier preparation and protocol algebra",
        "zero_center_coordinate_bits": 1, "input_center_bits_cap": series.max_center_bits,
        "zero_input_center_guard_passes": series.max_center_bits >= 1,
        "generated_scalar_center_rational_bits_cap": scalar.options.rational_bits,
        "zero_center_public_reserve_overhead_bits": reserve_overhead,
        "max_terms_with_sufficient_public_rational_reserve": sufficient_terms,
        "actual_generated_center_reserve_passes": None,
        "scalar_checked_public_center_magnitude_envelope": _attempt(lambda:
            bool(scalar.checked_inputs(rounding_squared, noise_cap))),
        "public_noise_envelope_derivation": {
            "center": "exact zero, as used by paper/structured master and signature plans",
            "rho_after_outward_32bit_rounding_inverse_margin_upper": 2**32,
            "operator_rounding_upper": str(operator_rounding),
            "formula": ("2*max_initial_diagonal*upper(1/sqrt(2*pi))*(4*D*(ticket_bits+1)+operator_rounding)"
                        if paper else "upper(sqrt((target-r_squared)/(2*pi)))*(4*D*(ticket_bits+1)+operator_rounding)"),
            "paper_initial_diagonal": "ceil(sqrt(max(target-r_squared))*2^B)/2^B; centering q<=1",
            "noise_abs_power_of_two_upper": 1 << max(0, (noise_integer_cap-1).bit_length()),
            "perturbation_abs_power_of_two_upper": 1 << max(0, (coefficient_cap-1).bit_length()),
            "rounding_output_formula": "ceil(public_noise_cap)+scalar_radius+1",
            "applies_to_160_and_192_with_same_ticket_grid_scalar_options": True,
            "premises": ["fixed plan prepared successfully with the existing spectral/series guards",
                "correct finite MPFR/interval/exact-ring operations as assumed by the sampler certificate",
                "the scalar draw succeeds inside its checked finite support; abort paths return no coefficient"],
            "this_is_a_public_class_envelope_not_private_plan_telemetry": True,
        },
        "perturbation_coordinate_cap_conditional_on_prepared_plan": coefficient_cap,
        "scalar_batch": batch, "continuous_ticket_bytes": fixed,
        "whole_samplef_cap_bytes": batch["selected_cap_bytes"] + fixed,
        "whole_samplef_entropy_guard_passes": batch["admitted"] and batch["selected_cap_bytes"] + fixed <= series.max_entropy_bytes,
        "actual_preparation_resource_passes": None,
    }


def _historical_execution():
    paper_validation = _read(PAPER_EVIDENCE / "validation.json")
    declared = paper_validation["source_sha256"]
    drift = [path for path, digest in declared.items() if sha256((ROOT / path).read_bytes()).hexdigest() != digest]
    rows = []
    for profile in profiles:
        receipt = _read(PAPER_EVIDENCE / (profile.name + ".json"))
        rows.append({"profile": profile.name, "receipt_path": (PAPER_EVIDENCE / (profile.name + ".json")).as_posix(),
            "receipt_sha256": sha256((ROOT / PAPER_EVIDENCE / (profile.name + ".json")).read_bytes()).hexdigest(),
            "functional_checks_passed": receipt["functional_checks_passed"],
            "measured_object_sizes_bytes": receipt["object_sizes_bytes"],
            "timings_seconds": receipt["timings_seconds"],
            "historical_functional_observation_only": True,
            "current_source_match": not drift, "numerical_bounds_revalidated": False})
    name = BRIDGE_EVIDENCE / "structured-execution-n512-d2w8.json"
    receipt = _read(name)
    manifest = _read(BRIDGE_EVIDENCE / "MANIFEST.json")
    entry = next(item for item in manifest["files"] if item["path"] == name.as_posix())
    digest = sha256((ROOT / name).read_bytes()).hexdigest()
    if entry["sha256"] != digest or entry["bytes"] != (ROOT / name).stat().st_size:
        raise ValueError("historical n512 receipt differs from frozen manifest")
    return {
        "paper": rows, "paper_source_drift": drift,
        "n512": {"receipt_path": name.as_posix(), "receipt_sha256": digest,
            "manifest_bound": True, "completed": receipt["completed"],
            "actual_entropy_bytes": receipt["actual_entropy_bytes"], "peak_rss_kib": receipt["peak_rss_KiB"],
            "raw_public_key_bytes": receipt["public_key_bytes"],
            "raw_master_snapshot_bytes": receipt["master_snapshot_bytes"],
            "raw_key_snapshot_bytes": receipt["key_snapshot_bytes"],
            "observed_audit_entropy_cap_bytes": receipt["audit_entropy_cap_bytes"],
            "numerical_bounds_revalidated": False,
            "scope": "historical standalone raw execution; not the larger fixed-service JSON envelope"},
        "n2048": {"full_lifecycle_executed": False, "measured_peak_memory_bytes": None,
                   "measured_wall_time_seconds": None},
    }


def build_report(*, precision_receipt=None):
    """Validate public runtime constructors without consuming sampler entropy."""
    from sage.all import RealIntervalField
    from sage.version import version as sage_version
    from ibme.ibs import srgg_paper_service, srgg_structured_service
    from .aggregate_budget import MAX_BYTES, MAX_COUNT, batch_certificate
    from .paper_backend import Backend
    from .paper_parameters import PaperParams
    from . import paper_objects, structured_backend, structured_execution, structured_geometry
    from .spectral_bounds import public_support_class_bound
    from .structured_samplef import series_certificate

    if sha256((ROOT / SOURCE_PDF).read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("paper checksum differs from frozen source")

    class NoEntropy:
        reads = 0
        def read(self, count):
            self.reads += 1
            raise AssertionError("public preflight must not sample")

    source = NoEntropy()
    backend = Backend(rng=source)
    rows = []
    points = [("paper", PaperParams(profile.name, interpretation)) for profile in profiles
              for interpretation in ("table-standard-deviation", "literal-density-width")]
    points.extend(("candidate", candidate) for candidate in _candidates())
    for kind, params in points:
        paper = kind == "paper"
        n, d, w = params.degree, params.rank, params.digits
        shape = dimensions(n, d, w)
        if paper:
            series, scalar_options = backend.series_options, backend.scalar_options
            gadget, scalar = backend._components(params)
            execution = {"actual_constructor": {"passes": None, "error_type": None},
                         "scope": "ExecutionParams gates are not applied to original-paper namespace"}
            master_target = tuple([params.master_first_squared] * (2 * d) + [params.master_second_squared])
            sign_target = tuple([params.signature_first_squared] * (2 * d) + [params.signature_second_squared])
            signature_cap, tail_cap = params.signature_norm_cap, 2**256 - 1
            master_noise, sign_noise = params.base**2 * params.r_squared, params.r_squared
            public_fields = paper_objects._record("public", params=params.record())
            record = paper_objects._record
            wire_cap, users, service = paper_objects.MAX_WIRE, paper_objects.MAX_USERS, srgg_paper_service
            label = params.profile_name + "/" + params.interpretation
            attempts, setup_attempts = backend.sign_max_attempts, backend.setup_max_attempts
        else:
            series, scalar_options = structured_execution.sampler_profile(structured_backend.PROFILE)
            gadget = structured_execution.GadgetRecurrence(params, scalar_options=scalar_options,
                aggregate_abort_bits=series.aggregate_abort_bits)
            scalar = gadget.scalar
            execution = _execution_guards(params, structured_execution.ExecutionParams)
            master_target = (Fraction(params.master_first_squared), Fraction(params.master_second_squared))
            sign_target = (Fraction(params.signature_first_squared), Fraction(params.signature_second_squared))
            signature_cap, tail_cap = params.signature_norm_squared_cap, isqrt(params.user_norm_squared_cap)
            master_noise, sign_noise = params.base**2 * params.r_squared, 2 * params.r_squared
            fields = dict(degree=n, rank=d, p=params.p, base=params.base, digits=w,
                r_squared=params.r_squared, master_squared=params.master_first_squared,
                signature_squared=params.signature_first_squared, raw_norm_cap=params.raw_norm_squared_cap,
                user_norm_cap=params.user_norm_squared_cap, signature_norm_cap=signature_cap,
                sign_max_attempts=params.sign_max_attempts)
            public_fields = {"schema": structured_execution.SCHEMA, "params": fields}
            record = structured_backend._record
            wire_cap, users, service = structured_backend.MAX_WIRE, structured_backend.MAX_USERS, srgg_structured_service
            label, attempts, setup_attempts = params.name, params.sign_max_attempts, 1
        envelope = wire_envelope(degree=n, rank=d, digits=w, modulus=params.modulus,
            parameters=public_fields, record=record, max_wire=wire_cap,
            max_state_bytes=service.MAX_STATE_BYTES, max_users=users, tail_coordinate_cap=tail_cap,
            signature_norm_cap=signature_cap)
        public_beta = Fraction(public_support_class_bound(degree=n, rows=2*d,
            columns=d*w)["t_spectral_squared_upper_exact"])
        # Paper keys have an encoding cap, not the candidate's public norm cap.
        key_norm_class = ((params.modulus // 2)**2 * d*n + tail_cap**2 * (1+w)*d*n
                          if paper else params.user_norm_squared_cap)
        sign_beta = Fraction(1) + Fraction(n, 2) * key_norm_class
        master = _sampling_resource(shape=shape["master"], target=tuple(map(_fraction, master_target)),
            noise_squared=master_noise, rounding_squared=params.r_squared, series=series, scalar=scalar,
            class_beta=public_beta, paper=paper, batch_certificate=batch_certificate,
            interval_field=RealIntervalField, series_certificate=series_certificate)
        signature = _sampling_resource(shape=shape["signature"], target=tuple(map(_fraction, sign_target)),
            noise_squared=sign_noise, rounding_squared=params.r_squared, series=series, scalar=scalar,
            class_beta=sign_beta, paper=paper, batch_certificate=batch_certificate,
            interval_field=RealIntervalField, series_certificate=series_certificate)
        u_batch = batch_certificate(scalar, n, error_bits=series.aggregate_abort_bits, max_bytes=MAX_BYTES)
        u_hard_cap = n * scalar.random_tape_bytes if paper else u_batch["selected_cap_bytes"]
        sign_call_cap = attempts * (signature["whole_samplef_cap_bytes"] + u_hard_cap)
        capacity = max(envelope["service_capacities_passing_envelope"], default=0)
        runtime_service = None
        if paper or execution["actual_constructor"]["passes"]:
            runtime_params = params if paper else structured_execution.ExecutionParams.from_candidate(params)
            runtime_service = {}
            for count in sorted({1, capacity, min(users, capacity+1)} - {0}):
                result = _attempt(lambda count=count: service._preflight(runtime_params, count))
                expected = count in envelope["service_capacities_passing_envelope"]
                if result["passes"] != expected:
                    raise ValueError("arithmetic envelope differs from runtime fixed-service preflight")
                runtime_service[str(count)] = result
        shape_bits = max(max(abs(value.numerator).bit_length(), value.denominator.bit_length())
            for value in tuple(map(_fraction, master_target + sign_target)) + (
                _fraction(params.r_squared), _fraction(master_noise), _fraction(sign_noise)))
        geometry_checks = {}
        for phase in ("master", "signature"):
            item = shape[phase]
            geometry_checks[phase] = {
                "degree_guard": 2 <= n <= structured_geometry.MAX_DEGREE and n & (n-1) == 0,
                "rows_guard": item["rows"] <= structured_geometry.MAX_MODULE_ROWS,
                "columns_guard": item["lower_columns"] <= structured_geometry.MAX_MODULE_COLUMNS,
                "witness_coefficients_guard": item["witness_coefficients"] <= structured_geometry.MAX_WITNESS_COEFFICIENTS,
                "public_width_rational_bits_guard": shape_bits <= structured_geometry.MAX_RATIONAL_BITS,
                "positive_widths_guard": min(master_target + sign_target) > 0 and min(master_noise, sign_noise, params.r_squared) > 0,
                "lower_scalar_margin_guard": (
                    master_target[-1] - master_noise > params.r_squared if phase == "master"
                    else sign_target[-1] - sign_noise > params.r_squared),
            }
        perturbation_cap = master["perturbation_coordinate_cap_conditional_on_prepared_plan"]
        # For -a/b in (-1,0], the scalar support is inside [-radius-1,radius].
        # z=a+b*k is consequently bounded by b*(radius+2), uniformly in a.
        digit_cap = params.base * (scalar.radius + 2)
        raw_cap = perturbation_cap + d*w*n*digit_cap
        full_key_cap = max(params.modulus//2, raw_cap)
        response_cap = signature["perturbation_coordinate_cap_conditional_on_prepared_plan"] + n*full_key_cap*(2*(scalar.radius+2)+1)
        rows.append({
            "label": label, "namespace": kind, "shape": shape,
            "execution_scope": ("original_paper_namespace_public_preflight" if paper else
                "public_candidate_preflight_execution_params_pass" if execution["actual_constructor"]["passes"] else
                "hypothetical_public_arithmetic_current_execution_params_reject"),
            "execution_parameter_preflight": execution, "geometry_public_guards": geometry_checks,
            "options": {"series": asdict(series), "scalar": asdict(scalar_options),
                        "actual_option_constructors_passed": True},
            "scalar_public_constructor": {"passed": True, "radius": scalar.radius,
                "gaussian_trials": scalar.gaussian_trials, "per_scalar_hard_tape_cap_bytes": scalar.random_tape_bytes,
                "gadget_all_residue_centers_checked": True,
                "signing_u_centers_checked": all(_attempt(lambda c=c: bool(scalar.checked_inputs(
                    params.r_squared, c)))["passes"] for c in (Fraction(-1), Fraction(-1,2), Fraction(0), Fraction(1,2)))},
            "master_samplef": master, "signature_samplef": signature,
            "gadget_batch": gadget.batch, "u_public_batch_diagnostic": u_batch,
            "u_aggregate_cap_enforced_in_runtime": not paper,
            "u_group_hard_cap_bytes": u_hard_cap,
            "finite_call_entropy": {"setup_hard_cap_bytes": 32 + setup_attempts * shape["master"]["witness_coefficients"],
                "one_extraction_hard_cap_bytes": master["whole_samplef_cap_bytes"] + gadget.batch["selected_cap_bytes"],
                "one_sign_call_hard_cap_bytes": sign_call_cap, "norm_attempt_cap": attempts,
                "cap_is_conditional_on_sampler_preparation_passing": True},
            "global_service_entropy_cap_bytes": None, "global_service_entropy_cap_enforced": False,
            "peak_memory_upper_bytes": None, "runtime_upper_seconds": None,
            "object_coordinate_envelope_conditional_on_prepared_plans": {
                "master_perturbation_abs_upper": perturbation_cap,
                "gadget_digit_abs_upper": digit_cap,
                "raw_coordinate_abs_upper": raw_cap, "hnf_full_key_coordinate_abs_upper": full_key_cap,
                "hnf_head_abs_upper": params.modulus//2,
                "signature_perturbation_abs_upper": signature["perturbation_coordinate_cap_conditional_on_prepared_plan"],
                "signing_u_abs_upper": scalar.radius+2,
                "zeta_u_plus_binary_challenge_abs_upper": 2*(scalar.radius+2)+1,
                "response_coordinate_abs_upper": response_cap,
                "raw_within_256bit_ring_input_cap": raw_cap.bit_length() <= 256,
                "response_within_256bit_ring_input_cap": response_cap.bit_length() <= 256,
                "derivation": [
                    "digitcap=b*(scalar_radius+2), uniformly for centers -a/b in (-1,0]",
                    "rawcap=Pmaster+(w*d*n)*digitcap, by CBD1 negacyclic coefficient convolution",
                    "fullkeycap=max(Q//2,rawcap), because HNF rebuild centers the first d polynomials modulo Q",
                    "shiftcap=2*(scalar_radius+2)+1, since zeta has two nonzero coefficients and challenge is binary",
                    "responsecap=Psignature+n*fullkeycap*shiftcap, by negacyclic coefficient convolution",
                ],
                "premises": "both sampler plans prepared; scalar/aggregate draws succeed; no private witness or center exported",
                "scope": "finite-support engineering bound; not a Gaussian/norm/acceptance probability"},
            "object_signature_shape_guards": {"degree_le_512": n <= 512,
                "response_polynomials_fit": shape["columns"]+1 <= (17 if paper else 41)},
            "wire_envelope": envelope, "actual_service_constructor_preflight": runtime_service,
            "seeded_xof": {"max_uniform_trials_per_value": 256,
                "matrix_stream_budget_bytes": d*d*n*4096, "identity_stream_budget_bytes": d*n*4096,
                "all_path_bytes_fit_stream_budget": ((params.modulus-1).bit_length()+7)//8 * 256 <= 4096,
                "uniform_rejection_never_happens": None},
            "complete_resource_admission": None,
        })
    fresh = None
    if precision_receipt is not None:
        path = Path(precision_receipt)
        if not path.is_absolute():
            path = ROOT / path
        receipt = _read(path)
        if receipt.get("schema") != "IBME/SRGG-FIXED-ROOT-NUMERICAL-PROFILE-COMPARISON/1":
            raise ValueError("matching public precision receipt required")
        expected_sources = {
            "experiments/research/candidates/srgg/paper_parameters.py",
            "experiments/research/candidates/srgg/paper_samplef.py",
            "experiments/research/candidates/srgg/structured_samplef.py",
            "experiments/research/candidates/srgg/sampling_error.py",
        }
        declared_sources = receipt.get("module_sha256_at_import", {})
        if set(declared_sources) != expected_sources:
            raise ValueError("precision receipt requires all four endpoint-sensitive source hashes")
        source_match = all(sha256((ROOT / name).read_bytes()).hexdigest() == digest
                           for name, digest in declared_sources.items())
        fresh = {"receipt_sha256": sha256(path.read_bytes()).hexdigest(), "profile": receipt["profile"],
            "status": receipt["status"], "source_hashes_match": source_match,
            "same_fixed_root_and_key_used": receipt["same_fixed_root_and_key_used"],
            "plan_preparation_read_no_entropy": receipt["plan_preparation_read_no_entropy"],
            "honest_verify_192": receipt["honest_verify_192"],
            "actual_entropy_bytes": receipt["total_entropy_bytes"],
            "scope": "one deterministic fixed-root lifecycle; not all-witness resource admission"}
    if source.reads:
        raise AssertionError("resource preflight consumed sampler entropy")
    return {
        "schema": SCHEMA, "scope": "HIBE-independent public resource guards and evidence coverage",
        "paper_sha256": SOURCE_SHA256,
        "environment": {"python": platform.python_version(), "sage": sage_version,
                        "platform": platform.platform(), "machine": platform.machine()},
        "source_sha256": {name: sha256((ROOT/name).read_bytes()).hexdigest() for name in SOURCES},
        "actual_entropy_bytes": 0, "private_state_read": False, "private_witness_constructed": False,
        "batch_global_limits": {"aggregate_max_bytes": MAX_BYTES, "aggregate_max_scalar_count": MAX_COUNT,
            "scope": "per validated batch; neither limit is a global service lifetime cap"},
        "rows": rows, "historical_execution_coverage": _historical_execution(),
        "current_precision_execution_coverage": fresh,
        "resource_probe_scope": "existing resource_probe measures small dense SPD fixtures, not these public structured/paper guards",
        "remaining_unknowns": [
            "private witness/history-specific contraction, actual term count and generated-center reserve",
            "all-witness runtime and peak memory; the code enforces dimensions/work/byte guards, not a RAM/time cap",
            "global service lifetime query counts and aggregate entropy cap",
            "HNF/final signature law, retry success probability and security admission",
        ],
        "complete_resource_admission": None, "security_claim": "none",
        "backend_admitted": False, "parameters_are_formal": False, "nist_security_category": None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--precision-receipt", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("--output already exists; use a fresh public receipt path")
    report = build_report(precision_receipt=args.precision_receipt)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as output:
        output.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"schema": SCHEMA, "rows": len(report["rows"]), "actual_entropy_bytes": 0,
                      "complete_resource_admission": None, "security_claim": "none"}))


if __name__ == "__main__":
    main()
