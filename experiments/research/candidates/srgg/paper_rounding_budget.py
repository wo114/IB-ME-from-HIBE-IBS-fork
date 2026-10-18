"""Sharper, independent rounding-normalizer budget at the original SRGG r.

This module does not change PaperParams, PaperSampleF or frozen experiments.
It replaces only a coarse theta-series estimate, using directed intervals.
Legacy frozen execution shapes and current corrected mathematical shapes are
reported separately.  The legacy finite arithmetic certificates used an
inexact QQ(RealNumber) endpoint conversion: they remain UNVALIDATED and are
not used to assert a valid total TV bound for either shape version.
The density convention is exp(-pi (x-c)^T C^-1 (x-c)).  Poisson summation gives

  |rho_(C,c)(Z^D)/sqrt(det C)-1|
      <= sum_(z != 0) exp(-pi z^T C z).

If C >= lambda I, set a >= exp(-pi lambda), t=2a/(1-a^3).  Since k^2 >=
1+3(k-1) for integers k>=1, the right side is at most (1+t)^D-1.  For
x=D*t<1, the binomial/geometric comparison gives (1+t)^D-1 <= x/(1-x).
This is uniform over ALL centers c, not an assertion that a center is zero.
The published branch uses C=r^2 I for its rounding kernel.  We retain the
existing conservative Peikert comparison min(1,8*epsilon), including its
epsilon<=1/2 prerequisite.  Continuous and integer reference laws must use
the same full center and the same unchanged perturbation shape Sigma_p.

A failed sufficient theta bound is inconclusive; a reported upper bound of
one does not assert that the actual TV distance equals one.  Local SampleF
component bounds do not identify the HNF key law or final signature law.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path

from sage.all import QQ, RealIntervalField

from .convolution_bridge import center_normalizer_certificate
from .paper_parameters import PaperParams
from .paper_profiles import profiles


SCHEMA = "IBME/SRGG-PAPER-ROUNDING-BUDGET/1"
ROOT = Path(__file__).resolve().parents[4]
RECEIPTS = ROOT / "docs/research/team-b-delivery/2026-10-16-srgg-paper-baseline"
LEGACY_MANIFEST_BYTES = 2496
LEGACY_MANIFEST_SHA256 = "b9320411803d7ead4b8756a8d04246a97ffa588f09fe135223f6ea9c9bcc7d00"
INTERPRETATIONS = ("table-standard-deviation", "literal-density-width")
MAX_DIMENSION = 32768
MAX_SHAPE = 1024


def _integer(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded exact integer required: " + name)
    return value


def _shape(value):
    if type(value) not in (int, Fraction):
        raise ValueError("exact integer or Fraction density shape required")
    value = Fraction(value)
    if not 0 < value <= MAX_SHAPE or max(
            value.numerator.bit_length(), value.denominator.bit_length()) > 4096:
        raise ValueError("density shape exceeds explicit rational resource gate")
    return value


def _endpoint(value):
    # QQ(RealNumber) chooses a simple rational approximation; it does NOT
    # preserve the exact outward endpoint.  exact_rational() is essential.
    rational = value.exact_rational()
    return Fraction(int(rational.numerator()), int(rational.denominator()))


def _probability(value):
    if type(value) not in (int, str, Fraction):
        raise ValueError("exact probability required")
    result = Fraction(value)
    if not 0 <= result <= 1:
        raise ValueError("probability outside [0,1]")
    return result


def rounding_tv(epsilon):
    """Retain the old local comparison; None means certificate inconclusive."""
    if epsilon is None:
        return Fraction(1)
    if type(epsilon) not in (int, Fraction):
        raise ValueError("nonnegative exact relative error required")
    epsilon = Fraction(epsilon)
    if epsilon < 0:
        raise ValueError("nonnegative exact relative error required")
    return Fraction(1) if epsilon > Fraction(1, 2) else min(Fraction(1), 8*epsilon)


def theta_certificate(*, dimension, density_shape, precision_bits=512):
    """All-center certificate from a verified lower eigenvalue, without draws.

    density_shape is an exact lower bound on lambda_min(C).  Callers explicitly
    distinguish a frozen execution shape from current PaperParams.r_squared.
    The directed exp enclosure is new evidence; it does not revise either.
    """
    dimension = _integer(dimension, "dimension", 1, MAX_DIMENSION)
    precision_bits = _integer(precision_bits, "precision_bits", 128, 2048)
    shape = _shape(density_shape)
    field = RealIntervalField(precision_bits)
    exact = QQ(shape.numerator)/shape.denominator
    interval = (-field.pi()*field(exact)).exp()
    a_lower, a = _endpoint(interval.lower()), _endpoint(interval.upper())
    if not 0 < a_lower <= a < 1:
        raise ValueError("directed exponential failed to certify 0<a<1")
    t = 2*a/(1-a**3)
    x = dimension*t
    epsilon = x/(1-x) if x < 1 else None
    result = {
        "dimension": dimension,
        "density_shape_lower_exact": str(shape),
        "precision_bits": precision_bits,
        "exp_minus_pi_shape_lower_exact": str(a_lower),
        "exp_minus_pi_shape_upper_exact": str(a),
        "scalar_nonzero_theta_upper_exact": str(t),
        "dimension_times_scalar_theta_upper_exact": str(x),
        "relative_normalizer_error_upper_exact": None if epsilon is None else str(epsilon),
        "nontrivial_relative_lower_certified": epsilon is not None and epsilon < 1,
        "rounding_comparison_prerequisite_passes": epsilon is not None and epsilon <= Fraction(1, 2),
        "rounding_tv_upper": str(rounding_tv(epsilon)),
        "all_centers": True,
        "same_center_and_unchanged_perturbation_shape_required": True,
        "method": "Gaussian Poisson summation; directed exp(-pi*lambda); k^2>=1+3(k-1); binomial/geometric comparison",
        "source_identity": "rho_(C,c)(Z^D)/sqrt(det(C)) = sum_z exp(-pi*z^T*C*z)*exp(2*pi*i*<z,c>)",
        "scope": "rounding-kernel normalizer and retained local Peikert bound only",
    }
    if epsilon is None:
        result["blocker"] = "D*t>=1: this sufficient certificate is inconclusive; actual TV is not inferred"
    elif epsilon > Fraction(1, 2):
        result["blocker"] = "epsilon>1/2: retained local rounding comparison is inconclusive"
    return result


def _receipt(params):
    suffix = "-density" if params.interpretation == "literal-density-width" else ""
    path = RECEIPTS / (params.profile_name + suffix + ".json")
    manifest_path = RECEIPTS / "MANIFEST.json"
    if not manifest_path.is_file() or manifest_path.stat().st_size != LEGACY_MANIFEST_BYTES:
        raise ValueError("frozen paper manifest byte count mismatch")
    manifest_data = manifest_path.read_bytes()
    if len(manifest_data) != LEGACY_MANIFEST_BYTES or sha256(manifest_data).hexdigest() != LEGACY_MANIFEST_SHA256:
        raise ValueError("frozen paper manifest hash mismatch")
    manifest = json.loads(manifest_data)
    if (manifest.get("schema") != "IBME/SRGG-PAPER-DELIVERY-MANIFEST/1"
            or type(manifest.get("files")) is not dict):
        raise ValueError("frozen paper manifest schema mismatch")
    entry = manifest["files"].get(path.name)
    if (type(entry) is not dict or type(entry.get("bytes")) is not int
            or type(entry.get("sha256")) is not str):
        raise ValueError("frozen paper receipt absent from original manifest")
    if not path.is_file() or path.stat().st_size > 2*1024*1024:
        raise ValueError("missing or oversized frozen paper receipt")
    data = path.read_bytes()
    if len(data) != entry["bytes"] or sha256(data).hexdigest() != entry["sha256"]:
        raise ValueError("frozen paper receipt bytes/hash differs from original manifest")
    report = json.loads(data)
    legacy = report.get("profile", {})
    current = params.record()
    source_keys = ("profile_name", "interpretation", "source_sha256",
                   "perturbation_noise_factor", "hnf_representative",
                   "gadget_remainder_representative", "pi_precision_bits",
                   "r_published_approximation")
    if report.get("schema") != "IBME/SRGG-PAPER-AUDIT/1" or not isinstance(legacy, dict) or any(
            key not in legacy or legacy[key] != current[key] for key in source_keys):
        raise ValueError("frozen paper receipt source/convention mismatch")
    return report, {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": len(data), "sha256": entry["sha256"],
        "manifest_bound": True,
        "manifest": {"path": manifest_path.relative_to(ROOT).as_posix(),
                     "bytes": LEGACY_MANIFEST_BYTES, "sha256": LEGACY_MANIFEST_SHA256},
    }


def _legacy_rounding_shape(params, receipt, frozen, phase, dimension):
    """Authenticate old exact shapes against the receipt's own density scale.

    No current pi conversion is substituted into a historical execution.
    All stage targets/noise are checked, not only the rounding diagonal.
    """
    scale = Fraction(receipt["notation"]["density_scale"])
    if scale <= 0 or (params.interpretation == "literal-density-width" and scale != 1):
        raise ValueError("invalid legacy density scale")
    shape = scale*params.source.r_stddev**2
    if type(frozen["dimension"]) is not int or frozen["dimension"] != dimension or Fraction(
            frozen["rounding_squared"]) != shape:
        raise ValueError("frozen stage dimension or legacy rounding shape mismatch")
    if phase == "master_sampler":
        first, second = params.source.master_first_stddev, params.source.master_second_stddev
        top = [scale*Fraction(first)**2]*(2*params.rank)
        noise = params.base**2*shape
    else:
        first, second = params.source.signature_first_stddev, params.source.signature_second_stddev
        top = ([scale*Fraction(first)**2]*(2*params.rank)
               +[scale*Fraction(second)**2]*(params.digits*params.rank))
        noise = shape
    if ([Fraction(value) for value in frozen["target_top_squared"]] != top
            or Fraction(frozen["target_lower_squared"]) != scale*Fraction(second)**2
            or Fraction(frozen["noise_squared"]) != noise):
        raise ValueError("frozen stage target/noise differs from legacy density scale")
    return shape, scale


def profile_report(profile_name, interpretation="table-standard-deviation", *, precision_bits=512):
    """Recompute mathematical theta bounds for old and current exact shapes.

    No trapdoor, witness or signing key is read.  Existing finite numerical
    and scalar errors are quoted ONLY as unvalidated historical quantities.
    Neither a corrected sampler run nor valid total finite TV is claimed.
    """
    params = PaperParams(profile_name, interpretation)
    receipt, receipt_source = _receipt(params)
    rows = []
    for phase, dimension in (("master_sampler", params.columns*params.degree),
                             ("signature_sampler", (params.columns+1)*params.degree)):
        frozen = receipt[phase]
        legacy_shape, legacy_scale = _legacy_rounding_shape(params, receipt, frozen, phase, dimension)
        old = center_normalizer_certificate(dimension, legacy_shape, 80)
        old_epsilon = old["relative_error_upper_exact"]
        old_tv = rounding_tv(None if old_epsilon is None else Fraction(old_epsilon))
        if old_tv != _probability(frozen["peikert_ideal_rounding_to_discrete_target_tv_upper"]):
            raise ValueError("frozen stage does not match the unchanged old rounding calculation")
        new = theta_certificate(dimension=dimension, density_shape=legacy_shape,
                                precision_bits=precision_bits)
        new_tv = Fraction(new["rounding_tv_upper"])
        numerical = _probability(frozen["finite_center_numerical_tv_upper"])
        scalar = _probability(frozen["scalar_batch"]["scalar_kernel_tv_including_aggregate_exact"])
        rows.append({
            "profile_name": params.profile_name, "interpretation": params.interpretation,
            "phase": phase, "dimension": dimension,
            "legacy_frozen_execution": {
                "parameter_record": receipt["profile"],
                "density_scale": str(legacy_scale),
                "rounding_squared": str(legacy_shape),
                "shape_source": "exact receipt density_scale times the unchanged published decimal squared; stage targets/noise checked",
                "old_center_normalizer_certificate": old,
                "old_rounding_tv_upper": str(old_tv),
                "improved_theta_certificate": new,
                "old_bound_divided_by_improved_bound_exact": str(old_tv/new_tv),
                "unvalidated_finite_components_from_frozen_run": {
                    "status": "unvalidated_due_to_endpoint_conversion_bug",
                    "usable_in_valid_tv_certificate": False,
                    "endpoint_conversion_issue": "QQ(RealNumber) did not retain exact directed endpoints; finite arithmetic must be revalidated",
                    "finite_center_numerical_tv_upper_as_recorded": str(numerical),
                    "public_coarse_numerical_envelope_as_recorded": str(Fraction(1, 2**96)),
                    "public_coarse_numerical_envelope_passed_as_recorded": numerical <= Fraction(1, 2**96),
                    "scalar_kernel_tv_including_aggregate_exact_as_recorded": str(scalar),
                    "finite_arithmetic_assumptions_as_recorded": frozen["finite_arithmetic_assumptions"],
                },
                "historical_arithmetic_sum_only": str(min(Fraction(1), numerical+scalar+new_tv)),
                "historical_sum_is_valid_tv_certificate": False,
                "frozen_local_samplef_upper_including_abort_as_recorded": str(_probability(frozen["full_target_integer_tv_upper_including_abort"])),
                "valid_local_samplef_tv_upper_including_abort": None,
                "reference_as_recorded": frozen["reference"],
                "frozen_receipt": receipt_source,
            },
            "current_corrected_mathematical_shape": {
                "parameter_record": params.record(),
                "rounding_squared": str(params.r_squared),
                "density_scale": str(params.shape(1)),
                "rounding_shape_equals_legacy": params.r_squared == legacy_shape,
                "theta_certificate": theta_certificate(dimension=dimension, density_shape=params.r_squared,
                                                       precision_bits=precision_bits),
                "finite_center_numerical_tv_upper": None,
                "scalar_kernel_tv_including_aggregate_exact": None,
                "valid_local_samplef_tv_upper_including_abort": None,
                "frozen_finite_components_transferred": False,
                "new_sampler_draws": 0,
                "status": "mathematical_rounding_normalizer_only; corrected finite implementation not rerun",
            },
            "samplef_rerun": False,
            "all_witnesses_or_full_histories_certified": False,
            "runtime_modified_by_budget_module": False,
            "published_width_inputs_changed": False,
            "full_ibs_tv_upper": None, "hnf_key_law_tv_upper": None,
            "full_signature_law_tv_upper": None,
            "security_claim": "none", "backend_admitted": False,
            "parameters_are_formal": False, "nist_security_category": None,
        })
    return rows


def report(*, precision_bits=512):
    _integer(precision_bits, "precision_bits", 128, 2048)
    # The source uses the larger m=(2+w)*(d+1)*n for its r choice. Local
    # preparation dimensions are smaller and must not replace this dimension.
    source_dimension = (2+2)*(4+1)*512
    shape = PaperParams("PARAM-III").r_squared
    source_theta = theta_certificate(dimension=source_dimension, density_shape=shape,
                                     precision_bits=precision_bits)
    first_dual_lower = 2*source_dimension*Fraction(source_theta["exp_minus_pi_shape_lower_exact"])
    epsilon = Fraction(1, 2**24)
    return {
        "schema": SCHEMA,
        "rows": [row for interpretation in INTERPRETATIONS for item in profiles
                 for row in profile_report(item.name, interpretation, precision_bits=precision_bits)],
        "evidence_kind": "exact theta recomputation at separately identified legacy/current shapes; legacy finite components unvalidated",
        "source_max_dimension_necessary_smoothing_check": {
            "dimension": source_dimension,
            "dimension_source": "Table 3/Section 5.1: (2+w)*(d+1)*n, maximum d=4",
            "exact_backend_rounding_shape": str(shape),
            "epsilon_source": "1/sqrt(2^40*256)=2^-24",
            "epsilon": str(epsilon),
            "shortest_dual_mass_lower_exact": str(first_dual_lower),
            "necessary_condition_strictly_fails_for_exact_backend_shape": first_dual_lower > epsilon,
            "local_stage_checks_do_not_replace_source_dimension": True,
            "published_rounded_r_changed": False,
        },
        "hibe_involved": False,
        "new_sampler_draws": 0,
        "finite_attack_tests_are_not_security_proofs": True,
        "full_ibs_tv_upper": None,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--precision-bits", type=int, default=512)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = report(precision_bits=args.precision_bits)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    print(json.dumps({"schema": SCHEMA, "rows": len(result["rows"]), "output": str(args.output)}))


if __name__ == "__main__":
    main()
