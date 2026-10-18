"""Authenticated current-shape finite perturbation budgets on one SRGG root.

The corrected fixed-root experiment at commit 38f2459 records six public
PaperSampleF preparation certificates.  Four distinct plans are relevant:
master160/master192 and signature160/signature192.  This module binds the
original receipt to its byte-exact manifest, checks its four corrected core
sources and supporting sources against current files, and verifies every
rounding/target/noise shape against current PaperParams.

For each FIXED plan, triangle inequality gives TV <= min(1, numerical +
scalar_batch_including_abort + rounding_theta).  The rounding term is the
strict all-center theta certificate from paper_rounding_budget.  Numerical
and scalar terms retain their public envelopes and original assumptions.
The abort atom is retained; no success conditioning is applied.  The ideal
reference is D_(Z^D,Sigma_p,c), Sigma_p=diag(target)-noise*T*T*, at the SAME
fixed witness and exact center c (zero for these prepared plans).

This certifies only that finite integer PERTURBATION sampler.  It does not
cover the gadget addition in full SampleF, HNF pushforward, key distribution,
final signature distribution, arbitrary witnesses or complete service/game
histories.  Historical endpoint-bug receipts are not used.  No sampler draw,
key creation, numerical-profile change or backend-default change occurs.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path

from .paper_backend import Backend
from .paper_parameters import PaperParams
from .paper_rounding_budget import theta_certificate


SCHEMA = "IBME/SRGG-CURRENT-FIXED-PLAN-PERTURBATION-BUDGET/1"
ROOT = Path(__file__).resolve().parents[4]
RECEIPTS = ROOT / "docs/research/team-b-delivery/2026-10-17-srgg-parameter-closure"
MANIFEST_BYTES = 23871
MANIFEST_SHA256 = "a0a837cd0d75dc9202c23981db0a401431a85d9a5ee42e17ba3d55627a84330f"
PRECISION_BYTES = 75007
PRECISION_SHA256 = "617e1f75d16983a4ec3e1b90e6270e5442d0e2db07114d1394a7c78481495b6f"
SOURCE_FILES = (
    "experiments/research/candidates/srgg/paper_parameters.py",
    "experiments/research/candidates/srgg/paper_samplef.py",
    "experiments/research/candidates/srgg/structured_samplef.py",
    "experiments/research/candidates/srgg/sampling_error.py",
)
SUPPORTING_SOURCE_FILES = (
    "experiments/research/candidates/srgg/paper_backend.py",
    "experiments/research/candidates/srgg/paper_profiles.py",
    "experiments/research/candidates/srgg/paper_precision_audit.py",
    "experiments/research/candidates/srgg/paper_rounding_budget.py",
)
REFERENCE = "D_(Z^D,Sigma_p,c), Sigma_p=diag(target)-noise T T*"
PUBLIC_NUMERICAL_ENVELOPE = Fraction(1, 2**96)
PLANS = (("master160_extract", "master", 160), ("master192", "master", 192),
         ("signature160", "signature", 160), ("signature192", "signature", 192))


def _precision(value):
    if type(value) is not int or not 128 <= value <= 2048:
        raise ValueError("theta_precision_bits must be an exact integer in [128,2048]")
    return value


def _probability(value):
    if type(value) not in (int, str, Fraction):
        raise ValueError("exact probability required")
    result = Fraction(value)
    if not 0 <= result <= 1:
        raise ValueError("probability outside [0,1]")
    return result


def _read_pinned(path, *, size, digest, label):
    if not path.is_file() or path.stat().st_size != size:
        raise ValueError(label+" byte count mismatch")
    data = path.read_bytes()
    if len(data) != size or sha256(data).hexdigest() != digest:
        raise ValueError(label+" hash mismatch")
    return json.loads(data)


def _authenticated_receipt():
    manifest = _read_pinned(RECEIPTS/"MANIFEST.json", size=MANIFEST_BYTES,
                            digest=MANIFEST_SHA256, label="fixed-root original manifest")
    if manifest.get("schema") != "IBME/SRGG-PARAMETER-CLOSURE-MANIFEST/1":
        raise ValueError("fixed-root original manifest schema mismatch")
    expected = {"bytes": PRECISION_BYTES, "sha256": PRECISION_SHA256}
    if manifest.get("files", {}).get("precision.json") != expected:
        raise ValueError("precision receipt differs from original manifest entry")
    receipt = _read_pinned(RECEIPTS/"precision.json", size=PRECISION_BYTES,
                           digest=PRECISION_SHA256, label="fixed-root precision receipt")
    if (receipt.get("schema") != "IBME/SRGG-FIXED-ROOT-NUMERICAL-PROFILE-COMPARISON/1"
            or receipt.get("status") != "completed"
            or receipt.get("profile") != "PARAM-III"
            or receipt.get("interpretation") != "table-standard-deviation"):
        raise ValueError("fixed-root precision receipt schema/profile/status mismatch")
    hashes = receipt.get("module_sha256_at_import", {})
    if set(hashes) != set(SOURCE_FILES):
        raise ValueError("precision receipt does not bind exactly the four corrected core sources")
    sources = manifest["selected_current_source_sha256"]
    verified = {}
    for name in SOURCE_FILES+SUPPORTING_SOURCE_FILES:
        path = ROOT/name
        if not path.is_file() or path.stat().st_size > 2*1024*1024:
            raise ValueError("missing or oversized current source: "+name)
        digest = sha256(path.read_bytes()).hexdigest()
        if sources.get(name) != digest or (name in SOURCE_FILES and hashes.get(name) != digest):
            raise ValueError("current source differs from fixed-root authenticated source: "+name)
        verified[name] = digest
    runner = "experiments/research/candidates/srgg/paper_precision_audit.py"
    if receipt.get("runner_sha256") != verified[runner]:
        raise ValueError("precision runner source hash mismatch")
    for name in ("same_fixed_root_and_key_used", "plan_preparation_read_no_entropy",
                 "table4_inputs_unchanged", "honest_verify_192"):
        if receipt.get(name) is not True:
            raise ValueError("fixed-root comparison condition missing: "+name)
    if (receipt.get("backend_default_changed") is not False
            or receipt.get("fixed_witness_reselected_for_numerical_profile") is not False
            or receipt.get("extraction_calls") != 1):
        raise ValueError("fixed-root/default invariants mismatch")
    return receipt, verified


def _check_plan(params, certificate, *, phase, numerical_bits):
    if phase not in ("master", "signature") or type(numerical_bits) is not int or numerical_bits not in (160, 192):
        raise ValueError("declared fixed-plan phase/numerical profile required")
    dimension = (params.columns+(phase == "signature"))*params.degree
    first = params.master_first_squared if phase == "master" else params.signature_first_squared
    second = params.master_second_squared if phase == "master" else params.signature_second_squared
    top = [first]*(2*params.rank)
    if phase == "signature":
        top += [second]*(params.digits*params.rank)
    noise = params.r_squared*(params.base**2 if phase == "master" else 1)
    if (type(certificate.get("dimension")) is not int or certificate["dimension"] != dimension
            or certificate.get("degree") != params.degree
            or Fraction(certificate["rounding_squared"]) != params.r_squared
            or [Fraction(x) for x in certificate["target_top_squared"]] != top
            or Fraction(certificate["target_lower_squared"]) != second
            or Fraction(certificate["noise_squared"]) != noise):
        raise ValueError("current fixed-plan target/rounding/noise/dimension mismatch")
    if (certificate.get("interval_endpoint_conversion") != "exact binary endpoint rational"
            or certificate.get("fixed_witness_residual_positive_definiteness_certified") is not True
            or certificate.get("parameter_widths_changed") is not False
            or certificate.get("reference") != REFERENCE):
        raise ValueError("current fixed-plan endpoint/geometry/reference condition mismatch")
    batch = certificate["scalar_batch"]
    if (batch.get("admitted") is not True or type(batch.get("count")) is not int
            or batch["count"] != dimension
            or batch.get("requires_independent_uniform_bytes") is not True
            or batch.get("all_original_gaussian_and_uniform_limits_retained") is not True
            or [Fraction(x) for x in batch["squared_width_class"]] != [params.r_squared]*2):
        raise ValueError("current scalar batch count/shape/entropy mismatch")
    scalar = _probability(batch["scalar_kernel_tv_including_aggregate_exact"])
    scalar_union = _probability(batch["scalar_kernel_tv_union_upper_exact"])
    aggregate_abort = _probability(batch["aggregate_budget_abort_upper_exact"])
    if scalar != min(Fraction(1), scalar_union+aggregate_abort):
        raise ValueError("scalar batch TV omits aggregate abort")
    numerical = _probability(certificate["finite_center_numerical_tv_upper"])
    if numerical not in (PUBLIC_NUMERICAL_ENVELOPE, Fraction(1)) or (
            certificate.get("public_numerical_at_most_2_minus_96") is not (numerical <= PUBLIC_NUMERICAL_ENVELOPE)):
        raise ValueError("public numerical envelope mismatch")
    if type(certificate.get("finite_arithmetic_assumptions")) is not list or not certificate["finite_arithmetic_assumptions"]:
        raise ValueError("finite arithmetic assumptions absent")
    return dimension, numerical, scalar


def report(*, theta_precision_bits=512):
    """Recompute only conditional fixed-plan perturbation TV, without draws."""
    _precision(theta_precision_bits)
    receipt, source_hashes = _authenticated_receipt()
    params = PaperParams("PARAM-III", "table-standard-deviation")
    if (receipt["parameter_record"] != params.record()
            or receipt["source_inputs"] != params.source.record()
            or receipt["notation"] != params.numerical_convention()):
        raise ValueError("current shape/source convention differs from precision experiment")
    # Constructing Backend does not prepare a plan or consume random bytes.
    default_options = asdict(Backend().series_options)
    if default_options != receipt["numerical_options_160"] or default_options["series_error_bits"] != 160:
        raise ValueError("backend default no longer matches the original 160-bit comparison")
    refined = dict(default_options, series_error_bits=192)
    if receipt["numerical_options_192"] != refined:
        raise ValueError("192-bit plan changed more than its numerical series target")
    certificates = receipt["certificates"]
    if (certificates["master160_setup"] != certificates["master160_extract"]
            or certificates["signature192"] != certificates["signature192_after_sign"]):
        raise ValueError("fixed-plan repeat preparation certificate mismatch")
    rows = []
    for label, phase, bits in PLANS:
        certificate = certificates[label]
        dimension, numerical, scalar = _check_plan(params, certificate, phase=phase, numerical_bits=bits)
        theta = theta_certificate(dimension=dimension, density_shape=params.r_squared,
                                  precision_bits=theta_precision_bits)
        rounding = _probability(theta["rounding_tv_upper"])
        total = min(Fraction(1), numerical+scalar+rounding)
        rows.append({
            "plan_label": label, "phase": phase, "series_error_bits": bits,
            "dimension": dimension, "degree": params.degree,
            "rounding_squared": str(params.r_squared),
            "target_top_squared": certificate["target_top_squared"],
            "target_lower_squared": certificate["target_lower_squared"],
            "noise_squared": certificate["noise_squared"],
            "reference": REFERENCE, "reference_center": "same exact prepared center c=0",
            "finite_center_numerical_tv_upper": str(numerical),
            "public_numerical_envelope": str(PUBLIC_NUMERICAL_ENVELOPE),
            "public_numerical_envelope_passes": numerical <= PUBLIC_NUMERICAL_ENVELOPE,
            "scalar_kernel_tv_including_aggregate_abort_upper": str(scalar),
            "scalar_batch_certificate": certificate["scalar_batch"],
            "rounding_theta_certificate": theta,
            "local_perturbation_tv_upper_including_abort": str(total),
            "local_bound_nontrivial": total < 1,
            "bound_status": "conditional fixed-plan perturbation certificate; current sources and exact shapes authenticated",
            "finite_arithmetic_assumptions": certificate["finite_arithmetic_assumptions"],
            "abort_atom_retained": True, "success_conditioned": False,
            "fixed_witness_only": True, "uniform_over_all_witnesses": False,
            "uniform_over_complete_histories": False,
            "gadget_hnf_and_final_signature_law_included": False,
            "complete_samplef_with_gadget_tv_upper": None,
            "hnf_key_law_tv_upper": None, "final_signature_law_tv_upper": None,
            "full_ibs_tv_upper": None,
            "security_claim": "none", "backend_admitted": False,
            "parameters_are_formal": False, "nist_security_category": None,
        })
    return {
        "schema": SCHEMA,
        "profile": params.record(), "notation": params.numerical_convention(),
        "evidence_kind": "authenticated current fixed-plan certificates plus exact theta recomputation",
        "frozen_experiment_commit": "38f2459",
        "precision_receipt": {"path": (RECEIPTS/"precision.json").relative_to(ROOT).as_posix(),
                              "bytes": PRECISION_BYTES, "sha256": PRECISION_SHA256},
        "manifest": {"path": (RECEIPTS/"MANIFEST.json").relative_to(ROOT).as_posix(),
                     "bytes": MANIFEST_BYTES, "sha256": MANIFEST_SHA256},
        "current_core_source_sha256_verified": {name: source_hashes[name] for name in SOURCE_FILES},
        "supporting_source_sha256_verified": {name: source_hashes[name] for name in SUPPORTING_SOURCE_FILES},
        "backend_default_series_error_bits": 160, "backend_default_changed": False,
        "new_sampler_draws": 0, "private_material_read_or_exported": False,
        "historical_endpoint_bug_finite_components_used": False,
        "new_root_or_key_generated": False, "same_fixed_root_and_key_used": True,
        "rows": rows, "hibe_involved": False,
        "complete_samplef_with_gadget_tv_upper": None, "full_ibs_tv_upper": None,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--theta-precision-bits", type=int, default=512)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("--output already exists; choose a fresh receipt path")
    result = report(theta_precision_bits=args.theta_precision_bits)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as output:
        output.write(json.dumps(result, indent=2, sort_keys=True)+"\n")
    print(json.dumps({"schema": SCHEMA, "rows": len(result["rows"]), "output": str(args.output)}))


if __name__ == "__main__":
    main()
