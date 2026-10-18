"""Fixed-root source-Schur master sampling to the paper's centered-HNF key law.

This binds one deterministic, already audited Table 4 root to the frozen
finite-to-joint Schur report.  The only probabilistic assertion is conditional
on fresh independent uniform bytes, the finite sampler's stated MPFR model,
and absence of external faults.  It is neither an all-Setup-root statement nor
a full issuance/signature service-history or security reduction.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path
import platform

from sage.all import QQ
from sage.version import version as sage_version

from ibme.core.randomness import DeterministicRandom
from ibme.ibs.srgg_paper_service import _preflight as fixed_service_preflight

from .paper_algebra import PaperRing, identity_target
from .paper_issuance_bridge import combine_issuance_tv, fixed_root_c_gate
from .paper_objects import SigningKey, _identity
from .paper_parameters import PaperParams
from .paper_rounding_budget import theta_certificate
from .paper_schur_backend import SourceSchurBackend
from .paper_schur_finite_chain import _fraction, fixed_root_finite_chain_certificate
from .paper_schur_joint_bound_audit import (
    _read_authentic_finite, build_report as recompute_joint_report,
)
from .paper_schur_normalizer import fixed_root_normalizer_certificate
from .paper_schur_numerical import SchurNumericalAudit


SCHEMA = "IBME/SRGG-SOURCE-SCHUR-FIXED-ROOT-ISSUANCE/1"
ROOT = Path(__file__).resolve().parents[4]
FINITE = ROOT / "docs/research/team-b-delivery/2026-10-18-srgg-finite-chain/finite-fixed-root.json"
JOINT = ROOT / "docs/research/team-b-delivery/2026-10-18-srgg-finite-chain/joint-fixed-root.json"
FINITE_MANIFEST = ROOT / "docs/research/team-b-delivery/2026-10-18-srgg-finite-chain/MANIFEST.json"
FINITE_MANIFEST_LF_SHA256 = "28dbeda70aa5606a8da82efceae9770178035e773fce9ddb9f947fbc41f9c6f1"
FINITE_PREFIX = "docs/research/team-b-delivery/2026-10-18-srgg-finite-chain/"
FINITE_DEPENDENCIES = (
    FINITE_PREFIX + "finite-fixed-root.json",
    FINITE_PREFIX + "joint-fixed-root.json",
    FINITE_PREFIX + "proof.md",
    "experiments/research/candidates/srgg/paper_schur_finite_chain.py",
    "experiments/research/candidates/srgg/paper_schur_joint_bound_audit.py",
    "experiments/research/candidates/srgg/paper_schur_convolution.py",
    "experiments/research/candidates/srgg/paper_schur_literal_moment.py",
    "experiments/research/candidates/srgg/paper_schur_normalizer.py",
    "experiments/research/candidates/srgg/paper_rounding_budget.py",
)
PREVIOUS_MANIFEST = ROOT / "docs/research/team-b-delivery/2026-10-18-srgg-source-schur/MANIFEST.json"
PREVIOUS_MANIFEST_SHA256 = "cb763a00b8f3c71dd27767ac05721abf61138e4fc9bc302471330e38d95cb081"
INHERITED_SOURCES = (
    "experiments/research/candidates/srgg/paper_backend.py",
    "experiments/research/candidates/srgg/paper_algebra.py",
    "experiments/research/candidates/srgg/paper_objects.py",
    "experiments/research/candidates/srgg/paper_issuance_bridge.py",
    "experiments/research/candidates/srgg/structured_geometry.py",
    "experiments/research/candidates/srgg/structured_execution.py",
    "experiments/research/candidates/srgg/aggregate_budget.py",
    "experiments/research/candidates/srgg/wide_scalar.py",
    "experiments/research/candidates/wang_pw/hashing.py",
    "src/ibme/core/randomness.py",
    "src/ibme/ibs/srgg_paper_service.py",
)


def _authenticated_reports(finite_path: Path, joint_path: Path) -> tuple[dict, dict, str, str, dict]:
    """Authenticate the previous source snapshot and independently redo the join."""
    raw_finite_manifest = FINITE_MANIFEST.read_bytes()
    if raw_finite_manifest.count(b"\r") != raw_finite_manifest.count(b"\r\n"):
        raise ValueError("finite-chain manifest contains noncanonical line endings")
    manifest_lf_sha = sha256(raw_finite_manifest.replace(b"\r\n", b"\n")).hexdigest()
    if manifest_lf_sha != FINITE_MANIFEST_LF_SHA256:
        raise ValueError("finite-chain manifest normalized LF bytes changed")
    finite_manifest = json.loads(raw_finite_manifest)
    finite_entries = finite_manifest.get("entries")
    if (finite_manifest.get("schema") != "IBME/SRGG-FINITE-CHAIN-DELIVERY-MANIFEST/1"
            or type(finite_entries) is not dict or
            not set(FINITE_DEPENDENCIES) <= set(finite_entries)):
        raise ValueError("finite-chain manifest dependency coverage differs")
    for name, entry in finite_entries.items():
        relative = Path(name)
        if (type(name) is not str or "\\" in name or relative.is_absolute() or
                any(part in ("", ".", "..") for part in relative.parts) or
                type(entry) is not dict or set(entry) != {"bytes", "sha256"}):
            raise ValueError("finite-chain manifest entry is not canonical")
        path = (ROOT / relative).resolve()
        if not path.is_relative_to(ROOT) or not path.is_file():
            raise ValueError("finite-chain manifest file missing or escaped")
        raw = path.read_bytes()
        if len(raw) != entry["bytes"] or sha256(raw).hexdigest() != entry["sha256"]:
            raise ValueError("finite-chain manifest dependency byte mismatch")
    finite_input_sha = sha256(Path(finite_path).read_bytes()).hexdigest()
    joint_input_sha = sha256(Path(joint_path).read_bytes()).hexdigest()
    if (finite_input_sha != finite_entries[FINITE_PREFIX + "finite-fixed-root.json"]["sha256"] or
            joint_input_sha != finite_entries[FINITE_PREFIX + "joint-fixed-root.json"]["sha256"]):
        raise ValueError("input receipt does not match finite-chain manifest")
    raw_manifest = PREVIOUS_MANIFEST.read_bytes()
    if sha256(raw_manifest).hexdigest() != PREVIOUS_MANIFEST_SHA256:
        raise ValueError("previous source-Schur manifest bytes changed")
    manifest = json.loads(raw_manifest)
    entries = manifest.get("files")
    if not isinstance(entries, dict):
        raise ValueError("previous source-Schur manifest lacks file entries")
    for path in INHERITED_SOURCES:
        entry = entries.get(path)
        raw = (ROOT / path).read_bytes()
        if (not isinstance(entry, dict) or entry.get("sha256") != sha256(raw).hexdigest()
                or entry.get("bytes") != len(raw)):
            raise ValueError("inherited setup/gadget/HNF source differs from frozen snapshot")
    finite_raw, finite = _read_authentic_finite(Path(finite_path))
    recomputed = recompute_joint_report(Path(finite_path))
    joint_raw = Path(joint_path).read_bytes()
    joint = json.loads(joint_raw)
    if joint != recomputed:
        raise ValueError("joint fixed-root report differs from current independent recomputation")
    if joint.get("finite_report_sha256") != sha256(finite_raw).hexdigest():
        raise ValueError("joint report does not bind the finite receipt")
    binding = {
        "schema": finite_manifest["schema"],
        "normalized_lf_sha256": manifest_lf_sha,
        "all_manifest_entries_sha256_verified": True,
        "entry_count": len(finite_entries),
        "dependent_file_sha256": {
            name: finite_entries[name]["sha256"] for name in FINITE_DEPENDENCIES
        },
    }
    return finite, joint, sha256(finite_raw).hexdigest(), sha256(joint_raw).hexdigest(), binding


def _master_shape(params: PaperParams, plan) -> None:
    """Check precisely the zero-centered original master target/noise geometry."""
    g = plan.geometry
    if (g.degree != params.degree or g.upper_polynomials != 2 * params.rank
            or g.lower_polynomials != params.rank * params.digits
            or tuple(_fraction(x) for x in g.top_squared) !=
            (Fraction(params.master_first_squared),) * (2 * params.rank)
            or _fraction(g.lower_squared) != Fraction(params.master_second_squared)
            or _fraction(g.noise_squared) != params.base**2 * Fraction(params.r_squared)
            or _fraction(g.rounding_squared) != Fraction(params.r_squared)):
        raise ValueError("source-Schur plan differs from original zero-centered master shape")


def _source_key_guard_envelope(params: PaperParams, plan, gadget) -> dict:
    """Reproduce the constructor's successful-draw envelope, then bound HNF.

    Failed scalar, ticket or entropy draws retain their abort atom.  No ideal
    unbounded Gaussian is subjected to the finite-object guard in this bound.
    """
    g = plan.geometry
    lower_cap = plan.lower_scalar.radius + 1
    bounds = [abs(g.noise_squared / g.lower_scalar) * sum(
        sum(abs(coefficient) for coefficient in poly.list()) for poly in row
    ) * lower_cap for row in g.witness]
    perturbation_cap = lower_cap
    for stage, leaf in zip(plan.plan.stages, plan.leaves):
        total = bounds[-1] + leaf.noise_cap
        perturbation_cap = max(perturbation_cap, int(total.ceil() + 1))
        bounds = [bound + sum(abs(coefficient) for coefficient in gain.list()) * leaf.noise_cap
                  + QQ(1) / 2**plan.options.vector_dyadic_bits
                  for bound, gain in zip(bounds[:-1], stage.gains)]
    digit_cap = params.base * (gadget.scalar.radius + 2)
    raw_cap = perturbation_cap + params.rank * params.digits * params.degree * digit_cap
    full_key_cap = max(params.modulus // 2, raw_cap)
    service_byte_cap = fixed_service_preflight(params, 1)
    if not raw_cap.bit_length() <= 256 or not full_key_cap.bit_length() <= 256:
        raise ValueError("finite source-Schur key coordinate guard not proved")
    return {
        "source_perturbation_coordinate_abs_upper": perturbation_cap,
        "gadget_digit_coordinate_abs_upper": digit_cap,
        "raw_coordinate_abs_upper": raw_cap,
        "centered_hnf_full_key_coordinate_abs_upper": full_key_cap,
        "raw_and_key_within_256bit_object_guard": True,
        "one_identity_fixed_service_byte_envelope": service_byte_cap,
        "finite_successful_draws_only": True,
        "external_storage_faults_included": False,
    }


def source_issuance_certificate(profile: str, interpretation: str, *,
                                identity: bytes = b"Alice", finite_report: Path = FINITE,
                                joint_report: Path = JOINT) -> dict:
    """Replay one frozen root and bind its first source-Schur issuance law.

    The deterministic seed is solely a fixture identifying the audited root.
    Distribution bounds assume independent uniform bytes, not this seed.
    Only Alice was used in the frozen signature geometry; other identities are
    outside this deliberately narrow same-root/same-identity receipt.
    """
    if type(profile) is not str or profile not in ("PARAM-I", "PARAM-II", "PARAM-III"):
        raise ValueError("original Table 4 profile required")
    if type(interpretation) is not str or interpretation not in (
            "table-standard-deviation", "literal-density-width"):
        raise ValueError("explicit original Gaussian interpretation required")
    if _identity(identity) != b"Alice":
        raise ValueError("frozen five-byte Alice identity required")
    finite, joint, finite_digest, joint_digest, manifest_binding = _authenticated_reports(
        Path(finite_report), Path(joint_report))
    pair = (profile, interpretation)
    finite_row = next(row for row in finite["rows"] if
                      (row["profile"], row["interpretation"]) == pair)
    joint_row = next(row for row in joint["rows"] if
                     (row["profile"], row["interpretation"]) == pair)
    params = PaperParams(*pair)
    seed = ("paper-baseline-" + profile + "-" + interpretation).encode("ascii")
    if (finite_row["paper_parameters"] != params.record() or
            finite_row["seed_sha256"] != sha256(seed).hexdigest() or
            joint_row["seed_sha256"] != finite_row["seed_sha256"] or
            finite_row["identity_bytes"] != len(identity) or
            finite_row["setup_attempts"] != 1 or finite_row["extraction_calls"] != 1):
        raise ValueError("fixed root/identity/parameter receipt mismatch")

    backend = SourceSchurBackend(rng=DeterministicRandom(seed))
    public, master = backend.setup(params)
    if (backend.setup_attempts != 1 or public.params != params or
            master.public_key != public or master.states):
        raise ValueError("fixture Setup root or first-issuance state changed")
    ring = PaperRing(params)
    if ring.build_public(public.a_hat, master.witness) != public.b:
        raise ValueError("fixture trapdoor/public relation changed")
    target = identity_target(public, identity)
    plan = backend._master_plan(params, master.witness)
    _master_shape(params, plan)
    audit = SchurNumericalAudit(plan)
    if (audit.public_certificate() != finite_row["master"]["numerical_input"] or
            fixed_root_finite_chain_certificate(audit) !=
            finite_row["master"]["finite_chain"] or
            fixed_root_normalizer_certificate(audit) !=
            finite_row["master"]["ideal_schur_normalizer"]):
        raise ValueError("replayed source-Schur master root differs from finite receipt")

    gadget, _scalar = backend._components(params)
    if gadget.params != params:
        raise ValueError("gadget parameters differ from fixed root")
    c_gate = fixed_root_c_gate(plan.geometry, lower_bound=64, precision_bits=192)
    if not c_gate["certified"]:
        raise ValueError("same-root centered gadget completion C gate is inconclusive")
    object_guard = _source_key_guard_envelope(params, plan, gadget)
    draws = params.rank * params.digits * params.degree
    digit = theta_certificate(dimension=draws, density_shape=Fraction(params.r_squared),
                              precision_bits=192)
    center = theta_certificate(dimension=draws, density_shape=Fraction(64),
                               precision_bits=192)
    perturbation_text = joint_row["master"]["finite_vs_joint_integer_gaussian_tv_upper_exact"]
    if (not joint_row["master"]["fixed_root_combined_tv_bound_nontrivial"] or
            perturbation_text is None):
        raise ValueError("authenticated fixed-root master perturbation bound missing")
    perturbation = Fraction(perturbation_text)
    gadget_scalar = Fraction(gadget.batch["scalar_kernel_tv_including_aggregate_exact"])
    digit_sum = Fraction(digit["dimension_times_scalar_theta_upper_exact"])
    center_error = center["relative_normalizer_error_upper_exact"]
    combined = combine_issuance_tv(
        perturbation_tv=perturbation, gadget_scalar_tv=gadget_scalar,
        digit_relative_sum=digit_sum,
        center_relative_error=None if center_error is None else Fraction(center_error))

    # This is a real, single first issuance on the same root and identity.  It
    # checks the deterministic map and guards; its test RNG is not a TV proof.
    key = backend.key_extract(master, identity)
    if (type(key) is not SigningKey or key.public_key != public or
            key.identity != identity or backend.extract_calls != 1 or
            backend.last_master_certificate != plan.public_certificate() or
            master.states.get(identity) != ("issued", key) or
            ring.matvec(ring.public_a(public), key.full, params.modulus) != target or
            SigningKey.from_bytes(key.to_bytes()).to_bytes() != key.to_bytes()):
        raise ValueError("same-root source-Schur extraction/HNF/codec check failed")

    bound = combined["complete_law_tv_upper_including_abort"]
    return {
        "schema": SCHEMA,
        "profile": profile, "interpretation": interpretation,
        "paper_parameters": params.record(),
        "identity_bytes": len(identity), "message_bytes": None, "repetitions": 1,
        "rng": "DeterministicRandom TEST FIXTURE ONLY",
        "independent_uniform_bytes_required_for_tv": True,
        "mpfr_and_exact_arithmetic_premises_required": True,
        "source_schur_backend": type(backend).__name__,
        "seed_sha256": sha256(seed).hexdigest(),
        "inherited_source_manifest_sha256": PREVIOUS_MANIFEST_SHA256,
        "setup_attempts": backend.setup_attempts,
        "extraction_calls": backend.extract_calls,
        "public_context_sha256": public.context.hex(),
        "finite_report_sha256": finite_digest,
        "joint_report_sha256": joint_digest,
        "finite_chain_manifest_binding": manifest_binding,
        "master_plan_numerical_input_replayed_exactly": True,
        "trapdoor_public_relation_verified": True,
        "gadget_identity_target_and_hnf_equation_verified": True,
        "first_key_canonical_roundtrip_verified": True,
        "same_root_c_gate": c_gate,
        "successful_finite_key_object_guard": object_guard,
        "finite_source_schur_to_joint_master_tv_upper_including_abort": str(perturbation),
        "gadget_scalar_tv_upper_including_aggregate_abort": str(gadget_scalar),
        "gadget_digit_normalizer_relative_sum_exact": str(digit_sum),
        "completed_square_center_theta_relative_error_exact": center_error,
        **combined,
        "reference": "centered-HNF pushforward of D_(Z^N,Sigma,0) conditioned on S_h",
        "reference_support": "S_h={u: h-Au mod Q has a centered representative in E_c}",
        "comparison_space": "mathematical_key_vectors_plus_abort",
        "abort_atom_retained": True,
        "gadget_fiber_bias_counted_once": True,
        "hnf_deterministic_pushforward_adds_no_tv_cost": True,
        "first_issuance_tv_bound_applies_under_iid_bytes_and_no_external_faults":
            bound is not None and Fraction(bound) < 1,
        "all_accepted_setup_roots_tv": None,
        "full_issuance_signature_fault_history_tv": None,
        "native_strong_security_proven": False,
        "private_material_exported": False,
        "rom_used": True, "teaching_parameters": False,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
    }


def build_report() -> dict:
    """Run all six original rows, exporting only public fixed-root evidence."""
    rows = [source_issuance_certificate(profile, interpretation)
            for profile in ("PARAM-I", "PARAM-II", "PARAM-III")
            for interpretation in ("table-standard-deviation", "literal-density-width")]
    source_path = "experiments/research/candidates/srgg/paper_source_issuance_bridge.py"
    return {
        "schema": "IBME/SRGG-SOURCE-SCHUR-FIXED-ROOT-ISSUANCE-REPORT/1",
        "scope": "six deterministic accepted Setup roots, one Alice first issuance per root; mathematical key vectors plus abort",
        "paper": {"path": "papers/2025_efficient_ibs_jia.pdf",
                  "sha256": rows[0]["paper_parameters"]["source_sha256"]},
        "environment": {"python": platform.python_version(), "sage": sage_version,
                        "platform": platform.platform()},
        "source_sha256": {source_path: sha256((ROOT / source_path).read_bytes()).hexdigest()},
        "rows": rows,
        "fixed_root_standard_interpretation_nontrivial_rows": sum(
            row["first_issuance_tv_bound_applies_under_iid_bytes_and_no_external_faults"]
            for row in rows if row["interpretation"] == "table-standard-deviation"),
        "literal_density_complete_issuance_bounds": None,
        "all_accepted_setup_roots_tv": None,
        "full_issuance_signature_fault_history_tv": None,
        "native_strong_security_proven": False,
        "private_material_exported": False,
        "rom_used": True, "teaching_parameters": False,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
    }


def main() -> None:
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
    print(json.dumps({"rows": len(report["rows"]),
                      "standard_nontrivial": report["fixed_root_standard_interpretation_nontrivial_rows"],
                      "literal_issuance_bound": report["literal_density_complete_issuance_bounds"],
                      "security_claim": report["security_claim"]}, sort_keys=True))


if __name__ == "__main__":
    main()
