"""Audit the missing random-issued-key to signing-law bridge for paper SRGG.

The original HNF reference gives positive mass to every integer tail.  A
single large *canonical* tail coordinate makes the signature conditional
covariance nonpositive.  Thus the existing one-fixture-key Schur certificate
cannot be promoted to a uniform certificate on the reference support.  This
module does not alter the paper backend, its parameters, or either law.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
from fractions import Fraction
from hashlib import sha256
from io import StringIO
import json
from math import isqrt
from pathlib import Path
import platform
import runpy

from sage.version import version as sage_version

from ibme.core.randomness import DeterministicRandom

from .paper_objects import SigningKey
from .paper_parameters import PaperParams
from .paper_samplef import WitnessGeometryError
from .paper_distribution_guard import SigningKeyGateRejection
from .paper_schur_backend import SourceSchurBackend


SCHEMA = "IBME/SRGG-PAPER-RANDOM-KEY-SIGN-LAW-AUDIT/1"
ROOT = Path(__file__).resolve().parents[4]
PREVIOUS = ROOT / "docs/research/team-b-delivery/2026-10-18-srgg-history-law-followup"
SOURCE = ROOT / "docs/research/team-b-delivery/2026-10-18-srgg-source-issuance/source-issuance.json"
PAPER = ROOT / "papers/2025_efficient_ibs_jia.pdf"
PROFILES = ("PARAM-I", "PARAM-II", "PARAM-III")
INTERPRETATIONS = ("table-standard-deviation", "literal-density-width")


def exact_fraction(value):
    """Retain exact Sage/Python rational values without float conversion."""
    if isinstance(value, bool):
        raise ValueError("exact rational required")
    if isinstance(value, Fraction):
        return value
    if callable(getattr(value, "numerator", None)):
        return Fraction(int(value.numerator()), int(value.denominator()))
    if type(value) in (int, str):
        return Fraction(value)
    raise ValueError("exact rational required")


def probability(value):
    if type(value) not in (int, str, Fraction):
        raise ValueError("exact probability required")
    result = Fraction(value)
    if not 0 <= result <= 1:
        raise ValueError("probability outside [0,1]")
    return result


def conditional_random_key_bound(*, issuance_tv, bad_key_mass,
                                 good_key_sign_call_tv, sign_calls):
    """One issue then bounded adaptive signs, with bad key charged once.

    Bad mass is under the *mathematical issuance reference*.  Signing TV must
    hold on every good reachable key and every matching adaptive history.
    Abort is a shared output symbol.  A missing premise returns None rather
    than accepting a fixture-key bound as a uniform one.
    """
    if type(sign_calls) is not int or not 0 <= sign_calls <= 1024:
        raise ValueError("bounded nonnegative sign-call count required")
    if issuance_tv is None:
        return None
    issue = probability(issuance_tv)
    if sign_calls == 0:
        return issue
    if any(x is None for x in (issuance_tv, bad_key_mass, good_key_sign_call_tv)):
        return None
    bad, sign = map(probability, (bad_key_mass, good_key_sign_call_tv))
    return min(Fraction(1), issue + bad + sign_calls * sign)


def tail_obstruction(params):
    """Smallest positive constant tail coefficient with a negative diagonal.

    For the original factor-one signature geometry, the conditional upper
    Schur matrix at each negacyclic Fourier root is

        D - beta * v v*,  beta = r^2*s2^2/(s2^2-r^2).

    Choose row j=2d (the first gadget tail row), v_j(X)=T and other tail
    entries zero.  Its diagonal is s2^2-beta*T^2, regardless of the HNF
    reconstructed head.  All computations here are exact rational arithmetic.
    """
    if type(params) is not PaperParams:
        raise TypeError("original PaperParams required")
    d = params.rank
    if params.digits < 1 or params.degree != 512:
        raise ValueError("original Table 4 shape required")
    lower = exact_fraction(params.signature_second_squared)
    noise = exact_fraction(params.r_squared)
    if not 0 < noise < lower:
        raise ValueError("original signature lower margin required")
    beta = noise * lower / (lower - noise)
    ratio = lower / beta
    threshold = isqrt(ratio.numerator // ratio.denominator) + 1
    diagonal = lower - beta * threshold**2
    if not diagonal < 0 or not beta * (threshold - 1)**2 <= lower:
        raise AssertionError("strict minimal obstruction threshold failed")
    if threshold.bit_length() > 256:
        raise ValueError("obstruction exceeds current canonical object guard")
    return {
        "full_row_index": 2*d,
        "tail_row_index": d,
        "constant_coefficient": threshold,
        "conditional_rank_one_beta_exact": str(beta),
        "diagonal_at_threshold_exact": str(diagonal),
        "previous_integer_does_not_make_this_diagonal_negative": True,
        "within_256_bit_coordinate_guard": True,
        "proof_scope": "one nonpositive Fourier diagonal, independent of HNF head; not a sampled attack key",
    }


def replay_canonical_obstruction(params, obstruction):
    """Check a real fixed-root public object and the unchanged sign builder.

    The deterministic seed labels a test root; no private key or synthetic
    signing-key bytes are exported.  This key is an ideal-reference support
    witness, not a claim about its probability under finite issuance.
    """
    seed = ("paper-baseline-" + params.profile_name + "-" +
            params.interpretation).encode("ascii")
    backend = SourceSchurBackend(rng=DeterministicRandom(seed))
    public, _master = backend.setup(params)
    count = (1 + params.digits)*params.rank
    zeros = (0,) * params.degree
    tail = [zeros for _ in range(count)]
    large = list(zeros)
    large[0] = obstruction["constant_coefficient"]
    tail[obstruction["tail_row_index"]] = tuple(large)
    key = SigningKey(public, b"Alice", tuple(tail))
    if (key.full[obstruction["full_row_index"]][0] != large[0] or
            SigningKey.from_bytes(key.to_bytes()).to_bytes() != key.to_bytes()):
        raise AssertionError("canonical synthetic key obstruction did not survive HNF/codec")
    try:
        backend._sign_plan(key)
    except (WitnessGeometryError, SigningKeyGateRejection):
        rejected = True
    else:
        rejected = False
    if not rejected:
        raise AssertionError("backend admitted a certified nonpositive signature geometry")
    return {"root_seed_sha256": sha256(seed).hexdigest(),
            "public_context_sha256": public.context.hex(),
            "canonical_synthetic_key_roundtrip": True,
            "unchanged_source_sign_plan_rejects": True,
            "synthetic_key_bytes_exported": False,
            "synthetic_key_probability_estimated": False}


def authenticated_history_rows():
    """Authenticate frozen predecessor before citing its separate law scopes."""
    namespace = runpy.run_path(str(PREVIOUS / "verify_delivery.py"))
    with redirect_stdout(StringIO()):
        namespace["main"]()
    raw = (PREVIOUS / "history-law.json").read_bytes()
    report = json.loads(raw)
    expected = [(p, i) for p in PROFILES for i in INTERPRETATIONS]
    rows = report.get("rows")
    if (type(rows) is not list or len(rows) != 6 or
            [(r.get("profile"), r.get("interpretation")) for r in rows] != expected):
        raise ValueError("authenticated history lacks original six rows")
    return rows, {"history_law_sha256": sha256(raw).hexdigest(),
                  "history_manifest_sha256": sha256((PREVIOUS / "MANIFEST.json").read_bytes()).hexdigest(),
                  "history_delivery_verified": True}


def build_report():
    history_rows, binding = authenticated_history_rows()
    source_raw = SOURCE.read_bytes()
    source = json.loads(source_raw)
    if (len(source.get("rows", [])) != 6 or
            any(old["authenticated_predecessors"]["source_issuance_sha256"] !=
                sha256(source_raw).hexdigest() for old in history_rows)):
        raise ValueError("source issuance envelope is not authenticated by history")
    source_rows = {(r["profile"], r["interpretation"]): r for r in source["rows"]}
    if set(source_rows) != {(p, i) for p in PROFILES for i in INTERPRETATIONS}:
        raise ValueError("source issuance rows changed")
    paper_sha = sha256(PAPER.read_bytes()).hexdigest()
    if paper_sha != "258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152":
        raise ValueError("original paper PDF differs")
    rows = []
    for old in history_rows:
        params = PaperParams(old["profile"], old["interpretation"])
        if old["paper_parameters"] != params.record():
            raise ValueError("predecessor parameter row differs")
        obstruction = tail_obstruction(params)
        envelope = source_rows[(params.profile_name, params.interpretation)][
            "successful_finite_key_object_guard"]["centered_hnf_full_key_coordinate_abs_upper"]
        if type(envelope) is not int or envelope <= obstruction["constant_coefficient"]:
            raise ValueError("prior finite successful-output envelope changed")
        replay = replay_canonical_obstruction(params, obstruction)
        if replay["root_seed_sha256"] != old["root_seed_sha256"] or replay[
                "public_context_sha256"] != old["public_context_sha256"]:
            raise ValueError("fixed-root predecessor binding differs")
        rows.append({
            "profile": params.profile_name, "interpretation": params.interpretation,
            "paper_parameters": params.record(),
            "identity_bytes": 5, "message_bytes": None,
            "repetitions": 1,
            "rom_used": True, "teaching_parameters": False,
            "rng": "DeterministicRandom TEST FIXTURE ONLY",
            "obstruction": obstruction, "canonical_replay": replay,
            "mathematical_reference_tail_support": "all integer tails: for any t, choose head congruent to h-A_tail*t (mod Q), with e=0 in E_c; Gaussian mass is positive",
            "uniform_all_reference_signing_keys_schur_certificate_possible": False,
            "bound_scope": "every_plan_passing_complete_gate_set",
            "guard_built_into_backend": True,
            "good_key_signing_bound_gate_uniform": True,
            "bad_key_mass_reason": ("strictly positive by the canonical tail obstruction; the conditional HNF "
                                    "denominator lacks a target-uniform lower bound"),
            "finite_successful_output_coordinate_envelope": envelope,
            "obstruction_below_coarse_finite_envelope": True,
            "finite_envelope_does_not_prove_obstruction_reachable": True,
            "actual_finite_issuance_mass_of_this_tail": None,
            "bad_key_mass_under_mathematical_issuance_reference": None,
            "uniform_good_key_sign_call_tv": None,
            "authenticated_issuance_tv_upper": old["one_fresh_issuance_tv_upper"],
            "fixture_key_sign_call_tv_upper_not_reused": old["same_fixture_key_one_sign_call_tv_upper"],
            "one_random_issued_key_then_two_sign_calls_tv": None,
            "all_accepted_setup_roots_tv": None,
            "external_fault_history_tv": None,
            "native_strong_security_proven": False,
            "security_claim": "none", "backend_admitted": False,
            "parameters_are_formal": False, "nist_security_category": None,
            "private_material_exported": False,
        })
    return {"schema": SCHEMA, "paper": {"path": "papers/2025_efficient_ibs_jia.pdf",
                                      "sha256": paper_sha},
            "environment": {"python": platform.python_version(), "sage": sage_version,
                            "platform": platform.platform()},
            "predecessor": binding,
            "bound_scope": "every_plan_passing_complete_gate_set",
            "guard_built_into_backend": True,
            "scope": "six deterministic accepted roots as witnesses; guarded backend; good-key signing bound is gate-uniform; beta_bad, gate masses and fault histories remain null",
            "coupling_formula": "min(1, delta_issue + beta_bad_key + s*epsilon_sign_good) for one issued key and s matching-history adaptive sign calls; beta charged once",
            "coupling_requires": "ideal-reference bad-key mass and uniform good-key sign-call TV, both currently null; fresh iid bytes, stated MPFR model, shared abort and no external faults",
            "route_ledger": [
                {"route": "all-reference-key uniform Schur/numerical certificate",
                 "result": "disproved by exact canonical tail obstruction in all six rows"},
                {"route": "reuse successful finite-output coordinate envelope as a safe-key gate",
                 "result": "fails: its upper envelope exceeds the obstruction threshold; no reachability probability follows"},
                {"route": "condition an unconditional Gaussian spectral-tail estimate on S_h",
                 "result": "not closed: target-specific P_D(S_h) denominator and HNF-wrap/spectral numerator lack quantitative certificates"},
            ],
            "rows": rows,
            "identity_bytes": 5, "message_bytes": None,
            "repetitions_per_row": 1,
            "rom_used": True, "teaching_parameters": False,
            "full_random_issuance_signing_history_tv": None,
            "security_claim": "none", "backend_admitted": False,
            "parameters_are_formal": False, "nist_security_category": None}


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
    print(json.dumps({"rows": len(report["rows"]),
                      "full_random_key_history": report["full_random_issuance_signing_history_tv"],
                      "security_claim": report["security_claim"]}, sort_keys=True))


if __name__ == "__main__":
    main()
