"""Exact obligations for a full SRGG issuer/signature/fault transcript.

This is an audit of the original-parameter research implementation, not a
distribution certificate for it.  In particular, identical fault-free key
laws and a signing certificate for one fixture key do not imply a bound for
randomly issued keys or for storage faults.  The finite counterexamples below
make those missing implications exact, rather than silently adding unrelated
partial bounds.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
SCHEMA = "IBME/SRGG-PAPER-FAULT-HISTORY-LAW/1"
PDF = "papers/2025_efficient_ibs_jia.pdf"
PDF_SHA256 = "258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152"
PREDECESSOR = (
    "docs/research/team-b-delivery/2026-10-18-srgg-history-law-followup/history-law.json"
)
SOURCE_ANCHORS = {
    "src/ibme/ibs/srgg_paper_service.py": (
        "def _load(self):", "def initialize(self, params, *, max_users=1):",
        "def key_extract(self, identity):", 'snapshot.master.states[identity] = ("pending", None)',
        'snapshot.master.states[identity] = ("issued", key)',
        'snapshot.master.states[identity] = ("failed", None)',
    ),
    "src/ibme/ibs/srgg_service.py": (
        "def _check_pending(self):", "def _begin(self):", "def _finish(self):",
        "def _block(self, snapshot=None):", "def _atomic_write(self, raw: bytes):",
        "os.replace(temporary, target)",
    ),
    "experiments/research/candidates/srgg/paper_schur_backend.py": (
        "def _sign_attempt_source(self, params, plan, scalar):", "def sign(self, key, message):",
        "for _ in range(self.sign_max_attempts):",
    ),
    "experiments/research/candidates/srgg/paper_objects.py": (
        "class SigningKey(IBSSigningKey):",
        "# PaperRing checks exact 256-bit coordinates, not a sampling norm class.",
    ),
    "experiments/research/candidates/srgg/paper_parameters.py": (
        "class PaperParams:", "def signature_first_squared(self):",
        "def signature_second_squared(self):",
    ),
    "experiments/research/candidates/srgg/structured_geometry.py": (
        "def shifted_schur_apply(self, upper):", "def signature_operator(*, degree, rank, digits, user_vector,",
        "noise_factor*_rational(r_squared)",
    ),
    "experiments/research/candidates/srgg/structured_execution.py": (
        "def reconstruct(self,public,target,tail):",
    ),
    "experiments/research/candidates/srgg/paper_algebra.py": (
        "def public_matrix(params, seed):", "class PaperRing(ExactRing):",
    ),
    "experiments/research/candidates/srgg/paper_schur_fourier.py": (
        "# Check the ORIGINAL full residual Sigma_p-r^2 I.",
        'raise WitnessGeometryError("source-Schur certified negative full residual direction")',
    ),
}


def _probability(value, name):
    if type(value) not in (int, Fraction):
        raise ValueError(f"{name} must be an exact int or Fraction")
    result = Fraction(value)
    if not 0 <= result <= 1:
        raise ValueError(f"{name} must be in [0,1]")
    if max(result.numerator.bit_length(), result.denominator.bit_length()) > 32768:
        raise ValueError(f"{name} exceeds the rational resource bound")
    return result


def exact_tv(left, right):
    """TV of two small explicit laws; outcomes are distinct public atoms."""
    def law(value, name):
        if type(value) is not dict or not value:
            raise ValueError(f"{name} must be a nonempty finite law")
        if any(type(atom) is not str or not atom for atom in value):
            raise ValueError(f"{name} atoms must be nonempty strings")
        weights = {atom: _probability(mass, name) for atom, mass in value.items()}
        if sum(weights.values(), Fraction(0)) != 1:
            raise ValueError(f"{name} masses must sum exactly to one")
        return weights

    a, b = law(left, "left"), law(right, "right")
    return sum((abs(a.get(atom, 0) - b.get(atom, 0))
                for atom in a.keys() | b.keys()), Fraction(0)) / 2


def fixture_key_counterexample(support_size=8):
    """Equal issuance, perfect fixture signing, yet large full-history TV.

    The key is uniform on 0..N-1.  Both worlds issue the *same* law and sign
    identically at key zero.  On every other key, the signature atoms differ.
    This is a finite probability counterexample, not an SRGG attack.
    """
    if type(support_size) is not int or not 2 <= support_size <= 4096:
        raise ValueError("counterexample support must be an integer in 2..4096")
    mass = Fraction(1, support_size)
    issuance = {str(i): mass for i in range(support_size)}
    real = {f"{i}:signature-0": mass for i in range(support_size)}
    reference = {f"{i}:signature-{0 if i == 0 else 1}": mass
                 for i in range(support_size)}
    result = exact_tv(real, reference)
    if result != Fraction(support_size - 1, support_size):
        raise RuntimeError("finite fixture-key counterexample drift")
    return {
        "support_size": support_size,
        "issuance_tv_exact": str(exact_tv(issuance, issuance)),
        "fixture_key_0_signing_tv_exact": "0",
        "complete_issue_then_sign_tv_exact": str(result),
        "can_approach_one_as_support_grows": True,
        "is_srgg_attack": False,
    }


def external_fault_counterexample(fault_probability=Fraction(1, 2)):
    """An unmodeled read fault adds exactly its probability to transcript TV."""
    p = _probability(fault_probability, "fault_probability")
    good = {"issued-key:signature": Fraction(1)}
    faulty = {"issued-key:signature": 1-p, "fault:read": p}
    # A zero-probability atom is harmless, but keep the law's support minimal.
    faulty = {atom: mass for atom, mass in faulty.items() if mass}
    return {
        "fault_probability_exact": str(p),
        "fault_free_issue_and_sign_tv_exact": "0",
        "complete_history_tv_exact": str(exact_tv(good, faulty)),
        "fault_label_retained": True,
        "is_srgg_attack": False,
    }


def conditional_microstep_bound(*, initial_complete_state_tv=None,
                                bad_signing_key_history_mass=None,
                                microsteps=()):
    """First-divergence bound *given* uniform complete microstep premises.

    Every bound must apply to the full next-state/observation kernel at every
    matching reachable history, including distinguishable abort/fault labels.
    A fault decision interleaved inside a sampler is another microstep; merely
    knowing the fault-free full-call sampler TV cannot be inserted here.
    ``bad_signing_key_history_mass`` bounds the reference probability that any
    sign uses a key outside the certified Good set, including after reload or
    corruption.  All counts are pathwise caps, not expected counts.
    """
    initial = _probability(initial_complete_state_tv, "initial_complete_state_tv") \
        if initial_complete_state_tv is not None else None
    bad = _probability(bad_signing_key_history_mass, "bad_signing_key_history_mass") \
        if bad_signing_key_history_mass is not None else None
    if type(microsteps) not in (tuple, list) or len(microsteps) > 128:
        raise ValueError("bounded ordered microstep ledger required")
    ledger = []
    total = Fraction(0)
    for item in microsteps:
        if type(item) is not dict or set(item) != {"kind", "count", "uniform_tv"}:
            raise ValueError("each microstep requires kind, count and uniform_tv")
        kind, count = item["kind"], item["count"]
        if type(kind) is not str or not kind or type(count) is not int or not 0 <= count <= 1 << 40:
            raise ValueError("invalid microstep kind or pathwise cap")
        delta = _probability(item["uniform_tv"], "uniform_tv") \
            if item["uniform_tv"] is not None else None
        if count and delta is None:
            total = None
        elif total is not None:
            total += count * (delta or 0)
        ledger.append({"kind": kind, "count": count,
                       "uniform_complete_kernel_tv": None if delta is None else str(delta)})
    full = None if initial is None or bad is None or total is None else min(1, initial+bad+total)
    return {
        "initial_complete_state_tv": None if initial is None else str(initial),
        "bad_signing_key_history_mass": None if bad is None else str(bad),
        "microsteps": ledger,
        "conditional_complete_history_tv_upper": None if full is None else str(full),
        "all_conditional_premises_verified_here": False,
    }


def source_map():
    result = {}
    for name, anchors in SOURCE_ANCHORS.items():
        data = (ROOT / name).read_bytes()
        lines = data.decode("utf-8").splitlines()
        positions = {}
        for anchor in anchors:
            hits = [i for i, line in enumerate(lines, 1) if anchor in line]
            if not hits:
                raise ValueError(f"source anchor missing: {name}: {anchor}")
            positions[anchor] = hits
        result[name] = {"sha256": sha256(data).hexdigest(), "anchors": positions}
    return result


def wire_valid_bad_sign_plan_witness():
    """A real Table 4 object passes wire checks but has negative sign Schur.

    The public root uses the all-zero CBD1 witness and its exact trapdoor
    relation.  The signing key is deliberately constructed, *not* sampled
    by Extract; this refutes an all-wire-valid-key premise only.  No private
    key or full public key is returned in this public audit record.
    """
    from sage.all import QQ
    from .paper_algebra import PaperRing, public_matrix
    from .paper_objects import PublicKey, SigningKey
    from .paper_parameters import PaperParams
    from .structured_geometry import signature_operator

    p = PaperParams("PARAM-I", "table-standard-deviation")
    zero = (0,) * p.degree
    witness = tuple(tuple(zero for _ in range(p.rank*p.digits))
                    for _ in range(2*p.rank))
    seed = bytes(32)
    ring = PaperRing(p)
    a_hat = public_matrix(p, seed)
    public = PublicKey(p, seed, a_hat, ring.build_public(a_hat, witness))
    if not ring.trapdoor_relation(public, witness):
        raise RuntimeError("zero CBD1 public relation failed")
    tail = [zero for _ in range((1+p.digits)*p.rank)]
    tail[0] = (100_000_000,) + (0,) * (p.degree-1)
    key = SigningKey(public, b"Alice", tuple(tail))
    if SigningKey.from_bytes(key.to_bytes()).to_bytes() != key.to_bytes():
        raise RuntimeError("large but wire-valid key did not round-trip")
    geometry = signature_operator(degree=p.degree, rank=p.rank, digits=p.digits,
        user_vector=key.full, first_squared=p.signature_first_squared,
        second_squared=p.signature_second_squared, r_squared=p.r_squared,
        noise_factor=1)
    index = p.rank
    basis = tuple(((1,) + (0,) * (p.degree-1)) if j == index else zero
                  for j in range(p.columns))
    rayleigh = QQ(geometry.shifted_schur_apply(basis)[index][0])
    if rayleigh >= 0:
        raise RuntimeError("constructed key did not refute positive Schur")
    return {
        "profile": p.profile_name, "interpretation": p.interpretation,
        "identity_length_bytes": 5, "tail_coefficient": 100_000_000,
        "key_wire_round_trip": True, "public_zero_witness_relation": True,
        "negative_shifted_schur_rayleigh_exact": str(rayleigh),
        "shows_all_wire_valid_keys_have_signing_certificate": False,
        "key_output_by_random_extract_claimed": False,
    }


def build_report():
    predecessor_bytes = (ROOT / PREDECESSOR).read_bytes()
    predecessor = json.loads(predecessor_bytes)
    if predecessor.get("schema") != "IBME/SRGG-PAPER-ADAPTIVE-HISTORY-FOLLOWUP/1/REPORT":
        raise ValueError("predecessor history law schema mismatch")
    if predecessor.get("full_random_issuance_signature_fault_history_tv") is not None:
        raise ValueError("predecessor full history was unexpectedly closed")
    if sha256((ROOT / PDF).read_bytes()).hexdigest() != PDF_SHA256:
        raise ValueError("frozen source PDF mismatch")
    rows = predecessor["rows"]
    expected = [(profile, convention) for profile in ("PARAM-I", "PARAM-II", "PARAM-III")
                for convention in ("table-standard-deviation", "literal-density-width")]
    if [(row["profile"], row["interpretation"]) for row in rows] != expected:
        raise ValueError("original Table 4 six-row order changed")
    for row in rows:
        if (row["random_issued_key_then_sign_history_tv"] is not None or
                row["faulty_storage_history_tv"] is not None or
                row["bad_issued_key_sign_plan_probability"] is not None):
            raise ValueError("predecessor full-law premise changed")
    return {
        "schema": SCHEMA,
        "source_pdf": PDF, "source_sha256": PDF_SHA256,
        "predecessor": {"path": PREDECESSOR,
                        "sha256": sha256(predecessor_bytes).hexdigest()},
        "source_map": source_map(),
        "scope": "original Table 4 independent IBS; complete persistent issuer, backend sign and external fault transcript obligations",
        "fixture_key_counterexample": fixture_key_counterexample(),
        "arbitrary_fault_counterexample": external_fault_counterexample(Fraction(1)),
        "wire_valid_bad_sign_plan_witness": wire_valid_bad_sign_plan_witness(),
        "conditional_hybrid": conditional_microstep_bound(
            initial_complete_state_tv=None, bad_signing_key_history_mass=None,
            microsteps=(
                {"kind": "first-issue including interleaved fault decisions", "count": 3,
                 "uniform_tv": None},
                {"kind": "sign including retries and interleaved fault decisions", "count": 2,
                 "uniform_tv": None},
                {"kind": "external storage/lock/crash microtransition", "count": 1,
                 "uniform_tv": None},
            )),
        "six_rows": [{
            "profile": row["profile"], "interpretation": row["interpretation"],
            "fixed_root_issuance_only_tv_upper": row["issuance_only_history_at_capacity_tv_upper"],
            "same_fixture_key_two_sign_calls_tv_upper": row[
                "same_fixture_key_two_adaptive_sign_calls_tv_upper"],
            "all_accepted_roots_initial_law_tv": None,
            "random_issued_key_bad_sign_plan_mass": None,
            "faulty_storage_conditional_kernel_tv": None,
            "full_issuance_signature_fault_history_tv": None,
        } for row in rows],
        "route_a": "pathwise deterministic replay when complete state, fresh entropy tape, OS/fault tape, schedule and observation map match; cannot compare unlike laws",
        "route_b": "adaptive complete-microstep TV hybrid; input conditional bounds for random keys and interleaved faults are missing",
        "route_c": "exact finite counterexamples and a wire-valid negative-Schur object reject shortcut composition; no further route attempted",
        "full_history_bound": None,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("--output already exists")
    result = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"rows": len(result["six_rows"]),
                      "full_history": result["full_history_bound"],
                      "wire_valid_bad_sign_plan": True}, sort_keys=True))


if __name__ == "__main__":
    main()
