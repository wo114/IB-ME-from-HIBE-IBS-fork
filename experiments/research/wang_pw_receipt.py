"""Run the corrected standalone Wang/PW lifecycle and emit a public-only receipt.
No secret key, signature vector, runtime seed or original user message is saved.
This is functional evidence, not a Gaussian-distance or security proof.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from ibme.core import DeterministicRandom, InvalidParameterError
from ibme.ibs import wang_pw as w

# Public synthetic test fixture, never used for deployment.
SEED = b"ibme-wang-pw-corrected-receipt-2026-10-13"
PARAMS = w.WangPWParams(n=2, q=7, m_bar=6, name="wang-pw-corrected-receipt")


def build_receipt():
    checks, measurements = {}, {}
    receipt = {
        "artifact": "corrected-standalone-wang-pw",
        "source_sha256": hashlib.sha256(Path(w.__file__).read_bytes()).hexdigest(),
        "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "params": PARAMS.as_dict(),
        "environment": {"python": platform.python_version(), "platform": platform.platform(),
                        "processor": platform.processor()},
        "checks": checks, "measurements": measurements,
        "inputs": {"identity_lengths_bytes": [5, 3, 5, 4],
                   "message_lengths_bytes": [0, 1, 11, 64],
                   "repetitions": "4 identities x 4 messages; single process; no accelerator",
                   "randomness": "public deterministic test fixture in driver",
                   "hash_model": "domain-separated SHAKE instantiation; no ideal-RO equivalence proof"},
        "boundaries": [
            "research parameters only; no security-level claim or backend admission",
            "SamplePre: G-trapdoor -> MP12 Lemma 5.3 full basis -> exact LLL -> GPV08 4.2",
            "not MP12 Algorithm 3 perturbation sampling",
            "scalar Gaussian: finite 12*sigma+1 window, Decimal(80), 128-bit thresholds, finite budget",
            "GPV distribution requires width hypotheses; neither exact infinite Gaussian nor security proven",
            "H2 has only 49 values here; message and cross-identity collisions are explicitly counted",
            "user_basis_seconds measures lazy basis generation; sign_seconds uses prepared bases; no optimized benchmark claim",
        ],
    }
    rng = DeterministicRandom(SEED)
    start = time.perf_counter()
    pk, msk = w.setup(PARAMS, rng=rng)
    measurements["setup_seconds"] = time.perf_counter()-start
    g = w.gadget_matrix(PARAMS.n, PARAMS.q)
    master_t = msk.r_a() + [[int(i == j) for j in range(PARAMS.w)] for i in range(PARAMS.w)]
    checks["master_trapdoor_equation"] = w._mat_mul(pk.matrix(), master_t, PARAMS.q) == g
    start = time.perf_counter()
    master_basis = w._trapdoor_kernel_basis(pk.matrix(), msk.r_a(), PARAMS.q)
    checks["master_basis_complete"] = w.verify_kernel_basis_is_complete(master_basis, pk.matrix(), PARAMS.q)
    measurements["master_basis_seconds"] = time.perf_counter()-start
    measurements["master_basis_index"] = abs(w._det_bareiss(list(map(list, zip(*master_basis)))))
    measurements["expected_index"] = PARAMS.q**PARAMS.n

    keys, extraction_seconds, basis_seconds = {}, [], []
    delegated, isolated, complete = [], [], []
    for identity in (b"Alice", b"Bob", b"Carol", b"Dave"):
        start = time.perf_counter()
        key = w.key_extract(msk, identity, rng=rng)
        extraction_seconds.append(time.perf_counter()-start)
        keys[identity] = key
        delegated.append(w._mat_mul(key.matrix(), key.r_x(), PARAMS.q) ==
                         w._mat_sub(key.h1(), g, PARAMS.q))
        isolated.append(not hasattr(key, "r_a_rows") and not hasattr(key, "r_a"))
        start = time.perf_counter()
        basis = key.sampling_basis
        basis_seconds.append(time.perf_counter()-start)
        complete.append(w.verify_kernel_basis_is_complete(basis, key.identity_matrix(), PARAMS.q))
    checks["delegated_equations"] = all(delegated)
    checks["user_keys_have_no_master_trapdoor_fields"] = all(isolated)
    checks["all_user_bases_complete"] = all(complete)
    measurements["key_extract_seconds"] = extraction_seconds
    measurements["user_basis_seconds"] = basis_seconds

    honest, total, message_collisions, distinct_rejected, tamper_rejected = 0, 0, 0, 0, 0
    norms, timings, wire_lengths = [], [], []
    for identity, key in keys.items():
        for message in (b"", b"m", b"hello world", b"\x00\xff"*32):
            start = time.perf_counter()
            sig = w.sign(key, message, rng=rng)
            timings.append(time.perf_counter()-start)
            total += 1
            honest += int(w.verify(pk, identity, message, sig))
            norms.append(sig.norm())
            wire_lengths.append(len(sig.to_bytes()))
            if w.hash_message_vector(pk, identity, message+b"!") == w.hash_message_vector(pk, identity, message):
                message_collisions += 1
            else:
                distinct_rejected += int(not w.verify(pk, identity, message+b"!", sig))
            # A has full row rank; choose a column known to change the syndrome.
            column = next(j for j in range(PARAMS.m) if any(row[j] for row in pk.a_rows))
            changed = list(sig.z)
            changed[column] += 1
            tamper_rejected += int(not w.verify(pk, identity, message, w.Signature(PARAMS, changed)))
    checks["all_honest_signatures_verify"] = honest == total == 16
    checks["distinct_hash_wrong_messages_rejected"] = distinct_rejected == total-message_collisions and distinct_rejected > 0
    checks["nonzero_column_tampering_rejected"] = tamper_rejected == total
    measurements.update(honest_accepted=honest, honest_attempted=total,
                        message_hash_collisions=message_collisions, distinct_wrong_messages_rejected=distinct_rejected,
                        sign_seconds=timings, max_signature_norm=max(norms),
                        verify_bound=PARAMS.verify_bound, public_wire_bytes=len(pk.to_bytes()),
                        signature_wire_bytes=wire_lengths)
    sample = w.sign(keys[b"Alice"], b"wire", rng=rng)
    checks["canonical_wire_roundtrip"] = (
        w.Signature.from_bytes(PARAMS, sample.to_bytes()) == sample
        and w.PublicKey.from_bytes(PARAMS, pk.to_bytes()) == pk)
    rejection_checks = []
    for constructor, wire in ((w.Signature.from_bytes, sample.to_bytes()), (w.PublicKey.from_bytes, pk.to_bytes())):
        for bad in (wire[:-1], wire+b"\x00"):
            try:
                constructor(PARAMS, bad)
                rejection_checks.append(False)
            except InvalidParameterError:
                rejection_checks.append(True)
    checks["wire_truncation_append_rejected"] = all(rejection_checks)

    first = w.key_extract_pw(msk, b"Alice", rng=rng)
    second = w.key_extract_pw(msk, b"Alice", rng=rng)
    checks["independent_extraction_uses_new_salt_fixture"] = first.salt != second.salt
    del msk
    r, s, sig = w.sign_pw(first, b"standalone", rng=rng)
    r2, s2, sig2 = w.sign_pw(first, b"standalone", rng=rng)
    checks["independent_user_sign_verify_without_authority"] = (
        w.verify_pw(pk, b"Alice", b"standalone", r, s, sig)
        and w.verify_pw(pk, b"Alice", b"standalone", r2, s2, sig2))
    checks["same_key_r_reused_new_s_drawn_fixture"] = r == r2 and s != s2
    checks["invalid_pw_types_and_short_salts_rejected"] = all(
        not w.verify_pw(pk, identity, message, rr, ss, sig)
        for identity, message, rr, ss in ((None, b"standalone", r, s),
                                         (b"Alice", 4, r, s), (b"Alice", b"standalone", r[:-1], s)))
    # Verify every cross-identity decision against independently computed modular sums.
    decisions, expected = [], []
    for i in range(32):
        identity = b"other-%d" % i
        iid = w.j_identity(identity, r, bits=PARAMS.internal_id_bits)
        msg = w.j_message(b"standalone", s, bits=PARAMS.internal_msg_bits)
        matrix = w.identity_matrix_from_public(pk, iid)
        rhs = w.hash_message_vector(pk, iid, msg)
        expected.append(all(sum(a*z for a, z in zip(row, sig.z)) % PARAMS.q == target
                            for row, target in zip(matrix, rhs)))
        decisions.append(w.verify_pw(pk, identity, b"standalone", r, s, sig))
    checks["cross_identity_decisions_match_equations"] = decisions == expected and False in decisions
    measurements["cross_identity_attempts"] = len(decisions)
    measurements["cross_identity_rejected"] = decisions.count(False)
    measurements["cross_identity_accepted_toy_collisions"] = decisions.count(True)
    checks["all_passed"] = all(checks.values())
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    start = time.perf_counter()
    receipt = build_receipt()
    receipt["elapsed_seconds"] = time.perf_counter()-start
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(receipt, ensure_ascii=False, indent=2)+"\n", encoding="utf-8", newline="\n")
    print(json.dumps({"all_passed": receipt["checks"]["all_passed"],
                      "check_count": len(receipt["checks"])-1,
                      "honest_accepted": receipt["measurements"]["honest_accepted"],
                      "source_sha256": receipt["source_sha256"],
                      "elapsed_seconds": receipt["elapsed_seconds"]}))
    return 0 if receipt["checks"]["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
