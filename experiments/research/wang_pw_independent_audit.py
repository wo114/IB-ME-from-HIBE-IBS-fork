"""Independent executable audit of the frozen Wang/PW delivery.

This is an audit driver, not an implementation or a passing-test substitute.
Exit 1 means that required code invariants failed; exit 2 is an unexpected
audit error. No keys, signatures, production seeds or user messages are saved.
The inspected module is never modified. Run from the repository root:
  python experiments/research/wang_pw_independent_audit.py --out audit.json
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import importlib.util
import itertools
import json
import math
import platform
import sys
import time
from dataclasses import replace
from fractions import Fraction
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from ibme.core import DeterministicRandom, InvalidParameterError  # noqa: E402
from ibme.core.hashing import hash_identity  # noqa: E402
from ibme.ibs import wang_pw as w  # noqa: E402

FROZEN_SHA256 = "119f1168003b99a39172ce1cb2513658a2ad56ca4925b6c33bcdeb09890c1b8d"


def run_audit():
    results = []

    def record(identifier, requirement, passed, **observed):
        results.append(dict(id=identifier, requirement=requirement,
                            status="PASS" if passed else "FAIL", observed=observed))

    # This seed is a public, synthetic regression fixture, never a runtime key.
    rng = DeterministicRandom(b"codex-wang-independent-audit-v1")
    params = w.WangPWParams(n=2, q=7, m_bar=6, name="codex-independent-audit")
    pk, msk = w.setup(params, rng=rng)
    sk = w.key_extract(msk, b"alice", rng=rng)
    signature = w.sign(sk, b"synthetic-message", rng=rng)
    record("C01", "honest standalone signature verifies",
           w.verify(pk, b"alice", b"synthetic-message", signature))
    record("C02", "delegated trapdoor satisfies F*T=G",
           w._mat_mul(sk.identity_matrix(), list(map(list, zip(*sk.trapdoor_columns()))),
                      params.q) == w.gadget_matrix(params.n, params.q))

    # Recovery uses only the material in the issued user key, not the local msk.
    recovered = w.MasterSecretKey(params, tuple(map(tuple, sk.a_bar())),
                                  tuple(map(tuple, sk.r_a())))
    victim = w.key_extract(recovered, b"unissued-bob", rng=rng)
    forged = w.sign(victim, b"synthetic-forgery", rng=rng)
    succeeds = w.verify(pk, b"unissued-bob", b"synthetic-forgery", forged)
    record("F01", "issued user key must not reveal the master trapdoor",
           recovered != msk and not succeeds,
           master_reconstructed_exactly=recovered == msk,
           unissued_identity_signature_accepted=succeeds)

    # Mirror the actual extraction path using only pk and public operations.
    stream = w._Stream(DeterministicRandom(b"public-only-key-extraction-fixture"))
    a = pk.matrix()
    identity = b"public-only-carol"
    h1 = w.hash_identity_matrix(params, identity)
    target = w._mat_sub(h1, w.gadget_matrix(params.n, params.q), params.q)
    basis = w.integer_kernel_basis(a, params.q)
    columns = [w.sample_coset(stream, basis,
                             w._gf_solve(a, [row[j] for row in target], params.q),
                             params.s_del * math.sqrt(len(basis)))
               for j in range(params.w)]
    public_sk = w.SigningKey(params, identity, hash_identity(identity, 32), pk.a_rows,
                            tuple((0,) * params.w for _ in range(params.m_bar)),
                            tuple(map(tuple, h1)), tuple(zip(*columns)), params.verify_bound)
    public_sig = w.sign(public_sk, b"public-only-message", rng=rng)
    public_success = w.verify(pk, identity, b"public-only-message", public_sig)
    record("F02", "paper DelTrap path must use the supplied master trapdoor",
           not public_success, public_only_extraction_and_signing=public_success,
           limitation="toy execution plus source dataflow; not a general SIS attack")

    # Change A while retaining every parameter, identity and message.
    a2 = pk.matrix()
    a2[0][0] = (a2[0][0] + 1) % params.q
    pk2 = w.PublicKey(params, tuple(map(tuple, a2)))
    id1 = [row[params.m:] for row in w.identity_matrix_from_public(pk, b"alice")]
    id2 = [row[params.m:] for row in w.identity_matrix_from_public(pk2, b"alice")]
    captured = []

    def capture_syndrome(_stream, _params, _f, _r, h2, _sigma):
        captured.append(list(h2))
        return [1] + [0] * (params.signature_dim - 1)

    with patch.object(w, "_sample_pre_perturbed", side_effect=capture_syndrome):
        for key in (sk, replace(sk, a_rows=pk2.a_rows)):
            w.sign(key, b"mpk-binding-check", rng=rng)
    record("F03", "H1/H2 transcripts must include the actual mpk as in Wang Fig.4",
           id1 != id2 and captured[0] != captured[1],
           different_public_matrices=pk.a_rows != pk2.a_rows,
           H1_identical=id1 == id2, H2_identical=captured[0] == captured[1],
           limitation="dependency check, not a cross-public-key forgery test")

    # Independent GPV trace; the mock chooses nearest planes to expose algebra,
    # not to claim a statistical test of the Gaussian law.
    with patch.object(w, "_sample_gaussian_z", side_effect=lambda _s, _w, c: round(c)):
        out = w.sample_coset(None, [[2, 0], [1, 3]], [1, 2], 6.0)
    record("F04", "coset sampler must target center -particular before adding particular",
           out == [0, -1], expected=[0, -1], actual=out)
    calls = []

    def fixed_coefficient(_stream, sigma, center):
        calls.append((sigma, center))
        return 1

    with patch.object(w, "_sample_gaussian_z", side_effect=fixed_coefficient):
        w.sample_coset(None, [[2, 0], [1, 3]], [0, 0], 6.0)
    record("F05", "GPV center updates must subtract z_i times the original basis vector",
           calls[1][1] == Fraction(-1, 2), expected_second_center="-1/2",
           actual_second_center=str(calls[1][1]))
    record("F06", "GPV coordinate widths must be sigma / GS norm",
           [v[0] for v in calls] == [2.0, 3.0], expected=[2.0, 3.0],
           actual=[v[0] for v in calls])

    # Exact finite support of the delivery's enumerator. Its basis is for an
    # INTEGER kernel, so all enumerated points have dot(g,z)=6, not 6 mod 7.
    g_basis = w._gadget_kernel_basis(3)
    enumerated = {
        tuple([6, 0, 0][i] + sum(c * b[i] for c, b in zip(cs, g_basis))
              for i in range(3)) for cs in w._coefficient_box(2, 8)
    }
    witness = (-1, 0, 0)
    mass = kept = 0.0
    for z in itertools.product(range(-8, 9), repeat=3):
        dot = sum((1 << i) * z[i] for i in range(3))
        if dot % 7 == 6:
            weight = math.exp(-sum(x * x for x in z) / 2)
            mass += weight
            if dot == 6:
                kept += weight
    record("F07", "gadget sampler must cover the modular coset, including short lifts",
           witness in enumerated, valid_missing_vector=list(witness),
           witness_syndrome=sum((1 << i) * witness[i] for i in range(3)) % 7,
           omitted_mass_in_coordinate_box=1 - kept / mass,
           scope="q=7,k=3,sigma=1, coordinate box [-8,8]^3; not an infinite-tail bound")

    # A distribution witness for the perturbation construction, not just its
    # second moment: rounding 2*integer-Gaussian can NEVER give an odd integer.
    denom = sum(math.exp(-x * x / 8) for x in range(-20, 21))
    odd_mass = sum(math.exp(-x * x / 8) for x in range(-20, 21) if x % 2) / denom
    perturb_source = inspect.getsource(w._sample_pre_perturbed)
    integer_rounding_present = ("gauss = [_sample_gaussian_z" in perturb_source
                               and "p = [round(" in perturb_source)
    record("F08", "round(L * integer Gaussian) is not the MP12 discrete perturbation law",
           not integer_rounding_present, source_contains_integer_gaussian_rounding=integer_rounding_present,
           diagonal_factor=2, actual_odd_probability=0,
           target_D_Z_sigma2_odd_mass_in_box=odd_mass,
           scope="constructive support counterexample; full covariance equality not established")

    reduced = w.lll_reduce([[2], [3]])
    record("F09", "dependent-input LLL must preserve the integer span",
           len(reduced) == 1 and abs(reduced[0][0]) == 1,
           input_generators=[[2], [3]], actual=reduced, expected_lattice="Z")
    false_complete = w.verify_kernel_basis_is_complete([[1]], [[1]], 7)
    record("F10", "kernel completeness predicate must check both inclusions",
           not false_complete, actual=false_complete,
           witness="basis [1] is not in kernel of A=[1] mod 7 (kernel is 7Z)")

    # Prove impossibility of acceptance without entering an infinite loop.
    threshold = -w._fixed_ln_lower_frac(Fraction(1, 1 << 128)) * 2 * w._sigma_sq_lower(.01)
    record("F11", "accepted Gaussian input domain must not contain impossible rejection loops",
           threshold >= Fraction(1, 4), center="1/2", sigma=.01,
           largest_possible_acceptance_threshold=float(threshold),
           smallest_squared_distance=.25, loop_entered=False)

    # Core arithmetic failure on a bounded input object; no wire/API integration.
    huge = w.Signature(params, (10 ** 400,) + (0,) * (params.signature_dim - 1))
    try:
        huge_result = w.verify(pk, b"alice", b"synthetic-message", huge)
        error = None
    except (OverflowError, ValueError) as exc:
        huge_result, error = None, type(exc).__name__
    record("F12", "verification must reject over-norm integer vectors without float overflow",
           huge_result is False, returned=huge_result, raised=error)

    # Public object integer inputs may not be silently rounded by int().
    try:
        fractional = w.Signature(params, (1.9,) + (0,) * (params.signature_dim - 1))
        accepted_fractional = fractional.z[0] == 1
    except InvalidParameterError:
        accepted_fractional = False
    record("F13", "integer signature constructor must reject non-integer coordinates",
           not accepted_fractional, fractional_coordinate_silently_truncated=accepted_fractional)

    # Existing local serialization claims strict canonicality.
    pk_blob = bytearray(pk.to_bytes())
    start = len(b"IBM1-WANGPW-PK") + 8
    coefficient = int.from_bytes(pk_blob[start:start + 4], "big")
    pk_blob[start:start + 4] = (coefficient + params.q).to_bytes(4, "big")
    try:
        alias_pk = w.PublicKey.from_bytes(params, pk_blob)
        alias = alias_pk == pk
    except InvalidParameterError:
        alias = False
    record("F14", "public-key wire parser must reject noncanonical coefficients >=q",
           not alias, alternate_encoding_of_same_public_key_accepted=alias)
    plain = w.Signature(params, (1,) + (0,) * (params.signature_dim - 1))
    wide = (b"IBM1-WANGPW-SIG" + params.signature_dim.to_bytes(4, "big")
            + (2).to_bytes(4, "big")
            + b"".join(x.to_bytes(2, "big", signed=True) for x in plain.z))
    try:
        alias = w.Signature.from_bytes(params, wide) == plain
    except InvalidParameterError:
        alias = False
    record("F15", "signature wire parser must enforce canonical coefficient width",
           not alias, alternate_encoding_of_same_signature_accepted=alias)

    # Frozen scheme already has a public key; validation must be self-contained.
    scheme = w.WangPWScheme(params, rng=rng)
    scheme.pk = pk
    salt = bytes(params.salt_bits // 8)
    try:
        invalid_result = scheme.verify_pw(None, b"m", salt, salt, signature)
        error = None
    except (TypeError, ValueError, InvalidParameterError) as exc:
        invalid_result, error = None, type(exc).__name__
    record("F16", "outer verifier must reject invalid identity types without throwing",
           invalid_result is False, returned=invalid_result, raised=error)
    bit_params = replace(params, salt_bits=9)
    record("F17", "requested salt entropy must not be silently floored to whole bytes",
           (bit_params.salt_bits // 8) * 8 >= bit_params.salt_bits,
           requested_bits=9, actual_generated_bits=(bit_params.salt_bits // 8) * 8)

    record("C03", "zero signature is rejected",
           not w.verify(pk, b"alice", b"m", w.Signature(params, (0,) * params.signature_dim)))
    module = Path(w.__file__)
    return dict(scope="standalone code only; no interface integration or formal parameter selection",
                subject_sha256=hashlib.sha256(module.read_bytes()).hexdigest(),
                expected_frozen_sha256=FROZEN_SHA256,
                environment=dict(python=platform.python_version(), platform=platform.platform()),
                parameters=params.as_dict(), checks=results,
                passed=sum(c["status"] == "PASS" for c in results),
                failed=sum(c["status"] == "FAIL" for c in results),
                verdict="FAIL" if any(c["status"] == "FAIL" for c in results) else "PASS")


def main():
    global w
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--subject", type=Path,
                        help="frozen original wang_pw.py (must match the audited SHA256)")
    args = parser.parse_args()
    if args.subject is not None:
        if hashlib.sha256(args.subject.read_bytes()).hexdigest() != FROZEN_SHA256:
            print("Frozen subject hash mismatch; refusing to run historical audit.")
            return 2
        spec = importlib.util.spec_from_file_location("frozen_wang_pw_audit", args.subject)
        w = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = w
        spec.loader.exec_module(w)
    actual_hash = hashlib.sha256(Path(w.__file__).read_bytes()).hexdigest()
    if actual_hash != FROZEN_SHA256:
        print("Source version changed: adapt the independent audit before using its verdict.")
        return 2
    start = time.perf_counter()
    receipt = run_audit()
    receipt["seconds"] = time.perf_counter() - start
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(receipt, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({k: receipt[k] for k in ("verdict", "passed", "failed", "subject_sha256", "seconds")},
                     ensure_ascii=False))
    return 1 if receipt["verdict"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
