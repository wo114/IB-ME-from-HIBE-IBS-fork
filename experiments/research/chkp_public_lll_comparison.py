"""Bounded replay of PUBLIC algebra fixtures; no private inputs or sampling.

Run with WSL ~/miniconda3/envs/sage/bin/python. --list is standard-library
only; the default runs fixed cases sequentially in isolated child processes.
Every timeout includes fixture construction, LLL, and exact checks. Reported
lll_seconds covers only the LLL call. No mode is chosen from earlier results.

The historical JSON in docs/research/2026-10-12-chkp-closure was transcribed from captured tool
outputs, not produced by rerunning this consolidated script. F01 and F02 are
different public matrices: only compare cases with the same fixture ID.
These are synthetic integer matrices, NOT actual RandBasis Gaussian draws.
The raw LLL probes check eta<=.501; runtime v2 additionally performs exact
integer size reduction to eta<=.5 and applies its frozen GS/Lovasz gates.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import time


DIMENSION = 64
Q = 1099511627791
FROZEN_PARENT_GS_SQUARED_BOUND = 150187181128720


def _case(fixture, algorithm, delta, transformation, limit=22):
    return dict(fixture=fixture, algorithm=algorithm, delta=delta,
                transformation=transformation, process_limit_seconds=limit)


CASES = {
    "f01-wrapper-transform": _case("F01", "wrapper", "999/1000", True, 25),
    "f01-proved-transform": _case("F01", "proved_mpfr_202", "999/1000", True, 25),
    "f01-ntl-transform": _case("F01", "ntl_exact", "999/1000", True, 25),
    "f01-wrapper-no-transform": _case("F01", "wrapper", "999/1000", False),
    "f01-proved-no-transform": _case("F01", "proved_mpfr_202", "999/1000", False),
    "f02-delta075": _case("F02", "wrapper", "3/4", False),
    "f02-delta090": _case("F02", "wrapper", "9/10", False),
    "f02-delta0999": _case("F02", "wrapper", "999/1000", False),
}


def worker(case_id):
    # Local repository code only. No secret-path, seed, or RNG argument exists.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
    from sage.all import QQ, ZZ, matrix
    from ibme.lattice.chkp.basis import (
        KernelBasis, ModMatrixReference, complete_kernel_basis,
    )
    from ibme.lattice.chkp.tobasis import to_basis

    case = CASES[case_id]
    d, q = DIMENSION, Q
    if case["fixture"] == "F01":
        public = ModMatrixReference(tuple(tuple(int(i == j) for j in range(d))
                                          for i in range(2)), q)
        base = matrix.diagonal(ZZ, [q, q] + [1] * (d-2))
    else:
        public = ModMatrixReference(tuple(tuple(
            int.from_bytes(sha256(f"PUBLIC-A/{i}/{j}".encode()).digest()[:6], "big") % q
            for j in range(d)) for i in range(2)), q)
        base = matrix(ZZ, complete_kernel_basis(public).basis_rows)
    mixing = matrix(ZZ, d, d, lambda i,j: (d*65536 if i == j else 0)
        + int.from_bytes(sha256(f"PUBLIC-DENSE/{d}/{i}/{j}".encode()).digest()[:2], "big")
        - 32768)
    fixture = to_basis(base*mixing, KernelBasis(public, base), max_dimension=512)
    original = matrix(ZZ, fixture.basis_rows).transpose()
    options = dict(delta=QQ(case["delta"]), eta=QQ(501)/1000,
                   transformation=case["transformation"])
    if case["algorithm"] == "wrapper":
        options["algorithm"] = "fpLLL:wrapper"
    elif case["algorithm"] == "proved_mpfr_202":
        # Historical d=64 probe: installed l2_min_prec(64,.999,.501,.0001)
        # returned 138; the probe used 138+64=202. No private geometry is used.
        options.update(algorithm="fpLLL:proved", fp="rr", prec=202)
    elif case["algorithm"] == "ntl_exact":
        options.update(algorithm="NTL:LLL", fp=None)
    else:
        raise ValueError("unknown fixed algorithm")
    started = time.perf_counter()
    returned = original.LLL(**options)
    elapsed = time.perf_counter() - started
    reduced, transform = returned if case["transformation"] else (returned, None)
    if transform is not None and transform*original != reduced:
        raise ArithmeticError("false exact transformation")
    if matrix(ZZ, public.rows)*reduced.transpose() % q != 0:
        raise ArithmeticError("output is outside the public kernel")
    if abs(reduced.det()) != q*q:
        raise ArithmeticError("output does not have the complete kernel index")
    star, _ = reduced.change_ring(QQ).gram_schmidt()
    squared = tuple(row.dot_product(row) for row in star.rows())
    mu = lambda i,j: reduced.row(i).dot_product(star.row(j))/squared[j]
    def lovasz(threshold):
        return all(squared[i] + mu(i,i-1)**2*squared[i-1] >= threshold*squared[i-1]
                   for i in range(1,d))
    return dict(case_id=case_id, **case, status="completed", dimension=d, q=q,
        lll_seconds=elapsed, precision_bits=options.get("prec"),
        exact_transform_checked=transform is not None, containment_checked=True,
        complete_index_checked=True,
        eta501=bool(all(abs(mu(i,j)) <= QQ(501)/1000 for i in range(d) for j in range(i))),
        lovasz74=bool(lovasz(QQ(74)/100)), lovasz99=bool(lovasz(QQ(99)/100)),
        frozen_parent_gs_bound_pass=bool(max(squared) <= FROZEN_PARENT_GS_SQUARED_BOUND),
        input_max_entry_bits=max(abs(int(x)).bit_length() for x in original.list()),
        random_bytes=0, security_claim="none")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="list fixed cases without Sage or LLL")
    parser.add_argument("--case", action="append", choices=tuple(CASES), help="run specified cases only")
    parser.add_argument("--worker", choices=tuple(CASES), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.list:
        print(json.dumps(dict(dimension=DIMENSION, q=Q, cases=CASES), indent=2))
        return 0
    if args.worker:
        print(json.dumps(worker(args.worker)))
        return 0
    results = []
    for case_id in args.case or CASES:
        case = CASES[case_id]
        started = time.perf_counter()
        try:
            process = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()),
                                      "--worker", case_id], capture_output=True, text=True,
                                     timeout=case["process_limit_seconds"])
            if process.returncode:
                result = dict(case_id=case_id, **case, status="error",
                              returncode=process.returncode, stderr=process.stderr[-4000:])
            else:
                result = json.loads(process.stdout)
        except subprocess.TimeoutExpired:
            # subprocess.run kills and reaps this child only; no other process
            # is signalled. This is an implementation timeout, not a proof of
            # mathematical failure or a basis-quality result.
            result = dict(case_id=case_id, **case, status="timeout")
        result["process_seconds"] = time.perf_counter() - started
        results.append(result)
    print(json.dumps(dict(schema="CHKP-PUBLIC-LLL-COMPARISON/1",
        results=results, security_claim="none", real_sampling_performed=False), indent=2))
    return 1 if any(item["status"] == "error" for item in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
