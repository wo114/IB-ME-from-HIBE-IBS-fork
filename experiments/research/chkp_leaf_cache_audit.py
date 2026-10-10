"""Public-toy CHKP cache/restore audit; no identity ROM or HIBE decryption.

Each seed uses the same root/parent construction as the leaf-path audit.
Sensitive snapshots exist only in a private TemporaryDirectory, never in the
report/repository. A new Python process restores without a sampler or RNG.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
from tempfile import TemporaryDirectory

from sage.env import SAGE_VERSION

from ibme.core.randomness import DeterministicRandom
from .chkp_basis import ModMatrixReference, ext_basis
from .chkp_basis_reduce import reduce_basis
from .chkp_genbasis import AP09Parameters, gen_basis
from .chkp_gpv import CHKPGPVSampler
from .chkp_randbasis import CHKPRandBasis
from .chkp_t2_audit import SEEDS, EPSILON_BITS, _required_width
from .chkp_leaf_cache import FixedLeafCache
from .chkp_leaf_cache_types import CacheScope, LeafPlan
from .chkp_leaf_cache_wire import pack_plan, parse_plan
from .gaussian_reference import draw_uniform_integer


RESTORE_MODULE = "experiments.research.chkp_leaf_cache_audit"


def prepare(seed):
    cfg = AP09Parameters(n=1, q=2, random_rows=2, m1=2, m2=8, hadamard_scale=4)
    rng = DeterministicRandom(seed.encode("ascii"))
    basis = gen_basis(cfg, rng=rng).basis
    public_root, upper = basis.public, cfg.gs_squared_bound
    widths = []
    for level in (1, 2):
        block = ModMatrixReference([[draw_uniform_integer(rng, cfg.q) for _ in range(10)]], cfg.q)
        expanded = ext_basis(basis, block)
        width = _required_width(expanded.public.ncols, max(upper, 1))
        widths.append(int(width))
        sampler = CHKPGPVSampler(expanded, width, epsilon_bits=EPSILON_BITS)
        if level == 2:
            break
        for y in range(cfg.q):
            sampler.sample((y,), rng=rng)
        basis = reduce_basis(CHKPRandBasis(sampler, max_vectors=40).sample(rng=rng).basis).basis
        upper = width*expanded.public.ncols
    if widths != [9064, 15952640]:
        raise AssertionError("Toy width schedule changed; update the declared experiment explicitly")
    context = json.dumps({"domain": "CHKP-CACHE-TOY-CONTEXT/1", "root_public": public_root.rows,
        "n": 1, "m": 10, "q": 2, "depth": 2, "s1_squared": widths[0], "s2_squared": widths[1],
        "epsilon_bits": EPSILON_BITS, "formal": False, "encryption_parameters": None},
        sort_keys=True, separators=(",", ":")).encode("ascii")
    return sampler, LeafPlan.from_sampler(sampler, [(0,), (1,)]), rng, CacheScope(context, b"rcv", 2, 2)


def restore_check(snapshot_path, request_path):
    request = json.loads(Path(request_path).read_text(encoding="utf-8"))
    scope = CacheScope(bytes.fromhex(request["context"]), bytes.fromhex(request["parent"]),
                       request["capacity"], request["max_entries"])
    plan = parse_plan(bytes.fromhex(request["plan"]), scope.capacity)
    raw = Path(snapshot_path).read_bytes()
    restored = FixedLeafCache.from_bytes(raw, expected_scope=scope)
    batch = restored.resolve(bytes.fromhex(request["child"]), plan)  # no sampler/RNG supplied
    return {"canonical_roundtrip": restored.to_bytes() == raw,
            "snapshot_sha256": hashlib.sha256(restored.to_bytes()).hexdigest(),
            "preimage_count": len(batch.preimages), "sampler_required": False}


def run_attempt(seed):
    sampler, plan, rng, scope = prepare(seed)
    store = FixedLeafCache(scope)
    first = store.resolve(b"phi", plan, sampler=sampler, rng=rng)
    snapshot = store.to_bytes()
    same = store.resolve(b"phi", plan) == first
    restored = FixedLeafCache.from_bytes(snapshot, expected_scope=scope)
    same = same and restored.resolve(b"phi", plan) == first
    same = same and all(restored.bit(b"phi", plan, i) == first.preimages[i] for i in range(scope.capacity))
    request = {"context": scope.public_context.hex(), "parent": scope.parent_identity.hex(),
               "capacity": scope.capacity, "max_entries": scope.max_entries,
               "child": b"phi".hex(), "plan": pack_plan(plan).hex()}
    with TemporaryDirectory(prefix="chkp-leaf-cache-") as directory:
        keyfile, requestfile = Path(directory)/"private-cache.bin", Path(directory)/"public-request.json"
        keyfile.touch(mode=0o600)
        keyfile.write_bytes(snapshot)
        requestfile.write_text(json.dumps(request), encoding="utf-8")
        child = subprocess.run([sys.executable, "-m", RESTORE_MODULE, "--restore-check", str(keyfile),
                                "--request", str(requestfile)], capture_output=True, text=True, timeout=60)
        if child.returncode != 0:
            raise RuntimeError("Fresh-process restore failed: "+child.stderr)
        evidence = json.loads(child.stdout)
    exact = evidence["canonical_roundtrip"] and evidence["snapshot_sha256"] == hashlib.sha256(snapshot).hexdigest()
    return {"seed": seed, "repeated_and_restored_vectors_identical": same,
            "fresh_process_identical_snapshot": exact, "fresh_process_exit": child.returncode,
            "capacity": scope.capacity, "preimage_count": len(first.preimages),
            "dimension": plan.public.ncols, "snapshot_bytes": len(snapshot),
            "leaf_squared_norms": [str(sum(x*x for x in v)) for v in first.preimages],
            "has_parent_basis_or_rng_in_snapshot": False, "private_snapshot_published": False,
            "outcome": "cache_restore_passed" if same and exact else "cache_restore_failed"}


def build_report():
    attempts = []
    for seed in SEEDS:
        try:
            attempts.append(run_attempt(seed))
        except Exception as exc:
            # An experiment harness, not a production failure handler. Retain
            # every declared failure without retry; do not publish secret data.
            attempts.append({"seed": seed, "outcome": "error", "error_type": type(exc).__name__})
    root = Path(__file__).resolve().parents[2]
    names = ("chkp_leaf_cache_types", "chkp_leaf_cache_wire", "chkp_leaf_cache",
             "chkp_leaf_cache_audit", "chkp_leaf_reference", "chkp_gpv", "chkp_randbasis",
             "chkp_basis_reduce", "online_gaussian_reference")
    paths = [f"experiments/research/{n}.py" for n in names]+["papers/2010_bonsai_trees_cash.pdf"]
    return {"created_utc": datetime.now(timezone.utc).isoformat(), "schema_version": 1,
            "scope": "fixed-capacity cache and trusted snapshot restore on public toy CHKP leaves",
            "security_claim": "none", "backend_admitted": False, "T2_complete": False, "T3_complete": False,
            "sampler_modified": False, "caps_relaxed": False,
            "declared_seeds": list(SEEDS), "seed_search_or_retry": False,
            "parameters": {"n": 1, "q": 2, "root_dimension": 10, "s1_squared": 9064,
                           "s2_squared": 15952640, "epsilon_bits_not_security_bits": 16},
            "identity_bytes": {"receiver": 3, "sender": 3}, "application_message_bytes": None,
            "target_source": "explicit (0,),(1,) fixtures, NOT implemented H/G",
            "attempts": attempts, "fixed_cache_gate_passed": all(a["outcome"] == "cache_restore_passed" for a in attempts),
            "environment": {"python": platform.python_version(), "sage": str(SAGE_VERSION), "platform": platform.platform()},
            "sha256": {p: hashlib.sha256((root/p).read_bytes()).hexdigest() for p in paths},
            "limitations": ["trusted precomputed matrix/targets and full public context required",
                "no H/G or full HIBE/IBME byte payload or noise/decryption",
                "no authenticated/encrypted storage, rollback protection or multiprocess transactions",
                "persist current state after success AND failure; older or forked owners can diverge",
                "formal parameters, budgets and security estimates remain open"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--restore-check", type=Path)
    parser.add_argument("--request", type=Path)
    args = parser.parse_args()
    if args.restore_check:
        print(json.dumps(restore_check(args.restore_check, args.request)))
        return 0
    report = build_report()
    encoded = json.dumps(report, indent=2, ensure_ascii=False)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    print(json.dumps({"fixed_cache_gate_passed": report["fixed_cache_gate_passed"],
                      "attempts": [a["outcome"] for a in report["attempts"]], "T3_complete": False}), file=sys.stderr)
    return 0 if report["fixed_cache_gate_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
