"""Sage HNF/LLL oracle for the corrected Wang/PW complete kernel bases.
Row vectors stay rows through HNF and LLL. No private vectors are emitted.
Run in the existing WSL ~/miniconda3/envs/sage environment; no hardcoded home.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
from sage.all import GF, QQ, ZZ, matrix
from ibme.core import DeterministicRandom
from ibme.ibs import wang_pw as wang

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
params = wang.WangPWParams(n=int(2), q=int(7), m_bar=int(6), name="wang-kernel-exact")
rng = DeterministicRandom(b"wang-kernel-exact-v2")
pk, msk = wang.setup(params, rng=rng)
sk = wang.key_extract(msk, b"alice", rng=rng)
results = []
for name, rows, basis in (
    ("public_kernel", pk.matrix(), wang.integer_kernel_basis(pk.matrix(), params.q)),
    ("master_trapdoor", pk.matrix(), wang._trapdoor_kernel_basis(pk.matrix(), msk.r_a(), params.q)),
    ("user_trapdoor", sk.identity_matrix(), list(map(list, sk.sampling_basis))),
):
    A = matrix(ZZ, rows)
    q, dim = int(params.q), int(A.ncols())
    ker = A.change_ring(GF(q)).right_kernel_matrix()
    generators = [[int(x.lift()) for x in row] for row in ker.rows()]
    generators += [[q*int(i == j) for j in range(dim)] for i in range(dim)]
    hnf = matrix(ZZ, generators).hermite_form(include_zero_rows=False)
    reduced = hnf.LLL()
    candidate = matrix(ZZ, basis)
    expected = q**int(A.change_ring(GF(q)).rank())
    forward = candidate.change_ring(QQ)*hnf.change_ring(QQ).inverse()
    backward = hnf.change_ring(QQ)*candidate.change_ring(QQ).inverse()
    checks = {
        "annihilates": all(int(x) % q == 0 for x in (A*candidate.transpose()).list()),
        "same_determinant": abs(candidate.det()) == abs(hnf.det()) == expected,
        "both_integer_inclusions": all(x in ZZ for x in forward.list()+backward.list()),
    }
    results.append({
        "basis": name, "dimension": dim, "expected_index": expected,
        "python_index": int(abs(candidate.det())), "sage_index": int(abs(hnf.det())),
        "sage_reduced_max_gs": max(float(v.norm()) for v in reduced.change_ring(QQ).gram_schmidt()[0].rows()),
        "checks": checks,
    })
receipt = {
    "source_sha256": hashlib.sha256(Path(wang.__file__).read_bytes()).hexdigest(),
    "oracle": "Sage HNF of GF kernel lifts plus qI; two-sided integer inclusion",
    "results": results,
    "all_passed": all(all(item["checks"].values()) for item in results),
    "security_claim": "none",
}
args.out.parent.mkdir(parents=True, exist_ok=True)
args.out.write_text(json.dumps(receipt, indent=2)+"\n", encoding="utf-8", newline="\n")
print(json.dumps({"all_passed": receipt["all_passed"], "basis_count": len(results)}))
raise SystemExit(0 if receipt["all_passed"] else 1)
