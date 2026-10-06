"""Read-only arithmetic/replay check for the conditional correctness ledger.

Run in the repository's prescribed WSL Sage environment:
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src ~/miniconda3/envs/sage/bin/python \
  docs/research/2026-10-06-correctness/verify_ledger.py --repo .
Prints JSON; does not write results, alter parameters, or generate production keys.
This is not a security proof or an independent random-sample experiment.
"""
import argparse
import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--repo", required=True, type=Path)
args = parser.parse_args()
repo = args.repo.resolve()
archive = repo / "docs/research/2026-10-05-round10/online-sampling-results.json"
if not archive.is_file() or not (repo / "src/ibme").is_dir():
    parser.error("--repo must identify the IB-ME source repository")
sys.path[:0] = [str(repo), str(repo / "src")]

from sage.all import QQ, ZZ, matrix, vector
from sage.env import SAGE_VERSION
from experiments.research.gaussian_reference import SamplingAbort
from experiments.research.online_mp12_reference import sampler_for_quality
from experiments.research.online_sampling_audit import AuditRandom

data = json.loads(archive.read_text(encoding="utf-8"))
chain = data["connected"]
row = chain["all_attempts"][0]
q = chain["q"]
a = matrix(ZZ, row["A"])
r = matrix(ZZ, row["delegated_R"])
q0, q1 = chain["master_quality_squared"], chain["user_quality_squared"]
_, parent = sampler_for_quality(
    q, a[:, :chain["m_bar"]], matrix(ZZ, row["R0"]), q0
)
_, user = sampler_for_quality(q, a, r, q1)
assert parent is not None and user is not None
assert parent.public_matrix() == a
assert user.public_matrix() == a.augment(matrix(ZZ, row["extension"]))
s2 = QQ(parent.r_squared * parent.sigma_squared)
t2 = QQ(user.r_squared * user.sigma_squared)
bound2 = t2 * user.dimension
assert (q, chain["n"], chain["w"], parent.dimension, user.dimension) == (
    2147483659, 1, 32, 33, 65
)
assert q1 == chain["w"] * parent.dimension * s2
assert bound2 == 17708094495

saved_checks = []
for index, sample in enumerate(row["first_user_outputs"]):
    v = vector(ZZ, sample["x"])
    ns = sum(x*x for x in v)
    assert int((user.public_matrix()*v)[0]) % q == sample["syndrome"]
    assert ns <= bound2
    saved_checks.append({"kind": "archived_sample", "index": index,
        "syndrome": sample["syndrome"], "norm_squared": int(ns)})
v = vector(ZZ, row["user_replay_output"])
ns = sum(x*x for x in v)
assert int((user.public_matrix()*v)[0]) % q == 12345 and ns <= bound2
saved_checks.append({"kind": "archived_replay", "syndrome": 12345,
    "norm_squared": int(ns)})

prefix = b"ibme-round10:attempt:0"
counts = dict(attempts=0, aborts=0, equation_failures=0,
              norm_failures=0, zero_outputs=0, archived_prefix_matches=0)
norms = []
for syndrome in (0, q-1):
    rng = AuditRandom(prefix + f":user:{syndrome}".encode())
    saved = [v["x"] for v in row["first_user_outputs"]
             if v["syndrome"] == syndrome]
    for j in range(32):
        counts["attempts"] += 1
        try:
            x = user.sample((syndrome,), rng=rng)
        except SamplingAbort:
            counts["aborts"] += 1
            continue
        ns = sum(ZZ(v)**2 for v in x)
        norms.append(ns)
        counts["equation_failures"] += int((user.public_matrix()
                                           * vector(ZZ, x))[0]) % q != syndrome
        counts["norm_failures"] += ns > bound2
        counts["zero_outputs"] += ns == 0
        if j < 2:
            assert list(x) == saved[j]
            counts["archived_prefix_matches"] += 1
assert counts["attempts"] == 64 and counts["archived_prefix_matches"] == 4
assert not any(counts[k] for k in
               ("aborts", "equation_failures", "norm_failures"))
assert len(norms) == 64

pc, uc = parent.certificate(), user.certificate()
e0, e1 = QQ(pc["tv_upper_including_abort"]), QQ(uc["tv_upper_including_abort"])
paths = [
    "papers/2023_tightly_secure_ibs_foo.pdf",
    "papers/2011_lattice_trapdoors_micciancio.pdf",
    "docs/research/2026-10-04-round7/FooLi经典ROM证明补全与修复路线.md",
    "docs/research/2026-10-05-round10/online-sampling-results.json",
    "experiments/research/online_gaussian_reference.py",
    "experiments/research/online_mp12_reference.py",
]
hashes = {p: hashlib.sha256((repo/p).read_bytes()).hexdigest() for p in paths}
manifest = json.loads((repo/"papers/manifest.json").read_text(encoding="utf-8"))
for entry in manifest["entries"]:
    if entry["file"] in hashes:
        assert hashes[entry["file"]] == entry["sha256"]

result = {
    "schema_version": 1,
    "evidence_baseline_commit": "800e4dd49790d0723b2a02be7698c713b93169f6",
    "executed_repository_head": subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip(),
    "scope": "research_sampler_equations_norms_and_local_certificates_only",
    "security_claim": "none",
    "environment": {"python": sys.version.split()[0],
                    "sage": SAGE_VERSION, "platform": platform.platform()},
    "parameters": {"q": q, "n": chain["n"], "m_bar": chain["m_bar"],
        "w": chain["w"], "m": parent.dimension, "D": user.dimension,
        "Q0": q0, "Q1": q1, "s_squared": str(s2), "t_squared": str(t2),
        "signature_bound_squared": str(bound2)},
    "archived_vectors_recomputed": saved_checks,
    "fixed_stream_replay": {"counts": counts,
        "min_norm_squared": int(min(norms)), "max_norm_squared": int(max(norms)),
        "new_independent_random_batch": False,
        "full_generation_delegation_replayed": False},
    "local_sampling_budget": {
        "master_single_TV_upper_exact": str(e0),
        "user_single_TV_upper_exact": str(e1),
        "delegation_TV_upper_exact": str(min(QQ(1), chain["w"]*e0)),
        "sampling_subtotal_upper_exact": str(chain["w"]*e0+e1),
        "sampling_subtotal_display_float": float(chain["w"]*e0+e1),
        "contains_abort": True,
        "is_total_correctness_failure_bound": False},
    "conditional_unfilled": {"epsilon_A": None, "delta_init": None,
        "tau_m": None, "tau_sig": None, "total_correctness_failure_bound": None,
        "FooLi_protocol_codec_state_verified": False},
    "source_sha256": hashes,
    "status": "PASS_WITH_LIMITATIONS",
}
print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
