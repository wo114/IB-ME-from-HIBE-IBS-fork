"""Read-only exact C64B audit: two SIS models, no MLWE or parameter grid.
Prints JSON only; save stdout with apply_patch outside the repository.
"""
import argparse
from dataclasses import asdict, replace
from datetime import datetime, timezone
from fractions import Fraction
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
import warnings

OVERRIDES = dict(kappa=64, gamma1=190000, gamma2=60000000000,
                 gamma3=27487784448, max_extract_attempts=4096,
                 max_sign_attempts=4096)
SOURCES = [
    "src/ibme/ibs/luo_module.py",
    "src/ibme/ibs/luo_module_math.py",
    "experiments/research/luo_module_security_screen.py",
    "experiments/research/luo_parameter_screen.py",
    "experiments/research/luo_joint_parameter_screen.py",
    "experiments/research/luo_robust_abort_certificate.py",
]


def source_hashes(repo):
    return {name: hashlib.sha256((repo/name).read_bytes()).hexdigest() for name in SOURCES}


def setup(repo):
    sys.path[:0] = [str(repo), str(repo/"src")]
    from ibme.ibs.luo_module import LuoModuleParams
    from experiments.research.luo_module_security_screen import witness_rows
    default = LuoModuleParams()
    candidate = replace(default, **OVERRIDES)
    return default, candidate, witness_rows(candidate)


def estimate(repo, estimator_path, mode):
    _, p, rows = setup(repo)
    from experiments.research.luo_parameter_screen import verify_estimator_checkout
    from experiments.research.luo_joint_parameter_screen import _cost_records
    from experiments.research.luo_module_security_screen import processor_model
    root, revision = verify_estimator_checkout(estimator_path)
    sys.path.insert(0, str(root))
    import estimator
    from estimator import SIS
    from estimator.reduction import ADPS16
    from sage.all import log, oo
    from sage.env import SAGE_VERSION
    if not Path(estimator.__file__).resolve().is_relative_to(root):
        raise RuntimeError("unexpected estimator import")
    row = rows[-1]
    params = SIS.Parameters(n=row["coefficient_rows"], m=row["coefficient_columns"],
        q=p.q, length_bound=row["uniform_screen_bound"], norm=oo, tag="C64B-common-box")
    start = time.perf_counter()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        costs = SIS.estimate(params, red_cost_model=ADPS16(mode=mode),
            red_shape_model="lgsa", catch_exceptions=False, quiet=True)
    if not costs:
        raise RuntimeError("empty SIS estimates")
    return dict(mode=mode, input=row, estimates=_cost_records(costs, log, oo),
        compute_seconds=time.perf_counter()-start,
        estimator_commit=revision, estimator_checkout_verified_clean=True,
        runtime=dict(python=sys.version, sage=SAGE_VERSION, platform=platform.platform(),
                     processor=processor_model(), estimator_import=str(Path(estimator.__file__).resolve())),
        warnings=sorted(set(str(w.message) for w in caught)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--estimator-path", required=True, type=Path)
    parser.add_argument("--mode", choices=("classical", "quantum"))
    args = parser.parse_args()
    repo, estimator_path = args.repo.resolve(), args.estimator_path.expanduser().resolve()
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.environ["GIT_OPTIONAL_LOCKS"] = "0"
    sys.dont_write_bytecode = True
    if args.mode:
        print(json.dumps(estimate(repo, estimator_path, args.mode)))
        return
    start = time.perf_counter()
    deadline = start + 175
    env = dict(os.environ)
    win_repo = subprocess.check_output(["wslpath", "-w", str(repo)], text=True).strip()
    git = ["/mnt/c/Program Files/Git/cmd/git.exe", "-C", win_repo]
    git_read = lambda *a: subprocess.check_output(git+list(a), text=True, env=env).strip()
    status_before = git_read("status", "--short")
    head_before = git_read("rev-parse", "HEAD")
    hashes_before = source_hashes(repo)
    default, p, rows = setup(repo)
    from experiments.research.luo_module_security_screen import compression_bounds, nonzero_conditions
    from experiments.research.luo_robust_abort_certificate import certificate
    for row in rows:
        row["q_half_slack"] = p.q-1-2*row["uniform_screen_bound"]
        row["estimated_in_this_run"] = row["name"] == "all-branches-relaxed"
    checks = {
        "constructor_accepts_exact_profile": True,
        "degree_power_of_two": p.degree > 0 and p.degree & (p.degree-1) == 0,
        "root_to_N_is_minus_one": pow(p.root, p.degree, p.q) == p.q-1,
        "root_to_2N_is_one": pow(p.root, 2*p.degree, p.q) == 1,
        "gamma1_gt_beta1": p.gamma1 > p.beta1,
        "gamma2_gt_beta2": p.gamma2 > p.beta2,
        "twice_gamma2_lt_q": 2*p.gamma2 < p.q,
        "beta2_lt_gamma3": p.beta2 < p.gamma3,
        "dropped_product_lt_gamma3": p.kappa*2**(p.dropped_bits-1) < p.gamma3,
        "twice_gamma3_divides_q_minus_one": (p.q-1) % (2*p.gamma3) == 0,
        "q_gt_four_gamma3": p.q > 4*p.gamma3,
        "all_witnesses_twice_B_lt_q_minus_one": all(r["below_q_half"] for r in rows),
        "fresh_nonzero_block_below_q": 2*p.kappa < p.q,
        "caps_at_most_4096": max(p.max_extract_attempts, p.max_sign_attempts) <= 4096,
    }
    assert all(checks.values()), checks
    cert = certificate(p, epsilon=Fraction(1,100), extracts=64,
                       signs=65536, oracle_queries=2**64, bits=1024)
    jobs = []
    for mode in ("classical", "quantum"):
        cap = min(85.0, deadline-time.perf_counter())
        command = [sys.executable, "-B", str(Path(__file__).resolve()),
                   "--repo", str(repo), "--estimator-path", str(estimator_path), "--mode", mode]
        tick = time.perf_counter()
        if cap <= 0:
            jobs.append(dict(mode=mode,status="not_run_total_deadline",command=command))
            continue
        try:
            run = subprocess.run(command, text=True, capture_output=True, timeout=cap, env=env)
            item = dict(mode=mode, timeout_seconds=cap, wall_seconds=time.perf_counter()-tick,
                        status="completed" if run.returncode == 0 else "failed",
                        exit_code=run.returncode, stderr=run.stderr, command=command)
            if run.returncode == 0:
                item["result"] = json.loads(run.stdout)
            else:
                item["stdout"] = run.stdout
        except subprocess.TimeoutExpired as exc:
            decode = lambda x: x.decode(errors="replace") if isinstance(x, bytes) else x
            item = dict(mode=mode, timeout_seconds=cap, wall_seconds=time.perf_counter()-tick,
                        status="timeout_no_estimate", exit_code=None,
                        stdout=decode(exc.stdout), stderr=decode(exc.stderr), command=command)
        jobs.append(item)
    challenge = math.comb(p.degree, p.kappa)*2**p.kappa
    output = dict(schema="IBME/LUO2024/C64B-SIDECAR/1", profile="C64B",
        timestamp_utc=datetime.now(timezone.utc).isoformat(), overrides=OVERRIDES,
        default_parameters=asdict(default), parameters=asdict(p), constructor_checks=checks,
        beta1=p.beta1, beta2=p.beta2, compression=compression_bounds(p), witnesses=rows,
        nonzero_conditions=nonzero_conditions(p), availability_certificate=cert,
        availability_proof_review="Not independently reproved here; external review progress is user-reported",
        entropy=dict(challenge_count=str(challenge), challenge_bits=math.log2(challenge),
                     generic_quantum_search_exponent=math.log2(challenge)/2,
                     C49_bits=math.log2(math.comb(p.degree,49)*2**49),
                     model="Uniform fixed-weight signed challenges; idealized search scale, not a reduction guarantee"),
        jobs=jobs, wall_seconds=time.perf_counter()-start, outer_timeout_seconds=180,
        mlwe_rerun=False, mlwe_input_unchanged=all(getattr(p,k)==getattr(default,k)
            for k in ("degree","k","l","q","eta")), grids_run=False,
        repo_head_before=head_before, repo_head_after=git_read("rev-parse","HEAD"),
        repository_status_before=status_before, repository_status_after=git_read("status","--short"),
        source_sha256_before=hashes_before, source_sha256_after=source_hashes(repo),
        private_material_generated=False, security_claim="none", backend_admitted=False,
        parameters_are_formal=False, approved_security_bits=None,
        limitations=["Coefficient-lattice heuristic screen, not full module-security reduction",
                     "Structured normalized matrices and block bounds relaxed to a uniform SIS box",
                     "ADPS16 quantum costs do not supply a QROM forking theorem",
                     "No CHKP or composition security admission",
                     "Availability certificate does not prove unforgeability"])
    print(json.dumps(output))


if __name__ == "__main__":
    main()

