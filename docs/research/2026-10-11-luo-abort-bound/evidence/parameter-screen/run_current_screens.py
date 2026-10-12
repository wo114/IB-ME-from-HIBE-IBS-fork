"""Read-only, current-profile runner. JSON goes to stdout; no grids or writes."""
import argparse
from dataclasses import asdict, replace
from datetime import datetime, timezone
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


def profiles(p):
    return [("current", p),
            ("proposal-k49-g145000-g2-34000000000-cap4096", replace(p, kappa=49, gamma1=145000,
                 gamma2=34000000000, max_extract_attempts=4096, max_sign_attempts=4096)),
            ("control-k64-g145000-g2-34000000000-cap4096", replace(p, gamma1=145000,
                 gamma2=34000000000, max_extract_attempts=4096, max_sign_attempts=4096))]


def conditional_route(p):
    """Numerical substitution of the user's UNPROVED route, not certification."""
    bc = 2*p.gamma2 - 4*p.beta2 - 1
    h = (p.q-1)//(2*p.gamma3)
    good = h*(2*p.gamma3-4*p.beta2-1)
    epsilon = 0.5
    log_f = p.degree*p.k*math.log(good/p.q)
    d0 = p.degree/bc**p.l
    dp = d0 + p.degree/bc**(p.l-1)
    delta_a = (dp + 2*d0*math.exp(2*log_f))/(epsilon**2*math.exp(2*log_f))
    log_p = p.degree*p.l*math.log(bc/(2*p.gamma2+1)) + math.log1p(-epsilon) + log_f
    px = ((2*p.gamma1-4*p.kappa*p.eta+1)/(2*p.gamma1+1))**(p.degree*(p.k+p.l))
    count = math.comb(p.degree,p.kappa)*2**p.kappa
    return dict(status="user_proposed_theorem_unproved_numerical_substitution_only",
        epsilon=epsilon, Bc=bc, h=h, good_residue_count=good, F=math.exp(log_f),
        delta_zero=d0, delta_pair=dp, delta_A_upper=delta_a,
        delta_A_upper_log2=math.log2(delta_a), sign_per_trial_lower=math.exp(log_p),
        sign_cap=p.max_sign_attempts, sign_abort_cond_goodA_log2=p.max_sign_attempts*math.log1p(-math.exp(log_p))/math.log(2),
        extract_per_trial_lower=px, extract_cap=p.max_extract_attempts,
        extract_abort_log2=p.max_extract_attempts*math.log1p(-px)/math.log(2),
        challenge_bits=math.log2(count), quantum_generic_search_exponent=math.log2(count)/2,
        numerical_precision="binary64; approximate, no outward-rounded certificate",
        exclusions=["proof validity", "uniform-draw abort", "hash/programming failures", "lifetime query budget", "overall security admission"])


def worker(repo, estimator_path, job):
    os.chdir(repo)
    sys.path[:0] = [str(repo), str(repo / "src")]
    from ibme.ibs.luo_module import LuoModuleParams
    from experiments.research.luo_module_security_screen import (
        arithmetic_audit, compression_bounds, finite_budget_checks,
        nonzero_conditions, processor_model, witness_rows,
    )
    from experiments.research.luo_parameter_screen import verify_estimator_checkout
    from experiments.research.luo_joint_parameter_screen import _cost_records
    root, revision = verify_estimator_checkout(estimator_path)
    sys.path.insert(0, str(root))
    import estimator
    from estimator import LWE, ND, SIS
    from estimator.reduction import ADPS16
    from sage.all import is_prime, log, oo
    from sage.env import SAGE_VERSION
    if not Path(estimator.__file__).resolve().is_relative_to(root):
        raise ValueError("unexpected estimator import")
    p = LuoModuleParams()
    started = time.perf_counter()
    result = dict(job=job, estimator_commit=revision, parameters=asdict(p),
                  security_claim="none", backend_admitted=False)
    if job == "arithmetic":
        old_path = repo / "docs/research/2026-10-09-admission/module-security.json"
        old = json.loads(old_path.read_text(encoding="utf-8"))
        prior = json.loads((repo / "docs/research/2026-10-09-m2b/joint-screen.json").read_text(encoding="utf-8"))
        mlwe = next(r for r in prior["module_rows"] if r["name"] == "table-200-flexible-gamma3-kappa64")
        sources = ["src/ibme/ibs/luo_module.py", "src/ibme/ibs/luo_module_math.py",
                   "experiments/research/luo_module_security_screen.py",
                   "experiments/research/luo_joint_parameter_screen.py",
                   "experiments/research/luo_parameter_screen.py",
                   "papers/2024_ibs_without_trapdoors_luo.pdf",
                   "docs/research/2026-10-09-admission/module-security.json",
                   "docs/research/2026-10-09-m2b/joint-screen.json"]
        alpha_paper = p.gamma2
        ratios = range((2**37 - 1 + alpha_paper - 1)//alpha_paper,
                       (2**38 - 2)//alpha_paper + 1)
        result.update(
            arithmetic=arithmetic_audit(), compression=compression_bounds(p),
            witnesses=witness_rows(p), nonzero=nonzero_conditions(p),
            budgets=finite_budget_checks(p),
            candidate_profiles=[dict(name=name,parameters=asdict(candidate),constructor_valid=True,
                route=conditional_route(candidate), witnesses=witness_rows(candidate)) for name,candidate in profiles(p)],
            challenge_count=str(math.comb(p.degree, p.kappa)*2**p.kappa),
            challenge_bits=math.log2(math.comb(p.degree, p.kappa)*2**p.kappa),
            challenge49_bits=math.log2(math.comb(p.degree, 49)*2**49),
            paper_38bit_fixed_gamma3=[dict(ratio=r, q=r*alpha_paper+1,
                                          prime=bool(is_prime(r*alpha_paper+1))) for r in ratios],
            old_parameters_exact_match=old["params"] == asdict(p),
            old_mlwe_math_exact_match=all(getattr(p,k)==v for k,v in mlwe["parameters"].items()),
            old_sis_costs={r["name"]:r["estimates"] for r in old["witnesses"]},
            old_mlwe_costs=mlwe["estimates"],
            source_sha256={s:hashlib.sha256((repo/s).read_bytes()).hexdigest() for s in sources},
            runtime=dict(python=sys.version, sage=SAGE_VERSION, platform=platform.platform(),
                         processor=processor_model(), estimator_import=str(Path(estimator.__file__).resolve())),
        )
    else:
        kind, mode = job.split("-", 1)
        records = []
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            if kind == "sis":
                selected = [("current",row) for row in witness_rows(p)]
                selected.extend((name,witness_rows(candidate)[-1]) for name,candidate in profiles(p)[1:])
                for profile,row in selected:
                    tick = time.perf_counter()
                    params = SIS.Parameters(n=row["coefficient_rows"], m=row["coefficient_columns"],
                        q=p.q, length_bound=row["uniform_screen_bound"], norm=oo, tag=row["name"])
                    costs = SIS.estimate(params, red_cost_model=ADPS16(mode=mode),
                        red_shape_model="lgsa", catch_exceptions=False, quiet=True)
                    if not costs:
                        raise RuntimeError("empty SIS estimates")
                    records.append(dict(profile=profile,name=row["name"],input=row,seconds=time.perf_counter()-tick,
                                        estimates=_cost_records(costs, log, oo)))
            else:
                params = LWE.Parameters(n=p.degree*p.l, m=p.degree*p.k, q=p.q,
                                       Xs=ND.Uniform(-p.eta,p.eta), Xe=ND.Uniform(-p.eta,p.eta))
                costs = LWE.estimate(params, red_cost_model=ADPS16(mode=mode),
                    red_shape_model="lgsa", deny_list=("arora-gb", "bkw"),
                    catch_exceptions=False, quiet=True)
                if not costs:
                    raise RuntimeError("empty LWE estimates")
                records = _cost_records(costs, log, oo, lwe=True)
            result.update(mode=mode, records=records, warnings=sorted(set(str(x.message) for x in caught)))
    result["compute_seconds"] = time.perf_counter()-started
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--estimator-path", required=True, type=Path)
    parser.add_argument("--job", choices=["arithmetic", "sis-classical", "sis-quantum", "lwe-classical", "lwe-quantum"])
    args = parser.parse_args()
    if args.job:
        print(json.dumps(worker(args.repo.resolve(), args.estimator_path.expanduser().resolve(), args.job)))
        return
    start = time.perf_counter()
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", GIT_OPTIONAL_LOCKS="0")
    # A Windows-managed worktree has a Windows absolute gitdir pointer. Use
    # Windows Git for its metadata, leaving both .git and the estimator alone.
    win_repo = subprocess.check_output(["wslpath","-w",str(args.repo)],text=True).strip()
    repo_git = ["/mnt/c/Program Files/Git/cmd/git.exe","-C",win_repo]
    before = subprocess.check_output(repo_git+["status","--short"],text=True,env=env)
    jobs = []
    for job, cap in [("arithmetic",60), ("sis-classical",90), ("sis-quantum",90),
                     ("lwe-classical",120), ("lwe-quantum",120)]:
        command = [sys.executable,"-B",str(Path(__file__).resolve()),"--repo",str(args.repo),
                   "--estimator-path",str(args.estimator_path),"--job",job]
        tick = time.perf_counter()
        try:
            run = subprocess.run(command, text=True, capture_output=True, timeout=cap, env=env)
            item = dict(job=job, timeout_seconds=cap, wall_seconds=time.perf_counter()-tick,
                        exit_code=run.returncode, status="completed" if run.returncode==0 else "failed",
                        stderr=run.stderr, command=command)
            if run.returncode==0:
                item["result"] = json.loads(run.stdout)
            else:
                item["stdout"] = run.stdout
        except subprocess.TimeoutExpired as exc:
            item = dict(job=job, timeout_seconds=cap, wall_seconds=time.perf_counter()-tick,
                        status="timeout_no_estimate", exit_code=None,
                        stdout=(exc.stdout or b"").decode() if isinstance(exc.stdout,bytes) else exc.stdout,
                        stderr=(exc.stderr or b"").decode() if isinstance(exc.stderr,bytes) else exc.stderr,
                        command=command)
        jobs.append(item)
    output = dict(schema="IBME/LUO2024/CURRENT-PROFILE-RERUN/1", timestamp_utc=datetime.now(timezone.utc).isoformat(),
        repo_head=subprocess.check_output(repo_git+["rev-parse","HEAD"],text=True,env=env).strip(),
        repository_status_before=before,
        repository_status_after=subprocess.check_output(repo_git+["status","--short"],text=True,env=env),
        jobs=jobs, wall_seconds=time.perf_counter()-start, grids_run=False,
        private_material_generated=False, security_claim="none", backend_admitted=False)
    print(json.dumps(output))


if __name__ == "__main__":
    main()
