"""Bounded sampler-contract audit, not a distribution or security proof.

Run in the prescribed WSL ~/miniconda3/envs/sage environment. Reads the
repository; writes only a new --output JSON if requested (never overwrites).
All synthetic/mocked probes are diagnostics, never real keys or IBS signatures.
"""
import argparse
from datetime import datetime, timezone
import hashlib
from itertools import product
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from unittest.mock import patch


def require(condition, description):
    if not condition:
        raise AssertionError(description)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    repo = args.repo.resolve()
    if not (repo / "experiments/research/online_mp12_reference.py").is_file():
        parser.error("--repo must identify the IB-ME source repository")
    if args.output and args.output.exists():
        parser.error("Refusing to overwrite existing evidence; choose a new filename")
    sys.path[:0] = [str(repo), str(repo / "src")]
    from sage.all import QQ, ZZ, matrix, vector
    from sage.env import SAGE_VERSION
    from experiments.research import online_mp12_reference as online
    from experiments.research.gaussian_reference import SamplingAbort
    from experiments.research.online_sampling_audit import AuditRandom

    paths = [
        "AGENTS.md", "ARCHITECTURE.md", "IMPLEMENTATION_SPEC.md",
        "docs/PROJECT_RESTART.md", "src/ibme/ibs/sis_ibs.py",
        "src/ibme/core/randomness.py",
        "experiments/research/online_gaussian_reference.py",
        "experiments/research/online_mp12_reference.py",
        "experiments/research/online_sampling_audit.py",
        "experiments/research/mp12_sampled_reference.py",
        "experiments/research/mp12_trapdoor_chain.py",
        "experiments/research/gaussian_reference.py",
        "experiments/research/general_gadget_reference.py",
        "tests/test_online_sampling_reference.py",
        "docs/research/2026-10-05-round10/online-sampling-results.json",
        "docs/research/2026-10-05-round10/任意中心在线采样与MP12扩展核验.md",
        "docs/research/2026-10-05-round8/MP12完整SampleD有限误差与随机带核验.md",
        "docs/research/2026-10-06-correctness/FooLi-条件式正确性定理与参数账本.md",
        "docs/research/2026-10-06-correctness/verify_ledger.py",
        "docs/research/2026-10-06-correctness/lean-l3/FooLiL3/ClosedL3.lean",
        "docs/research/2026-10-06-correctness/lean-l3/FooLiL3/EventBounds.lean",
        "docs/research/2026-10-06-correctness/lean-l3/FooLiL3/IdealDelegation.lean",
        "papers/2023_tightly_secure_ibs_foo.pdf",
        "papers/2011_lattice_trapdoors_micciancio.pdf",
    ]

    def hashes():
        return {p: hashlib.sha256((repo / p).read_bytes()).hexdigest() for p in paths}

    before = hashes()
    probes = []
    _, parent = online.sampler_for_quality(3, [[1]], [[1, -1]], 2)
    require(parent is not None, "toy parent admission")
    pcert = parent.certificate()
    require(QQ(pcert["spherical_target_width_squared"]) == 189, "r^2 kappa mapping")
    probes.append({"name": "squared_width_mapping", "pass": True,
                   "q": 3, "Q": 2, "r_squared": 9, "gamma": 5,
                   "kappa": 21, "output_dimension": 3, "width_squared": 189})

    # These finite examples check consistency, not a proof over all trapdoors.
    profiles = set()
    members = 0
    for pair in product(range(-1, 2), repeat=2):
        _, candidate = online.sampler_for_quality(3, [[1]], [pair], 2)
        require(candidate is not None, "small public class admission")
        c = candidate.certificate()
        profiles.add((c["public_tape_bytes"], c["tv_upper_including_abort"],
                      c["spherical_target_width_squared"]))
        members += 1
    require(len(profiles) == 1, "public class should share conservative error/tape")
    probes.append({"name": "small_class_consistency", "pass": True,
                   "members": members, "universal_proof": False})

    for u in range(3):
        x = parent.sample((u,), rng=AuditRandom(f"alignment-equation-{u}".encode()))
        require(int((parent.public_matrix() * vector(ZZ, x))[0]) % 3 == u,
                "raw sample equation")
    probes.append({"name": "three_syndrome_equations", "pass": True})

    # Forced outputs isolate postprocessing semantics. They are NOT samples
    # from the certified law and cannot be used as evidence about its distance.
    with patch.object(parent.perturbation, "sample", return_value=(0, 0, 0)), \
         patch.object(parent.gadget, "sample", return_value=(0, 0)):
        require(parent.sample((0,), rng=object()) == (0, 0, 0), "raw zero retained")
    probes.append({"name": "raw_zero_not_filtered", "pass": True, "mocked": True})
    large = (3 * 1000, 0, 0)
    with patch.object(parent.perturbation, "sample", return_value=large), \
         patch.object(parent.gadget, "sample", return_value=(0, 0)):
        require(parent.sample((0,), rng=object()) == large, "raw large vector retained")
        require(sum(x*x for x in large) > 189 * 3, "forced vector exceeds norm bound")
    probes.append({"name": "raw_norm_not_filtered", "pass": True, "mocked": True})

    full = b"\xff" * parent.random_tape_bytes
    messages = []
    with patch.object(online, "SecureRandom", side_effect=AssertionError("entropy fallback")):
        for _ in range(2):
            try:
                parent.sample_from_tape((0,), full)
            except SamplingAbort as exc:
                messages.append(str(exc))
            else:
                raise AssertionError("forced tape must abort")
    require(len(messages) == 2 and messages[0] == messages[1], "abort replay")
    probes.append({"name": "full_sampled_abort_replay_no_fallback", "pass": True,
                   "exception": "SamplingAbort", "diagnostic_tape": "all-ff"})

    class RejectingBands:
        def __init__(self):
            self.read_sizes = []

        def read(self, n):
            self.read_sizes.append(n)
            return b"\xff" * n

    source = RejectingBands()
    try:
        online.delegate_stream(parent, [[0, 2]], rng=source)
    except SamplingAbort:
        pass
    else:
        raise AssertionError("delegation must propagate the first column abort")
    require(source.read_sizes == [parent.random_tape_bytes], "no retry or next column on abort")
    probes.append({"name": "delegation_abort_is_not_retried", "pass": True,
                   "bands_read": 1})

    for tape in (full[:-1], full + b"\x00"):
        try:
            parent.sample_from_tape((0,), tape)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid tape length must be a configuration error")
    probes.append({"name": "invalid_tape_length_is_value_error", "pass": True})
    profile, rejected = online.sampler_for_quality(3, [[1]], [[10, 10]], 2)
    require(rejected is None and profile["status"] == "quality_rejected", "quality rejection")
    probes.append({"name": "quality_rejection_is_distinct_from_sampling_abort", "pass": True})

    archive = json.loads((repo / paths[14]).read_text(encoding="utf-8"))["connected"]
    row = archive["all_attempts"][0]
    a = matrix(ZZ, row["A"])
    delegated = matrix(ZZ, row["delegated_R"])
    extension = matrix(ZZ, row["extension"])
    _, master = online.sampler_for_quality(archive["q"], a[:, :archive["m_bar"]],
        matrix(ZZ, row["R0"]), archive["master_quality_squared"])
    _, user = online.sampler_for_quality(archive["q"], a, delegated,
        archive["user_quality_squared"])
    require(master is not None and user is not None, "archived stages admitted")
    require((a * (-delegated) - extension + master.g).apply_map(
        lambda x: x % archive["q"]).is_zero(), "Foo-Li plus sign")
    require(user.public_matrix() == a.augment(extension), "user trapdoor negation mapping")
    probes.append({"name": "archive_sign_and_matrix_mapping", "pass": True})

    stages = {}
    for name, sampler in (("master", master), ("user", user)):
        c = sampler.certificate()
        eps = QQ(c["MP12_smoothing_epsilon_upper"])
        mu_p = QQ(c["perturbation"]["tv_upper_including_abort"])
        mu_g = QQ(c["gadget"]["tv_upper_including_abort"])
        exact_sum = min(QQ(1), 4 * eps / (1 - eps)**2 + mu_p + mu_g)
        reported = QQ(c["tv_upper_including_abort"])
        require(exact_sum <= reported <= 1, "outward-rounded local certificate arithmetic")
        require(c["spherical_target_width_squared"] == str(sampler.r_squared * sampler.sigma_squared),
                "archive width mapping")
        stages[name] = {key: c[key] for key in (
            "q", "n", "w", "output_dimension", "r_squared", "Sigma_scalar",
            "Sigma_G_scalar", "spherical_target_width_squared",
            "MP12_smoothing_epsilon_upper", "tv_upper_including_abort", "public_tape_bytes")}
        stages[name]["unrounded_formula_upper_exact"] = str(exact_sum)
    probes.append({"name": "two_stage_certificate_arithmetic", "pass": True,
                   "proves_distribution_contract": False})
    require(archive["user_quality_squared"] == master.w * master.dimension *
            master.r_squared * master.sigma_squared, "L3 threshold")
    require(user.dimension * user.r_squared * user.sigma_squared == 17708094495,
            "L4 threshold")
    probes.append({"name": "ledger_quality_and_signature_thresholds", "pass": True})

    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(repo / "src"))
    commands = [
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
         "tests/test_online_sampling_reference.py"],
        [sys.executable, "docs/research/2026-10-06-correctness/verify_ledger.py", "--repo", "."],
    ]
    logs = []
    for command in commands:
        proc = subprocess.run(command, cwd=repo, env=env, capture_output=True,
                              text=True, timeout=180)
        logs.append({"argv": command, "returncode": proc.returncode,
                     "stdout": proc.stdout, "stderr": proc.stderr})
        require(proc.returncode == 0, json.dumps(logs[-1], ensure_ascii=False))
    require("66 passed" in logs[0]["stdout"] and "skipped" not in logs[0]["stdout"],
            "expected all 66 Sage tests, without skips")
    ledger = json.loads(logs[1]["stdout"])
    require(ledger["status"] == "PASS_WITH_LIMITATIONS", "ledger diagnostics")
    after = hashes()
    require(before == after, "evidence inputs changed during audit")
    result = {
        "schema_version": 1, "utc": datetime.now(timezone.utc).isoformat(),
        "repository_head": subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"],
                                                   text=True).strip(),
        "status": "PASS_DIAGNOSTICS_WITH_OPEN_CONTRACTS",
        "security_claim": "none", "formal_parameters_selected": False,
        "actual_C2_C3_C4_C5_jointly_verified": False,
        "new_Lean_proofs": 0, "production_keys_or_IBS_signatures_generated": 0,
        "environment": {"sage": SAGE_VERSION, "python": sys.version.split()[0],
                        "platform": platform.platform(), "logical_cpus": os.cpu_count()},
        "probes": probes, "probe_count": len(probes), "stages": stages,
        "tests_and_ledger_replay": logs,
        "source_sha256": before, "inputs_unchanged": True,
        "audit_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "limits": [
            "finite examples and mocked branches are not uniform distribution proofs",
            "reference TV relies on independent uniform bytes and directed interval arithmetic",
            "MP12 smoothing epsilon is not the C2 master-matrix dualTheta bound",
            "full generation/delegation stress run was not repeated; archived debug trapdoors reused",
            "no production Foo-Li codec, persistent seed lifecycle, or formal parameter clearance",
            "no benchmark or independent expert review; fixed test streams are not security evidence",
        ],
    }
    content = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output:
        with args.output.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(content + "\n")
        print(json.dumps({"output": str(args.output), "status": result["status"],
                          "probes": len(probes), "pytest": logs[0]["stdout"].strip()}, ensure_ascii=False))
    else:
        print(content)


if __name__ == "__main__":
    main()
