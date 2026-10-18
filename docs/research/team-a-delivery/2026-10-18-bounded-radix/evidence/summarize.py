"""Summarize committed PUBLIC small-parameter receipts without opening keys."""

from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def main():
    check_path = ROOT/"docs/research/team-a-delivery/2026-10-18-3m-feasibility/evidence/check-sources.py"
    spec = importlib.util.spec_from_file_location("public_receipt_checker",check_path)
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    records = []
    providers = 0
    for name in ("n2-b1024-q93.json","n2-b4096-q93.json","n4-b4096-q93.json","n8-b4096-q93.json"):
        raw = (HERE/name).read_bytes()
        receipt = json.loads(raw)
        if receipt["status"] != "passed":
            raise ValueError("success summary accepts only completed predeclared runs; retain failures separately")
        p = receipt["parameters"]
        providers += checker.check_record(receipt)
        fresh = json.loads((HERE/(name[:-5]+"-restored.json")).read_bytes())
        assert fresh["status"] == "passed" and fresh["entropy_reads"] == 0 and fresh["state_unchanged"]
        assert fresh["fixed_preimages_checked"] == 256
        phase = {row["name"]:row for row in receipt["phases"]}
        records.append(dict(file=name,sha256=sha256(raw).hexdigest(),source_commit=receipt["source_commit"],
            n=p["parameters"]["n"],q=str(p["parameters"]["q"]),radix_bits=p["parameters"]["radix_bits"],
            w=p["w"],m=p["m"],root_r_squared=p["parameters"]["root_r_squared"],
            measured_seconds={k:phase[k]["seconds"] for k in ("root-generation","parent-delegation","leaf-256-sampling","strict-object-restore")},
            sampled_process_tree_peak_rss_bytes=max(x["sampled_process_tree_peak_rss_bytes"] for x in receipt["phases"]),
            persistent_object_bytes=receipt["sizes"],parent_R_packed_bytes=receipt["parent_R_packed_bytes"],
            entropy_bytes=receipt["entropy_bytes"],root_parent_leaf_generations=[1,1,256],
            fresh_process_restore_zero_entropy=True,full_IBME_execution=False))
    strict = json.loads((HERE/"strict-a.json").read_bytes())
    source = records[0]["source_commit"]
    for path,expected in strict["source_sha256"].items():
        assert path.startswith(("ci/","tests/","src/ibme/")) and ".." not in Path(path).parts
        raw = subprocess.check_output(["git","show",source+":"+path],cwd=ROOT)
        assert sha256(raw).hexdigest() == expected,path
    catalog = json.loads((HERE/"tests.json").read_bytes())
    assert catalog["code_source_commit"] == source
    for entry in catalog["runs"]:
        assert sha256((HERE/entry["file"]).read_bytes()).hexdigest() == entry["sha256"]
    summary = dict(status="passed",schema="BOUNDED-HIGH-RADIX-SMALL-RUNTIME/1",records=records,
        code_source_commit=source,provider_occurrences=providers,
        strict_CI_source_files_checked=len(strict["source_sha256"]),strict_A_counts=strict["counts"],
        runtime_limit_per_run_seconds=300,outer_retries=0,private_state_files_opened=0,
        target_n4096_executed=False,small_n_costs_are_not_target_runtime_extrapolations=True,
        actual_high_dimension_runtime_seconds=None,security_claim="none",backend_admitted=False,parameters_are_formal=False)
    (HERE/"summary.json").write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({k:v for k,v in summary.items() if k!="records"},indent=2))


if __name__ == "__main__": main()
