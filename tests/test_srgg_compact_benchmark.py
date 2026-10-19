"""Real process observation and public-output/statistics boundaries."""
import json
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="measurement requires Linux /proc")
if sys.platform == "linux":
    from experiments.research.candidates.srgg.benchmark_process import public_worker_result, supervise
    from experiments.research.candidates.srgg.compact_benchmark import summarize


def test_unknown_worker_fields_do_not_publish_exception_or_private_data(tmp_path):
    path = tmp_path/"worker.json"
    path.write_text(json.dumps({"status": "failed", "phases": [], "private_material_exported": False,
                                "exception_detail": "PRIVATE_SENTINEL"}))
    result = public_worker_result(path)
    assert result["status"] == "worker-report-rejected"
    assert "PRIVATE_SENTINEL" not in json.dumps(result)


@pytest.mark.parametrize("raw", ['{"status":', '{"status":"failed","private_material_exported":false}'])
def test_interrupted_worker_report_is_failed_without_stopping_schedule(tmp_path, raw):
    path = tmp_path/"worker.json"
    path.write_text(raw)
    result = public_worker_result(path)
    assert result["status"] in ("worker-report-invalid", "worker-report-rejected")
    assert result["phases"] == []


def test_external_sampler_observes_owned_child_and_keeps_kernel_peak_separate(tmp_path):
    code = """
import json,resource,time
from pathlib import Path
start=time.monotonic_ns()
data=bytearray(8*1024*1024)
time.sleep(0.12)
end=time.monotonic_ns()
Path('worker.json').write_text(json.dumps({'status':'passed','private_material_exported':False,
'phases':[{'name':'allocation','start_ns':start,'end_ns':end,'seconds':(end-start)/1e9}],
'kernel_lifetime_peak_rss_bytes':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024}))
"""
    script = tmp_path/"worker.py"
    script.write_text(code.replace("Path('worker.json')", "Path("+repr(str(tmp_path/"worker.json"))+")"))
    result = supervise([sys.executable, str(script)], tmp_path, timeout_seconds=5)
    assert result["status"] == "passed" and result["process_exit_code"] == 0
    assert result["sampled_tree_peak_rss_bytes"] >= 8*1024*1024
    assert result["phases"][0]["rss_sample_count"] > 0
    assert result["kernel_lifetime_peak_rss_bytes"] > 0
    assert (tmp_path/"rss-samples.jsonl.gz").is_file()


def test_failed_runs_are_counted_and_within_root_repeats_are_not_independent_roots():
    rows = [{"profile_name": "PARAM-I", "mode": "generate", "status": "passed",
             "phases": [{"name": "sign-warm-0", "seconds": 1}, {"name": "sign-warm-1", "seconds": 9}],
             "process_wall_seconds": 12, "sampled_tree_peak_rss_bytes": 20,
             "object_sizes_bytes": {k: {"json": 100, "compact": 25} for k in ("public", "master", "key", "signature")}},
            {"profile_name": "PARAM-I", "mode": "generate", "status": "failed", "phases": []}]
    result = summarize(rows)["PARAM-I"]["modes"]["generate"]
    assert result["scheduled"] == 2 and result["passed"] == 1
    assert result["phase_seconds_per_run_medians"]["sign-warm"] == {
        "count": 1, "min": 5, "median": 5, "max": 5}
