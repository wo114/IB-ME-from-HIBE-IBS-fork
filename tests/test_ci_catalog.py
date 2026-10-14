"""CI acceptance boundaries: absent code, skips and stale reports cannot pass."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from ci import run
from ibme.assembly.catalog import ROUTES, algorithm_catalog


def test_all_nineteen_routes_match_catalog_and_ci():
    config = run.load_config()
    result = algorithm_catalog()
    assert result["counts"] == {"hibe": 8, "ibs": 11}
    assert len(ROUTES) == len({r.id for r in ROUTES}) == 19
    assert {r.id for r in ROUTES} == {s["id"] for s in config["algorithms"]}
    assert all(r["execution"] == "not_executed" and r["security_claim"] == "none"
               for r in result["routes"])
    assert not any(r["id"] in ("mock", "sis") for r in result["routes"])
    catalog = (run.ROOT / "docs/ALGORITHM_CATALOG.md").read_text(encoding="utf-8")
    assert all(route.id in catalog for route in ROUTES)


def write_config(root, config):
    (root / "ci").mkdir(exist_ok=True)
    (root / "ci/suites.json").write_text(json.dumps(config), encoding="utf-8")


@pytest.mark.parametrize("mutation", [
    lambda c: c["algorithms"].pop(),
    lambda c: c["algorithms"].append(c["algorithms"][0]),
    lambda c: c["algorithms"][0].update(tests=["tests/../secret.py"]),
    lambda c: c["algorithms"][0].update(tests=["/tmp/test_stolen.py"]),
    lambda c: c["algorithms"][0].update(source_markers=["C:/private.py"]),
    lambda c: c["algorithms"][0].update(environment="shell"),
    lambda c: c["algorithms"][0].update(allow_skips="true"),
])
def test_bad_config_fails_closed(tmp_path, mutation):
    config = copy.deepcopy(run.load_config())
    mutation(config)
    write_config(tmp_path, config)
    with pytest.raises(ValueError):
        run.load_config(tmp_path)


def test_new_algorithm_tests_are_discovered_without_workflow_edit(tmp_path):
    spec = next(s for s in run.load_config()["algorithms"] if s["id"] == "yu2026")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/test_yu_fresh_delivery.py").write_text("", encoding="utf-8")
    (tmp_path / "tests/test_another_algorithm.py").write_text("", encoding="utf-8")
    assert run.selected_files(spec, tmp_path) == ["tests/test_yu_fresh_delivery.py"]


def test_missing_tests_with_delivered_source_is_an_error(tmp_path):
    config = copy.deepcopy(run.load_config())
    first = config["algorithms"][0]
    first["source_markers"] = ["delivered.py"]
    (tmp_path / "delivered.py").write_text("", encoding="utf-8")
    write_config(tmp_path, config)
    with pytest.raises(ValueError, match="source exists but no dedicated tests"):
        run.plan(tmp_path)


@pytest.mark.parametrize("code,passed,skipped,xfailed,allow,status", [
    (0, 1, 0, 0, False, "passed"),
    (0, 0, 2, 0, True, "failed"),
    (0, 0, 0, 2, True, "failed"),
    (0, 2, 1, 0, False, "failed_skips"),
    (0, 2, 1, 0, True, "partial"),
    (0, 2, 0, 1, False, "passed_with_known_xfails"),
    (1, 2, 0, 0, False, "failed"),
    (5, 0, 0, 0, True, "failed"),
])
def test_failure_skip_xfail_and_empty_are_distinct(code, passed, skipped, xfailed, allow, status):
    assert run.outcome(code, dict(passed=passed, skipped=skipped, xfailed=xfailed),
                       allow_skips=allow) == status


def test_junit_counts_actual_cases_not_claimed_totals(tmp_path):
    xml = tmp_path / "results.xml"
    xml.write_text("""<testsuites tests="999" failures="0"><testsuite>
      <testcase name="ok"/>
      <testcase name="fail"><failure/></testcase>
      <testcase name="error"><error/></testcase>
      <testcase name="skip"><skipped type="pytest.skip"/></testcase>
      <testcase name="known"><skipped type="pytest.xfail"/></testcase>
    </testsuite></testsuites>""", encoding="utf-8")
    assert run.junit_result(xml) == dict(tests=5, passed=1, failed=1, errors=1, skipped=1, xfailed=1)


def test_missing_receipts_and_pending_routes_are_visible():
    planned = run.plan()
    rows = {row["id"]: row for row in planned["rows"]}
    assert rows["cert-falcon"]["status"] == "awaiting_tests"
    assert rows["wang-pw"]["status"] == rows["srgg2025"]["status"] == "scheduled"
    text, failed = run.render_summary(planned, {})
    assert failed and "awaiting_tests" in text and "not_executed" in text
    receipts = {row["id"]: {"status": "passed"} for row in planned["rows"] if row["test_files"]}
    text, failed = run.render_summary(planned, receipts)
    assert not failed and "| cert-falcon | primitive | awaiting_tests |" in text
    receipts["wang-pw"]["status"] = "failed"
    assert run.render_summary(planned, receipts)[1]


def test_stale_receipts_cannot_survive_new_invocation(tmp_path):
    for suffix in ("json", "xml"):
        output = tmp_path / suffix
        output.mkdir()
        (output / ("framework." + suffix)).write_text("stale", encoding="utf-8")
        with pytest.raises(ValueError, match="fresh output"):
            run.run_suite("framework", output)


def test_cli_lists_routes_without_runtime_or_entropy():
    script = """
import os
def forbidden(*args, **kwargs):
    raise AssertionError("catalog consumed entropy")
os.urandom = forbidden
from ibme.cli import main
raise SystemExit(main(['list-algorithms', '--json']))
"""
    env = dict(os.environ, PYTHONPATH=str(run.ROOT / "src") + os.pathsep + str(run.ROOT))
    result = subprocess.run([sys.executable, "-B", "-c", script],
                            env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert len(data["routes"]) == 19 and data["execution"] == "not_executed"
