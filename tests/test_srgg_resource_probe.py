"""Actual public sampler fixture probes, including admission rejection paths."""

import json
import subprocess

import pytest

from experiments.research.candidates.srgg import resource_probe as probe


def _sage():
    pytest.importorskip("sage.all")


def test_probe_grid_covers_leaf_degrees_and_bounded_boundary_cases():
    cases = probe.default_grid()
    assert {case.leaf_degree for case in cases if case.dimension <= 128} == {2, 4, 8, 16, 32, 64, 128}
    assert all(case.dimension <= 129 for case in cases)
    assert len({case.name for case in cases}) == len(cases)
    assert any(case.dimension == 129 for case in cases)
    assert any(case.width_squared > 10**12 for case in cases)


@pytest.mark.parametrize("overrides", [
    {"dimension": 130}, {"leaf_degree": 3}, {"algorithm": "other"},
    {"width_squared": True}, {"rational_bits": 8193},
])
def test_probe_inputs_cannot_silently_raise_production_resource_limits(overrides):
    values = dict(name="bad", algorithm="f", fixture="diagonal", dimension=2, leaf_degree=2)
    values.update(overrides)
    with pytest.raises(ValueError):
        probe.Case(**values)


def test_real_diagonal_samplef_measures_preparation_draw_and_replays():
    _sage()
    case = probe.Case("test-diagonal-replay", "f", "diagonal", 4, 4)
    left, right = probe.run_case(case), probe.run_case(case)
    for result in (left, right):
        assert result["status"] == "success"
        assert result["prepare_seconds"] >= 0
        assert result["injected_entropy_bytes_before_draw"] == 0
        assert result["test_randomness"]["deterministic_test_only"] is True
        for draw in result["draws"]:
            assert draw["output_dimension"] == 4
            assert draw["elapsed_seconds"] >= 0
            assert 0 < draw["entropy_bytes"] <= result["public_certificate"]["public_entropy_upper_bytes"]
    assert [draw["output_sha256"] for draw in left["draws"]] == [
        draw["output_sha256"] for draw in right["draws"]]
    assert left["public_certificate"]["full_target_tv_upper_including_abort"] is None


def test_real_low_rank_samplep_exercises_schur_and_records_linux_rss():
    _sage()
    result = probe.run_case(probe.Case("test-lowrank-schur", "p", "rank-one", 8, 2), repetitions=1)
    assert result["status"] == "success"
    assert result["public_certificate"]["block_size"] == 2
    assert result["draws"][0]["output_dimension"] == 8
    assert result["injected_entropy_bytes_before_draw"] == 0
    if probe.platform.system() == "Linux":
        assert result["rss_final"]["ru_maxrss_kib"] > 0
        assert result["rss_final"]["ru_maxrss_kib"] >= result["rss_after_import"]["ru_maxrss_kib"]


@pytest.mark.parametrize("case,reason", [
    (probe.Case("reserve64", "f", "diagonal", 64, 64), "rational resource reserve"),
    (probe.Case("dense129", "f", "diagonal", 129, 129), "dimension limit"),
    (probe.Case("width", "f", "diagonal", 2, 2, width_squared=10**12+1), "width outside"),
    (probe.Case("small-reserve", "f", "rank-one", 8, 8, rational_bits=2048), "rational resource reserve"),
])
def test_real_admission_rejections_are_distinct_from_draw_aborts(case, reason):
    _sage()
    result = probe.run_case(case, repetitions=1)
    assert result["status"] == "preflight_rejected"
    assert reason in result["rejection_reason"]
    assert result["prepare_seconds"] >= 0
    assert result["injected_entropy_bytes_before_draw"] == 0
    assert result["draws"] == []
    assert result["public_certificate"] is None


def test_timeout_is_censored_and_retains_the_last_preparation_phase(monkeypatch):
    def timeout(*args, **kwargs):
        progress = json.dumps({"event": "phase", "phase": "prepare", "elapsed_seconds": 1})
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"], output=progress.encode())

    monkeypatch.setattr(probe.subprocess, "run", timeout)
    result = probe.run_isolated_case(probe.Case("test-timeout", "f", "diagonal", 2, 2), timeout_seconds=1)
    assert result["status"] == "timeout"
    assert result["last_phase"] == "prepare"
    assert result["timing_is_censored"] is True
    assert "public_certificate" not in result


def test_worker_failure_does_not_fabricate_fixture_results(monkeypatch):
    class Failed:
        returncode = 1
        stdout = "non-JSON startup output"
        stderr = "expected synthetic failure"

    monkeypatch.setattr(probe.subprocess, "run", lambda *args, **kwargs: Failed())
    result = probe.run_isolated_case(probe.Case("test-worker-error", "f", "diagonal", 2, 2))
    assert result["status"] == "worker_error"
    assert result["returncode"] == 1
    assert "draws" not in result
