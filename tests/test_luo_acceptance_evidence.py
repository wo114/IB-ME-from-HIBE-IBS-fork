"""Fast validation of experiment summaries, independent of expensive crypto."""
import importlib.util
import json
from dataclasses import asdict
from pathlib import Path

import pytest


def load_script(name):
    path = Path(__file__).resolve().parents[1] / "experiments/research" / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_historical_recount():
    result = load_script("audit_luo_acceptance_evidence").audit()
    assert result["B"]["natural_aborts"] == 0
    assert result["D"]["pairs_with_different_sign_attempts"] == 14


def rows(module):
    return [dict(rep=rep, stage=stage, format=fmt, seconds=str(rep + 1),
                 serialized_bytes="", status="ok", error_type="")
            for rep in range(5) for stage, fmt in module.STAGES]


def test_benchmark_summary_exact_units():
    module = load_script("luo_acceptance_benchmark")
    result = module.summarize(rows(module), 5)
    assert len(result) == 10
    assert all(r["n"] == 5 and r["median_seconds"] == 3 and r["q1_seconds"] == 2 and r["q3_seconds"] == 4 for r in result.values())


def test_benchmark_public_parameter_metadata_is_json_safe():
    module = load_script("luo_acceptance_benchmark")
    data = module.public_parameter_json(asdict(module.RESEARCH_HIBE_PARAMS))
    restored = json.loads(json.dumps(data))
    assert bytes.fromhex(restored["limits"]["backend_id"]["value"]) == module.RESEARCH_HIBE_PARAMS.limits.backend_id


def test_benchmark_failed_postcondition_marks_row():
    module = load_script("luo_acceptance_benchmark")
    data = rows(module)
    with pytest.raises(ValueError):
        module.validate_result(data[-1], False)
    assert data[-1]["status"] == "invalid"
    assert data[-1]["error_type"] == "EvidenceValidationError"
    with pytest.raises(ValueError):
        module.summarize(data, 5)


def test_benchmark_interrupt_metadata_is_incomplete(tmp_path, monkeypatch):
    module = load_script("luo_acceptance_benchmark")
    monkeypatch.setattr(module, "environment", lambda: {})

    def interrupt(**kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(module, "make_research_runtime", interrupt)
    output = tmp_path / "interrupted"
    with pytest.raises(KeyboardInterrupt):
        module.main(output, 1)
    metadata = json.loads((output / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["completed"] is False
    assert metadata["failure_type"] == "KeyboardInterrupt"
    assert not (output / "summary.json").exists()


@pytest.mark.parametrize("change", ["missing", "duplicate", "failure", "negative", "nan", "unexpected"])
def test_benchmark_summary_rejects_bad_evidence(change):
    module = load_script("luo_acceptance_benchmark")
    data = rows(module)
    if change == "missing":
        data.pop()
    elif change == "duplicate":
        data.append(data[0].copy())
    elif change == "failure":
        data[0]["status"] = "error"
    elif change == "unexpected":
        data[0]["stage"] = "unknown"
    else:
        data[0]["seconds"] = "-1" if change == "negative" else "nan"
    with pytest.raises(ValueError):
        module.summarize(data, 5)
