"""The public benchmark receipt must never repeat private failures."""
import json
import sys

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from experiments.research.candidates.srgg import paper_runtime_benchmark as subject


def test_cli_redacts_private_exception(tmp_path, monkeypatch, capsys):
    marker = "SECRET-WITNESS-COEFFICIENT-DO-NOT-EXPORT"

    def fail(*args, **kwargs):
        raise ValueError(marker)

    monkeypatch.setattr(subject, "benchmark", fail)
    output = tmp_path / "public-failure.json"
    monkeypatch.setattr(sys, "argv", ["srgg-paper-runtime", "--profile", "PARAM-I",
                                       "--output", str(output)])
    with pytest.raises(SystemExit) as caught:
        subject.main()
    assert caught.value.code == 1
    terminal = capsys.readouterr()
    raw = output.read_text(encoding="utf-8")
    assert marker not in raw + terminal.out + terminal.err
    assert "Traceback" not in terminal.err
    report = json.loads(raw)
    assert report["status"] == "execution-failed"
    assert report["error_type"] == "ValueError"
    assert report["private_material_exported"] is False


def test_cli_refuses_to_overwrite_receipt(tmp_path, monkeypatch):
    output = tmp_path / "frozen.json"
    output.write_text("frozen", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["srgg-paper-runtime", "--profile", "PARAM-I",
                                       "--output", str(output)])
    with pytest.raises(SystemExit) as caught:
        subject.main()
    assert caught.value.code == 2
    assert output.read_text(encoding="utf-8") == "frozen"
