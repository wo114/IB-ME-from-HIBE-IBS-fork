"""Public CLI failure receipts must not serialize private backend exceptions."""
import json
import sys

import pytest
pytest.importorskip("sage.all", reason="specified WSL Sage required")

from experiments.research.candidates.srgg import paper_audit


@pytest.mark.parametrize("sampler", ["joint", "source-schur"])
def test_cli_failure_hides_private_exception_payload(tmp_path, monkeypatch, capsys, sampler):
    private = "PRIVATE-WITNESS-COEFFICIENT-1234567890123456789"
    def fail(*args, **kwargs):
        raise ValueError(private)
    monkeypatch.setattr(paper_audit, "audit", fail)
    output = tmp_path/"public-failure.json"
    monkeypatch.setattr(sys, "argv", ["srgg-paper-audit", "--sampler", sampler, "--output", str(output)])
    with pytest.raises(SystemExit) as caught:
        paper_audit.main()
    assert caught.value.code == 1
    data = output.read_text()
    terminal = capsys.readouterr()
    assert private not in data+terminal.out+terminal.err
    report = json.loads(data)
    assert report["status"] == "execution-failed"
    assert report["error_type"] == "ValueError"
    assert not report["private_material_exported"]
    assert "Traceback" not in terminal.err
