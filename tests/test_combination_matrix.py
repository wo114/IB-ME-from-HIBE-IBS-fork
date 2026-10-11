"""Exercise the common matrix driver, including independent mock selections.

Actual ABB10/Luo/SIS matrix receipts are generated separately with the same
driver. Mock results here are explicitly TEST-ONLY, never CHKP stand-ins.
"""

import json

import pytest

from experiments.run_combination_matrix import case_definitions, main, run_case, summarize


@pytest.fixture(scope="module", params=("mock-direct-mock-byteauth",
                                       "mock-hybrid-luo-matrix-byteauth"))
def receipt(request):
    return run_case(request.param, case_definitions()[request.param])


def test_shared_driver_exercises_independent_choices(receipt):
    assert receipt["status"] == "pass", receipt
    assert receipt["classification"] == "test_only"
    assert receipt["executed_checks"] >= 25
    names = {check["name"] for check in receipt["checks"] if check["status"] == "pass"}
    assert {"honest_roundtrip", "wrong_sender", "wrong_receiver", "both_wrong",
            "restored_decrypt", "inner_authentication_rejects", "forged_outer_ots_valid",
            "ibs_wrong_message", "ibs_wrong_identity", "empty_roundtrip"} <= names


@pytest.mark.parametrize("results", [[], [{"status": "blocked", "executed_checks": 0}],
                                    [{"status": "pass", "executed_checks": 0}],
                                    [{"status": "fail", "executed_checks": 5}]])
def test_empty_or_failed_execution_cannot_be_success(results):
    assert summarize(results)["status"] == "incomplete"


def test_execution_exceptions_are_reported_not_passed(monkeypatch):
    import experiments.run_combination_matrix as runner

    def broken_runtime(*args, **kwargs):
        raise RuntimeError("deliberate backend failure")

    monkeypatch.setattr(runner, "build_runtime", broken_runtime)
    result = run_case("failure-injection", dict(hibe="mock", ibs="mock", allow_mock=True))
    assert result["status"] == "fail"
    assert result["failed_stage"] == "build_runtime"
    assert result["executed_checks"] == 0
    assert summarize([result])["status"] == "incomplete"


def test_report_contains_no_serialized_secrets(receipt):
    report = summarize([receipt])
    assert report["status"] == "pass"
    assert report["security_claim"] == "none"
    assert report["backend_admitted"] is False
    assert set(receipt["sizes"]) == {"public_key", "sender_key", "receiver_key", "signature", "ciphertext"}
    assert all(type(size) is int and size > 0 for size in receipt["sizes"].values())
    assert "master_key" not in json.dumps(report)


def test_cli_preserves_existing_receipt(tmp_path):
    output = tmp_path / "receipt.json"
    output.write_text("existing evidence", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main(["--case", "mock-direct-mock-byteauth", "--output", str(output)])
    assert exc.value.code == 2
    assert output.read_text(encoding="utf-8") == "existing evidence"


def test_duplicate_case_is_not_counted_as_two_combinations():
    with pytest.raises(SystemExit) as exc:
        main(["--case", "mock-direct-mock-byteauth", "--case", "mock-direct-mock-byteauth"])
    assert exc.value.code == 2
