"""UI scheduling tests. No cryptographic execution or algorithm claims."""
import importlib
import threading
import pytest


def make_jobs(operations):
    return importlib.import_module("ibme.webui.jobs").DemoJobs(operations)


def test_submission_waits_for_the_main_thread_pump_and_hides_input():
    calls = []
    jobs = make_jobs({"encrypt": lambda payload: calls.append(
        (threading.get_ident(), payload["message"])) or {"ok": True}})
    payload = {"message": "private input"}
    submitted = jobs.submit("encrypt", payload)
    payload["message"] = "changed by caller"
    assert calls == []
    assert submitted["status"] == "queued"
    assert "private input" not in str(jobs.snapshot())
    assert jobs.run_pending(timeout=0) is True
    assert calls == [(threading.get_ident(), "private input")]
    assert jobs.snapshot()["status"] == "completed"
    assert jobs.snapshot()["result"] == {"ok": True}


def test_polling_and_duplicate_submission_do_not_wait_for_a_long_operation():
    entered, release = threading.Event(), threading.Event()
    def operation(payload):
        jobs.report("签发发送者密钥")
        entered.set()
        assert release.wait(2)
        return {"ok": True}
    jobs = make_jobs({"bootstrap": operation})
    jobs.submit("bootstrap", {})
    worker = threading.Thread(target=lambda: jobs.run_pending(timeout=0))
    worker.start()
    try:
        assert entered.wait(2)
        state = jobs.snapshot()
        assert state["status"] == "running"
        assert state["phase"] == "签发发送者密钥"
        with pytest.raises(RuntimeError, match="正在"):
            jobs.submit("bootstrap", {})
    finally:
        release.set()
        worker.join(2)
    assert jobs.snapshot()["status"] == "completed"


def test_failed_backend_is_a_failed_job_and_keeps_no_previous_result():
    def failed(payload):
        raise ValueError("backend did not finish")
    jobs = make_jobs({"decrypt": failed})
    jobs.submit("decrypt", {})
    jobs.run_pending(timeout=0)
    state = jobs.snapshot()
    assert state["status"] == "failed"
    assert state["error"] == "backend did not finish"
    assert state["result"] is None
    assert "bottom" not in state


def test_result_snapshot_is_a_copy_and_only_the_latest_job_is_retained():
    jobs = make_jobs({"reset": lambda payload: {"state": {"active": False}}})
    first = jobs.submit("reset", {})
    jobs.run_pending(timeout=0)
    snapshot = jobs.snapshot()
    snapshot["result"]["state"]["active"] = True
    assert jobs.snapshot()["result"]["state"]["active"] is False
    second = jobs.submit("reset", {})
    assert second["id"] != first["id"]
    assert jobs.snapshot()["result"] is None


def test_unknown_operation_is_rejected_without_creating_a_job():
    jobs = make_jobs({})
    with pytest.raises(ValueError):
        jobs.submit("arbitrary-import", {})
    assert jobs.snapshot() is None


def test_synchronous_compatibility_call_is_executed_by_the_pump():
    owner_thread = threading.get_ident()
    jobs = make_jobs({"state": lambda payload: {"thread": threading.get_ident()}})
    results = []
    caller = threading.Thread(target=lambda: results.append(jobs.call("state", {})))
    caller.start()
    assert jobs.run_pending(timeout=2)
    caller.join(2)
    assert results[0]["result"]["thread"] == owner_thread
