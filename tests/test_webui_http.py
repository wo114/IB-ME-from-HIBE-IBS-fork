"""HTTP responsiveness and routing tests, without crypto backends."""
import json
import threading
from contextlib import contextmanager
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from ibme.webui import server
from ibme.webui.jobs import DemoJobs


@contextmanager
def serve(monkeypatch, jobs):
    monkeypatch.setattr(server, "_JOBS", jobs)
    monkeypatch.setattr(server.Handler, "log_message", lambda *args: None)
    http = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{http.server_port}"
    finally:
        http.shutdown()
        http.server_close()
        thread.join(2)


def request(url, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = Request(url, data=data, headers={"Content-Type": "application/json"})
    return urlopen(req, timeout=2)


def test_assets_and_job_polling_stay_available_during_long_work(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    def long_operation(payload):
        with server._LOCK:
            jobs.report("签发密钥")
            entered.set()
            assert release.wait(3)
        return {"ok": True}
    jobs = DemoJobs({"bootstrap": long_operation})
    with serve(monkeypatch, jobs) as base:
        with request(base + "/api/jobs", {"operation": "bootstrap", "payload": {}}) as response:
            assert response.status == 202
        worker = threading.Thread(target=lambda: jobs.run_pending(timeout=0))
        worker.start()
        try:
            assert entered.wait(2)
            for path, mime in (("/", "text/html"), ("/app.js", "text/javascript"), ("/app.css", "text/css")):
                with request(base + path) as response:
                    assert response.status == 200
                    assert response.headers["Content-Type"].startswith(mime)
            with request(base + "/api/jobs") as response:
                assert json.load(response)["job"]["phase"] == "签发密钥"
            with pytest.raises(HTTPError) as error:
                request(base + "/api/state")
            with error.value as response:
                response.read()
                assert response.code == 409
            with pytest.raises(HTTPError) as error:
                request(base + "/api/jobs", {"operation": "bootstrap"})
            with error.value as response:
                response.read()
                assert response.code == 409
        finally:
            release.set()
            worker.join(2)


@pytest.mark.parametrize("invalid", [None, [], {}, 123])
def test_malformed_job_operation_is_a_client_error(monkeypatch, invalid):
    with serve(monkeypatch, DemoJobs({})) as base:
        with pytest.raises(HTTPError) as error:
            request(base + "/api/jobs", {"operation": invalid})
        with error.value as response:
            response.read()
            assert response.code == 400


def test_unknown_static_path_is_not_served(monkeypatch):
    with serve(monkeypatch, DemoJobs({})) as base:
        with pytest.raises(HTTPError) as error:
            request(base + "/../server.py")
        with error.value as response:
            response.read()
            assert response.code == 404


def test_reading_state_does_not_replace_the_last_operation(monkeypatch):
    monkeypatch.setattr(server, "_SESSION", None)
    jobs = DemoJobs({"check": lambda payload: {"ok": True}})
    original = jobs.submit("check", {})
    jobs.run_pending(timeout=0)
    def unexpected_queue(*args):
        raise AssertionError("a read-only state request must not create a job")
    monkeypatch.setattr(jobs, "call", unexpected_queue)
    with serve(monkeypatch, jobs) as base:
        with request(base + "/api/state") as response:
            assert json.load(response)["active"] is False
    assert jobs.snapshot()["id"] == original["id"]
