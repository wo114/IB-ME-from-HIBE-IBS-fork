"""One in-memory operation, executed by the caller's main-thread pump.

HTTP threads submit and poll only. No cryptographic object or request payload
is included in a polling snapshot. A finished result is replaced by the next
job, so this is not an unbounded history of plaintext or session snapshots.
"""
from __future__ import annotations

import copy
import queue
import threading
import time
import uuid


class JobBusyError(RuntimeError):
    pass


class DemoJobs:
    def __init__(self, operations):
        self._operations = dict(operations)
        self._lock = threading.Lock()
        self._queue = queue.Queue(maxsize=1)
        self._job = None

    def _snapshot(self, job):
        if job is None:
            return None
        started = job["started"]
        end = job["finished"] or time.perf_counter()
        return copy.deepcopy({
            "id": job["id"], "operation": job["operation"],
            "status": job["status"], "phase": job["phase"],
            "elapsed": 0 if started is None else end - started,
            "result": job["result"], "error": job["error"],
        })

    def submit(self, operation, payload):
        if type(operation) is not str or operation not in self._operations or type(payload) is not dict:
            raise ValueError("未知操作或请求格式错误")
        with self._lock:
            if self._job and self._job["status"] in ("queued", "running"):
                raise JobBusyError("当前操作正在执行，请等待完成")
            job = {
                "id": uuid.uuid4().hex, "operation": operation,
                "status": "queued", "phase": "等待执行", "started": None,
                "finished": None, "result": None, "error": None,
                "done": threading.Event(),
            }
            self._job = job
            self._queue.put_nowait((job, copy.deepcopy(payload)))
            return self._snapshot(job)

    def snapshot(self):
        with self._lock:
            return self._snapshot(self._job)

    def report(self, phase):
        with self._lock:
            if self._job and self._job["status"] == "running":
                self._job["phase"] = str(phase)

    def call(self, operation, payload):
        """Compatibility path for synchronous HTTP endpoints."""
        submitted = self.submit(operation, payload)
        with self._lock:
            job = self._job
            if job["id"] != submitted["id"]:
                raise JobBusyError("会话状态已变化，请重新连接")
        job["done"].wait()
        with self._lock:
            return self._snapshot(job)

    def run_pending(self, timeout=0.2):
        """Call only from the main interpreter thread in the real server."""
        try:
            job, payload = self._queue.get(timeout=timeout)
        except queue.Empty:
            return False
        with self._lock:
            job.update(status="running", phase="正在执行", started=time.perf_counter())
        try:
            result = self._operations[job["operation"]](payload)
        except Exception as exc:
            with self._lock:
                job.update(status="failed", phase="执行失败", error=str(exc))
        else:
            with self._lock:
                job.update(status="completed", phase="已完成", result=result)
        finally:
            with self._lock:
                job["finished"] = time.perf_counter()
                job["done"].set()
            self._queue.task_done()
        return True
