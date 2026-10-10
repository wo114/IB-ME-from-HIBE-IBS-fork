"""Local lock contention, fail-closed errors and release after process exit."""

import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from ibme.cli_state import LOCK_FILE, StateBusyError, key_issuance_lock


def test_nested_writers_fail_closed_and_leave_one_permanent_lock_file(tmp_path):
    with key_issuance_lock(tmp_path):
        with pytest.raises(StateBusyError):
            with key_issuance_lock(tmp_path, timeout=0):
                pytest.fail("second writer entered")
    assert (tmp_path/LOCK_FILE).read_bytes() == b"\0"
    with key_issuance_lock(tmp_path, timeout=0):
        pass


def test_exception_inside_transaction_releases_ownership(tmp_path):
    with pytest.raises(RuntimeError):
        with key_issuance_lock(tmp_path):
            raise RuntimeError("test transaction failure")
    with key_issuance_lock(tmp_path, timeout=0):
        pass


@pytest.mark.parametrize("timeout", [-1,31,True,float("nan"),float("inf"),"1"])
def test_bad_timeout_rejected_before_creating_lock(tmp_path, timeout):
    with pytest.raises(ValueError):
        with key_issuance_lock(tmp_path, timeout=timeout):
            pass
    assert not (tmp_path/LOCK_FILE).exists()


def test_missing_state_and_filesystem_error_do_not_fall_back(tmp_path):
    with pytest.raises(ValueError):
        with key_issuance_lock(tmp_path/"missing"):
            pass
    (tmp_path/LOCK_FILE).mkdir()
    with pytest.raises(OSError):
        with key_issuance_lock(tmp_path):
            pass


def test_killed_writer_releases_os_lock_without_deleting_lock_file(tmp_path):
    source=Path(__file__).resolve().parents[1]/"src"
    script="""import sys,time
from pathlib import Path
from ibme.cli_state import key_issuance_lock
root=Path(sys.argv[1])
with key_issuance_lock(root):
    (root/'ready').write_text('ready')
    time.sleep(30)
"""
    process=subprocess.Popen([sys.executable,"-B","-c",script,str(tmp_path)],
                             env={**os.environ,"PYTHONPATH":str(source)},stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        end=time.monotonic()+10
        while not (tmp_path/"ready").exists():
            if process.poll() is not None:
                _,error=process.communicate()
                pytest.fail("lock child failed: "+error)
            if time.monotonic()>=end: pytest.fail("lock child readiness timeout")
            time.sleep(0.01)
        with pytest.raises(StateBusyError):
            with key_issuance_lock(tmp_path,timeout=0):
                pytest.fail("active writer lock bypassed")
        process.kill()
        process.communicate(timeout=5)
        with key_issuance_lock(tmp_path,timeout=1):
            pass
        assert (tmp_path/LOCK_FILE).exists()
    finally:
        if process.poll() is None: process.kill()
        process.communicate(timeout=5)
