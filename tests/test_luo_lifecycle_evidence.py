"""Fast synthetic controls for the independent lifecycle evidence auditor."""
import importlib.util
from pathlib import Path

import pytest


def auditor():
    path = Path(__file__).resolve().parents[1] / "experiments/research/audit_luo_lifecycle.py"
    spec = importlib.util.spec_from_file_location("audit_luo_lifecycle", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture(module):
    calls, events = [], []
    for s, i, m, r in sorted(module.EXPECTED):
        base = dict(system=s, identity_len=i, message_len=m, repetition=r)
        calls.append(dict(**base, status="ok", failure_type="", verify_reference="True",
                          verify_compact="True", math_fields_equal="yes", roundtrip_equal="yes",
                          reference_bytes=29455, compact_bytes=16063, sign_attempts=2, sign_seconds=.1))
        events.append(dict(**base, stage="sign", format="reference", status="ok", error_type="",
                           seconds=.1, sign_attempts=2))
        for stage in ("encode", "decode", "verify"):
            for fmt in ("reference", "compact"):
                events.append(dict(**base, stage=stage, format=fmt, status="ok", error_type="",
                                   seconds=.01, math_fields_equal="yes"))
    for s in range(3):
        events.append(dict(system=s, identity_len=0, message_len=0, repetition=-1,
                           stage="setup", format="", seconds=.01, status="ok", error_type=""))
        for count, i in enumerate((0, 1, 5, 64)):
            events.append(dict(system=s, identity_len=i, message_len=0, repetition=-1,
                               stage="master_state_recover", cache_entries=count,
                               format="", seconds=.01, status="ok", error_type=""))
        for i in module.LENGTHS:
            for stage in ("extract_cold", "extract_cached", "signing_key_recover"):
                events.append(dict(system=s, identity_len=i, message_len=0, repetition=-1,
                                   stage=stage, format="", seconds=.01, status="ok", error_type="",
                                   extract_attempts=0 if stage == "extract_cached" else 1))
    metadata = dict(completed=True, failure_type=None, interrupted=False, security_claim="none",
                    backend_admitted=False, parameters_are_formal=False)
    return calls, events, metadata


def test_exact_54_call_matrix():
    module = auditor()
    result = module.audit_rows(*fixture(module))
    assert result["normal_calls"] == 54 and result["sign_attempts"] == 108


@pytest.mark.parametrize("change", ["missing_call", "duplicate_call", "verify_false", "bad_format",
                                  "nan", "negative", "missing_event", "attempts", "interrupted",
                                  "cache_resampled", "failed_call", "missing_setup", "missing_master_restore"])
def test_reject_corrupted_lifecycle_evidence(change):
    module = auditor()
    calls, events, metadata = fixture(module)
    if change == "missing_call": calls.pop()
    elif change == "duplicate_call": calls.append(calls[0].copy())
    elif change == "verify_false": calls[0]["verify_compact"] = "False"
    elif change == "bad_format": events[1]["format"] = "unknown"
    elif change == "nan": events[0]["seconds"] = float("nan")
    elif change == "negative": events[0]["seconds"] = -1
    elif change == "missing_event": events.pop(1)
    elif change == "attempts": calls[0]["sign_attempts"] = 3
    elif change == "interrupted": metadata.update(completed=False, interrupted=True, failure_type="KeyboardInterrupt")
    elif change == "cache_resampled":
        next(r for r in events if r["stage"] == "extract_cached")["extract_attempts"] = 1
    elif change == "missing_setup": events[:] = [r for r in events if r["stage"] != "setup"]
    elif change == "missing_master_restore": events[:] = [r for r in events if r["stage"] != "master_state_recover"]
    else: calls[0].update(status="error", failure_type="LuoModuleSamplingAbort")
    with pytest.raises(ValueError):
        module.audit_rows(calls, events, metadata)


@pytest.mark.parametrize("change", ["none", "missing", "duplicate", "size", "label"])
def test_archived_final_sizes_and_negative_controls(change):
    module = auditor()
    path = Path(__file__).resolve().parents[1] / "docs/research/2026-10-11-luo-lifecycle/evidence/final/primitive-sizes-codex-final.csv"
    data = module.read_csv(path)
    if change == "none":
        module.audit_sizes(data)
        return
    if change == "missing": data.pop()
    elif change == "duplicate": data.append(data[0].copy())
    elif change == "size": data[0]["bytes"] = "1"
    else: data[0]["includes_public_key"] = "False"
    with pytest.raises(ValueError):
        module.audit_sizes(data)
