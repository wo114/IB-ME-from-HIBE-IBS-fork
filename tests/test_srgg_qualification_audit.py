"""A wider rounding profile must execute the real persistent lifecycle."""
import json
from dataclasses import replace
import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage is required")

from ibme.core.randomness import DeterministicRandom
from experiments.research.candidates.srgg.qualification_audit import profiles, run_profile


def test_density_width3_profile_real_lifecycle_and_public_negative_control():
    name = "density-width3-n8"
    report = run_profile(name, profiles()[name], roots=1,
                         rng_factory=lambda index: DeterministicRandom(b"qualification-audit"))
    root = report["roots"][0]
    assert root["setup_succeeded"] and root["public_negative_control"]["accepted"]
    assert len(root["identities"]) == 2
    for item in root["identities"]:
        assert item["issuance_succeeded"] and item["cached_same_key"]
        assert item["restored_public_matches"] and item["restore_succeeded"]
        assert item["truncated_wire_rejected"] and item["appended_wire_rejected"]
        assert [s["message_bytes"] for s in item["signatures"]] == [0, 32, 4096]
        assert all(s["verified"] for s in item["signatures"])
    encoded = json.dumps(report)
    for forbidden in ['"seed"', '"tail"', '"private_shape"', '"random_tape"']:
        assert forbidden not in encoded
    assert not report["root_reselection"] and not report["parameters_are_formal"]


def test_invalid_audit_root_count_is_rejected_before_setup():
    for count in (0, 9, True):
        with pytest.raises(ValueError):
            run_profile("bad", profiles()["baseline-n8"], roots=count)


def test_measurement_and_negative_control_failures_preserve_completed_roots(monkeypatch):
    from experiments.research.candidates.srgg import qualification_audit as audit
    def fail(*args):
        raise OSError("injected public measurement failure")
    monkeypatch.setattr(audit, "_public_state_size", fail)
    monkeypatch.setattr(audit, "public_forgery", fail)
    report = run_profile("fault-injection", replace(profiles()["baseline-n8"], degree=2), roots=2,
                         rng_factory=lambda index: DeterministicRandom(b"qualification-fault"+bytes([index])))
    assert len(report["roots"]) == 2
    assert all(root["setup_succeeded"] for root in report["roots"])
    assert all(root["state_measurement_failure_class"] == "OSError" for root in report["roots"])
    assert report["roots"][0]["public_negative_control"] == {"failure_class": "OSError"}
    assert all(item["restore_succeeded"] for root in report["roots"] for item in root["identities"])


def test_workspace_creation_failures_are_reported_without_reselection(monkeypatch):
    from experiments.research.candidates.srgg import qualification_audit as audit
    def fail(**kwargs):
        raise OSError("injected workspace failure")
    monkeypatch.setattr(audit.tempfile, "TemporaryDirectory", fail)
    report = run_profile("workspace-fault", profiles()["baseline-n8"], roots=2)
    assert len(report["roots"]) == 2
    assert all(root["workspace_creation_failure_class"] == "OSError" for root in report["roots"])
    assert not any(root["setup_succeeded"] for root in report["roots"])


def test_workspace_cleanup_failure_does_not_erase_real_lifecycle(monkeypatch):
    from experiments.research.candidates.srgg import qualification_audit as audit
    real = audit.tempfile.TemporaryDirectory
    class CleanupFault:
        def __init__(self, **kwargs):
            self.inner = real(**kwargs)
            self.name = self.inner.name
        def cleanup(self):
            self.inner.cleanup()
            raise OSError("injected failure after actual cleanup")
    monkeypatch.setattr(audit.tempfile, "TemporaryDirectory", CleanupFault)
    report = run_profile("cleanup-fault", replace(profiles()["baseline-n8"], degree=2), roots=1,
                         rng_factory=lambda index: DeterministicRandom(b"qualification-cleanup"))
    root = report["roots"][0]
    assert root["workspace_cleanup_failure_class"] == "OSError"
    assert root["setup_succeeded"] and all(item["restore_succeeded"] for item in root["identities"])
