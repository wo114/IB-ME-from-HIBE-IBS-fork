"""Probe rejection paths and public receipt policy; no fake crypto timings."""
import json

import pytest

from experiments.research.backend_optimization_probe import (
    validate_inputs, expected_suite, assert_installed_providers, public_failure, summarize_pairs, failed_batch,
)


@pytest.mark.parametrize("label", ("A", "B", "C", "Luo", "Falcon"))
def test_exact_suite_no_mock_and_security_upgrade(label):
    config = expected_suite(label)
    validate_inputs(label, config, roots=1 if label == "C" else 3, repetitions=3)
    assert config.to_dict()["security_claim"] == "none"
    assert config.to_dict()["backend_admitted"] is False
    assert config.to_dict()["allow_mock"] is False
    data = config.to_dict()
    data["hybrid_limits"]["max_payload_bytes"] += 1
    from ibme.assembly import SuiteConfig
    with pytest.raises(ValueError, match="frozen"):
        validate_inputs(label, SuiteConfig.from_dict(data), roots=3, repetitions=3)


@pytest.mark.parametrize("label,roots,repetitions", (("B",1,3), ("C",3,3), ("A",True,3), ("Luo",3,2)))
def test_invalid_experiment_shape_rejected(label, roots, repetitions):
    with pytest.raises(ValueError):
        validate_inputs(label, expected_suite(label), roots=roots, repetitions=repetitions)


def test_source_checkout_cannot_pass_as_installed_provider(tmp_path):
    root = tmp_path/"installed"
    root.mkdir()
    with pytest.raises(ValueError, match="installed"):
        assert_installed_providers({"ibme.protocol.prepared": {"path": str(tmp_path/"checkout"/"prepared.py")}}, root)


def test_public_failures_never_include_exception_text_or_private_bytes():
    report = public_failure("derive", RuntimeError("SECRET-PRIVATE-BYTES"))
    assert report == dict(status="failed", failure_stage="derive", exception_type="RuntimeError", no_outer_retry=True)
    assert "SECRET" not in json.dumps(report)
    nested = dict(label="A", records=["private"], secret="SECRET", **report)
    batch = failed_batch("A", [], nested)
    assert batch == dict(label="A", records=[], **report)


def test_recompute_paired_summary_does_not_pool_independent_roots():
    records = []
    for root in range(3):
        records.append(dict(root=root, phases=[dict(name="encrypt", mode=mode, seconds=seconds, status="passed")
            for mode, seconds in (("off", 4.), ("on", 2.), ("off", 6.), ("on", 3.))]))
    result = summarize_pairs(records)
    assert result["encrypt"]["root_speedups"] == [2., 2., 2.]
    assert result["encrypt"]["independent_roots"] == 3
    records[0]["phases"][0]["status"] = "failed"
    with pytest.raises(ValueError):
        summarize_pairs(records)


def test_address_control_has_valid_inner_and_outer_before_changing_hibe_address():
    from experiments.research.backend_optimization_probe import address_mismatch_ciphertext
    from ibme.core.randomness import DeterministicRandom
    from ibme.hibe.mock import MockHIBE
    from ibme.ibs.mock import MockIBSBackend
    from ibme.protocol.baseline import BASELINE_MOCK_PARAMS, BOTTOM
    from ibme.protocol.byteauth import ByteAuthenticatedIBME
    proto = ByteAuthenticatedIBME(MockHIBE(), MockIBSBackend())
    public, master = proto.setup(BASELINE_MOCK_PARAMS, rng=DeterministicRandom(b"TEST-ONLY-CONTROL"))
    sender = proto.skgen(master, b"Alice")
    receiver = proto.rkgen(master, b"Bob")
    good = address_mismatch_ciphertext(proto, public, sender, b"Bob", b"Bob", b"Alice")
    assert proto.decrypt(public, receiver, b"Alice", good.to_bytes()) == b"address-control"
    for rcv, snd in ((b"Wrong", b"Alice"), (b"Bob", b"Wrong"), (b"Wrong", b"Wrong")):
        bad = address_mismatch_ciphertext(proto, public, sender, b"Bob", rcv, snd)
        assert bad.ots_key.verify(bad.signed_body(), bad.signature)
        assert proto.decrypt(public, receiver, b"Alice", bad.to_bytes()) is BOTTOM
