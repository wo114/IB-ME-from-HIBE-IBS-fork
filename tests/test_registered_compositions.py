"""Selected real teaching/research combinations; run this file under Sage.

No skip/xfail or mock substitutions: missing adapters/dependencies and failed
controls fail the selected case. The JSON manifest is explicit CI scope, not
automatic admission of every registered pairing or a security proof.
"""

from pathlib import Path

import pytest

from experiments.run_combination_matrix import load_suite_file, run_case, summarize


CASES, LABELS = load_suite_file(Path(__file__).resolve().parents[1] / "ci/combinations.json",
                               with_labels=True)


@pytest.mark.parametrize("name,selection", tuple(CASES.items()), ids=tuple(CASES))
def test_selected_real_combination(name, selection):
    assert selection["allow_mock"] is False
    assert LABELS[name] == {"hibe": "teaching", "ibs": "research"}
    receipt = run_case(name, selection)
    # Assertion output is a public receipt: no serialized keys/ciphertexts.
    assert receipt["status"] == "pass", receipt
    assert receipt["execution"] == "executed" and receipt["preflight_only"] is False
    assert receipt["classification"] == "research"
    assert receipt["preflight"]["metadata"]["test_only"] is False
    assert receipt["security_claim"] == "none"
    assert receipt["backend_admitted"] is receipt["parameters_are_formal"] is False
    names = {check["name"] for check in receipt["checks"] if check["status"] == "pass"}
    required = {
        "honest_roundtrip", "ciphertext_roundtrip", "wrong_sender", "wrong_receiver", "both_wrong",
        "public_restore", "master_restore", "sender_restore", "receiver_restore", "restored_decrypt",
        "byteauth_context", "byteauth_inner_bytes", "byteauth_signature", "byteauth_ots_key",
        "ibs_honest", "ibs_wrong_message", "ibs_wrong_identity", "reused_signature_rejects_altered_payload",
        "forged_outer_ots_valid", "inner_authentication_rejects", "inner_rejection_reached_ibs", "empty_roundtrip",
    }
    required.update(f"{bad}_{layer}" for bad in ("truncated", "appended", "duplicate", "wrong_version")
                    for layer in ("loader", "decrypt"))
    assert required <= names
    for attack in ("changed_signature", "random_signature"):
        assert names & {attack + "_wire_rejected", attack + "_verify_rejected"}
    if receipt["preflight"]["metadata"]["primitive_persistent_identity_cache"]["ibs"]:
        assert {"fixed_identity_repeated_extract", "fixed_identity_after_restore"} <= names
    assert receipt["executed_checks"] == len(receipt["checks"]) == len(names)
    assert all(size > 0 for size in receipt["sizes"].values())
    report = summarize([receipt])
    assert report["status"] == "pass" and report["executed_cases"] == 1
    assert report["evidence_counts"]["test_only"] == {"cases": 0, "checks": 0}
    assert report["evidence_counts"]["research"]["checks"] == receipt["executed_checks"]
    assert report["security_proof_count"] == 0
