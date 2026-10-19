"""C2 receipt scope and workspace checks; fake CLI is never crypto evidence."""
from copy import deepcopy
import json
import os
from pathlib import Path
import runpy
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT/"docs/research/team-c-delivery/2026-10-19-lai-publication"


@pytest.fixture
def receipt():
    return json.loads((PUBLIC/"evidence/target-c2-receipt.json").read_bytes())


def test_frozen_target_receipt_is_complete(receipt):
    verify = runpy.run_path(str(PUBLIC/"verify_delivery.py"))["verify_target_receipt"]
    verify(receipt)


@pytest.mark.parametrize("change", ["tiny", "empty-identities", "identity-missing", "plaintext-leak",
                                    "empty-tamper", "tamper-accepted", "tamper-process-failed", "honest-failed"])
def test_partial_or_wrong_target_receipt_cannot_pass(receipt, change):
    verify = runpy.run_path(str(PUBLIC/"verify_delivery.py"))["verify_target_receipt"]
    if change == "tiny": receipt["parameters"]["n"] = 256
    elif change == "empty-identities": receipt["wrong_identity"] = {}
    elif change == "identity-missing": receipt["wrong_identity"].pop("both_wrong")
    elif change == "plaintext-leak": receipt["wrong_identity"]["wrong_sender"]["output_bytes"] = 1
    elif change == "empty-tamper": receipt["outer_tamper"]["cases"] = {}
    elif change == "tamper-accepted": receipt["outer_tamper"]["cases"]["truncated_ct"]["rejected"] = False
    elif change == "tamper-process-failed": receipt["outer_tamper"]["rc"] = 2
    else: receipt["honest"]["rc"] = 2
    with pytest.raises(RuntimeError): verify(receipt)


def test_generator_requires_frozen_target_suite():
    from ibme.assembly import make_suite
    from experiments.research.candidates.lai.target_c2_receipt import validate_c2_meta
    from ibme.core.errors import InvalidParameterError
    suite = make_suite(hibe="lai-ideal-hibe", hibe_params="target-research", ibs="luo-module", transport="hybrid")
    meta = dict(suite=suite.to_dict(), suite_digest=suite.digest)
    assert validate_c2_meta(meta) == suite.to_dict()
    for changed in (dict(meta, suite_digest="0"*64),
                    dict(meta, suite=make_suite(hibe="lai-ideal-hibe", ibs="luo-module", transport="hybrid").to_dict())):
        with pytest.raises((ValueError, InvalidParameterError)): validate_c2_meta(changed)


@pytest.mark.parametrize("separate_ciphertext", [False, True])
def test_setup_recipe_supports_new_explicit_paths(tmp_path, separate_ciphertext):
    if os.name != "posix": pytest.skip("bash control-flow check runs in prescribed WSL")
    fake = tmp_path/"fake-python"
    fake.write_text("#!/usr/bin/env python3\nimport pathlib,sys\n"
                    "if 'encrypt' in sys.argv:\n"
                    "    pathlib.Path(sys.argv[sys.argv.index('--out')+1]).write_bytes(b'fixture only')\n"
                    "print('fake CLI workspace fixture only')\n", encoding="utf-8")
    fake.chmod(0o700)
    state = tmp_path/"new state"
    ciphertext = tmp_path/"external"/"ct.bin" if separate_ciphertext else state/"ct.bin"
    result = subprocess.run(["bash", str(ROOT/"experiments/research/candidates/lai/target_state_setup.sh"),
                             str(state), str(ciphertext)],
        env=dict(os.environ, PYTHON=str(fake)), capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert ciphertext.read_bytes() == b"fixture only"
    assert (state/"message.bin").read_bytes() == b"target-cli-msg"
    assert len((state/"timings.txt").read_text().splitlines()) == 5


def test_existing_input_paths_are_preserved(tmp_path):
    if os.name != "posix": pytest.skip("bash control-flow check runs in prescribed WSL")
    script = ROOT/"experiments/research/candidates/lai/target_state_setup.sh"
    state = tmp_path/"existing"; state.mkdir(); sentinel = state/"sentinel"; sentinel.write_bytes(b"preserve")
    result = subprocess.run(["bash", str(script), str(state)], capture_output=True, timeout=30)
    assert result.returncode == 2 and sentinel.read_bytes() == b"preserve"
    fresh = tmp_path/"fresh"; ciphertext = tmp_path/"existing.ct"; ciphertext.write_bytes(b"preserve ciphertext")
    result = subprocess.run(["bash", str(script), str(fresh), str(ciphertext)], capture_output=True, timeout=30)
    assert result.returncode == 2 and not fresh.exists() and ciphertext.read_bytes() == b"preserve ciphertext"
