# -*- coding: utf-8 -*-
"""Step-17 C (3/4): format/state and CLI cross-system rejection contracts.

Only the same-public-key test probes the signature loader. Every CLI state is
set up independently, even when its label has the same A/B suffix.
Teaching ABB10 Hybrid + Luo only: security_claim: none /
backend_admitted: false / parameters_are_formal: false.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

from ibme.core.errors import SerializationError
from ibme.core.randomness import DeterministicRandom
from ibme.protocol.baseline import BOTTOM
from ibme.protocol.luo_hybrid import make_research_runtime, RESEARCH_HIBE_PARAMS, RESEARCH_IBS_PARAMS, PROFILE_NAME

REPO_SRC = (Path(__file__).resolve().parents[2] / "src").resolve()


def rng(label):
    return DeterministicRandom(b"step17-c3:" + label)


def _cli_env():
    return {
        **os.environ,
        "PYTHONPATH": str(REPO_SRC),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1",
        "PYTHONIOENCODING": "utf-8",
    }


def _fresh_cli(arguments, cwd):
    return subprocess.run(
        [sys.executable, "-B", "-X", "utf8", "-m", "ibme.cli", *arguments],
        cwd=cwd, env=_cli_env(), capture_output=True, text=True,
        encoding="utf-8", errors="strict", timeout=180,
    )


@pytest.fixture(scope="module", autouse=True)
def assert_subprocess_imports_repo_src():
    """Portability gate: the subprocess must import ibme from the repo src dir,
    not from an accidental editable install on this machine."""
    probe = subprocess.run(
        [sys.executable, "-B", "-X", "utf8", "-c",
         "import ibme; print(ibme.__file__)"],
        cwd=REPO_SRC.parent, env=_cli_env(), capture_output=True, text=True,
        encoding="utf-8", errors="strict", timeout=60,
    )
    assert probe.returncode == 0, probe.stderr
    located = Path(probe.stdout.strip()).resolve()
    assert located.is_file() and located.is_relative_to(REPO_SRC), (
        f"ibme imported from {located}, not the repo src {REPO_SRC}")


def _setup_state(root, name, fmt):
    state = root / name
    cmd = ["setup", "--params", PROFILE_NAME, "--state", str(state)]
    if fmt == "compact":
        cmd += ["--signature-format", "compact"]
    result = _fresh_cli(cmd, root)
    assert result.returncode == 0, result.stderr
    for who in (["issue-sender-key", "Alice"], ["issue-receiver-key", "Bob"]):
        issued = _fresh_cli([*who, "--state", str(state)], root)
        assert issued.returncode == 0, issued.stderr
    return state


@pytest.fixture(scope="module")
def cli_states(tmp_path_factory):
    root = tmp_path_factory.mktemp("step17-c3")
    states = {}
    for fmt in ("reference", "compact"):
        for tag in ("A", "B"):
            states[f"{fmt}-{tag}"] = _setup_state(root, f"state-{fmt}-{tag}", fmt)
    return root, states


def test_default_signature_format_is_reference(cli_states):
    _, states = cli_states
    meta = json.loads((states["reference-A"] / "state.json").read_text(encoding="utf-8"))
    assert meta.get("signature_format") == "reference"


def test_old_state_without_selector_decrypts_reference_ciphertext(cli_states):
    root, states = cli_states
    state = states["reference-A"]
    metadata_path = state / "state.json"
    original_metadata = metadata_path.read_bytes()
    meta = json.loads(original_metadata.decode("utf-8"))
    meta.pop("signature_format", None)
    try:
        metadata_path.write_text(json.dumps(meta), encoding="utf-8")
        message, cipher, output = root / "m.bin", root / "c.bin", root / "o.bin"
        message.write_bytes(b"legacy-selector")
        args = ["--state", str(state), "--sender", "Alice", "--receiver", "Bob"]
        encrypted = _fresh_cli(["encrypt", *args, "--in", str(message), "--out", str(cipher)], root)
        assert encrypted.returncode == 0, encrypted.stderr
        decrypted = _fresh_cli(["decrypt", *args, "--in", str(cipher), "--out", str(output)], root)
        assert decrypted.returncode == 0, decrypted.stderr
        assert output.read_bytes() == b"legacy-selector"
    finally:
        metadata_path.write_bytes(original_metadata)


def test_cross_format_same_public_key_reference_payload_rejected_by_compact():
    """Use the same public/long-term keys in both runtimes. A signature-loader
    spy and direct SerializationError probe identify format rejection."""
    p_ref, _ = make_research_runtime(signature_format="reference", ibs_rng=rng(b"r-ibs"),
                                     ots_rng=rng(b"r-ots"))
    public, master = p_ref.setup(RESEARCH_HIBE_PARAMS, ibs_params=RESEARCH_IBS_PARAMS, rng=rng(b"r-setup"))
    sender = p_ref.skgen(master, b"Alice")
    receiver = p_ref.rkgen(master, b"Bob", rng=rng(b"r-receiver"))
    msg = b"same-key cross format"
    ct = p_ref.encrypt(public, sender, b"Bob", msg, rng=rng(b"r-enc"))
    assert p_ref.decrypt(public, receiver, b"Alice", ct, rng=rng(b"r-dec")) == msg  # honest control
    p_comp, _ = make_research_runtime(signature_format="compact", ibs_rng=rng(b"c-ibs"),
                                      ots_rng=rng(b"c-ots"))
    with patch.object(p_comp.ibs_backend, "load_signature", wraps=p_comp.ibs_backend.load_signature) as load:
        assert p_comp.decrypt(public, receiver, b"Alice", ct, rng=rng(b"c-dec")) is BOTTOM
    load.assert_called_once()
    assert load.call_args.args[0] is public.ipk
    with pytest.raises(SerializationError):
        p_comp.ibs_backend.load_signature(public.ipk, load.call_args.args[1])
    # reverse direction: compact ciphertext under the SAME public key, reference runtime
    p_comp_enc, _ = make_research_runtime(signature_format="compact", ibs_rng=rng(b"ce-ibs"),
                                          ots_rng=rng(b"ce-ots"))
    ct_c = p_comp_enc.encrypt(public, sender, b"Bob", msg, rng=rng(b"c-enc"))
    assert p_comp.decrypt(public, receiver, b"Alice", ct_c, rng=rng(b"c-dec2")) == msg  # compact honest control (same pk)
    with patch.object(p_ref.ibs_backend, "load_signature", wraps=p_ref.ibs_backend.load_signature) as load:
        assert p_ref.decrypt(public, receiver, b"Alice", ct_c, rng=rng(b"r-dec2")) is BOTTOM
    load.assert_called_once()
    assert load.call_args.args[0] is public.ipk
    with pytest.raises(SerializationError):
        p_ref.ibs_backend.load_signature(public.ipk, load.call_args.args[1])


@pytest.mark.parametrize("enc_key,dec_key", [("reference-A", "reference-B"), ("compact-A", "compact-B"),
                                             ("reference-A", "compact-A"), ("compact-A", "reference-A")])
def test_cli_dual_state_cross_public_key_decrypt(cli_states, enc_key, dec_key):
    """All four pairs use independently set-up systems, including the A/A
    pairs. Assert exit code 1 and no plaintext; no precise failure-layer claim."""
    root, states = cli_states
    state_a, state_b = states[enc_key], states[dec_key]
    message, cipher, output = root / f"m-{enc_key}.bin", root / f"c-{enc_key}.bin", root / f"o-{dec_key}.bin"
    message.write_bytes(b"dual-state")
    args_a = ["--state", str(state_a), "--sender", "Alice", "--receiver", "Bob"]
    assert _fresh_cli(["encrypt", *args_a, "--in", str(message), "--out", str(cipher)], root).returncode == 0
    args_b = ["--state", str(state_b), "--sender", "Alice", "--receiver", "Bob"]
    result = _fresh_cli(["decrypt", *args_b, "--in", str(cipher), "--out", str(output)], root)
    assert result.returncode == 1
    assert not output.exists()


def test_cli_cross_key_msk_bytes_unchanged(cli_states):
    """Cross-system rejection preserves msk.bin bytes only; this does not
    snapshot the receiver cache or the complete state directory."""
    root, states = cli_states
    state_b = states["reference-B"]
    before = (state_b / "msk.bin").read_bytes()
    message, cipher, output = root / "m-cache.bin", root / "c-cache.bin", root / "o-cache.bin"
    message.write_bytes(b"cache")
    args_a = ["--state", str(states["compact-A"]), "--sender", "Alice", "--receiver", "Bob"]
    assert _fresh_cli(["encrypt", *args_a, "--in", str(message), "--out", str(cipher)], root).returncode == 0
    args_b = ["--state", str(state_b), "--sender", "Alice", "--receiver", "Bob"]
    assert _fresh_cli(["decrypt", *args_b, "--in", str(cipher), "--out", str(output)], root).returncode == 1
    assert (state_b / "msk.bin").read_bytes() == before
