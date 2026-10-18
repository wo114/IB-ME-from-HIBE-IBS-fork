"""Fast tests for the interactive demo helpers.

These tests deliberately avoid Setup and native engines. They cover the demo's
input/route policy and the no-session state; the real protocol lifecycle is
exercised in the WSL Sage environment by the demo itself.
"""
import pytest

from ibme.webui import server


def test_selection_defaults_and_demo_scope():
    assert server._selection({}) == (
        "latte", "cert-ml-dsa", "hybrid", "byteauth-v1", "reference"
    )
    assert server._selection({
        "hibe": "latte", "ibs": "luo-module",
        "transport": "hybrid", "protocol": "byteauth-v1",
        "signature_format": "compact",
    }) == ("latte", "luo-module", "hybrid", "byteauth-v1", "compact")
    with pytest.raises(server.DemoError, match="LATTE-3"):
        server._selection({"hibe": "chkp", "ibs": "cert-ml-dsa"})
    with pytest.raises(server.DemoError, match="ML-DSA"):
        server._selection({"hibe": "latte", "ibs": "srgg2025"})
    with pytest.raises(server.DemoError):
        server._selection({"transport": "unknown"})


def test_identity_validation_uses_utf8_length_and_rejects_controls():
    assert server._identity_bytes("Alice", "发送者", 64) == b"Alice"
    assert len(server._identity_bytes("密码", "身份", 6)) == 6
    with pytest.raises(server.DemoError):
        server._identity_bytes("", "身份", 64)
    with pytest.raises(server.DemoError):
        server._identity_bytes("A" * 65, "身份", 64)
    with pytest.raises(server.DemoError):
        server._identity_bytes("密码", "身份", 5)
    with pytest.raises(server.DemoError):
        server._identity_bytes("A\nB", "身份", 64)


def test_message_validation_uses_utf8_length():
    assert server._message_bytes("hi", 10) == b"hi"
    with pytest.raises(server.DemoError):
        server._message_bytes("", 10)
    with pytest.raises(server.DemoError):
        server._message_bytes("A" * 11, 10)
    with pytest.raises(server.DemoError):
        server._message_bytes("密码", 5)


def test_no_session_state_is_inactive_and_keeps_security_flags():
    server.api_reset()
    state = server.api_state()
    assert state["active"] is False
    assert state["security"]["claim"] == "none"
    assert state["security"]["backend_admitted"] is False
    assert state["security"]["parameters_are_formal"] is False
