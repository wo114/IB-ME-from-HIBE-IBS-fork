"""Explicit provider extensions for new HIBE/IBS adapters.

These are registry/assembly contract tests, not cryptographic security tests.
"""

from dataclasses import replace

import pytest

from ibme import cli
from ibme.assembly import default_registry, make_suite, validate_suite
from ibme.core.errors import InvalidParameterError


def _external_specs():
    prototypes = default_registry()
    return (
        replace(prototypes.get("hibe", "mock"), id="external-hibe"),
        replace(prototypes.get("ibs", "mock"), id="external-ibs"),
    )


def test_explicit_provider_adds_a_pair_without_editing_default_registry():
    calls = []

    def provider():
        calls.append("called")
        return _external_specs()

    registry = default_registry(extra_providers=(provider,))
    assert calls == ["called"]
    config = make_suite(
        hibe="external-hibe", ibs="external-ibs", allow_mock=True,
        registry=registry,
    )
    report = validate_suite(config, registry=registry)
    assert report.ok, report.errors
    assert report.metadata["test_only"] is True

    clean = default_registry()
    for role, identifier in (("hibe", "external-hibe"), ("ibs", "external-ibs")):
        with pytest.raises(InvalidParameterError, match="no fallback"):
            clean.get(role, identifier)


def test_provider_batch_is_atomic_when_one_descriptor_is_invalid():
    registry = default_registry()
    candidate = replace(registry.get("hibe", "mock"), id="must-not-leak")
    duplicate = replace(registry.get("ibs", "mock"), id="sis")

    with pytest.raises(InvalidParameterError, match="duplicate"):
        registry.register_provider(lambda: (candidate, duplicate))
    with pytest.raises(InvalidParameterError, match="no fallback"):
        registry.get("hibe", "must-not-leak")


@pytest.mark.parametrize("provider", [None, "module.path", lambda: None, lambda: ()])
def test_provider_requires_explicit_callable_descriptors(provider):
    registry = default_registry()
    with pytest.raises(InvalidParameterError, match="provider"):
        registry.register_provider(provider)


def test_extra_specs_use_the_same_validation_and_do_not_replace_builtins():
    hibe, _ = _external_specs()
    registry = default_registry(extra_specs=(hibe,))
    assert registry.get("hibe", "external-hibe") == hibe
    with pytest.raises(InvalidParameterError, match="duplicate"):
        default_registry(extra_specs=(replace(hibe, id="latte"),))


def test_cli_parser_defers_signature_format_vocabulary_to_selected_ibs():
    args = cli.build_parser().parse_args([
        "check", "--hibe", "latte", "--ibs", "srgg2025",
        "--signature-format", "canonical-json-v1",
    ])
    assert args.signature_format == "canonical-json-v1"

    unsupported = make_suite(
        hibe="mock", ibs="mock", allow_mock=True,
        signature_format="future-wire-v2",
    )
    report = validate_suite(unsupported)
    assert not report.ok
    assert "signature format" in " ".join(report.errors)
