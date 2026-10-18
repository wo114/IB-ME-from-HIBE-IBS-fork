"""Caller-owned registration and lifecycle for paper source-Schur SRGG.

The six presets are the original Table 4 rows under the two explicit Gaussian
readings.  The tests do not compare security or claim admission.
"""
from dataclasses import asdict, replace
from fractions import Fraction

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.core.randomness import DeterministicRandom
from ibme.assembly.registry import BackendRegistry
from ibme.ibs.srgg_paper import guarded as guarded_module
from ibme.ibs.srgg_paper.guarded import GuardedSourceSchurBackend
from ibme.ibs.srgg_paper.registration import (
    BACKEND_ID, backend_spec, check_object, signature_size,
)
from ibme.ibs.srgg_paper.service import (
    GuardedSourceSchurFixedIssuer, SourceSchurFixedIssuer,
)
from experiments.research.candidates.srgg.paper_distribution_chain import (
    ChainCertificateError,
)
from experiments.research.candidates.srgg.paper_parameters import PaperParams
from experiments.research.candidates.srgg.paper_schur_backend import SourceSchurBackend
from experiments.research.gaussian_reference import SamplingAbort


class NoRead:
    def read(self, _count):
        raise AssertionError("cached/public operation consumed entropy")


def test_descriptor_exposes_six_unchanged_table4_presets():
    spec = backend_spec()
    registry = BackendRegistry([spec])
    assert registry.get("ibs", BACKEND_ID) is spec
    assert spec.params_type is PaperParams
    assert set(spec.presets) == {
        f"{profile}-{interpretation}"
        for profile in ("PARAM-I", "PARAM-II", "PARAM-III")
        for interpretation in ("table-standard-deviation", "literal-density-width")
    }
    assert spec.default_preset("direct") in spec.presets
    for params in spec.presets.values():
        assert spec.parse_params(asdict(params)) == params
        spec.validate_configuration(params, {})
        assert spec.signature_size(params, "canonical-json-v1") > 0
        assert spec.signature_size(params, "reference") > 0
    with pytest.raises(InvalidParameterError):
        spec.parse_params({"degree": 512})
    with pytest.raises(InvalidParameterError):
        spec.parse_params(dict(asdict(spec.presets["PARAM-I-table-standard-deviation"]),
                              profile_name=True))
    with pytest.raises(InvalidParameterError):
        spec.validate_configuration(None, {})


def test_table4_values_are_not_modified():
    expected = {
        "PARAM-I": (2, Fraction("42086491.7")),
        "PARAM-II": (3, Fraction("63653172.0")),
        "PARAM-III": (4, Fraction("86573930.5")),
    }
    for name, (rank, gamma) in expected.items():
        params = PaperParams(name)
        assert params.degree == 512
        assert params.p == 16383
        assert params.base == 31
        assert params.digits == 2
        assert params.modulus == 15744063
        assert params.rank == rank
        assert Fraction(params.source.gamma) == gamma
        assert params.signature_norm_cap <= gamma**2 < params.signature_norm_cap + 1


def test_source_schur_registration_runs_a_real_table4_lifecycle():
    spec = backend_spec()
    params = PaperParams("PARAM-I", "literal-density-width")
    backend = spec.factory(
        DeterministicRandom(b"paper-source-schur-registration-lifecycle"),
        "canonical-json-v1")
    assert type(backend) is SourceSchurBackend
    public, master = backend.setup(params)
    key = backend.key_extract(master, b"Alice")
    message = b"paper source-Schur registration contract"
    signature = backend.sign(key, message)
    assert backend.verify(public, b"Alice", message, signature) is True
    assert backend.verify(public, b"Bob", message, signature) is False
    assert backend.verify(public, b"Alice", message + b"!", signature) is False
    tampered = replace(signature, response=(
        (signature.response[0][0] + 1,) + signature.response[0][1:],
    ) + signature.response[1:])
    assert backend.verify(public, b"Alice", message, tampered) is False
    assert public.to_bytes() and master.to_bytes() and key.to_bytes()
    assert type(public).from_bytes(public.to_bytes()) == public
    assert type(key).from_bytes(key.to_bytes()) == key
    assert backend.load_signature(public, signature.to_bytes()) == signature
    for value in (public, master, key):
        check_object(value, params)
    with pytest.raises(SerializationError):
        check_object(public, PaperParams("PARAM-II", "literal-density-width"))
    assert spec.master_public_key(master) == public
    assert signature_size(params, "canonical-json-v1") >= len(signature.to_bytes())


def test_source_schur_fixed_issuer_defaults_to_source_backend(tmp_path):
    issuer = SourceSchurFixedIssuer(tmp_path / "default")
    assert type(issuer.backend) is SourceSchurBackend
    assert not issuer.path.exists()


def test_source_schur_fixed_issuer_persists_and_reopens_without_entropy(tmp_path):
    params = PaperParams("PARAM-I", "literal-density-width")
    issuer = SourceSchurFixedIssuer(
        tmp_path / "issuer",
        SourceSchurBackend(rng=DeterministicRandom(b"paper-source-schur-service")))
    public = issuer.initialize(params, max_users=2)
    key = issuer.key_extract(b"Alice")
    assert key.public_key == public
    reopened = SourceSchurFixedIssuer(
        issuer.path, SourceSchurBackend(rng=NoRead()),
        expected_public=public, expected_params=params)
    assert reopened.key_extract(b"Alice").to_bytes() == key.to_bytes()

def test_guarded_backend_runs_a_real_table4_lifecycle():
    params = PaperParams("PARAM-I", "literal-density-width")
    backend = GuardedSourceSchurBackend(
        rng=DeterministicRandom(b"paper-baseline-PARAM-I-literal-density-width"))
    public, master = backend.setup(params)
    key = backend.key_extract(master, b"Alice")
    message = b"guarded paper source-Schur lifecycle"
    signature = backend.sign(key, message)
    assert backend.verify(public, b"Alice", message, signature) is True
    assert backend.verify(public, b"Bob", message, signature) is False


def test_guarded_root_gate_failure_is_retryable(monkeypatch):
    def fail(*_args, **_kwargs):
        raise ChainCertificateError("injected root gate failure")
    monkeypatch.setattr(guarded_module, "require_gates", fail)
    backend = GuardedSourceSchurBackend(
        rng=DeterministicRandom(b"paper-source-schur-guarded-retry"),
        setup_max_attempts=1)
    with pytest.raises(SamplingAbort):
        backend.setup(PaperParams("PARAM-I", "literal-density-width"))
    assert backend.setup_attempts == 1


def test_guarded_service_defaults_to_guarded_backend(tmp_path):
    issuer = GuardedSourceSchurFixedIssuer(tmp_path / "guarded")
    assert type(issuer.backend) is GuardedSourceSchurBackend
    assert not issuer.path.exists()
