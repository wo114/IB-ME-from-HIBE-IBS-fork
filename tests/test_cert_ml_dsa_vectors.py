"""Published NIST TEST vectors, including public TEST secret keys only."""
import gzip
import hashlib
import json
import os
from pathlib import Path

import pytest

from ibme.ibs.certified.mldsa import MLDSA
from ibme.ibs.certified.native.build import PREFIX


FIXTURE = Path(__file__).parent / "fixtures/cert_mldsa/acvp-pure.json.gz"
DATA = json.loads(gzip.decompress(FIXTURE.read_bytes()))
BIN = Path(os.environ.get("IBME_CERTIFIED_SIGNATURE_BIN_DIR", str(PREFIX / "bin")))
NATIVE = os.name == "posix" and all((BIN / f"ibme-mldsa{n}").is_file() for n in (44, 65, 87))


def test_vector_fixture_provenance():
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == "201573224ca3c999397e6650aba5791b4d72c19a2adac3a9640762162f76236b"
    assert DATA["source_commit"] == "975de31eb83d87039ec88934fdc47d8c312b892d"
    assert {kind: sum(v["kind"] == kind for v in DATA["vectors"])
            for kind in ("keyGen", "sigGen", "sigVer")} == {"keyGen": 75, "sigGen": 90, "sigVer": 45}


@pytest.fixture(scope="module")
def engines():
    return {f"ML-DSA-{n}": MLDSA(f"ml-dsa-{n}") for n in (44, 65, 87)}


@pytest.mark.skipif(not NATIVE, reason="requires explicitly built ML-DSA native engines in WSL/Linux")
@pytest.mark.parametrize("vector", DATA["vectors"], ids=lambda v: f'{v["kind"]}-{v["parameter_set"]}-{v["group_id"]}-{v["test_id"]}')
def test_nist_pure_external_vector(vector, engines):
    engine = engines[vector["parameter_set"]]
    raw = lambda name: bytes.fromhex(vector[name])
    if vector["kind"] == "keyGen":
        public, secret = engine.keypair(raw("seed"))
        assert hashlib.sha256(public).hexdigest() == vector["pk_sha256"]
        assert hashlib.sha256(secret).hexdigest() == vector["sk_sha256"]
        assert engine.public_from_secret(secret) == public
    elif vector["kind"] == "sigGen":
        signature = engine.sign(raw("sk"), raw("message"), raw("rnd"), context=raw("context"))
        assert hashlib.sha256(signature).hexdigest() == vector["signature_sha256"]
        assert engine.canonical_signature(signature)
        public = engine.public_from_secret(raw("sk"))
        assert public is not None
        assert engine.verify(public, raw("message"), signature, context=raw("context"))
    else:
        assert engine.verify(raw("pk"), raw("message"), raw("signature"), context=raw("context")) is vector["test_passed"]
