"""Read only the selected engines' metadata/SHA; never create keys/signatures.

Run in the prescribed WSL Sage interpreter; this independent provenance query
is not presented as metadata captured inside earlier measurement workers.
"""

from hashlib import sha256
import json
from unittest.mock import patch

from ibme.core.randomness import SecureRandom
from ibme.hibe.latte.engine import Native
from ibme.hibe.latte.params import LATTEParams
from ibme.ibs.certified.falcon import Falcon


def forbidden(*args, **kwargs):
    raise AssertionError("provenance query attempted entropy, key generation or signing")


original_call = Native.call
def metadata_only(self, operation, data):
    if operation != "meta": forbidden()
    return original_call(self, operation, data)


with patch.object(SecureRandom, "read", forbidden), patch.object(Falcon, "keypair", forbidden), patch.object(Falcon, "sign", forbidden), patch.object(Native, "call", metadata_only):
    latte = Native(LATTEParams())
    falcon = Falcon("falcon-padded-512")
    print(json.dumps(dict(schema="FULL-SYSTEM-NATIVE-PROVENANCE/1", query="independent read-only query",
        latte=dict(metadata=json.loads(latte.call("meta", b"")), binary_sha256=sha256(latte.path.read_bytes()).hexdigest()),
        falcon=dict(metadata=falcon.metadata, binary_sha256=falcon.binary_sha256),
        project_entropy_reads=0, key_generations=0, signatures=0), indent=2, sort_keys=True))
