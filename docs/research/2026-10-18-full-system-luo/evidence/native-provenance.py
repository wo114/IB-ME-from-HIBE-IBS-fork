"""Independent post-run metadata/SHA query for the selected LATTE engine."""

from hashlib import sha256
import json
from unittest.mock import patch

from ibme.core.randomness import SecureRandom
from ibme.hibe.latte.engine import Native
from ibme.hibe.latte.params import LATTEParams


def forbidden(*args,**kwargs):
    raise AssertionError("metadata query attempted generation or entropy")


original = Native.call
def metadata_only(self,operation,data):
    if operation != "meta": forbidden()
    return original(self,operation,data)


with patch.object(SecureRandom,"read",forbidden),patch.object(Native,"call",metadata_only):
    native = Native(LATTEParams())
    print(json.dumps(dict(schema="LATTE-NATIVE-PROVENANCE/1",query="independent post-run read-only query",
        metadata=json.loads(native.call("meta",b"")),binary_sha256=sha256(native.path.read_bytes()).hexdigest(),
        project_entropy_reads=0,keys_generated=0),indent=2,sort_keys=True))
