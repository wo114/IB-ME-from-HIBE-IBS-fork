"""Post-run, public metadata query only; no keys, signatures or randomness.

Run from the repository root in the documented WSL environment. This query
supplements the benchmark's constructor ABI checks; it is not a claim that
the executable hashes were logged inside each original timed worker.
"""

import hashlib
import json
from ibme.hibe.latte.engine import Native
from ibme.hibe.latte.params import LATTEParams
from ibme.ibs.certified.mldsa import MLDSA

latte = Native(LATTEParams())
mldsa = MLDSA("ml-dsa-44")
print(json.dumps(dict(schema="FULL-IBME-NATIVE-POST-RUN-QUERY/1", status="passed",
    timing="post-run query, not in-worker binary-hash capture", newly_built_engines=0,
    new_roots=0, new_keys=0, new_signatures=0,
    engines=[dict(name="latte3", path=str(latte.path),
                  sha256=hashlib.sha256(latte.path.read_bytes()).hexdigest(),
                  metadata=json.loads(latte.call("meta", b""))),
             dict(name="ml-dsa-44", path=str(mldsa.binary),
                  sha256=mldsa.binary_sha256, metadata=mldsa.metadata)],
    security_claim="none", backend_admitted=False, parameters_are_formal=False), indent=2))
