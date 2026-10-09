"""Verify the two published signature transports with public data only."""

import argparse
import base64
import json
from pathlib import Path

from ibme.core.errors import SerializationError
from ibme.ibs import LuoModulePublicKey, LuoModuleIBSBackend, LuoModuleCompactIBSBackend


def verify(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    public = LuoModulePublicKey.from_bytes(base64.b64decode(data["public_key_base64"], validate=True))
    identity, message = bytes.fromhex(data["identity_hex"]), bytes.fromhex(data["message_hex"])
    reference, compact = LuoModuleIBSBackend(), LuoModuleCompactIBSBackend()
    raw = reference.load_signature(public, base64.b64decode(data["reference_signature_base64"], validate=True))
    packed = compact.load_signature(public, base64.b64decode(data["compact_signature_base64"], validate=True))
    if not (reference.verify(public, identity, message, raw) and compact.verify(public, identity, message, packed)
            and raw.to_bytes() == packed.signature.to_bytes()
            and not compact.verify(public, b"Other", message, packed)):
        raise RuntimeError("public vector Verify/differential failed")
    for backend, encoded in ((reference, packed.to_bytes()), (compact, raw.to_bytes())):
        try:
            backend.load_signature(public, encoded)
        except SerializationError:
            pass
        else:
            raise RuntimeError("decoder silently accepted the other transport")
    return dict(public_only_verify=True, canonical_differential=True, decoder_fallback=False,
                reference_bytes=len(raw.to_bytes()), compact_bytes=len(packed.to_bytes()), security_claim="none")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vectors", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.vectors)))


if __name__ == "__main__": main()
