"""Lossless Luo transport and actual complete-IBME size differential.

One mathematical IBS signature is represented in two transports. Protocol
worlds use fresh, disjoint OTS streams: no Lamport key signs two bodies here.
Only public vectors, counts, sizes and digests leave memory.
"""

import argparse
import base64
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import platform
import sys

import cryptography
from cryptography.hazmat.backends import default_backend

from ibme.core.encoding import decode_bytes
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.luo_module import LuoModuleIBSBackend, LuoModuleParams
from ibme.ibs.luo_module_codec import (
    LuoModuleCompactIBSBackend, LuoModuleCompactSignature, MAGIC_COMPACT,
    compact_layout, encode_compact, decode_compact,
)
from ibme.protocol.baseline import BaselineIBME, BOTTOM
from ibme.protocol.luo_hybrid import (
    make_research_runtime, RESEARCH_HIBE_PARAMS, RESEARCH_IBS_PARAMS, MAX_APPLICATION_BYTES,
)


def require(condition, label):
    if not condition: raise RuntimeError(label)


def random(label): return DeterministicRandom(b"luo-compact-audit:" + label)


def oracle_pack(values, width):
    bits = "".join(format(x, f"0{width}b") for x in values)
    bits += "0" * (-len(bits) % 8)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def verify_oracle(signature, compact):
    version, pos = decode_bytes(compact, len(MAGIC_COMPACT))
    kind, pos = decode_bytes(compact, pos)
    fields = []
    for _ in range(7):
        item, pos = decode_bytes(compact, pos)
        fields.append(item)
    require(pos == len(compact) and kind == b"SIGNATURE", "oracle frame")
    p, layout = signature.params, compact_layout(signature.params)
    flat = lambda vector: tuple(value for poly in vector for value in poly)
    expected = (p.to_bytes(), signature.context,
                oracle_pack(tuple(x + layout["z_max"] for x in flat(signature.z)), layout["z_width"]),
                oracle_pack(tuple(int(x != 0) for x in signature.c), 1),
                oracle_pack(tuple(int(x < 0) for x in signature.c if x), 1),
                oracle_pack(flat(signature.w1), layout["w1_width"]), oracle_pack(flat(signature.h), 1))
    require(tuple(fields) == expected, "independent bit-string oracle disagrees")
    return dict(compact_version=version.decode(), independently_checked_fields=7, bit_string_oracle=True)


def hash_transcript(backend, public, identity, message, signature):
    import ibme.ibs.luo_module as module
    original, calls = module.challenge, []
    def capture(params, domain, encoded):
        calls.append((domain, encoded))
        return original(params, domain, encoded)
    module.challenge = capture
    try:
        require(backend.verify(public, identity, message, signature), "public Verify failed")
    finally:
        module.challenge = original
    require(tuple(x[0] for x in calls) == (module.DOMAIN_H1, module.DOMAIN_H2), "unexpected public hash transcript")
    return tuple(calls)


def primitive_audit():
    backend = LuoModuleIBSBackend(rng=random(b"primitive-ibs"))
    public, master = backend.setup(LuoModuleParams())
    key = backend.key_extract(master, b"Alice")
    signature = backend.sign(key, b"reference")
    reference, compact = signature.to_bytes(), encode_compact(signature)
    restored = decode_compact(compact, public)
    require(restored.to_bytes() == reference and encode_compact(restored) == compact, "lossless canonical fixed point")
    verifier = LuoModuleCompactIBSBackend()
    wrapped = verifier.load_signature(public, compact)
    first = hash_transcript(backend, public, b"Alice", b"reference", signature)
    second = hash_transcript(verifier, public, b"Alice", b"reference", wrapped)
    require(first == second, "complete hash domains/inputs changed")
    require(not verifier.verify(public, b"Other", b"reference", wrapped), "wrong sender accepted")
    require(not verifier.verify(public, b"Alice", b"changed", wrapped), "changed message accepted")
    primitive = dict(layout=compact_layout(public.params), reference_bytes=len(reference), compact_bytes=len(compact),
                     saved_bytes=len(reference) - len(compact), reduction_percent=100 * (1 - len(compact) / len(reference)),
                     canonical_fixed_point=True, public_only_verify=True, hash_domains_and_inputs_equal=True,
                     hash_inputs=[dict(domain=domain.decode(), bytes=len(encoded), sha256=sha256(encoded).hexdigest())
                                  for domain, encoded in first],
                     extract_attempts=backend.last_extract_attempts, sign_attempts=backend.last_sign_attempts,
                     oracle=verify_oracle(signature, compact))
    vectors = dict(security_claim="none", backend_admitted=False, identity_hex=b"Alice".hex(), message_hex=b"reference".hex(),
                   public_key_base64=base64.b64encode(public.to_bytes()).decode(),
                   reference_signature_base64=base64.b64encode(reference).decode(),
                   compact_signature_base64=base64.b64encode(compact).decode())
    primitive["public_vector_sha256"] = {name: sha256(base64.b64decode(vectors[name])).hexdigest()
                                         for name in ("public_key_base64", "reference_signature_base64", "compact_signature_base64")}
    return primitive, vectors


def complete_audit():
    # Same public parameters, long-term keys, identities and application inputs.
    # Codec worlds draw independent fresh signing/OTS/encryption randomness.
    ref, _ = make_research_runtime(ibs_rng=random(b"reference-ibs"), ots_rng=random(b"reference-ots"))
    compact, _ = make_research_runtime(signature_format="compact", ibs_rng=random(b"compact-ibs"), ots_rng=random(b"compact-ots"))
    public, master = ref.setup(RESEARCH_HIBE_PARAMS, ibs_params=RESEARCH_IBS_PARAMS, rng=random(b"protocol-setup"))
    sender = ref.skgen(master, b"Alice")
    receiver = ref.rkgen(master, b"Bob", rng=random(b"protocol-rk"))
    other_receiver = ref.rkgen(master, b"Carol", rng=random(b"protocol-other-rk"))
    rows, ots_seen, mismatch_count = [], set(), 0
    for index, message in enumerate((b"", bytes(range(32)), b"x" * MAX_APPLICATION_BYTES)):
        row = dict(message_bytes=len(message))
        for format_name, protocol in (("reference", ref), ("compact", compact)):
            label = f"{format_name}:{index}".encode()
            cipher = protocol.encrypt(public, sender, b"Bob", message, rng=random(b"enc:" + label))
            require(protocol.decrypt(public, receiver, b"Alice", cipher.to_bytes(), rng=random(b"dec:" + label)) == message,
                    "complete protocol roundtrip")
            ots = cipher.ots_key.to_bytes()
            require(ots not in ots_seen, "Lamport key reused across compared bodies")
            ots_seen.add(ots)
            require(cipher.ots_key.verify(cipher.signed_body(), cipher.signature), "outer OTS positive control")
            baseline = BaselineIBME(protocol.hibe_backend, protocol.ibs_backend)
            hybrid = baseline.load_ciphertext(cipher.inner_bytes).hibe_ct
            if index == 0:
                for rk, claimed in ((receiver, b"Other"), (other_receiver, b"Alice"), (other_receiver, b"Other")):
                    require(protocol.decrypt(public, rk, claimed, cipher, rng=random(b"mismatch:" + label)) is BOTTOM,
                            "identity mismatch accepted")
                    mismatch_count += 1
            row[format_name] = dict(complete_ciphertext_bytes=len(cipher.to_bytes()), baseline_bytes=len(cipher.inner_bytes),
                                   hybrid_bytes=len(hybrid.to_bytes()), capsule_bytes=len(hybrid.capsule), dem_bytes=len(hybrid.body),
                                   public_ciphertext_sha256=sha256(cipher.to_bytes()).hexdigest(),
                                   outer_ots_public_sha256=sha256(ots).hexdigest())
        saved = row["reference"]["complete_ciphertext_bytes"] - row["compact"]["complete_ciphertext_bytes"]
        require(saved == 13392, "whole packet saving does not equal lossless signature saving")
        require(row["reference"]["capsule_bytes"] == row["compact"]["capsule_bytes"], "capsule boundary changed")
        row.update(saved_bytes=saved, whole_ciphertext_reduction_percent=100 * saved / row["reference"]["complete_ciphertext_bytes"])
        rows.append(row)
    return dict(rows=rows, honest_roundtrips=6, identity_mismatches_rejected=mismatch_count,
                distinct_ots_keys=len(ots_seen), reused_ots_keys=0, setups=1, repeats_per_format_message=1,
                sender_bytes=5, receiver_bytes=3, same_long_term_keys=True, same_security_parameters=True,
                same_protocol="BYTEAUTH/1 over HYBRID-HIBE/1", timing_measured=False,
                notes="Independent randomness avoids signing two comparison bodies with one Lamport key. Size is parameter-determined; no speed or A+B<C claim.")


def processor_model():
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        for line in cpuinfo.read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"): return line.split(":", 1)[1].strip()
    return platform.processor() or "unavailable"


def audit():
    primitive, vectors = primitive_audit()
    complete = complete_audit()
    try:
        from sage.env import SAGE_VERSION
    except ImportError:
        SAGE_VERSION = None
    root = Path(__file__).resolve().parents[2]
    files = ("src/ibme/ibs/luo_module.py", "src/ibme/ibs/luo_module_math.py", "src/ibme/ibs/luo_module_codec.py",
             "src/ibme/protocol/luo_hybrid.py", "src/ibme/protocol/hybrid_hibe.py", "src/ibme/protocol/byteauth.py",
             "src/ibme/core/lamport_ots.py", "src/ibme/cli.py", "experiments/research/luo_compact_audit.py")
    result = dict(security_claim="none", backend_admitted=False, admitted_secure_combinations=0,
                  algorithm_instances_added=0, hash_input_or_parameters_changed=False,
                  ibs_params=asdict(RESEARCH_IBS_PARAMS), inner_hibe_params=asdict(RESEARCH_HIBE_PARAMS.inner_params),
                  python=sys.version, sage=SAGE_VERSION, cryptography=cryptography.__version__,
                  openssl=default_backend().openssl_version_text(), platform=platform.platform(), processor=processor_model(),
                  entropy="Deterministic test-only streams, distinct OTS keys for every packet",
                  rom="Inherited classic ROM hash interpretation; no new ROM/QROM proof",
                  teaching_hibe=True, variable_time=True, max_application_bytes=MAX_APPLICATION_BYTES,
                  primitive=primitive, complete_ibme=complete,
                  source_sha256_lf={name: sha256((root / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest() for name in files},
                  notes=["Lossless transport with strict decoding; security parameters and H1/H2 input encodings are unchanged.",
                         "Signed z is biased without reduction mod q; w1 has 11 bits including the 1024 carry; all h bits are stored.",
                         "No key, seed, signing mask or DEM key is exported. Public primitive vectors are optional separate output.",
                         "Test success is not a security proof. Teaching HIBE and Luo proof/parameter release remain WIP."])
    return result, vectors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--vectors-output", type=Path)
    args = parser.parse_args()
    result, vectors = audit()
    if args.vectors_output:
        args.vectors_output.parent.mkdir(parents=True, exist_ok=True)
        args.vectors_output.write_text(json.dumps(vectors, indent=2) + "\n", encoding="utf-8")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(dict(reference_signature_bytes=result["primitive"]["reference_bytes"],
                             compact_signature_bytes=result["primitive"]["compact_bytes"],
                             honest_roundtrips=result["complete_ibme"]["honest_roundtrips"], security_claim="none")))
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__": main()
