"""One saved real MP12/CHKP-reference + Luo/Hybrid/BYTEAUTH lifecycle.

New ignored private directory only; never overwrite/restart a pending run.
Restore mode forbids generation entropy and does not need the native engine.
The explicit n2 public attack is a required negative control, not a security
upgrade. All secret keys, capsules' seeds and challenge plaintext stay private.
"""

import argparse
from dataclasses import asdict, replace
from hashlib import sha256
from itertools import product
import json
from pathlib import Path
import platform
import subprocess
import sys
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ibme.assembly import build_runtime, SuiteConfig
from ibme.core.errors import SerializationError
from ibme.core.lamport_ots import generate_lamport_key
from ibme.protocol.baseline import PublicKey, MasterSecret, SenderKey, ReceiverKey, BaselineIBME, is_bottom
from ibme.protocol.byteauth import ByteAuthCiphertext
from ibme.protocol.hybrid_hibe import derive_dem_key, encoded_identity
from experiments.research.ibme_rounded_noise import build_rounded_noise
from .hibe_registry import research_suite, research_registry
from .hibe_reference import MP12HIBECiphertext,MP12HIBELeaf,MP12HIBEPublicKey
from .seed_kem import decode_phase

ROOT = Path(__file__).resolve().parents[3]
CHALLENGE = b"A-reference complete IBME lifecycle, not a security claim"


class NoEntropy:
    def read(self,count): raise AssertionError("restore/reuse requested generation entropy")


def digest(data): return sha256(data).hexdigest()


def decode_public(runtime,raw):
    return PublicKey.from_bytes(raw,runtime.decoders["hpk"],runtime.decoders["ipk"])


def public_n2_attack(public,hybrid_ct):
    """Only public matrices/known target identities/finite noise support.

    Identity columns disclose s_i+e_i. For n2 enumerate the bounded e_i,
    filter against the whole public LWE preamble, then derive the DEM seed.
    Never accepts a private key, basis, preimage or entropy tape.
    """
    pk = public.inner
    if pk.params.n!=2: raise ValueError("bounded negative control is n2 only")
    raw = MP12HIBECiphertext.from_bytes(hybrid_ct.capsule).capsule
    receiver = encoded_identity(b"Bob",public.limits,b"P")
    sender = encoded_identity(b"Alice",public.limits,b"C")
    rows,targets,q = pk.oracle.leaf_rows(receiver,sender),pk.oracle.targets(receiver,sender),pk.params.q
    radius = build_rounded_noise(pk.params.noise_params).radius
    if radius>64: raise ValueError("negative-control search budget exceeded")
    candidates,trials = [],0
    for error in product(range(-radius,radius+1),repeat=2):
        trials+=1
        secret = tuple((raw.preamble[i]-error[i])%q for i in range(2))
        if any(min((b-sum(row[j]*s for row,s in zip(rows,secret)))%q,
                   (sum(row[j]*s for row,s in zip(rows,secret))-b)%q)>radius
               for j,b in enumerate(raw.preamble)):
            continue
        bits=[]
        for target,value in zip(targets,raw.terminals):
            phase = (value-sum(a*s for a,s in zip(target,secret)))%q
            bit = decode_phase(phase,q);offset = (phase-bit*(q//2))%q
            if min(offset,q-offset)>radius: break
            bits.append(bit)
        if len(bits)!=256: continue
        seed = bytes(sum(bits[8*i+j]<<(7-j) for j in range(8)) for i in range(32))
        try:
            payload = AESGCM(derive_dem_key(seed,public.context)).decrypt(
                hybrid_ct.nonce,hybrid_ct.body,hybrid_ct.aad())
        except Exception:
            continue
        candidates.append(CHALLENGE in payload)
    return dict(attack="bounded n2 identity-column error enumeration",secret_keys_supplied=False,
        noise_support_radius=radius,trials=trials,valid_dem_decryptions=len(candidates),
        challenge_plaintext_recovered=any(candidates),security_claim="none",backend_admitted=False)


def restore_only(directory):
    directory = Path(directory)
    config = SuiteConfig.from_json((directory/"suite.json").read_bytes())
    registry = research_registry(Path("/nonexistent-native-engine-for-restore"))
    runtime = build_runtime(config,registry=registry)
    pk = decode_public(runtime,(directory/"public.bin").read_bytes())
    master = MasterSecret.from_bytes((directory/"master-final.bin").read_bytes(),
        runtime.decoders["hmsk"],runtime.decoders["imsk"])
    receiver = ReceiverKey.from_bytes((directory/"bob.bin").read_bytes(),runtime.decoders["sk1"])
    sender = SenderKey.from_bytes((directory/"alice.bin").read_bytes(),runtime.decoders["sk"])
    runtime.validate_master(pk,master);runtime.validate_receiver(pk,receiver);runtime.validate_sender(pk,sender)
    raw = (directory/"ciphertext.bin").read_bytes()
    value = runtime.proto.decrypt(pk,receiver,b"Alice",raw,rng=NoEntropy())
    # Master receiver cache and the standalone receiver both carry the issued
    # fixed leaf; no callbacks/native conversion/entropy are available here.
    again = runtime.proto.rkgen(master,b"Bob",rng=NoEntropy())
    cached = runtime.proto.decrypt(pk,again,b"Alice",raw,rng=NoEntropy())
    return dict(message_matches=value==CHALLENGE and cached==CHALLENGE,
        master_byte_equal=master.to_bytes()==(directory/"master-final.bin").read_bytes(),
        receiver_byte_equal=receiver.to_bytes()==(directory/"bob.bin").read_bytes(),
        sender_byte_equal=sender.to_bytes()==(directory/"alice.bin").read_bytes(),
        entropy_reads_permitted=False,native_engine_available=False,
        new_root_parent_or_leaf_generations=0,security_claim="none",backend_admitted=False)


def run(binary,directory,output):
    directory,output = Path(directory).resolve(),Path(output).resolve()
    allowed = (ROOT/"test-results").resolve()
    if (not directory.is_relative_to(allowed) or directory==allowed
            or not output.is_relative_to(allowed) or output.is_relative_to(directory)
            or output.exists()):
        raise ValueError("new ignored private directory and separate new public output required")
    directory.mkdir(parents=True,exist_ok=False)
    pending = directory/"generation.pending";pending.write_bytes(b"reserved one real lifecycle; never restart here\n")
    started = time.monotonic();events=[]
    def event(stage):
        events.append(dict(stage=stage,elapsed_seconds=time.monotonic()-started))
        (directory/"progress.json").write_text(json.dumps(events,indent=2)+"\n",encoding="utf-8")
        print(json.dumps(events[-1]),flush=True)
    config,registry = research_suite(binary)
    runtime = build_runtime(config,registry=registry);proto = runtime.proto
    (directory/"suite.json").write_bytes(config.to_json().encode("ascii"))
    master = None
    try:
        event("real_computational_root_setup")
        public,master = proto.setup(runtime.hibe_params,ibs_params=runtime.ibs_params)
        (directory/"public.bin").write_bytes(public.to_bytes())
        (directory/"master-root.bin").write_bytes(master.to_bytes())
        event("real_receiver_Bob_DelTrap")
        bob = proto.rkgen(master,b"Bob")
        (directory/"master-Bob.bin").write_bytes(master.to_bytes())
        alice = proto.skgen(master,b"Alice")
        (directory/"alice.bin").write_bytes(alice.to_bytes())
        ct = proto.encrypt(public,alice,b"Bob",CHALLENGE)
        (directory/"ciphertext.bin").write_bytes(ct.to_bytes())
        checks={}
        event("real_leaf_Bob_Alice_fixed256")
        checks["both_match"] = proto.decrypt(public,bob,b"Alice",ct)==CHALLENGE
        event("real_leaf_Bob_Eve_fixed256")
        checks["sender_mismatch"] = is_bottom(proto.decrypt(public,bob,b"Eve",ct))
        event("real_receiver_Mallory_DelTrap")
        mallory = proto.rkgen(master,b"Mallory")
        event("real_leaf_Mallory_Alice_fixed256")
        checks["receiver_mismatch"] = is_bottom(proto.decrypt(public,mallory,b"Alice",ct))
        event("real_leaf_Mallory_Eve_fixed256")
        checks["both_mismatch"] = is_bottom(proto.decrypt(public,mallory,b"Eve",ct))
        event("wire_attack_controls_and_reuse")
        checks["same_receiver_no_entropy"] = proto.rkgen(master,b"Bob",rng=NoEntropy()).to_bytes()==bob.to_bytes()
        checks["same_leaf_no_entropy"] = proto.decrypt(public,bob,b"Alice",ct,rng=NoEntropy())==CHALLENGE
        raw = ct.to_bytes()
        for name,index in [("outer_context",len(b"IBME:BYTEAUTH-CT:v1")+4),
            ("middle_region",len(raw)//2),("outer_signature",len(raw)-1)]:
            altered=bytearray(raw);altered[index]^=1
            checks[name+"_tamper_rejected"] = is_bottom(proto.decrypt(public,bob,b"Alice",bytes(altered),rng=NoEntropy()))
        for name,data in [("truncated",raw[:-1]),("appended",raw+b"x"),("duplicated",raw+raw)]:
            checks[name+"_rejected"] = is_bottom(proto.decrypt(public,bob,b"Alice",data,rng=NoEntropy()))
        # Public re-signing with a fresh outer key is valid OTS but breaks the
        # commitment signed inside by IBS. The attack gets no IBS signing key.
        newkey = generate_lamport_key()
        resigned = replace(ct,ots_key=newkey.public_key,signature=b"\x00"*len(ct.signature))
        resigned = replace(resigned,signature=newkey.sign(resigned.signed_body()))
        checks["fresh_outer_key_resign_rejected"] = is_bottom(proto.decrypt(public,bob,b"Alice",resigned,rng=NoEntropy()))
        for name,blob,loader in [("public",public.to_bytes(),lambda b:decode_public(runtime,b)),
            ("receiver",bob.to_bytes(),lambda b:ReceiverKey.from_bytes(b,runtime.decoders["sk1"]))]:
            checks[name+"_roundtrip"] = loader(blob).to_bytes()==blob
            for suffix,bad in [("truncate",blob[:-1]),("append",blob+b"x")]:
                try: loader(bad)
                except SerializationError: checks[name+"_"+suffix+"_rejected"]=True
                else: checks[name+"_"+suffix+"_rejected"]=False
        (directory/"master-final.bin").write_bytes(master.to_bytes())
        (directory/"bob.bin").write_bytes(bob.to_bytes())
        (directory/"mallory.bin").write_bytes(mallory.to_bytes())
        event("public_n2_privacy_negative_control")
        hybrid_ct = BaselineIBME.load_ciphertext(proto,ct.inner_bytes).hibe_ct
        attack = public_n2_attack(public.hpk,hybrid_ct)
        if not attack["challenge_plaintext_recovered"]:
            raise AssertionError("required n2 public attack was not reproduced")
        event("fresh_process_restore_without_engine_or_entropy")
        child = subprocess.run([sys.executable,"-m","experiments.research.first_suite.hibe_probe",
            "--restore-only",str(directory)],cwd=ROOT,capture_output=True,text=True,timeout=90)
        if child.returncode: raise RuntimeError("fresh process restore failed; private diagnostics withheld")
        restored = json.loads(child.stdout)
        checks["fresh_restore_matches"] = restored["message_matches"]
        checks["fresh_restore_canonical"] = all(restored[k] for k in
            ("master_byte_equal","receiver_byte_equal","sender_byte_equal"))
        if not all(checks.values()): raise AssertionError("one or more real lifecycle checks failed")
        result=dict(profile="A-HIBE-SOURCE-REFERENCE/1",config=config.to_dict(),capacity=runtime.capacity,
            hibe_parameters=asdict(runtime.hibe_params.inner_params),ibs_parameters=asdict(runtime.ibs_params),
            root_generation=runtime.hibe.inner_backend.last_setup_receipt,
            dimensions=[84,168,252],seed_bits=256,root_generations=1,parent_generations=2,leaf_generations=4,
            checks=checks,checks_passed=sum(checks.values()),fresh_process=restored,public_negative_control=attack,
            sizes=dict(public=len(public.to_bytes()),master=len(master.to_bytes()),sender=len(alice.to_bytes()),
                receiver_Bob=len(bob.to_bytes()),receiver_Mallory=len(mallory.to_bytes()),ciphertext=len(raw),
                raw_seed_capsule=len(hybrid_ct.capsule)),
            elapsed_seconds=time.monotonic()-started,events=events,
            identity_original_bytes=[3,5],identity_inner_bytes=86,message_bytes=len(CHALLENGE),repetitions=1,
            python=platform.python_version(),os=platform.platform(),
            native_engine_sha256=digest(Path(binary).read_bytes()),
            source_checkout_only=True,default_registry_modified=False,random_oracle_model="classical ROM conditions pending",
            parameters_are_formal=False,security_claim="none",backend_admitted=False,
            not_covered=["secure parameters", "original CHKP theorem unchanged for MP12 variant",
                "installed-wheel deployment", "default CLI registration", "constant-time or rollback protection",
                "fair performance comparison", "QROM proof"])
        output.parent.mkdir(parents=True,exist_ok=True)
        with output.open("x",encoding="utf-8") as f:f.write(json.dumps(result,indent=2)+"\n")
        pending.unlink();event("completed")
        return result
    except BaseException:
        if master is not None: (directory/"master-failed.bin").write_bytes(master.to_bytes())
        event("failed_pending_retained_no_restart")
        raise


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary",type=Path,default=ROOT/"test-results/qfall-target/release/ibme-qfall-private-root")
    p.add_argument("--private-directory",type=Path);p.add_argument("--output",type=Path)
    p.add_argument("--restore-only",type=Path);a=p.parse_args(argv)
    if a.restore_only: print(json.dumps(restore_only(a.restore_only)));return 0
    if a.private_directory is None or a.output is None:p.error("explicit new private/output paths required")
    r=run(a.binary,a.private_directory,a.output)
    print(json.dumps(dict(checks_passed=r["checks_passed"],public_attack=r["public_negative_control"],
        elapsed_seconds=r["elapsed_seconds"])),flush=True);return 0


if __name__=="__main__":raise SystemExit(main())
