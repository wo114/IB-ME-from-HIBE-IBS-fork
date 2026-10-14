"""ABB saved real keys + Luo C64B + the shared Hybrid/BYTEAUTH protocol.

Requires a completed source-pinned full ABB lifecycle. Never generates an
alternate HIBE root or substitutes a teaching backend. Wrong identities are
encrypted to different public paths and tested against the same genuine
Bob/Alice receiver key; no wrong-path key generation is hidden in the test.
All secret state and ciphertexts stay in the new private output directory.
"""

import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import platform
from time import perf_counter

from ibme.core.encoding import encode_bytes,encode_message
from ibme.core.lamport_ots import generate_lamport_key
from ibme.hibe.abb_rom import ABBROMHIBE,ABBPublicKey,ABBMasterSecret,ABBLevel1Key,ABBLevel2Key
from ibme.hibe.abb_rom.registration import VERSION
from ibme.ibs.luo_module import LuoModulePublicKey,LuoModuleMasterSecret,LuoModuleSigningKey
from ibme.ibs.luo_module_codec import LuoModuleCompactIBSBackend,LuoModuleCompactSignature
from ibme.ibs.luo_module_profiles import c64b_params
from ibme.protocol.baseline import PublicKey,MasterSecret,SenderKey,ReceiverKey,Ciphertext,BOTTOM,encode_signature
from ibme.protocol.byteauth import ByteAuthenticatedIBME,authenticate_inner,encode_bound_message
from ibme.protocol.hybrid_hibe import HybridHIBE,HybridLimits,HybridPublicKey,HybridMasterSecret
from .hibe_probe import CountedSystemEntropy,NoIssuanceEntropy,source_fingerprints,write_private


def fingerprints():
    import ibme.ibs.luo_module as luo
    import ibme.ibs.luo_module_math as math
    import ibme.ibs.luo_module_codec as codec
    import ibme.ibs.luo_module_profiles as profiles
    import ibme.protocol.baseline as baseline
    import ibme.protocol.byteauth as byteauth
    import ibme.protocol.hybrid_hibe as hybrid
    import ibme.core.lamport_ots as ots
    result=source_fingerprints()
    for module in (luo,math,codec,profiles,baseline,byteauth,hybrid,ots):
        result[module.__name__]=hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
    result[__name__]=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return result


def require_completed(directory):
    if not (directory/'completed').is_file():
        raise ValueError('completed actual full ABB lifecycle required')
    receipt=json.loads((directory/'receipt.json').read_text())
    if not (receipt['status']=='passed' and receipt['full_HIBE_lifecycle'] is True and
            receipt['source_unchanged_during_execution'] is True and receipt['root_generations']==1 and
            receipt['payload_bytes']==32 and receipt['parent_identity_bytes']==receipt['child_identity_bytes']==86):
        raise ValueError('actual ABB lifecycle acceptance precondition failed')
    return receipt


def run(source,output,baseline_commit):
    original=require_completed(source)
    output.mkdir(parents=True,exist_ok=False)
    pending=output/'pending';pending.write_text('restore actual ABB\n')
    before=fingerprints();started=perf_counter()
    entropy=CountedSystemEntropy();ibs_entropy=CountedSystemEntropy();ots_entropy=CountedSystemEntropy()
    record=dict(schema='ABB-LUO-SAVED-REAL-COMBO/1',status='running',baseline_commit=baseline_commit,
        original_ABB_baseline=original['baseline_commit'],original_root_generations=1,new_HIBE_root_generations=0,
        hibe_identity_bytes=[86,86],application_identity_bytes=[3,5],application_message_bytes=32,
        inner_HIBE_seed_bytes=32,repetitions=1,rng='default counted system CSPRNG',checks=[],stages=[],
        full_IBME_combination=False,security_claim='none',backend_admitted=False,parameters_are_formal=False,
        source_sha256_before=before,environment=dict(python=platform.python_version(),platform=platform.platform()))
    def stage(name,operation):
        record['current_stage']=name;pending.write_text(name+'\n')
        (output/'progress.json').write_text(json.dumps(record,indent=2)+'\n')
        at=perf_counter();result=operation()
        record['stages'].append(dict(stage=name,seconds=perf_counter()-at,status='passed'))
        return result
    def check(name,condition):
        if not condition:raise AssertionError(name)
        record['checks'].append(name)
    try:
        raw_public=ABBPublicKey.from_bytes((source/'public.bin').read_bytes())
        raw_master=ABBMasterSecret.from_bytes((source/'master.bin').read_bytes())
        check('restored_ABB_full_public_binding',raw_master.public_key==raw_public)
        limits=HybridLimits(backend_id=VERSION.encode('ascii'))
        hybrid=HybridHIBE(ABBROMHIBE(),backend_id=limits.backend_id,public_key_type=ABBPublicKey,
            master_type=ABBMasterSecret,level1_type=ABBLevel1Key,level2_type=ABBLevel2Key)
        hpk=HybridPublicKey(limits,raw_public);hmsk=HybridMasterSecret(hpk,raw_master)
        ibs=LuoModuleCompactIBSBackend(rng=ibs_entropy)
        ipk,imsk=stage('actual Luo C64B Setup',lambda:ibs.setup(c64b_params()))
        proto=ByteAuthenticatedIBME(hybrid,ibs,ots_rng=ots_entropy)
        public,master=PublicKey(hpk,ipk),MasterSecret(hmsk,imsk)
        sender=stage('actual Luo Alice identity extraction',lambda:proto.skgen(master,b'Alice'))
        other_sender=stage('actual Luo Charlie identity extraction',lambda:proto.skgen(master,b'Charlie'))
        guard=NoIssuanceEntropy()
        receiver=stage('restore already issued genuine ABB Bob parent',lambda:proto.rkgen(master,b'Bob',rng=guard))
        hybrid.derive(receiver.level1_key,b'Alice',rng=guard)
        check('fixed_ABB_tree_restore_without_issuance_entropy',guard.calls==0)
        message=bytes(range(32))
        check('application_message_is_32_bytes',len(message)==32)
        record['hibe_params']=raw_public.params.to_record()
        record['ibs_params']={name:getattr(ipk.params,name) for name in __import__('ibme.ibs.luo_module',fromlist=['FIELDS']).FIELDS}
        honest=stage('honest Encrypt with real ABB seed and Luo signature',lambda:proto.encrypt(public,sender,b'Bob',message,rng=entropy))
        check('canonical_full_ciphertext',proto.load_ciphertext(honest.to_bytes()).to_bytes()==honest.to_bytes())
        write_private(output/'ciphertext.bin',honest.to_bytes())
        recovered=stage('honest Decrypt with 256 fresh actual SamplePre calls',lambda:proto.decrypt(public,receiver,b'Alice',honest,rng=entropy))
        check('both_identities_match',recovered==message)
        for name,key,rcv in (('receiver_wrong',sender,b'Carol'),('sender_wrong',other_sender,b'Bob'),
                             ('both_wrong',other_sender,b'Carol')):
            ct=stage(name+' actual Encrypt',lambda key=key,rcv=rcv:proto.encrypt(public,key,rcv,message,rng=entropy))
            result=stage(name+' actual Decrypt',lambda ct=ct:proto.decrypt(public,receiver,b'Alice',ct,rng=entropy))
            check(name,result is BOTTOM)
        raw=honest.to_bytes();guard=NoIssuanceEntropy()
        variants=(('truncated',raw[:-1]),('appended',raw+b'x'),('duplicate',raw+raw),
                  ('unknown_version',bytes([raw[0]^1])+raw[1:]),
                  ('ciphertext_bytes_changed',raw[:len(raw)//2]+bytes([raw[len(raw)//2]^1])+raw[len(raw)//2+1:]),
                  ('OTS_signature_changed',raw[:-1]+bytes([raw[-1]^1])))
        for name,data in variants:
            check(name,proto.decrypt(public,receiver,b'Alice',data,rng=guard) is BOTTOM)
        check('outer_wire_rejects_before_private_GPV',guard.calls==0)
        new_ots=generate_lamport_key(rng=ots_entropy)
        resigned=authenticate_inner(public,honest.inner_bytes,new_ots)
        check('replacement_OTS_is_valid',resigned.ots_key.verify(resigned.signed_body(),resigned.signature))
        check('replacement_OTS_rejected_by_encrypted_IBS_binding',stage('replacement OTS actual Decrypt',
            lambda:proto.decrypt(public,receiver,b'Alice',resigned,rng=entropy)) is BOTTOM)
        for name,random_forgery in (('IBS_signature_changed',False),('random_IBS_forgery',True)):
            key=generate_lamport_key(rng=ots_entropy)
            envelope=encode_bound_message(key.public_key.commitment(),message)
            signature=ibs.sign(sender.signing_key,encode_message(b'Bob',envelope))
            original_signature=signature.signature
            z=[list(row) for row in original_signature.z]
            if random_forgery:
                z=[[int.from_bytes(entropy.read(2),'big')-32768 for _ in row] for row in z]
            else:
                bound=ipk.params.gamma2-ipk.params.beta2-1
                z[0][0]+=1 if z[0][0]<bound else -1
            bad=LuoModuleCompactSignature(replace(original_signature,z=tuple(tuple(row) for row in z)))
            check(name+'_fails_native_IBS_verify',not ibs.verify(ipk,b'Alice',encode_message(b'Bob',envelope),bad))
            payload=encode_signature(bad)+encode_bytes(envelope)
            inner=stage(name+' actual ABB Encrypt',lambda payload=payload:hybrid.encrypt(hpk,b'Bob',b'Alice',payload,rng=entropy))
            forged=authenticate_inner(public,Ciphertext(inner).to_bytes(),key)
            check(name,stage(name+' actual Decrypt',lambda forged=forged:proto.decrypt(public,receiver,b'Alice',forged,rng=entropy)) is BOTTOM)
        decoders=hybrid.component_decoders()
        restored_public=PublicKey.from_bytes(public.to_bytes(),decoders['hpk'],LuoModulePublicKey)
        restored_master=MasterSecret.from_bytes(master.to_bytes(),decoders['hmsk'],LuoModuleMasterSecret)
        restored_sender=SenderKey.from_bytes(sender.to_bytes(),LuoModuleSigningKey)
        restored_receiver=ReceiverKey.from_bytes(receiver.to_bytes(),decoders['sk1'])
        check('full_combination_object_restore',restored_public==public and restored_master==master and
              restored_sender==sender and restored_receiver==receiver)
        for name,value in (('public.bin',public),('master.bin',master),('sender.bin',sender),('receiver.bin',receiver)):
            write_private(output/name,value.to_bytes())
        record.update(status='passed',full_IBME_combination=True,
            wire_bytes=dict(public=len(public.to_bytes()),sender=len(sender.to_bytes()),
                            receiver=len(receiver.to_bytes()),ciphertext=len(honest.to_bytes())))
    except (Exception,KeyboardInterrupt) as exc:
        record.update(status='failed',failure_type=type(exc).__name__)
        # Exception values may contain private matrices or payloads.
    record.update(seconds=perf_counter()-started,HIBE_private_entropy_bytes=entropy.bytes_used,
        IBS_private_entropy_bytes=ibs_entropy.bytes_used,OTS_private_entropy_bytes=ots_entropy.bytes_used,
        source_sha256_after=fingerprints())
    record['source_unchanged_during_execution']=record['source_sha256_before']==record['source_sha256_after']
    if not record['source_unchanged_during_execution']:record['status']='failed-source-changed'
    (output/'receipt.json').write_text(json.dumps(record,indent=2)+'\n')
    if record['status']=='passed':pending.rename(output/'completed')
    print(json.dumps({name:record.get(name) for name in ('status','current_stage','seconds','failure_type','full_IBME_combination')}))
    return 0 if record['status']=='passed' else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--abb-private-directory',type=Path,required=True)
    parser.add_argument('--private-output-directory',type=Path,required=True)
    parser.add_argument('--baseline-commit',required=True)
    args=parser.parse_args()
    return run(args.abb_private_directory,args.private_output_directory,args.baseline_commit)


if __name__=='__main__':raise SystemExit(main())
