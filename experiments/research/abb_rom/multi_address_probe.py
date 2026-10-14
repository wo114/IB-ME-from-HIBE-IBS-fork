"""Two genuine receivers by two genuine senders on one completed ABB root.

Copy the authoritative completed tree once into a new private output directory.
Keep the original files read-only. Genuine new addresses use system entropy;
cache restores forbid issuance entropy. Raw CPA wrong-key recovery is reported
as nonmatching bytes, never relabelled authenticated BOTTOM.
"""
import argparse
import json
from pathlib import Path
import resource
from time import perf_counter

from ibme.hibe.abb_rom import ABBROMHIBE,ABBPublicKey,ABBMasterSecret,ABBLevel1Key,ABBLevel2Key,ABBCiphertext
from .hibe_probe import CountedSystemEntropy,NoIssuanceEntropy,paths,source_fingerprints,write_private,safe_failure_chain
from .saved_combo_probe import require_completed


def run(source,output,baseline):
    origin=require_completed(source)
    output.mkdir(parents=True,exist_ok=False)
    pending=output/'pending';pending.write_text('restore completed real tree\n')
    before=source_fingerprints();started=perf_counter();entropy=CountedSystemEntropy()
    record=dict(schema='ABB-TWO-BY-TWO-ACTUAL/1',status='running',baseline_commit=baseline,
        original_root_baseline=origin['baseline_commit'],root_generations=1,new_root_generations=0,
        parent_count=2,children_per_parent=2,identity_bytes=[86,86],payload_bytes=32,repetitions=1,
        rng='default counted system CSPRNG',source_sha256_before=before,stages=[],checks=[],
        security_claim='none',backend_admitted=False,parameters_are_formal=False,
        raw_CPA_mismatch_is_not_authenticated_rejection=True)
    master=None
    def stage(name,fn):
        record['current_stage']=name;pending.write_text(name+'\n')
        (output/'progress.json').write_text(json.dumps(record,indent=2)+'\n')
        at=perf_counter();used=entropy.bytes_used;result=fn()
        record['stages'].append(dict(stage=name,status='passed',seconds=perf_counter()-at,
                                    private_entropy_bytes=entropy.bytes_used-used))
        return result
    def check(name,value):
        if not value:raise AssertionError(name)
        record['checks'].append(name)
    try:
        public=ABBPublicKey.from_bytes((source/'public.bin').read_bytes())
        master=ABBMasterSecret.from_bytes((source/'master.bin').read_bytes())
        check('same_completed_public_key',master.public_key==public)
        record['params']=public.params.to_record()
        backend=ABBROMHIBE(persist_pending=lambda owner:write_private(output/'master.bin',master.to_bytes()))
        write_private(output/'public.bin',public.to_bytes());write_private(output/'master.bin',master.to_bytes())
        parents={};leaves={}
        for rcv in (b'Bob',b'Carol'):
            parent_id,_=paths(rcv,b'Alice')
            guard=NoIssuanceEntropy()
            parent=stage(rcv.decode()+' real parent',lambda parent_id=parent_id,rcv=rcv:
                backend.extract(master,parent_id,rng=guard if rcv==b'Bob' else entropy))
            if rcv==b'Bob':check('original_parent_restores_without_issuance',guard.calls==0)
            parents[rcv]=parent
            for sender in (b'Alice',b'Charlie'):
                _,child_id=paths(rcv,sender)
                guard=NoIssuanceEntropy()
                existing=(rcv,sender)==(b'Bob',b'Alice')
                leaf=stage(rcv.decode()+'/'+sender.decode()+' real leaf',lambda parent=parent,child_id=child_id,existing=existing:
                    backend.derive(parent,child_id,rng=guard if existing else entropy))
                if existing:check('original_leaf_restores_without_issuance',guard.calls==0)
                leaves[rcv,sender]=leaf
                write_private(output/(rcv.decode()+'-'+sender.decode()+'-leaf.bin'),leaf.to_bytes())
                write_private(output/'master.bin',master.to_bytes())
            write_private(output/(rcv.decode()+'-parent.bin'),parent.to_bytes())
        seed=entropy.read(32);ciphertexts={}
        for (rcv,sender),leaf in leaves.items():
            rcv_id,child_id=paths(rcv,sender)
            ct=stage(rcv.decode()+'/'+sender.decode()+' original noisy 256bit Encrypt',lambda:
                backend.encrypt(public,rcv_id,child_id,seed,rng=entropy))
            restored=ABBCiphertext.from_bytes(ct.to_bytes())
            check(rcv.decode()+'/'+sender.decode()+' ciphertext canonical',restored.to_bytes()==ct.to_bytes())
            recovered=stage(rcv.decode()+'/'+sender.decode()+' 256 fresh SamplePre Decrypt',lambda:
                backend.decrypt(leaf,restored,rng=entropy))
            check(rcv.decode()+'/'+sender.decode()+' honest recovery',recovered==seed)
            ciphertexts[rcv,sender]=restored
            write_private(output/(rcv.decode()+'-'+sender.decode()+'-ciphertext.bin'),ct.to_bytes())
        honest=ciphertexts[b'Bob',b'Alice']
        for name,key in (('receiver_wrong',(b'Carol',b'Alice')),('sender_wrong',(b'Bob',b'Charlie')),
                         ('both_wrong',(b'Carol',b'Charlie'))):
            recovered=stage(name+' genuine wrong-key raw Decrypt',lambda key=key:
                backend.decrypt(leaves[key],honest,rng=entropy))
            check(name+' raw bytes differ',recovered!=seed)
        restored=ABBMasterSecret.from_bytes(master.to_bytes());guard=NoIssuanceEntropy()
        for rcv,parent in parents.items():
            parent_id,_=paths(rcv,b'Alice');reused=backend.extract(restored,parent_id,rng=guard)
            check(rcv.decode()+' parent codec and cache',reused.to_bytes()==parent.to_bytes())
            for sender in (b'Alice',b'Charlie'):
                _,child_id=paths(rcv,sender);leaf=backend.derive(reused,child_id,rng=guard)
                check(rcv.decode()+'/'+sender.decode()+' leaf codec and cache',leaf.to_bytes()==leaves[rcv,sender].to_bytes())
                check(rcv.decode()+'/'+sender.decode()+' public binding',backend.validate_key_binding(public,leaf))
        check('two_by_two_restore_issuance_entropy_zero',guard.calls==0)
        record.update(status='passed',genuine_two_by_two_lifecycle=True,
            issued_parent_count=2,issued_leaf_count=4,wire_bytes=dict(master=len(master.to_bytes()),
            parent=[len(parents[name].to_bytes()) for name in (b'Bob',b'Carol')],
            leaf=[len(value.to_bytes()) for value in leaves.values()]))
    except (Exception,KeyboardInterrupt) as exc:
        record.update(status='failed',failure_chain=safe_failure_chain(exc))
        if master is not None:write_private(output/'master.bin',master.to_bytes())
    record.update(seconds=perf_counter()-started,private_entropy_bytes=entropy.bytes_used,
        peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,source_sha256_after=source_fingerprints())
    record['source_unchanged_during_execution']=record['source_sha256_before']==record['source_sha256_after']
    if not record['source_unchanged_during_execution']:record['status']='failed-source-changed'
    (output/'receipt.json').write_text(json.dumps(record,indent=2)+'\n')
    if record['status']=='passed':pending.rename(output/'completed')
    print(json.dumps({key:record.get(key) for key in ('status','current_stage','seconds','genuine_two_by_two_lifecycle')}))
    return 0 if record['status']=='passed' else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--abb-private-directory',required=True,type=Path)
    parser.add_argument('--private-output-directory',required=True,type=Path)
    parser.add_argument('--baseline-commit',required=True)
    args=parser.parse_args()
    return run(args.abb_private_directory,args.private_output_directory,args.baseline_commit)


if __name__=='__main__':raise SystemExit(main())
