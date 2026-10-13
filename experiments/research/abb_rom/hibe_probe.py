"""Real ABB vertical research probe; private state never enters the receipt.

Each new directory is one instance. Issuance failure persists in master.bin,
and pending is retained. --restore-only reads that authoritative state and
only reuses already issued addresses; it never decrypts without fresh GPV.
"""

import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import resource
import signal
import shutil
import threading
from time import perf_counter
from sage.version import version as sage_version

from ibme.core.randomness import SecureRandom
from ibme.hibe.abb_rom.backend import ABBROMHIBE, ABBSamplingAbort, check_setup_profile
from ibme.hibe.abb_rom.objects import ABBPublicKey, ABBMasterSecret, ABBLevel1Key, ABBLevel2Key, ABBCiphertext
from ibme.hibe.abb_rom.params import ABBROMParams
from ibme.hibe.abb_rom.profiles import q104_research_params
from ibme.hibe.abb_rom.registration import VERSION
from ibme.protocol.hybrid_hibe import HybridLimits, encoded_identity


class CountedSystemEntropy:
    def __init__(self):
        self.source=SecureRandom()
        self.bytes_used=0
    def read(self,count):
        result=self.source.read(count)
        self.bytes_used+=len(result)
        return result


class NoIssuanceEntropy:
    calls=0
    def read(self,count):
        self.calls+=1
        raise AssertionError("fixed/failed address attempted new private sampling")


def write_private(path,raw):
    temporary=path.with_name(path.name+".pending-write")
    with temporary.open("xb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary,path)


def source_fingerprints():
    import ibme.hibe.abb_rom.backend as backend
    import ibme.hibe.abb_rom.identity as identity
    import ibme.hibe.abb_rom.key_validation as validation
    import ibme.hibe.abb_rom.objects as objects
    import ibme.hibe.abb_rom.params as params
    import ibme.hibe.abb_rom.primitives as primitives
    import ibme.hibe.abb_rom.trapgen as trapgen
    import ibme.hibe.abb_rom.bit_encryption as bits
    import ibme.hibe.abb_rom.parameter_screen as screen
    import ibme.hibe.abb_rom.profiles as profiles
    import experiments.research.ibme_rounded_noise as noise
    import experiments.research.gaussian_reference as uniform
    import experiments.research.first_suite.entropy as checked_entropy
    import ibme.lattice.matrix_sampling.scalar as scalar
    import ibme.lattice.matrix_sampling.gpv as gpv
    import ibme.lattice.matrix_sampling.basis as basis
    import ibme.lattice.matrix_sampling.randbasis as randbasis
    import ibme.lattice.matrix_sampling.modular as modular
    import ibme.lattice.matrix_sampling.exact_gram as exact_gram
    result={}
    for module in (backend,identity,validation,objects,params,primitives,scalar,gpv,basis,randbasis,modular,
                   trapgen,bits,screen,profiles,noise,uniform,checked_entropy,exact_gram):
        path=Path(module.__file__)
        result[module.__name__]=hashlib.sha256(path.read_bytes()).hexdigest()
    result[__name__]=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    native_source=Path(__file__).parent/'native'/'exact_gram.cpp'
    result['native.exact_gram.cpp']=hashlib.sha256(native_source.read_bytes()).hexdigest()
    for name,selected in (('native.exact_gram',os.environ.get('IBME_EXACT_GRAM_EXECUTABLE')),
                          ('native.flatter',shutil.which('flatter'))):
        if selected:
            result[name]=hashlib.sha256(Path(selected).read_bytes()).hexdigest()
    return result


def process_tree_rss(pid,proc_root=Path('/proc')):
    """Conservative sum of resident memory, including native grandchildren."""
    entries={}
    for entry in proc_root.iterdir():
        if not entry.name.isdecimal():continue
        try:
            status={line.split(':',1)[0]:line.split(':',1)[1].strip()
                    for line in (entry/'status').read_text().splitlines() if ':' in line}
            entries[int(entry.name)]=(int(status['PPid']),int(status.get('VmRSS','0 kB').split()[0]))
        except (OSError,KeyError,ValueError):continue  # process exited during observation
    selected={pid}
    while True:
        children={child for child,(parent,_) in entries.items() if parent in selected}
        expanded=selected|children
        if expanded==selected:break
        selected=expanded
    return sum(entries.get(child,(0,0))[1] for child in selected),selected


def paths():
    limits=HybridLimits(backend_id=VERSION.encode("ascii"))
    return encoded_identity(b"Bob",limits,b"P"),encoded_identity(b"Alice",limits,b"C")


def restore_only(directory):
    master=ABBMasterSecret.from_bytes((directory/"master.bin").read_bytes())
    public=ABBPublicKey.from_bytes((directory/"public.bin").read_bytes())
    if master.public_key!=public:
        raise ValueError("authoritative master/public mismatch")
    parent_id,child_id=paths()
    backend=ABBROMHIBE();guard=NoIssuanceEntropy()
    if parent_id not in master.parents:
        raise ValueError("no fixed parent address to restore; no implicit issuance")
    if master.parents[parent_id] is None:
        try: backend.extract(master,parent_id,rng=guard)
        except ABBSamplingAbort:
            return dict(status="passed-failed-address-restore",failed_parent_retained=True,new_private_entropy_calls=guard.calls)
        raise AssertionError("failed parent was reissued")
    parent=backend.extract(master,parent_id,rng=guard)
    if child_id not in parent.children:
        raise ValueError("no fixed child address to restore; no implicit issuance")
    if parent.children[child_id] is None:
        try: backend.derive(parent,child_id,rng=guard)
        except ABBSamplingAbort:
            return dict(status="passed-failed-address-restore",failed_child_retained=True,new_private_entropy_calls=guard.calls)
        raise AssertionError("failed child was reissued")
    leaf=backend.derive(parent,child_id,rng=guard)
    if (parent.to_bytes()!=(directory/"parent.bin").read_bytes() or
            leaf.to_bytes()!=(directory/"leaf.bin").read_bytes()):
        raise ValueError("fixed issued key differs from saved key")
    return dict(status="passed-issued-address-restore",new_private_entropy_calls=guard.calls,
        decryption_rerun=False,fresh_SamplePre_still_required_for_decryption=True)


def run(directory,params,baseline_commit,max_rss_mib):
    check_setup_profile(params)  # full public gate before directory or entropy
    directory.mkdir(parents=True,exist_ok=False)
    pending=directory/"pending"
    pending.write_text("setup\n")
    before=source_fingerprints()
    record=dict(schema="ABB-REAL-HIBE-VERTICAL/1",status="running",params=params.to_record(),
        parent_identity_bytes=86,child_identity_bytes=86,payload_bytes=32,repetitions=1,
        rng="default system CSPRNG, explicitly counted",root_generations=0,
        baseline_commit=baseline_commit,source_sha256_before=before,stages=[],
        full_HIBE_lifecycle=False,full_IBME_combination=False,security_claim="none",
        backend_admitted=False,parameters_are_formal=False,matrix_RO_indifferentiability_verified=False,
        observer_rss_budget_mib=max_rss_mib,
        observer_rss_scope='sum of parent and all live descendants, shared pages counted per process',
        environment=dict(python=platform.python_version(),sage=sage_version,platform=platform.platform(),
            processor_model=next((line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines()
                if line.startswith('model name')),'unavailable')))
    entropy=CountedSystemEntropy();master=None;parent=None
    backend=ABBROMHIBE(persist_pending=lambda owner:write_private(directory/"master.bin",master.to_bytes()))
    started=perf_counter()
    stop=threading.Event()
    peak_tree_rss=[0]

    def observe_rss():
        while not stop.wait(1):
            rss,descendants=process_tree_rss(os.getpid())
            peak_tree_rss[0]=max(peak_tree_rss[0],rss)
            if rss>max_rss_mib*1024:
                (directory/"resource-interruption.json").write_text(json.dumps(dict(
                    reason="declared observer RSS budget exceeded",rss_kib=rss,budget_mib=max_rss_mib,
                    requested_signal="SIGINT",stage=record.get("current_stage"),
                    not_a_paper_or_distribution_failure=True),indent=2)+"\n")
                # Interrupt this experiment's native children as well. Waiting
                # for a child does not make parent-only SIGINT a resource stop.
                for child in descendants-{os.getpid()}:
                    try:os.kill(child,signal.SIGINT)
                    except ProcessLookupError:pass
                os.kill(os.getpid(),signal.SIGINT)
                return

    observer=threading.Thread(target=observe_rss,daemon=True)
    observer.start()

    def stage(name,operation):
        pending.write_text(name+"\n")
        record["current_stage"]=name
        (directory/"progress.json").write_text(json.dumps(record,indent=2)+"\n")
        at=perf_counter();used=entropy.bytes_used
        result=operation()
        record["stages"].append(dict(stage=name,status="passed",seconds=perf_counter()-at,
            private_entropy_bytes=entropy.bytes_used-used))
        return result

    parent_id,child_id=paths()
    try:
        public,master=stage("actual AP09 setup",lambda:backend.setup(params,rng=entropy))
        record["root_generations"]=1
        write_private(directory/"public.bin",public.to_bytes())
        write_private(directory/"master.bin",master.to_bytes())
        # Only this process writes the tree. Root/parent serializers use
        # reentrant locks; the callback is not a multi-writer transaction API.
        parent=stage("actual parent SampleR/BasisDel",lambda:backend.extract(master,parent_id,rng=entropy))
        write_private(directory/"master.bin",master.to_bytes())
        leaf=stage("actual leaf SampleR/BasisDel",lambda:backend.derive(parent,child_id,rng=entropy))
        write_private(directory/"master.bin",master.to_bytes())
        write_private(directory/"parent.bin",parent.to_bytes())
        write_private(directory/"leaf.bin",leaf.to_bytes())
        payload=entropy.read(32)
        ct=stage("256 actual original noisy bit Encrypts",lambda:backend.encrypt(public,parent_id,child_id,payload,rng=entropy))
        write_private(directory/"ciphertext.bin",ct.to_bytes())
        restored=ABBCiphertext.from_bytes(ct.to_bytes())
        recovered=stage("256 fresh actual SamplePre Decrypts",lambda:backend.decrypt(leaf,restored,rng=entropy))
        if recovered!=payload:raise ArithmeticError("honest 32 B payload did not recover")
        restored_master=ABBMasterSecret.from_bytes(master.to_bytes())
        guard=NoIssuanceEntropy()
        reused=backend.extract(restored_master,parent_id,rng=guard)
        reused_leaf=backend.derive(reused,child_id,rng=guard)
        if reused_leaf.to_bytes()!=leaf.to_bytes() or guard.calls:
            raise ArithmeticError("fixed key restore changed key or consumed private entropy")
        record.update(status="passed",full_HIBE_lifecycle=True,codec_five_roles_verified=True,
            issued_address_reuse_private_entropy_calls=guard.calls,
            wire_bytes=dict(public=len(public.to_bytes()),master=len(master.to_bytes()),
                parent=len(parent.to_bytes()),leaf=len(leaf.to_bytes()),ciphertext=len(ct.to_bytes())))
    except (Exception,KeyboardInterrupt) as exc:
        record.update(status="failed",failure_type=type(exc).__name__)
        if master is not None:
            # This file remains the sole authoritative state, including FAILED.
            write_private(directory/"master.bin",master.to_bytes())
            record["failed_parent_retained"]=master.parents.get(parent_id,"absent") is None
            record["failed_child_retained"]=(None if parent is None else parent.children.get(child_id,"absent") is None)
        elif entropy.bytes_used:
            record["root_generations"]=None  # Setup did not return; do not invent a completed root count
    finally:
        stop.set()
    record.update(seconds=perf_counter()-started,private_entropy_bytes=entropy.bytes_used,
        peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        peak_process_tree_rss_kib=peak_tree_rss[0],
        source_sha256_after=source_fingerprints())
    record["source_unchanged_during_execution"]=record["source_sha256_after"]==before
    if not record["source_unchanged_during_execution"]:
        record["status"]="failed-source-changed"
    (directory/"receipt.json").write_text(json.dumps(record,indent=2)+"\n")
    if record["status"]=="passed":pending.rename(directory/"completed")
    print(json.dumps({k:record.get(k) for k in ("status","current_stage","seconds","private_entropy_bytes","failure_type")}))
    return 0 if record["status"]=="passed" else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-directory",required=True,type=Path)
    parser.add_argument("--params-file",type=Path)
    parser.add_argument("--baseline-commit",default="uncommitted-WIP")
    parser.add_argument("--restore-only",action="store_true")
    parser.add_argument("--max-rss-mib",type=int,default=8192)
    args=parser.parse_args()
    if args.restore_only:
        if args.params_file:parser.error("restore uses embedded exact parameters")
        print(json.dumps(restore_only(args.private_directory)))
        return 0
    params=q104_research_params() if args.params_file is None else ABBROMParams.from_bytes(args.params_file.read_bytes())
    if not 1024<=args.max_rss_mib<=16384:parser.error("observer RSS budget must be 1024..16384 MiB")
    return run(args.private_directory,params,args.baseline_commit,args.max_rss_mib)


if __name__=="__main__":raise SystemExit(main())
