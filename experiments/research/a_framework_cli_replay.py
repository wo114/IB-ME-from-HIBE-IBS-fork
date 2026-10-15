"""Actual CLI replay of completed A trees, optionally from an installed wheel.

Structured H/G replay forbids all entropy. ABB forbids new issuance while
allowing its mandatory 256 fresh decryption preimages. Raw diagnostics and
private state remain in the explicitly named NEW ignored directory.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

CHILD = r'''
import contextlib,hashlib,io,json,sys,time
from pathlib import Path
site,kind=sys.argv[1:3]
if site!='-':sys.path.insert(0,site)
from ibme.core.randomness import SecureRandom
entropy=0;reads=0;preimages=0
original=SecureRandom.read
def counted(self,n):
    global entropy,reads
    reads+=1
    if kind=='structured':raise AssertionError('structured restore consumed entropy')
    value=original(self,n);entropy+=len(value);return value
SecureRandom.read=counted
class NoIssuance:
    def read(self,n):raise AssertionError('restoration attempted new issuance')
if kind=='structured':
    from ibme.hibe.mp12_structured.backend import StructuredMP12HIBE as HIBE
    from ibme.lattice.matrix_sampling import mp12_extension
    def forbidden(*a,**k):raise AssertionError('structured restore invoked sampler')
    mp12_extension.delegate_extension=forbidden
    mp12_extension.StructuredLeftSampler.sample=forbidden
else:
    from ibme.hibe.abb_rom.backend import ABBROMHIBE as HIBE
    from ibme.lattice.matrix_sampling import MatrixFiniteGPV
    old_sample=MatrixFiniteGPV.sample
    def sampled(self,*a,**k):
        global preimages
        preimages+=1;return old_sample(self,*a,**k)
    MatrixFiniteGPV.sample=sampled
def no_setup(*a,**k):raise AssertionError('restored CLI invoked new HIBE Setup')
HIBE.setup=no_setup
def cached(function):
    def call(self,*a,**k):k['rng']=NoIssuance();return function(self,*a,**k)
    return call
HIBE.extract=cached(HIBE.extract);HIBE.derive=cached(HIBE.derive)
from ibme.cli import main
out=io.StringIO();err=io.StringIO();exception=None;start=time.perf_counter()
with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
    try:code=main(sys.argv[3:])
    except BaseException as exc:code=99;exception=type(exc).__name__
providers={}
for name,module in list(sys.modules.items()):
    path=getattr(module,'__file__',None)
    if path and path.endswith('.py') and (name.startswith('ibme.') or name.startswith('experiments.')):
        p=Path(path).resolve()
        if site!='-' and not p.is_relative_to(Path(site).resolve()):raise AssertionError('provider outside installed root')
        providers[name]=dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest())
print(json.dumps(dict(code=code,exception=exception,stdout=out.getvalue(),stderr=err.getvalue(),
    seconds=time.perf_counter()-start,entropy_reads=reads,entropy_bytes=entropy,
    fresh_preimages=preimages,providers=providers,isolated=bool(sys.flags.isolated))))
'''


def snapshot(state):
    return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in state.iterdir()
            if p.is_file() and p.suffix in (".bin", ".json")}


def prepare(source, directory):
    from ibme.assembly import SuiteConfig, build_runtime, validate_suite
    from ibme.protocol.baseline import PublicKey, MasterSecret
    from ibme.cli import _selected_metadata, _state_object, _atomic_write_state
    if not (source/"completed").is_file(): raise ValueError("completed framework source required")
    config = SuiteConfig.from_json((source/"suite.json").read_bytes())
    runtime = build_runtime(config); d = runtime.decoders
    public = PublicKey.from_bytes((source/"public.bin").read_bytes(), d["hpk"], d["ipk"])
    master = MasterSecret.from_bytes((source/"master.bin").read_bytes(), d["hmsk"], d["imsk"])
    runtime.validate_master(public, master)
    state = directory/"state"; state.mkdir()
    meta = _selected_metadata(config, validate_suite(config), hashlib.sha256(public.to_bytes()).hexdigest())
    for filename, role, raw in (("mpk.bin", "mpk", public.to_bytes()), ("msk.bin", "msk", master.to_bytes())):
        _atomic_write_state(state/filename, _state_object(raw, meta, role))
    _atomic_write_state(state/"state.json", (json.dumps(meta, sort_keys=True, indent=2)+"\n").encode())
    return state


def run(args):
    directory = args.private_directory.resolve(); directory.mkdir(parents=True, exist_ok=False)
    site = args.install_root.resolve() if args.install_root else None
    if site:
        if Path.cwd().resolve().is_relative_to(args.checkout.resolve()): raise ValueError("installed replay cwd must be outside checkout")
        sys.path.insert(0, str(site))
    records, start = [], time.perf_counter()
    state = args.existing_state.resolve() if args.existing_state else prepare(args.import_framework.resolve(), directory)
    def command(name, argv, expected=0, preimages=0):
        child = [sys.executable, *( ["-I"] if site else [] ), "-c", CHILD, str(site) if site else "-", args.kind, *map(str, argv)]
        completed = subprocess.run(child, capture_output=True, text=True, timeout=1800)
        if completed.returncode: raise RuntimeError(name+" interpreter failure")
        row = json.loads(completed.stdout)
        (directory/(name+".private-log.json")).write_text(json.dumps(row, indent=2))
        row.pop("stdout"); row.pop("stderr"); row.update(name=name, expected_code=expected)
        records.append(row)
        if row["code"] != expected or row["fresh_preimages"] != preimages:
            raise RuntimeError(name+" CLI result or sampling count mismatch")
        if args.kind == "structured" and row["entropy_reads"] != 0: raise AssertionError("zero-entropy restore failed")
        if preimages == 0 and row["entropy_bytes"] != 0: raise AssertionError("cached issuance or rejection consumed entropy")
        if args.kind == "abb" and preimages and row["entropy_bytes"] <= 0: raise AssertionError("ABB replay did not use fresh entropy")
        if site and not row["isolated"]: raise AssertionError("installed child not isolated")
        (directory/"progress.json").write_text(json.dumps(dict(stage=name, commands=len(records))))
        return row
    if args.import_framework:
        for role, names in (("sender", ("Alice", "Charlie")), ("receiver", ("Bob", "Carol"))):
            for name in names: command(role+"-"+name, ["issue-"+role+"-key", name, "--state", state])
        paths = [(i,j,args.import_framework/f"ciphertext-{i}-{j}.bin") for i in range(2) for j in range(2)]
        message = bytes(range(32))
    else:
        paths = [(0,0,args.ciphertext.resolve())]; message = args.message.read_bytes()
    before = snapshot(state)
    for i, j, ct in paths:
        output = directory/f"decrypted-{i}-{j}.bin"
        command(f"decrypt-{i}-{j}", ["decrypt", "--state", state, "--sender", ("Alice","Charlie")[j],
            "--receiver", ("Bob","Carol")[i], "--in", ct, "--out", output], preimages=256 if args.kind=="abb" else 0)
        assert output.read_bytes() == message
    original = paths[0][2]; wire = original.read_bytes()
    if args.import_framework:
        for label, sender, receiver in (("wrong-sender","Charlie","Bob"), ("wrong-receiver","Alice","Carol"), ("both-wrong","Charlie","Carol")):
            output = directory/(label+".output")
            command(label,["decrypt","--state",state,"--sender",sender,"--receiver",receiver,"--in",original,"--out",output],expected=1)
            assert not output.exists()
    for label, raw in (("truncated",wire[:-1]),("appended",wire+b"x"),("duplicate",wire+wire),("changed",wire[:-1]+bytes([wire[-1]^1]))):
        input_path=directory/(label+".input");input_path.write_bytes(raw);output=directory/(label+".output")
        command(label,["decrypt","--state",state,"--sender","Alice","--receiver","Bob","--in",input_path,"--out",output],expected=1)
        assert not output.exists()
    command("repeat-sender",["issue-sender-key","Alice","--state",state])
    command("repeat-receiver",["issue-receiver-key","Bob","--state",state])
    assert snapshot(state)==before and not list(state.glob("*.pending"))
    providers={}
    for row in records:
        for name, value in row.pop("providers").items():
            if name in providers: assert providers[name]==value
            providers[name]=value
    report=dict(schema="A-FRAMEWORK-CLI-REPLAY/1",status="passed",kind=args.kind,source_commit=args.source_commit,
        imported_original_framework_tree=bool(args.import_framework), existing_original_cli_state=bool(args.existing_state),
        new_hibe_roots=0,new_hibe_keys=0,new_ibs_keys=0,new_signatures=0,
        matching_paths=len(paths),commands=records,providers=providers,state_unchanged_after_publication=True,
        installed_only=bool(site),installed_root=str(site) if site else None,isolated_children=bool(site),
        cwd_outside_checkout=not Path.cwd().resolve().is_relative_to(args.checkout.resolve()),
        structured_restore_zero_entropy=args.kind=="structured",abb_restore_requires_fresh_preimages=args.kind=="abb",
        seconds=time.perf_counter()-start,message_bytes=len(message),repetitions=1,
        security_claim="none",backend_admitted=False,parameters_are_formal=False)
    args.output.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(dict(status="passed",commands=len(records),installed=bool(site))),flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--kind",choices=("abb","structured"),required=True)
    p.add_argument("--private-directory",type=Path,required=True)
    p.add_argument("--checkout",type=Path,required=True)
    p.add_argument("--install-root",type=Path)
    source=p.add_mutually_exclusive_group(required=True)
    source.add_argument("--import-framework",type=Path)
    source.add_argument("--existing-state",type=Path)
    p.add_argument("--ciphertext",type=Path);p.add_argument("--message",type=Path)
    p.add_argument("--output",type=Path,required=True);p.add_argument("--source-commit",default="development")
    args=p.parse_args()
    if args.output.exists(): raise ValueError("new public receipt required")
    if args.existing_state and (not args.ciphertext or not args.message): raise ValueError("existing ciphertext/message required")
    run(args)


if __name__=="__main__":main()
