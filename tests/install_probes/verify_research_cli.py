"""A real installed CLI lifecycle from outside the source checkout.

Every subprocess uses python -I and one explicit installed-package import root.
Native conversion is configured only where new roots/receiver keys need it.
Private state stays in the explicitly supplied ignored test workspace.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

MESSAGE=b"Installed A research backend CLI roundtrip"
BOOTSTRAP="import sys; sys.path.insert(0,sys.argv.pop(1)); from ibme.cli import main; raise SystemExit(main(sys.argv[1:]))"


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--install-root",type=Path,required=True)
    p.add_argument("--checkout",type=Path,required=True)
    p.add_argument("--engine",type=Path,required=True)
    p.add_argument("--private-directory",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    checkout=a.checkout.resolve();install=a.install_root.resolve()
    directory=a.private_directory.resolve();output=a.output.resolve()
    allowed=(checkout/"test-results").resolve()
    assert sys.flags.isolated==1 and not Path.cwd().resolve().is_relative_to(checkout)
    if not directory.is_relative_to(allowed) or output.is_relative_to(directory) or output.exists():
        raise ValueError("new ignored private directory and separate new public receipt required")
    directory.mkdir(parents=True,exist_ok=False)
    pending=directory/"generation.pending";pending.write_bytes(b"one installed CLI lifecycle; no restart\n")
    state=directory/"state";message=directory/"message.bin";ciphertext=directory/"ciphertext.bin"
    message.write_bytes(MESSAGE)
    events=[];start=time.monotonic()
    def invoke(name,args,*,engine):
        env=dict(os.environ)
        env.pop("PYTHONPATH",None);env.pop("IBME_QFALL_PRIVATE_ENGINE",None)
        if engine:env["IBME_QFALL_PRIVATE_ENGINE"]=str(a.engine.resolve())
        command=[sys.executable,"-I","-c",BOOTSTRAP,str(install),*args]
        print(json.dumps({"stage":name,"elapsed_seconds":time.monotonic()-start}),flush=True)
        completed=subprocess.run(command,cwd=Path.cwd(),env=env,capture_output=True,text=True,timeout=180)
        (directory/(name+".stdout.txt")).write_text(completed.stdout,encoding="utf-8")
        (directory/(name+".stderr.txt")).write_text(completed.stderr,encoding="utf-8")
        events.append(dict(stage=name,exit_code=completed.returncode,engine_configured=engine,
            elapsed_seconds=time.monotonic()-start))
        (directory/"progress.json").write_text(json.dumps(events,indent=2)+"\n",encoding="utf-8")
        return completed
    def success(name,args,engine=False):
        result=invoke(name,args,engine=engine)
        if result.returncode:raise RuntimeError(f"installed CLI {name} failed; see ignored diagnostics")
        return result
    success("setup",["setup","--state",str(state),"--hibe","mp12-chkp-reference",
        "--hibe-params","n2-reference","--ibs","luo-module","--transport","hybrid",
        "--signature-format","compact"],engine=True)
    success("issue_sender",["issue-sender-key","Alice","--state",str(state)])
    success("issue_receiver",["issue-receiver-key","Bob","--state",str(state)],engine=True)
    success("encrypt",["encrypt","--state",str(state),"--sender","Alice","--receiver","Bob",
        "--in",str(message),"--out",str(ciphertext)])
    recovered=directory/"recovered.bin"
    success("first_decrypt",["decrypt","--state",str(state),"--sender","Alice","--receiver","Bob",
        "--in",str(ciphertext),"--out",str(recovered)])
    assert recovered.read_bytes()==MESSAGE
    # The stored full receiver basis and fixed leaf do not require the native
    # engine for either first leaf generation or subsequent cached decrypt.
    restored=directory/"restored.bin"
    success("restored_decrypt",["decrypt","--state",str(state),"--sender","Alice","--receiver","Bob",
        "--in",str(ciphertext),"--out",str(restored)])
    assert restored.read_bytes()==MESSAGE
    success("existing_receiver_reuse",["issue-receiver-key","Bob","--state",str(state)])
    raw=ciphertext.read_bytes();bad=bytearray(raw);bad[-1]^=1
    tampered=directory/"tampered.bin";tampered.write_bytes(bad)
    failed_output=directory/"must-not-exist.bin"
    rejection=invoke("tamper_rejected",["decrypt","--state",str(state),"--sender","Alice","--receiver","Bob",
        "--in",str(tampered),"--out",str(failed_output)],engine=False)
    assert rejection.returncode!=0 and not failed_output.exists()
    result=dict(schema="A-INSTALLED-CLI-LIFECYCLE/1",installed_root=str(install),
        isolated_subprocesses=True,cwd_outside_checkout=True,source_python_import_roots_added=False,
        stages=events,message_bytes=len(MESSAGE),repetitions=1,
        matching_message_recovered=True,second_process_recovered_without_engine=True,
        existing_receiver_reused_without_engine=True,modified_ciphertext_rejected=True,
        complete_ciphertext_bytes=len(raw),elapsed_seconds=time.monotonic()-start,
        native_engine_sha256=hashlib.sha256(a.engine.read_bytes()).hexdigest(),
        parameters=dict(n=2,q=549755813911,r_width_squared=16),
        security_claim="none",backend_admitted=False,parameters_are_formal=False,
        known_n2_privacy_attack_unchanged=True,limitations=["debugging parameters","no formal model/security admission"])
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open("x",encoding="utf-8") as f:f.write(json.dumps(result,indent=2)+"\n")
    pending.unlink()
    print(json.dumps({"stages":len(events),"elapsed_seconds":result["elapsed_seconds"],"ciphertext_bytes":len(raw)}))
    return 0


if __name__=="__main__":raise SystemExit(main())
