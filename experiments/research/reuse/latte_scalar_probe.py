"""Deterministic entropy-flow counterexample, NOT a sampler replacement.

Uses MIT-licensed upstream functions verbatim in a bounded public C harness.
The comparison edit only changes Box-Muller reads to the buffer just filled.
It establishes a source-level defect, not a distribution/security proof.
"""

from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent
VENDOR = HERE/"vendor/latte"


def _function(source,name):
    match=re.search(r"(?:static inline )?int64_t "+name+r"\([^;]*?\)\s*\{",source)
    if match is None: raise ValueError("pinned LATTE function not found")
    start,position=match.start(),match.end()-1
    balance=0
    for end in range(position,len(source)):
        if source[end]=="{":balance+=1
        if source[end]=="}":balance-=1
        if balance==0:return source[start:end+1]
    raise ValueError("incomplete source function")


def source_check():
    manifest=json.loads((VENDOR/"UPSTREAM.json").read_text())
    raw=(VENDOR/"sample_z.upstream.c").read_bytes()
    if sha256(raw).hexdigest()!=manifest["files"]["sample_z.upstream.c"]["sha256"]:
        raise ValueError("LATTE source differs from pinned input")
    source=raw.decode()
    scalar=_function(source,"sample_z")
    return dict(revision=manifest["revision"],source_sha256=sha256(raw).hexdigest(),
                fresh_box_muller_buffer_filled="fastrandombytes((unsigned char *)r_bm, BOX_MULLER_BYTES);" in scalar,
                fresh_box_muller_buffer_read="*((uint64_t *)r_bm)" in scalar or "*((uint64_t *)(r_bm + 8))" in scalar,
                reused_comparison_buffer_read="*((uint64_t *)r)" in scalar and "*((uint64_t *)(r + 8))" in scalar)


def run_probe(directory):
    check=source_check()
    source=(VENDOR/"sample_z.upstream.c").read_text()
    scalar=_function(source,"sample_z")
    comparison=_function(source,"cosac_comp")
    defines=[]
    for line in source.splitlines():
        if line.startswith("#define "):
            name=line.split()[1]
            if name.startswith(("FP_","COSAC_")) or name in ("BOX_MULLER_BYTES","COMP_ENTRY_SIZE","DISCRETE_BYTES"):
                defines.append(line)
    constants="static const double pi2=2*M_PI;\nstatic const double sqrt_pi2=2/(M_SQRT1_2*M_2_SQRTPI);\n"
    harness=r'''
#include <stdint.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int mode=0,calls=0;
void fastrandombytes(unsigned char *out, unsigned long count) {
    calls++;
    if(calls>16) exit(41);
    memset(out,0,count);
    if(calls==1) {if(count!=12) exit(42);memset(out,255,count);}
    else if(calls==2) {if(count!=24) exit(43);}
    else if(calls==3) {
        if(count!=16) exit(44);
        uint64_t a=mode?0:((1ULL<<53)-1);
        uint64_t b=mode?((1ULL<<51)-1):0;
        memcpy(out,&a,8);memcpy(out+8,&b,8);
    }
}
'''
    main='\nint main(int argc,char **argv){mode=atoi(argv[1]);long long x=sample_z(0.0,3.0);printf("%lld %d\\n",x,calls);return 0;}\n'
    directory=Path(directory)
    directory.mkdir(parents=True,exist_ok=True)
    outputs={}
    patched=scalar.replace("*((uint64_t *)r)","*((uint64_t *)r_bm)").replace("*((uint64_t *)(r + 8))","*((uint64_t *)(r_bm + 8))")
    if scalar==patched:raise ValueError("expected pinned buffer reads not present")
    notice="/* Public diagnostic adapted from LATTE; copyright Raymond K. Zhao; MIT notice in vendor/latte/LICENSE. */\n"
    for name,body in (("upstream",scalar),("buffer_edit",patched)):
        file=directory/(name+".c")
        binary=directory/name
        file.write_text(notice+harness+"\n"+"\n".join(defines)+"\n"+constants+comparison+"\n"+body+main)
        subprocess.run(["gcc","-O1","-fno-strict-aliasing",str(file),"-lm","-o",str(binary)],check=True,capture_output=True,timeout=30)
        values=[]
        for mode in (0,1):
            p=subprocess.run([str(binary),str(mode)],check=True,capture_output=True,text=True,timeout=3)
            value,calls=map(int,p.stdout.split())
            values.append(dict(mode=mode,result=value,entropy_calls=calls))
        outputs[name]=values
    return dict(source=check,controlled_comparison=outputs,
                upstream_ignores_changed_fresh_box_muller_bytes=outputs["upstream"][0]["result"]==outputs["upstream"][1]["result"],
                buffer_edit_restores_dependence=outputs["buffer_edit"][0]["result"]!=outputs["buffer_edit"][1]["result"],
                statistical_sampling_test=False,production_patch_admitted=False,
                security_claim="none",backend_admitted=False)
