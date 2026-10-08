"""Same-output benchmark for complete synthetic HIBE+IBS context absorption.

Measures the context/stream subtask only, including framing, cold preparation,
reads and digest checking. No cryptographic key, HIBE ciphertext or IBS signature
is generated. Both algorithms bind every byte and keep the same block format.
"""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import ssl
import statistics
import sys
from time import perf_counter

from .foo_li_runtime_reference import AddressStream, DOMAINS, VERSION, framed
from .prepared_context_stream import PreparedAddressStream


def run(factory, hibe_public, ibs_public, blocks):
    start=perf_counter()
    context=framed(b"joint-public-context-v1",hibe_public,ibs_public)
    address=framed(VERSION.encode(),DOMAINS[4],context,
        b"public-fixed-test-input-not-a-secret",b"sender",b"message")
    stream=factory(address,blocks*AddressStream.BLOCK)
    checksum=hashlib.sha256()
    for _ in range(blocks):checksum.update(stream.read(AddressStream.BLOCK))
    elapsed=perf_counter()-start
    assert stream.remaining==0
    return elapsed,checksum.hexdigest(),len(address)


def report(repetitions):
    if not 3<=repetitions<=31:
        raise ValueError("Use 3..31 repetitions")
    cases=[]
    for size in [4096,65536,1048576]:
        hibe,ibs=b"H"*(size//2),b"I"*(size//2)
        for blocks in [1,16,128]:
            old,new=[],[]
            reference=None
            # Warm the library; EACH timed run still has its own cold prefix.
            for factory in [AddressStream,PreparedAddressStream]:
                _,value,_=run(factory,hibe,ibs,blocks)
                if reference is None:reference=value
                else:assert value==reference
            orders=[]
            for rep in range(repetitions):
                order=[AddressStream,PreparedAddressStream] if rep%2==0 else [PreparedAddressStream,AddressStream]
                orders.append([x.__name__ for x in order])
                for factory in order:
                    elapsed,value,address_bytes=run(factory,hibe,ibs,blocks)
                    assert value==reference
                    (old if factory is AddressStream else new).append(elapsed)
            a,b=statistics.median(old),statistics.median(new)
            cases.append({"synthetic_HIBE_public_bytes":len(hibe),"synthetic_IBS_public_bytes":len(ibs),
                "total_public_bytes":size,"address_bytes":address_bytes,"blocks":blocks,
                "stream_output_bytes":blocks*AddressStream.BLOCK,"repetitions":repetitions,
                "baseline_seconds":old,"prepared_seconds":new,"baseline_median_s":a,
                "prepared_median_s":b,"median_speedup":a/b,"order":orders,
                "SHA256_of_output":reference,"output_equal_every_run":True,
                "cold_framing_and_preparation_included":True,
                "baseline_address_absorptions":blocks,"prepared_address_absorptions":1})
    return {"schema_version":1,"date":"2026-10-08","security_claim":"none",
        "scope":"synthetic joint public-context framing and SHAKE stream subtask; not full IBME",
        "environment":{"python":sys.version.split()[0],"platform":platform.platform(),
            "processor":platform.processor(),"machine":platform.machine(),"OpenSSL":ssl.OPENSSL_VERSION},
        "block_bytes":AddressStream.BLOCK,"sender_identity_bytes":6,"receiver_identity_bytes":None,"message_bytes":7,
        "parameter_source":"synthetic HIBE/IBS byte contexts, not scheme security parameters",
        "HIBE_ciphertexts_generated":0,"IBS_signatures_generated":0,"real_keys_generated":0,
        "cases":cases,"limitations":["Subtask speedup is not end-to-end protocol speedup",
            "No peak RSS measurement or security-level claim","Small/one-block inputs may not benefit",
            "No change to logical oracle queries, domains, randomness outputs or frozen reference snapshots"]}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repetitions",type=int,default=7)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    result=report(args.repetitions)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
    for c in result['cases']:
        print(f"{c['total_public_bytes']//1024:4} KiB, {c['blocks']:3} blocks: "
              f"{c['baseline_median_s']:.6f}s -> {c['prepared_median_s']:.6f}s, {c['median_speedup']:.2f}x")


if __name__=="__main__":main()
