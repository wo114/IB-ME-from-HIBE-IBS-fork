from copy import deepcopy
import hashlib,json
from pathlib import Path
from experiments.research.abb_rom.tight_parameter_frontier import build_frontier_report,finalize_frontier
base=Path("docs/research/team-a-delivery/2026-10-18-abb-noise-tradeoff/parameter-card.json")
source=Path("docs/research/team-a-delivery/2026-10-18-abb-tight-frontier/parameter-card.json")
original=json.loads(source.read_text())
current=build_frontier_report(base,build_cdf=True)
current["estimator"]=deepcopy(original["estimator"])
for row,frozen in zip(current["rows"],original["rows"],strict=True):
    row["estimator_results"]=deepcopy(frozen["estimator_results"])
finalize_frontier(current)
def payload(report):
    j=deepcopy(report)
    for key in ("environment","measurements","source_sha256"): j.pop(key,None)
    j["finite_ciphertext_noise"].pop("build_seconds",None)
    return j
if payload(current)!=payload(original):
    print("different sections:",[k for k in payload(original) if payload(current).get(k)!=payload(original)[k]])
    raise ValueError("frontier mathematical replay differs")
current["review_replay"]={"source_card_sha256":hashlib.sha256(source.read_bytes()).hexdigest(),"geometry_and_CDF_recomputed":True,"estimator_rerun":False,"original_estimates_and_their_timings_reused":True,"mathematical_payload_matches_original":True}
import argparse
parser=argparse.ArgumentParser(description="Public frontier/CDF replay; original estimator results are reused")
parser.add_argument("--output",type=Path,required=True)
output=parser.parse_args().output
with output.open("x",encoding="utf-8") as stream: json.dump(current,stream,indent=2,allow_nan=False);stream.write("\n")
print("Four frontier rows and finite CDF replayed; original estimates reused; mathematical payload unchanged")
