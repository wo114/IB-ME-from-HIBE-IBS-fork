"""把 forge_ibs_lll.sage 求得的短向量送进真实 verify()，确认伪造成立。"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from ibme.core.randomness import DeterministicRandom  # noqa: E402
from ibme.ibs.sis_ibs import (  # noqa: E402
    SisIBSBackend, IBS_EDUCATION_PARAMS, SisSignature,
)

from forge_ibs_lll_export import IDENTITY, MESSAGE, SEED  # noqa: E402

z = json.load(open("isis_forged_z.json"))["z"]
backend = SisIBSBackend(rng=DeterministicRandom(SEED))
public_key, _ = backend.setup(IBS_EDUCATION_PARAMS)
signature = SisSignature(z)
norm = math.sqrt(signature.norm_squared)
accepted = backend.verify(public_key, IDENTITY, MESSAGE, signature)
print(f"LLL 伪造签名 ||z|| = {norm:.2f}   验签界 = {public_key.norm_bound:.2f}")
print(f"非零分量 {sum(1 for v in z if v)} / {len(z)}")
print(f"backend.verify(...) -> {accepted}")
sys.exit(0 if accepted else 1)
