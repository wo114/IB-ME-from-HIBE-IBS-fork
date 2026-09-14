"""导出一个真实的 ISIS 实例（F_id, h2）供 forge_ibs_lll.sage 使用。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from ibme.core.randomness import DeterministicRandom  # noqa: E402
from ibme.ibs.sis_ibs import (  # noqa: E402
    SisIBSBackend, IBS_EDUCATION_PARAMS, f_id_matrix, h2_vector,
)

IDENTITY = b"Alice"
MESSAGE = b"lll-forgery-target"
SEED = b"lll-case"

backend = SisIBSBackend(rng=DeterministicRandom(SEED))
public_key, _ = backend.setup(IBS_EDUCATION_PARAMS)
f_id = f_id_matrix(public_key, IDENTITY)
target = h2_vector(public_key, IDENTITY, MESSAGE)
json.dump(
    {
        "q": public_key.q, "n": f_id.rows, "cols": f_id.cols,
        "beta": public_key.norm_bound,
        "F": f_id.to_lists(), "h2": target.to_list(),
    },
    open("isis_case.json", "w"),
)
print(f"已导出 isis_case.json: n={f_id.rows} cols={f_id.cols} "
      f"q={public_key.q} beta={public_key.norm_bound:.1f}")
