"""实测诚实签名与伪造签名的范数分布，判断验签界是否存在可行取值。

方案要成立的必要条件是存在一个界 beta 满足::

    max(诚实签名范数) <= beta < min(攻击者可达的伪造范数)

本脚本只报告实测数据，不做任何理论外推。伪造侧使用线性代数解（随机列子集
搜索取最短）；用 LLL 可以得到更短的伪造，见 forge_ibs_lll.sage。

用法::

    python experiments/attacks/norm_distribution.py [--honest 1000] [--forge 30]
"""

from __future__ import annotations

import argparse
import math
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from ibme.core.randomness import DeterministicRandom  # noqa: E402
from ibme.ibs.sis_ibs import (  # noqa: E402
    SisIBSBackend,
    IBS_EDUCATION_PARAMS,
    SisSignature,
    f_id_matrix,
    h2_vector,
)

from forge_ibs import solve_square  # noqa: E402


def summary(name, values):
    values = sorted(values)
    count = len(values)
    print(
        f"  {name:<10} n={count:<5} min={values[0]:7.1f}  "
        f"p5={values[count // 20]:7.1f}  median={values[count // 2]:7.1f}  "
        f"max={values[-1]:7.1f}"
    )
    return values


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--honest", type=int, default=1000)
    parser.add_argument("--forge", type=int, default=30)
    parser.add_argument("--subsets", type=int, default=60,
                        help="每个伪造目标尝试的列子集数量，取最短结果")
    args = parser.parse_args()

    backend = SisIBSBackend(rng=DeterministicRandom(b"norm-distribution"))
    public_key, master = backend.setup(IBS_EDUCATION_PARAMS)
    print(f"参数 {IBS_EDUCATION_PARAMS.name}: n={public_key.n} q={public_key.q} "
          f"cols={public_key.f_id_cols} beta={public_key.norm_bound:.1f}")
    print()

    honest = []
    per_identity = max(1, args.honest // 10)
    for index in range(10):
        signing_key = backend.key_extract(master, b"identity-%d" % index)
        for i in range(per_identity):
            signature = backend.sign(signing_key, b"message-%d-%d" % (index, i))
            honest.append(math.sqrt(signature.norm_squared))

    rng = random.Random(99)
    forged, accepted = [], 0
    for trial in range(args.forge):
        identity = b"target-%d" % (trial % 7)
        message = b"forged-%d" % trial
        f_id = f_id_matrix(public_key, identity)
        target = h2_vector(public_key, identity, message)
        grid, size, cols = f_id.to_lists(), f_id.rows, f_id.cols
        best = None
        for _ in range(args.subsets):
            columns = rng.sample(range(cols), size)
            solution = solve_square(
                [[grid[i][j] for j in columns] for i in range(size)],
                target.to_list(),
                public_key.q,
            )
            if solution is None:
                continue
            vector = [0] * cols
            for column, value in zip(columns, solution):
                vector[column] = (
                    value - public_key.q if value > public_key.q // 2 else value
                )
            norm = math.sqrt(sum(v * v for v in vector))
            if best is None or norm < best[0]:
                best = (norm, vector)
        if best is None:
            continue
        norm, vector = best
        forged.append(norm)
        if backend.verify(public_key, identity, message, SisSignature(vector)):
            accepted += 1

    print("=== 实测范数分布 ===")
    honest = summary("诚实", honest)
    forged = summary("伪造", forged)
    print(f"  伪造签名被 verify() 接受: {accepted} / {len(forged)}")
    print()
    print("=== 是否存在可行的验签界 ===")
    print(f"  需要满足: max(诚实)={honest[-1]:.1f} <= beta < min(伪造)={forged[0]:.1f}")
    feasible = honest[-1] < forged[0]
    print(f"  可行: {feasible}")
    if not feasible:
        print("  -> 两个区间重叠，不存在任何 beta 能接受全部诚实签名并拒绝全部伪造。")
    else:
        print("  -> 本次采样未重叠；但 LLL 可得到更短的伪造，见 forge_ibs_lll.sage。")
    print(f"  当前 beta = {public_key.norm_bound:.1f}，高于两者，因此两者皆被接受。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
