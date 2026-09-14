# -*- coding: utf-8 -*-
r"""用 LLL 求 ISIS 最短伪造解（需要 SageMath）。

forge_ibs.py 用朴素线性代数即可伪造；本脚本进一步说明攻击者能把范数压到多低，
从而判断"收紧验签界 beta"是否可行。

做法：所有满足 ``F_id z = h2 (mod q)`` 的整数解构成陪集 ``z0 + L``，其中
``L = {z : F_id z = 0 mod q}``。用核空间基与 ``q*I`` 张成 ``L``，LLL 约化后
再用 Babai 最近平面把 ``z0`` 归约到该陪集的短代表元。

用法（在 WSL 的 sage 环境中）::

    # 第一步：导出实例
    python experiments/attacks/forge_ibs_lll_export.py
    # 第二步：求短解
    ~/miniconda3/envs/sage/bin/sage experiments/attacks/forge_ibs_lll.sage
"""

import json
import os

CASE = os.environ.get("IBME_ISIS_CASE", "isis_case.json")
OUT = os.environ.get("IBME_ISIS_OUT", "isis_forged_z.json")

data = json.load(open(CASE))
q, cols, beta = data["q"], data["cols"], data["beta"]
F = Matrix(GF(q), data["F"])
h2 = vector(GF(q), data["h2"])
print("ISIS 实例: F 为 %d x %d over Z_%d, 验签界 beta = %.1f"
      % (F.nrows(), cols, q, beta))

z0 = vector(ZZ, [int(x) for x in F.solve_right(h2)])
print("  (a) 朴素解              ||z|| = %.2f" % float(z0.norm()))

kernel = F.right_kernel_matrix()
basis = Matrix(ZZ, kernel.nrows() + cols, cols)
for i in range(kernel.nrows()):
    for j in range(cols):
        basis[i, j] = int(kernel[i, j])
for j in range(cols):
    basis[kernel.nrows() + j, j] = q

reduced = basis.LLL()
reduced = reduced.matrix_from_rows(
    [i for i in range(reduced.nrows()) if not reduced[i].is_zero()]
)
print("  解格: %d x %d, 最短基向量 ||b1|| = %.2f"
      % (reduced.nrows(), reduced.ncols(), float(reduced[0].norm())))

gram, _ = reduced.gram_schmidt()
target = vector(QQ, z0)
for i in reversed(range(reduced.nrows())):
    gi = gram[i]
    if gi.is_zero():
        continue
    target = target - round((target * gi) / (gi * gi)) * vector(QQ, reduced[i])
z = vector(ZZ, [ZZ(round(x)) for x in target])
assert F * vector(GF(q), list(z)) == h2, "约化后不再满足 F_id z = h2"

print("  (b) LLL + Babai 约化后  ||z|| = %.2f   非零分量 %d/%d"
      % (float(z.norm()), sum(1 for x in z if x != 0), cols))
json.dump({"z": [int(x) for x in z]}, open(OUT, "w"))
print("  已导出到 %s，可交给 forge_ibs_lll_verify.py 送入真实 verify()" % OUT)
