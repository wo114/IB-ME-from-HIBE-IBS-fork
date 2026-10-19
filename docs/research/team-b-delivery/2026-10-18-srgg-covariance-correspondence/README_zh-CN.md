# SRGG 表 3 与算法 7 的协方差对应审计

Jia、Liu、Tang、Wang，*Constructing Efficient Identity-Based Signatures on Lattices*，DOI `10.1049/ise2/6684889`。本包仅核对仓库冻结的[论文 PDF](../../../../papers/2025_efficient_ibs_jia.pdf)（SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`）§2.2 第 3 页、表 3 第 6 页和算法 7 第 8 页；不修改原后端，也不替换原参数。

论文扰动 shape 减去 `r²[y;1][yᵗ,1]`，但算法 7 把标量 Gaussian 乘以满足 `ζζ*=2` 的 `ζ=1+X^(n/2)`。[精确代数与路线记录](proof.md)表明，该变量在 `c+ζR` 上的**密度 shape 为 `2r²`**。原始 `n=512` 下，陪集指数为 `2^256`，精确归一化常数依赖挑战。在通常的、仅作条件分析的独立连续 Gaussian 卷积中，输出 shape 为 `Σ̄+r²[y;1][yᵗ,1]`，而不是论文写的目标 `Σ̄`。把密度 shape 换成物理协方差或标准差，仍保留相对因子 2。不能把这个连续运算说成实际离散签名的协方差或完整分布。

[独立检查程序](../../../../experiments/research/candidates/srgg/paper_covariance_correspondence.py)用精确整数／有理数环恒等式产生 [JSON 回执](covariance-correspondence.json)。[定向测试](../../../../tests/test_srgg_paper_covariance_correspondence.py)用独立构造的 Sage 系数矩阵、小维度穷举和原始规模稀疏实例交叉核验。Table 4 三行及代码明确列出的两种宽度解释均未改动；PDF 相关页面也已渲染目视核对。

在仓库根目录、规定的 WSL Sage 环境运行：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_covariance_correspondence
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_covariance_correspondence.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python docs/research/team-b-delivery/2026-10-18-srgg-covariance-correspondence/verify_delivery.py
```

实测测试结果与边界见[验收记录](validation.json)。主路线及两条替代路线都未统一论文印出的两个公式；路线及失败原因保留在 `proof.md`。作者意图、完整签名分布和安全界仍未闭合。`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。
