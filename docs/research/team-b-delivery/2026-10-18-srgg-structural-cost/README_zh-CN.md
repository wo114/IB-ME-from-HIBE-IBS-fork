# 《Constructing Efficient Identity-Based Signatures on Lattices》结构攻击成本审计

**作者：**Huiwen Jia、Ying Liu、Chunming Tang、Lin Wang。**来源：***IET Information Security*（2025），DOI [10.1049/ise2/6684889](https://doi.org/10.1049/ise2/6684889)；本地冻结原文 `papers/2025_efficient_ibs_jia.pdf`，SHA-256 为 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。

本包只审计原文 Table 4 参数下一个明确的攻击成本边界，属于公开代数核验，不是正式安全等级复现。原文 §5.2.1–5.2.3 和 Table 5 报告通用 LWE/SIS 的 BKZ/Core-SVP 估计；本包没有重跑估计器，也不推出 NIST 等级。

三档原参数均有 `Q=15,744,063 < 2γ`。在单位块的一列放入单个整数系数 `Q`，其余为零，得到一个非零、范数为 `Q` 的**无限制整数 Q-MSIS、短核界为 `2γ`** 的解。稀疏输出只写一个非零系数，不读取公钥矩阵，不调用 BKZ。实际模 `2Q` 验证矩阵的 `2A` 块也把该向量送到零；这对每把公钥、每个被接受的 Setup 根成立。它只给出这项精确定义的短核搜索的成本上界，不等于恢复主私钥或对新消息直接伪造。

已知一个合法签名时，攻击者可扫描响应前 `4dn` 个系数并尝试一次 `±Q` 变动；承诺和消息挑战不变。设原响应平方范数为 `S`、这些系数中的最大绝对值为 `M`，则最佳单系数变动后的平方范数恰为 `S+Q²−2QM`；当它不超过 `floor(γ²)` 时，通过原范数门。本包只给出这个**条件式**判据，没有把它写成成功概率。既有真实运行中的同消息替换回执是另一份证据，本包没有新增签名攻击实验。

| 档位 | `d` | 原文 `γ` | 可变动响应系数数 | `Q < γ` | 原文 Table 5 经典密钥／伪造位数 |
|---|---:|---:|---:|---|---|
| PARAM-I | 2 | 42,086,491.7 | 4,096 | 是 | 105 / 103 |
| PARAM-II | 3 | 63,653,172.0 | 6,144 | 是 | 178 / 171 |
| PARAM-III | 4 | 86,573,930.5 | 8,192 | 是 | 255 / 242 |

该单系数见证在 `3`、`31²`、`43`、`127` 各系数 CRT 分量上都为零。相应的环因子次数 `256`、`32`、`256`、`8` 本身不是攻击成本。另一项精确反例说明：仅保留每第 64 个系数来映到八次子环**不保持乘法**，因为 `X`、`X^63` 的投影都为零，而二者乘积的投影为 `Y=X^64`。真正的商域 CRT 投影保持乘法，但短向量全环提升、被接受根的分布以及 CRT／子域 CVP 的具体成本仍未建立。

审查入口为[证明和范围](proof.md)、[机器回执](structural-cost.json)、[验证记录](validation.json)与[英文 README](README.md)。在规定 WSL Sage 中复跑：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_structural_cost --output /tmp/srgg-structural-cost-fresh.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_structural_cost.py
```

原 Table 4 输入、既有两种 Gaussian 记号解释和后端均未改动；不涉及 HIBE。仍保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。功能代数检查不代替安全归约。若把原文 Theorem 1 的 `q` 映射到原表 `Q`，其 `q>2γ` 条件不满足；原文 `q/Q/2Q` 映射及原生 strong 游戏对应仍待核。
