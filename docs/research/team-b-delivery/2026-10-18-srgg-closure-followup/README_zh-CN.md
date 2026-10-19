# SRGG 原表参数闭合续审：可核验增量，整体 WIP

论文：Jia、Liu、Tang、Wang，*Constructing Efficient Identity-Based Signatures on Lattices*，DOI `10.1049/ise2/6684889`。仓库冻结 PDF 为 [`papers/2025_efficient_ibs_jia.pdf`](../../../../papers/2025_efficient_ibs_jia.pdf)，SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。本批基线提交 `e38b2ea`，继续核原论文 Table 4 三组 `n=512,p=16383,b=31,w=2,q=961,Q=15744063,d=2/3/4`；只处理 SRGG 独立 IBS，不改 HIBE。

## 已取得的限定结论

| 主题 | 本批新证据 | 适用边界 |
|---|---|---|
| 有限 Fourier/Schur 数值 | [`schur-fixed-root-numerical-normalizer.json`](schur-fixed-root-numerical-normalizer.json)：三组 × 两种 Gaussian 解释共六个真实、固定、成功发钥根；独立区间重放检查 master/sign 的 gain 与 covariance 误差各至多 `2^-128`，同一成功历史上的中心系数误差至多 `2^-96` | 固定根上的局部数值关系；完整整数输出 TV 和所有输入的有限 FFT/Box–Muller 误差仍为 `null` |
| 理想逐环归一化偏差 | 同一回执证明六个固定根的理想 Schur pivot eigenvalue ≥64；Poisson 全中心 normalizer 界与乘积倾斜给理想逐环离散链到同 shape 联合离散 Gaussian 的 TV 上界：I master/sign `2^-278/2^-277`，II/III `2^-277/2^-276` | 只比较**理想数学链**，不覆盖有限采样器、全部可接受 Setup 根或发钥/签名后的服务分布；证明与前提见 [`paper_schur_normalizer.py`](../../../../experiments/research/candidates/srgg/paper_schur_normalizer.py) |
| Setup 正定与重试 | [`setup-conditioning.json`](setup-conditioning.json)：原表两种记号解释的严格正定门等价于 `||M(R)||²<L²`。普通矩阵 Bernstein 界三行均退化为 1；唯一替代稀疏 `ℓ1` 门给每次接受概率正下界 `2^-6371/2^-15031/2^-27375`，并列 64 次重试及请求字节上限 | 下界过小，**不能**证明有用的中止概率；数值准备成功、接受后的根分布和真实 Setup 总错误仍为 `null` |
| 环结构 | [`ring-crt-31sq.json`](ring-crt-31sq.json)：实际构造 `31²` 分量上 `X^512+1` 的 16 个 32 次 Hensel 提升因子与幂等元，验证投影、两两正交、求和及多项式重构 | 原表其余素因子的域分解与 HNF/MSIS 形状在[前批预检](../2026-10-18-srgg-source-schur/hardness-preflight-current.json)；本批未从因子次数推出攻击成本或 CBD1/接受根的整体困难性 |
| 多次调用历史 | [`paper_history_law.py`](../../../../experiments/research/candidates/srgg/paper_history_law.py) 给初态和逐次完整转换都已知 TV 时，至多 `2^40` 次自适应发钥/签名/故障历史的精确 union 上界，保留中止/故障原子 | Source-Schur 单次全 TV、全接受根初态 law、故障 kernel 未知，**当前 SRGG 历史上界为 `null`** |
| 资源 | [`resource-observations.md`](resource-observations.md) 对照七轮最终回执，列出对象字节、一次 setup/extract/sign 时间及整次 sign 硬耗熵帽 | 单次 Python/Sage 重叠运行，不是作者 C/ANS/1000 次性能复现；峰值 RAM、时限、服务终身熵仍缺 |

原文与实现的冲突、`r≈1.16` 必要平滑门、`q/Q/2Q`、`ζ` 因子和 native strong 的真实同消息替换，见[`来源与安全复核`](source-and-security-review.md)。已知反例和未确认公式均保留，不能把本批数学局部结论拼成完整安全归约。

## 复核入口

在仓库根目录的 WSL `~/miniconda3/envs/sage` 环境运行：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_ring_crt_lift --output build/recheck-ring-crt.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_setup_conditioning > build/recheck-setup-conditioning.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_schur_numerical_audit --output build/recheck-schur-numerical.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg*.py
```

命令的输出目标须使用不存在的新路径，以保留旧回执。原表七轮完整生命周期和先前全部失败证据保持原状；本批没有重新跑作者 C/ANS/1000 次基准。当前安全标记是 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。功能测试、有限反例和局部 TV 界不能替代完整安全证明。

本批完整 SRGG 回归为 **1714 passed、0 failed，375.37 秒**；详细边界见 [`validation.json`](validation.json)。包内文件的哈希与安全标记可用 `python docs/research/team-b-delivery/2026-10-18-srgg-closure-followup/verify_followup.py` 检查，清单见 [`MANIFEST.json`](MANIFEST.json)。
