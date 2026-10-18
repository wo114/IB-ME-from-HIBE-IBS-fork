# SRGG 原表 `r≈1.16` 的精确平滑门核验（WIP）

本批只核 Jia、Liu、Tang、Wang 论文 §5.1 选用的 `η_ε(Z^m)` 数值，不改参数或代码中的采样宽度。冻结原文是 [`papers/2025_efficient_ibs_jia.pdf`](../../../../papers/2025_efficient_ibs_jia.pdf)，SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。§2.2 第 3 页**明确定义** `ρ(x)=exp(−π⟨x,x⟩)` 及 `η_ε(Λ)=min{s>0:ρ(sΛ*)≤1+ε}`；Table 3 第 6 页却把 `r=η_ε(Z^m)`，§5.1 第 9 页写 `r≈1.16`。取原表最大的 `d=4,w=2,n=512`，得到 `m=(2+w)(d+1)n=10240`；原文 `Q_s=2^40`、`ε=1/√(Q_s·256)=2^-24`。

**按原文明确的 `η` 定义**，独立整数格的对偶 theta 条件严格给出

```text
2.9077794 < η_ε(Z^10240) < 2.9077796
```

因此原文“`r=η_ε(...)≈1.16`”的等号与这个两位近似**内部不一致**。若额外假设作者暗中把 `η` 除以 `√(2π)`，当成物理标准差，则换算后的阈值落在 `1.1600361–1.1600363`，确实四舍五入为 `1.16`；§4.2.1 称 `r²` 为方差，也使这个解释值得保留，但原文的 `η` 定义没有写这一步。当前实现的**精确数值** `r=1.16` 在两支解释下都略低于各自阈值。这里保留 Table 4 和程序原值，不偷偷替换成 `2.90778`，也不让任何正式参数准入。

证明在 [`proof.md`](proof.md)。[`smoothing-eta.json`](smoothing-eta.json) 保存 512-bit 有向指数区间、整数格 theta 尾项和两个严格括区的可重算十进制外包络；[`validation.json`](validation.json) 记录环境与测试。代码和测试分别为 [`paper_smoothing_eta.py`](../../../../experiments/research/candidates/srgg/paper_smoothing_eta.py)、[`test_srgg_paper_smoothing_eta.py`](../../../../tests/test_srgg_paper_smoothing_eta.py)。在指定 WSL Sage 环境运行：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_smoothing_eta.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python docs/research/team-b-delivery/2026-10-18-srgg-smoothing-eta/verify_delivery.py
```

该核验没有抽样、身份、消息、签验、HIBE 或 ROM 查询；重复次数不适用。环境为 Windows 11 主机/WSL2、Sage 10.9/Python 3.13.15、Intel Core Ultra 7 255HX/约 31.4 GiB RAM。原文 Table 4 三组仍是研究输入，不是已准入正式参数；本批不复现作者 C/ANS/1000 次性能，也不证明完整 IBS 安全。`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。
