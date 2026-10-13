# SRGG 相关扰动与真实提取组件

本批补上原先缺失的完整相关高斯扰动，并接到已有真实 gadget 提取。代码是 `experiments/research/candidates/srgg/perturbation.py` 与 `perturbation_audit.py`；不是完整 SRGG IBS，不包含 Sign/Verify、消息挑战、状态对象或公共注册。

## 原文选择与实现边界

[原稿](../../../../papers/2025_efficient_ibs_jia.pdf)的 Algorithms 1/3、Table 3 使用 `sigma²=b²*r²`；正文相关位置写 `r²` 的差异保留，不静默混用。完整系数空间目标为：

```text
Sigma_p = Sigma - b²*r² * [R; I] * [R; I]^T
```

新 `MasterPerturbation` 对完整 `Sigma_p` 使用已有 `OnlineNonSphericalSampler`，执行真实有限误差的 GPV 条件采样，保留非零交叉协方差。它实现的是该相关离散 Gaussian 目标分布的参考替代，**不是原稿 Algorithm 4 的连续正态扰动 + 固定 r 随机舍入逐行实现**。原图 `sqrt(d-r²)` 与输入 f 的记号问题仍需澄清；`literal_SampleF_implemented=false`。

公开宽度类必须覆盖实际私有形状，并通过精确正定、shifted floor、Loewner、算术位数、Gaussian/随机带资源门。输出错误类时中止，不回退独立坐标或均匀采样。用户可分别注入扰动和 gadget 随机源；默认均使用系统随机字节。私有 witness、协方差、扰动/提取向量从 repr 和公开 audit 隐去。白名单目标 TV 只属于扰动组件，gadget fiber 界属于 gadget；不把相加数值称为整个密钥分布或 IBS 的安全证明。

## 两套方程必须分别记录

```text
原始实际采样：A*y_raw = H - e (mod Q)
HNF重建之后：A*y     = H     (mod Q)
```

二者由独立 Sage 系数矩阵/商环直接复核。HNF 会改变首块；重建正确性不说明重建 key 与原目标椭球 Gaussian 同分布。`same_Gaussian_claim=false`，`full_IBS_implemented=false`。新代码不会把 `Ay=H` 的功能成功写成卷积/HNF 分布定理已经闭合。

## 本次独立小实例

`degree=2, rank=1, p=5, b=3, digits=1`，gadget模数q=3、总模数Q=15。公开目标宽度平方为 `(512,128)`，r²=4，sigma²=36；完整扰动系数维度6，下块为92I。公开坐标条件宽度类 `[64,512]` 覆盖全部81个CBD1主witness，均以精确算术检查。

新增21项测试先因组件缺失失败，再实现并通过；覆盖实际相关性诊断、81个witness的宽度类、真实gadget与两套独立方程、随机源重放/故障、资源与正定门、无fallback及秘密输出白名单。相关回归和64次新执行收据见同目录 validation.json 与 srgg-audit.json。参数只用于研究，小实例不提供MLWE/MSIS安全性。

复现（在已激活的仓库规定 Sage 环境中，从仓库根执行）：

```bash
PYTHONPATH=src python -m experiments.research.candidates.srgg.perturbation_audit --repetitions 64
PYTHONPATH=src python -m pytest tests/test_srgg_perturbation.py tests/test_srgg_sampling.py tests/test_srgg_geometry.py tests/test_srgg_algebra.py
```

后继需先完成选定版本的记号/噪声因子对应、完整 SampleF 或明确的分布替代论证、卷积和HNF密钥分布、固定身份服务，再实施完整SRGG签名链；不能用此组件把目录状态改成完整IBS。
