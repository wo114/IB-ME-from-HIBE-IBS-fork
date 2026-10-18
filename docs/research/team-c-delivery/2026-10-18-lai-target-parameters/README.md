# C1 Lai：PLWE 安全参数候选与配置选择（WIP）

日期：2026-10-18。范围：把 A 点研究参数扩展到 **128-bit 级别的 PLWE 候选**，先筛若干组，再确定一组配置。本文是启发式参数筛查，不是 NIST 等级、HIBE 安全证明或正式准入。

## 1. 结论

**选定 `c2-2048-2p38`：`n=2048, q=274877976577, k=39, l=2, p=2, σ=2, σ_r=1`。**

- PLWE 系数实例估计：**169.9 bit 经典 / 154.2 bit 量子**（固定 estimator、标准攻击；混合攻击未计入，见 §4）。
- 两级生命周期在 Sage 里真实跑通一次（86 B 身份、32 B 消息）：setup 2.79 s、extract 42.21 s、derive 645.0 s、encrypt 121.04 s、decrypt 21.79 s；解密一致。
- 作为目标候选，它的对象很大：PK 1.62 MB、MSK 2.42 MB、SK1 18.8 MB、SK2 34.8 MB、内层 CT 1.23 MB；这是当前 A 点之外的“可用性代价”。
- `c3-2048-2p39` 作为正确性余量更大的备选（164.1/148.9 bit），尚未跑生命周期；`c1-1024` 只有 74.2/67.3 bit，淘汰；A 点只有 11.7/10.6 bit，只能作研究基线。

## 2. 候选表

| 候选 | n | q（bit） | k | 经典/量子估计 | 正确性余量代理 | 结论 |
|---|---|---|---|---|---|---|
| A 点 | 256 | 2,147,484,161（32） | 32 | 11.7 / 10.6 | 1.67 | 研究基线，淘汰 |
| C1 | 1024 | 34,359,754,753（36） | 36 | 74.2 / 67.3 | 1.51 | <128，淘汰 |
| **C2** | **2048** | **274,877,976,577（39）** | **39** | **169.9 / 154.2** | **2.76** | **选定** |
| C3 | 2048 | 549,755,904,001（40） | 40 | 164.1 / 148.9 | 5.25 | 备选，未跑生命周期 |

所有 q 均为素数且 `q≡1 mod 2n`；C2/C3 的 q 在 5 字节系数范围内（`q<2^40`）。

## 3. 尺寸（86 B 身份、公式）

| 候选 | 环元素 | PK | MSK | SK1 | SK2 | 内层 CT |
|---|---|---|---|---|---|---|
| A | 1,024 B | 133 KB | 199 KB | 1.32 MB | 2.40 MB | 101 KB |
| C1 | 5,120 B | 748 KB | 1.12 MB | 8.14 MB | 14.96 MB | 568 KB |
| **C2** | **10,240 B** | **1.62 MB** | **2.42 MB** | **18.82 MB** | **34.80 MB** | **1.23 MB** |
| C3 | 10,240 B | 1.66 MB | 2.48 MB | 19.71 MB | 36.51 MB | 1.26 MB |

C2 的实际单次运行（86 B 身份）：PK 1,617,969 B、MSK 2,416,693 B、SK1 18,821,265 B、SK2 34,795,753 B、CT 1,228,844 B；与公式相差几十字节。

## 4. 估计模型与限制

固定 [lattice-estimator](https://github.com/malb/lattice-estimator) `53da5982597709ba0fdf94ea37a84d822310fd84`，ADPS16 Core-SVP 经典 0.292 / 量子 0.265，LGSA。输入按 PLWE 的系数 LWE 处理：

- 秘密维度 `n`，样本数 `m=(l+k)·n`（公开 `a` 的 l+k 个环样本）；
- `Xs=D(σ)`，`Xe=D(p·σ)`（p=2）；
- 标准攻击 `usvp`、`bdd`、`dual`；`bdd_hybrid`/`bdd_mitm_hybrid`/`dual_hybrid` 在 `n=2048, q≈2^38–2^39` 触发 estimator 的 `math domain error`，未计入，因此这些数字是**不完整攻击集**的启发式结果，不是安全证明。

正确性余量代理：以 n=256 的 q=2^30 失败（残差/容差=1.126）和 q=2^31 通过为基线，按 `n^1.9`、`k^2`、`σ^3` 缩放；C2 代理余量 2.76，实测单次通过。它不是完整误差界证明。

## 5. 选择理由

- C2 是第一个同时满足 **经典与量子估计 ≥128 bit**、且真实生命周期跑通的候选；
- C1 在 n=1024 上只有 74/67 bit，单纯加 q 不能把它推到 128；
- C3 的 q 更大、正确性余量更高，但安全估计略低、尺寸/时间更大；作为 C2 失败时的备选；
- A 点保留为研究/演示参数，不参与安全参数比较。

## 6. 未做与风险

1. 混合攻击未估计；若后续 estimator 修复/补充，C2/C3 的 128-bit 结论可能改变。
2. C2 只跑了 **1 个随机种子**、1 条诚实路径；没有目标参数的错配/篡改/截断/重放矩阵。
3. 没有 perturbation；Klein 采样仍是功能级，不是证明级 `ringSampleD`。
4. C2 已作为 `target-research` 显式 preset 登记，但不是默认 preset；`lai-ideal-hibe` 的默认/CLI 起点仍是 A 点。要把它提升为默认目标配置，需要参数审查、负测试、CLI/状态容量检查和性能评估。
5. 尺寸/时间：SK2 约 35 MB、CT 约 1.23 MB、完整生命周期约 13 分钟（Sage）；目标演示需评估是否可接受或改 C/优化实现。
6. 本文不声称 NIST category、QROM 安全或完整 HIBE 安全；`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。

## 7. 复现

候选表与尺寸计算：

```sh
PYTHONPATH=src:. python -m experiments.research.candidates.lai.target_parameters
```

估计器运行使用固定 checkout（仓库外）：

```sh
# 模型：LWE.Parameters(n, m=(2+k)*n, q, Xs=D(2), Xe=D(4))
# ADPS16 classical/quantum, lgsa, deny_list=("arora-gb","bkw",
#   "bdd_hybrid","bdd_mitm_hybrid","dual_hybrid")
```

C2 生命周期探针已入仓：`experiments/research/candidates/lai/target_probe.py`。运行：

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python \
  -m experiments.research.candidates.lai.target_probe
```

记录的单次运行使用 86 B 身份、32 B 消息、固定种子；不是 JUnit/CI 收据，也不是多随机种子统计。
