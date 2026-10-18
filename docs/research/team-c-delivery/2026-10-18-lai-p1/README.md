# C1 Lai P1：IBE 与两级 HIBE 研究后端（教学参数，WIP）

状态：**研究后端 WIP，未登记、未准入**。`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。本交付不改变 `lai-ideal-hibe` 在 registry 中的可用性，也不把它计入完整 HIBE 数量。

## 1. 范围与文件

| 文件 | 内容 |
|---|---|
| [`experiments/research/candidates/lai/backend.py`](../../../../experiments/research/candidates/lai/backend.py) | 参数、环运算、Klein/GPV 采样、`ringDelTrap`、Babai 反演、单层 IBE、两级 HIBE、消息编码、密文规范序列化 |
| [`tests/test_lai_p1.py`](../../../../tests/test_lai_p1.py) | 20 项正负测试；Windows 无 Sage 时整模块 skip |
| 本文件 | 参数、命令、结果、限制和下一步 |

P1 只回答“这条路的工程生命周期能不能闭合”，不回答安全/匿名性/正式参数。按项目 2026-10-18 工作前提，安全与匿名性引用原文/工作假设，不在本批补证明。

## 2. 参数与构造

教学参数：`q=1048609`（素数，`q≡1 mod 16`）、`n=8`、`k=21`、`l=2`、`p=2`、`σ=2`、`σ_r=1`、深度 2。`R_q=F_q[x]/(x^8+1)`，gadget `g=(1,2,…,2^20)`。

对应关系：

| 原文/主张 | P1 实现 | 说明 |
|---|---|---|
| §5.2 Setup / Extract / Encrypt / Decrypt | `LaiScheme.setup/extract/encrypt/decrypt` | 消息打包为 `R_p^k` 的二进制系数，含 1 字节长度前缀 |
| Algorithm 4 `ringGenTrap` | `setup` | `a0^T R + a1 = g` 逐列检查 |
| Algorithm 9 `ringDelTrap` | `_GadgetSampler.ring_del_trap` | 输出修正为 `m×k`；旧 tag 归一化 `(h'g - a1)/h` |
| Algorithm 7 / `ringSampleD` | `_GadgetSampler.ring_sample_d` | Klein/GPV 陪集采样，未加 perturbation |
| Algorithm 5 / `ringInvert` | `_GadgetSampler.babai_invert` | `V=qS^{-T}` 对偶基、逐系数 nearest plane + 容差检查 |
| HIBE “Derive=Extract”、密钥线性增长 | `derive` | 每层追加 `a_ID` 块：`F1=(a;a_id1)`，`F2=(F1;a_ID)`，`u` 随层增长 |
| Theorem 10 / PLWE | 不声明 | 仅记录为原文引用；参数不是安全参数 |

## 3. 关键实现决策与发现

### 3.1 身份编码必须是“短”的

原文没有给出身份到 `R_q` 的具体编码。P1 最初用 SHAKE 输出**均匀**环元素，结果加密的 `e1=-e0^T R` 项不再小：`R=R0+Σ id_i R_i` 被均匀 `id_i` 放大，解密残差约 **2.06×10^6**，超过 Babai 容差 **2.43×10^5**，level 1 与 level 2 都失败。

改为**二进制身份编码**（每个系数 0/1，来自 SHAKE 的 n 个 bit）后，`id_i R_i` 保持短，level 1/2 生命周期闭合。这是 P1 的显式研究选择，不是原文逐字规定；它解释了资格核验中“身份编码未落实”的具体后果。身份空间因此是每层 `2^n` 个（n=8 时 256 个），不是完整 `R_q`。

### 3.2 单位 tag 与中止

`h_id`、`h'` 都按单位采样；解密显式检查 `h_id+h'` 可逆，非单位直接拒绝。加密端不知道 `h_id`，因此无法保证 `h_id+h'` 必为单位；当前记录为小概率解密中止，未做预算。

### 3.3 序列化

密文使用 `LAI1` magic + 4 字节 body 长度 + level + `h'` + `u` + `v`；每个环元素固定 `3n` 字节（`q<2^24`），解码检查 magic、长度、维度、系数范围和尾随字节。密钥/公钥尚未序列化。

## 4. 运行与结果

WSL：SageMath 10.9 / Python 3.13.15。

```sh
cd '/mnt/c/Users/A/OneDrive/文档/IB-ME-from-HIBE-IBS'
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest tests/test_lai_p1.py -q
```

结果：**20 passed in 6.39s**。与资格测试合并运行：**35 passed in 8.51s**。另跑 10 个随机种子、各含 level 1 + level 2 生命周期：**10/10**。

覆盖：

- `ringGenTrap` 关系；level 1 / level 2 委派关系；
- level 1、level 2 加解密往返；密文序列化往返；
- 错误身份（同层）、错误子身份、错误 `h'`、非单位 `h'`；
- `u`/`v` 篡改；截断、追加、坏 magic、越界系数、错误 level/维度；
- 16 字节最大消息、空消息、非零 padding 拒绝；
- 3 个额外随机种子的完整生命周期。

## 5. 未实现与已知风险

1. **无 perturbation**：Klein 输出只是“接近”目标离散高斯，不是证明级 `ringSampleD`；分布质量由 P0 的小参数统计支持，不等于安全证明。
2. **参数是教学参数**：`n=8`、`q≈10^6`，没有任何安全等级；正式参数需按 `n` 与 `q` 的缩放重新筛选。
3. **深度 2、`p=2`、消息 ≤16 字节**：不是通用 HIBE 后端；`depth>2`、`p>2` 未实现。
4. **身份空间小**：二进制编码每层 `2^n`；若需完整环身份，需要重新处理 `id_i R_i` 的宽度或改加密的 `R` 构造。
5. **未接入 registry/CLI**：`lai-ideal-hibe` 仍为 `unavailable-v1`，`algorithm_catalog` 仍 `not_executed`；本批不改变 3/8 HIBE 盘点。
6. **无密钥/公钥序列化、无 constant-time、无侧信道处理**。
7. **Bobai 容差是充分条件**：实际实现可能出现边界失败；当前测试用固定种子，未做全参数扫描。

## 6. 下一步

- **P2（可选）**：把 backend 接到 registry/CLI，补公钥/密钥/密文的统一对象与组合测试；仍保持 `none/false/false`。
- **参数缩放**：按 P0 的 `noise ≈ n^1.9` 与 `tolerance ≈ q/4.3` 扫 `n=1024/2048/4096` 的 `q,σ,k`，给余量表；再用 lattice estimator 核验安全窗口。
- **采样质量**：加 perturbation 或 GPV 精确采样，比较宽度与分布；若宽度上升，回到参数缩放。
- **身份编码**：若必须支持完整 `R_q` 身份，需要证明/实现 `id_i R_i` 不破坏噪声界，或改成分块/短身份编码；不能直接把均匀 hash 身份接进来。

## 7. 安全声明

本交付是功能/工程验证，不构成 PLWE、ring-SIS、HIBE 或匿名的安全证明；测试通过不代表安全等级。所有参数为教学参数，`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。
