# SRGG 尺寸归因更正：稠密矩阵、环表示与实际对象

日期：2026-10-18。论文：Jia、Liu、Tang、Wang，*Constructing Efficient Identity-Based Signatures on Lattices*，DOI `10.1049/ise2/6684889`。本更正依据冻结的原表与已有代码、公开回执，不新增采样或安全结论。[English](report.en.md)。

## 应修正的结论

**不能用“SRGG 需要 6.7–26.8 GB”描述方案固有尺寸或当前后端内存。** 该数字是旧 `n=512,w=8,d=2/3/4` 条件研究点的一份完整稠密 master shape 矩阵，假设每条目 64 B 后计算的载荷场景。它不是密钥、签名、实际峰值 RSS，也不是论文 Table 4 的 `w=2`。

同一方阵的环系数表示槽位少 512 倍；在相同 64 B/系数假设下，master 为 **13.1–52.4 MB**。当前 `structured`、论文 joint 和 `source-schur` 路线已使用环多项式、低秩算子或频率小矩阵，避开完整系数稠密展开。因此“必须先实现结构化才能运行 n512”是已被后续实现推进的历史待办，不能继续作为当前状态。

## 同对象、同假设下的数值

对一个 `L×L` 的环方阵，`R=QQ[X]/(X^n+1)`：稠密系数算子有 `L²n²` 个条目，完整环方阵有 `L²n` 个系数。两者的槽位比恰为 `n`。这里 master 的 `L=(2+w)d`，signature 的 `L=(2+w)d+1`。

以下统一假设 64 B/条目或系数。GB/MB 用十进制，GiB/MiB 用二进制；QQ 分子/分母增长、interval 精度与 Python/Sage 容器并不保证满足此假设。

| 旧 w=8、秩 d | master 稠密 GB | master 环系数 MB（MiB） | signature 稠密 GB | signature 环系数 MB（MiB） |
|---:|---:|---:|---:|---:|
| 2 | 6.7108864 | 13.1072（12.5） | 7.398752256 | 14.450688（13.78125） |
| 3 | 15.0994944 | 29.4912（28.125） | 16.122904576 | 31.490048（30.03125） |
| 4 | 26.8435456 | 52.4288（50） | 28.202500096 | 55.083008（52.53125） |

旧文档中列出的 7.4–28.2 GB 是 signature 方阵；不能与 master 的 6.7–26.8 GB 混为同一列。原始 [parameter-feasibility.md](../2026-10-16-srgg-qualification/parameter-feasibility.md) 本已限定单矩阵情景并写明结构槽位比；本更正修复的是超出其适用范围的总结，不改写冻结证据。

论文 Table 4 的 `n=512,w=2,d=2/3/4` 用同一假想场景得到：

| 原表 | master 完整环方阵 MB | signature 完整环方阵 MB |
|---|---:|---:|
| PARAM-I | 2.097152 | 2.654208 |
| PARAM-II | 4.718592 | 5.537792 |
| PARAM-III | 8.388608 | 9.469952 |

这些也不是当前 RSS：现实现可保存低秩 witness、Schur pivot/gain 与必要缓存，未必物化完整环方阵；同时存在的工作区和有理数增长又可能增加开销。512 倍槽位缩减不能直接作为峰值内存、时间加速或通信压缩的实测倍数。

## 当前实际编码尺寸

下表直接读取 [source-schur 最终生命周期](../2026-10-18-srgg-source-schur/README_zh-CN.md) 的三份 `param-*-bounded-final-lifecycle.json`，均为原表、默认记号解释、一个固定 TEST 随机流生命周期、5 B 身份和 32 B 消息；不是本批新运行或统计均值。

| 原表 | public JSON B | user-key JSON B | master JSON B | signature JSON B |
|---|---:|---:|---:|---:|
| PARAM-I | 34,522 | 84,190 | 102,682 | 35,334 |
| PARAM-II | 76,935 | 176,721 | 218,451 | 51,126 |
| PARAM-III | 136,604 | 303,760 | 377,733 | 67,112 |

这些是当前严格 JSON 的实物字节，独立于 sampler 工作区。`SigningKey.to_bytes()` 嵌入 public 的 hex 和 tail；master 包含 public、witness 与已发钥缓存。因此它们也不能直接与论文的纯压缩系数分量或 C/rANS 尺寸排名。原表 PARAM-I 的额外系统随机生命周期也已冻结，本表选定三份一致口径的 TEST 回执，不将其混计。

## 工程修正顺序

1. 报告、选型和展示分别列“算法系数数量／当前 wire 实物／当前执行时间／峰值 RSS”。将 GB 情景标为旧 dense 参考表示，不能据此淘汰当前 SRGG。
2. 继续复用现有环/频域后端。已有小维精确测试比较 matvec、伴随、二次型相关算子与原稠密结果；本次复跑结构几何和 source-Schur 样本测试，不更改采样路径、原参数或 guard。
3. 若下一步优化通信，单独做版本化紧凑二进制 codec，并统计纯系数和完整封装两种尺寸。必须保留身份／公钥绑定、规范解析、恢复和失败状态；不能把去掉嵌套公钥或 JSON 的收益算成环表示的 512 倍。
4. 若下一步优化 RAM/时间，先在同原表、同后端、同冷／热与缓存边界测进程树 RSS、准备／发钥／签名耗时和峰值时刻，再决定缓存复用或释放策略。本包没有这些新实测，也不预报统一倍数。

## 复核与交付

纯标准库、零熵计算器 [representation_audit.py](../../../../experiments/research/candidates/srgg/representation_audit.py) 对照旧冻结模型，输出两套参数的表示账本及上述实物尺寸，并绑定输入／源码 SHA-256。无需分配大矩阵、密钥或调用 Sage：

```text
python -m experiments.research.candidates.srgg.representation_audit --output docs/research/team-b-delivery/2026-10-18-srgg-size-accounting/representation-audit.json
python -m experiments.research.candidates.srgg.representation_audit --output docs/research/team-b-delivery/2026-10-18-srgg-size-accounting/representation-audit.json --check
```

新增范围测试 8 passed；规定 WSL Sage 的既有结构几何及 source-Schur 测试 24 passed；[validation.json](validation.json) 记录命令。所有旧 sampler 源码、参数、回执和 manifest 保持原字节。安全元数据继续 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。表示更正不处理其它安全或参数问题，功能测试不替代安全证明。
