# Shorter and Faster Identity-Based Signatures with Tight Security in the (Q)ROM from Lattices

作者：Éric Sageloli、Pierre Pébereau、Pierrick Méaux、Céline Chevalier。来源：HAL v1，DOI `10.1007/978-3-031-33488-7_24`。本批为 2026-10-19 B 组环版工程交付；[论文与实现对应](SOURCE_MAP.md)列明版本、公式和实现选择。

**这次已经把两组论文大参数真正跑通。** 完成了 Setup、全部身份发钥列、两次签名验签、十项负控，以及独立进程恢复后的验签与再次签名。恢复既有身份钥时，两档取熵均为零。它是独立 Sageloli RSIS 原语交付，尚未接入默认公共选择器或与 HIBE 配对。

## 具体补齐了什么

1. **大整数和大对象编码。** 支持 `q=3^65/3^153` 的 104/243 位公钥系数；公钥、根、身份钥直接保存环多项式系数，严格解析 v3 格式。旧 v2 不自动迁移。
2. **能够在论文规模运行的 Gaussian 采样器。** 用 Fourier 频率分解和低秩平方根，最大特征分解仅 k×k，保留完整相关扰动、逐系数离散 Gaussian 舍入和三进制陪集 Gaussian。没有构造几十万维的完整协方差矩阵。
3. **精确环算术和恢复。** 公共大整数点积用 FLINT；小整数矩阵积用有幅度检查的双素数 NTT/CRT。恢复重新检查根和每个身份钥的全部环列。持久化失败留下 pending，阻断自动重发。

实现位于 [`experiments/research/candidates/sageloli/ring/`](../../../../experiments/research/candidates/sageloli/ring/)。这是原 Sageloli 环路线的显式 v3 实现，不增加论文算法数；矩阵 SIS 和原 v2 代码均保留。

## 本次实际结果

每档 1 套独立系统随机状态；身份 21 B；首次消息 33 B，第二次消息 34 B，恢复后新消息 42 B。每档新建、恢复各一个独立进程。下表单位 MiB/GiB 为 2 的幂，原始字节数见收据。

| 实测项 | Param I | Param II |
|---|---:|---:|
| `(d,k,l)` | `(2048,65,132)` | `(2048,153,308)` |
| Setup | 4.993 s | 43.554 s |
| 完整身份发钥 | 85.135 s，65 列 | 520.232 s，153 列 |
| 首次签名（含采样计划准备） | 9.285 s | 38.611 s |
| 同钥第二次签名 | 2.016 s | 5.017 s |
| 首次验签 | 0.517 s | 1.362 s |
| 新建运行进程峰值 RSS | 1.361 GiB | 6.194 GiB |
| 恢复运行进程峰值 RSS | 1.366 GiB | 6.262 GiB |
| 公钥 wire | 3.352 MiB | 18.649 MiB |
| 签名 wire | 3.078 MiB | 7.203 MiB |
| 身份钥 wire（含公钥） | 137.415 MiB | 754.961 MiB |
| 持久主状态（含一把已发身份钥） | 149.272 MiB | 819.929 MiB |
| 两次诚实签名、十项负控 | 全部通过 | 全部通过 |
| 完整恢复／恢复后新签名 | 通过／通过，恢复 0 熵 | 通过／通过，恢复 0 熵 |

负控包括错误身份、消息、响应系数、两种盐、公钥上下文、全零响应、截断、追加和重复字段。主状态不是论文中单独的 msk：它还保存已发身份钥账本。当前签名采用 int64 槽，公钥按整字节槽编码，未实现信息熵最优压缩；不能把本表直接当作论文 Table 7 的最短尺寸。

这是单次工程可行性实测，不是多算法公平基准：机器还有其它研究进程，未隔离 CPU。环境为 Intel Core Ultra 7 255HX、WSL Ubuntu 24.04、约 15 GiB WSL 内存、Sage 10.9/Python 3.13.15、NumPy 2.5.3、g++ 13.3.0；本批 OpenBLAS/OMP 各 4 线程。原始新建运行总耗时约 106.29/620.23 s，取熵约 13.03/69.78 GB；这些成本也保留在收据中。

新建 I/II 的固定源码分别为 `78f3267`/`03b0e5e`。最终边界保护版本为 `c29b45d`：修正极值输入检查、随机源字节长度、优化模式下的断言遗漏，并去掉公开证书中的私有谱统计。两档均在该最终计算版本重新构建原生库并做零熵恢复、新签名和验签。**上表首次新建耗时仍对应原固定版本，不冒称在最终版本重做了两次新建。** [公开证据](evidence/)保留源码指纹及必要的旧源码快照。

## 如何复放

在仓库根、规定的 WSL `~/miniconda3/envs/sage` 环境执行，需要既有 g++ 与 Sage 前缀中的 FLINT/GMP 开发文件。先显式构建原生库，记录输出的 `path`：

```bash
export PYTHONPATH=src:. PYTHONDONTWRITEBYTECODE=1
export OPENBLAS_NUM_THREADS=4 OMP_NUM_THREADS=4
~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.sageloli.ring.native \
  --directory ~/.cache/ibme-native-tools/sageloli-ring-v3
```

把下列 `NATIVE_SO` 换成上一步 path、`SOURCE_COMMIT` 换成实际执行源码的提交号。私有目录和输出必须换成未使用路径；失败原件保留，不删除 pending、不自动换种子重试：

```bash
~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.sageloli.ring.run \
  --profile I --mode fresh --native NATIVE_SO --source-commit SOURCE_COMMIT \
  --private-directory ~/.cache/ibme/sageloli-v3/new-I-01 \
  --output test-results/sageloli-new-I-fresh.json
~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.sageloli.ring.run \
  --profile I --mode recover --native NATIVE_SO --source-commit SOURCE_COMMIT \
  --private-directory ~/.cache/ibme/sageloli-v3/new-I-01 \
  --output test-results/sageloli-new-I-recover.json
```

Param II 将 `--profile` 改成 `II`，同时更换私有目录和输出路径。默认实验保护为 4 小时、12 GiB 进程峰值与 256 GiB 取熵预算；时间/RSS在阶段回调处检查，不能理解成操作系统逐指令硬限制。私钥、状态、签名样本和采样计划不进入本交付。

源码/字节证据验证及专项回归：

```bash
python docs/research/team-b-delivery/2026-10-19-sageloli-ring-target/verify.py
python -O docs/research/team-b-delivery/2026-10-19-sageloli-ring-target/verify.py
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 ~/miniconda3/envs/sage/bin/python -m pytest -q \
  -p no:cacheprovider tests/test_sageloli_*.py tests/sageloli_native
```

本次完整回归为 **180 passed，0 failed/error/skipped，218.66 s**，覆盖旧版与新版、严格编码、独立环运算对照、Gaussian 数学检查、真实签验、固定发钥及损坏/故障恢复。[JUnit](evidence/tests.xml)保存逐项结果。第一次测试因输出管道 BrokenPipe 中断，记录保留在本地；该轮不计通过，以上是完整重跑结果。另在 `python -O` 下实际执行小参数新建和独立进程恢复，均通过。

默认 CI 的 Sageloli glob 覆盖原 v2 与新增结构数学测试；原生构建、`tests/sageloli_native` 和两档大参数运行按本页命令显式验收，不把一次 CI 计划当作大参数实测。

本批文件包括 `ring/` 实现、`tests/test_sageloli_ring_structured.py` 与 `tests/sageloli_native/`、公开证据导出器、本目录中英 README/公式对应/验证器/收据，以及 v2 契约页的新版本入口。发布前已同步合入上游 `b92967b`，未修改其它算法或默认注册器。

## 声明与交付范围

采用原文安全性作为项目研发前提，实际参数来自 Table 6/Appendix E 并向上取整平方宽度。连续 Gaussian 的浮点特征分解、FFT 和有限随机网格总误差尚未认证，仍为 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。两档论文参数的原文估计强度也不同，本批未重新估计安全位数或升级 NIST 等级。

原先“只有小参数运行、大参数编码/采样器缺失”的工程状态已由本交付推进；默认公共 registry/CLI 接入、真实 HIBE 配对和统一条件性能比较仍由后续集成验收确认。
