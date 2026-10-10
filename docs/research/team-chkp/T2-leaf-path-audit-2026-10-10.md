# T2：一级随机化基＋二级仅原像的最小路径核查

日期：2026-10-10。实现基点：`6d0e88f`。范围为独立研究采样路径；不修改 HIBE 接口、协议、正式参数或采样器，不替代 T3/T4。

## 1. 结论与验收范围

**限定的最小采样路径通过，T2 整体仍为 WIP。**

| 固定对照 | 本轮实际结果 | 能得出的结论 |
|---|---|---|
| 一级 RandBasis，不做一级 LLL，二级仅原像 | 0/4；均在二级 SampleD 准入时被宽度限制拒绝 | 仅省略二级 RandBasis 不能修复坏基几何 |
| 一级 RandBasis＋已有可选 LLL，二级仅原像 | 4/4；每个种子采两个目标，8/8 原像方程精确成立 | 该小参数最小采样链可以走通，不需要第二次 RandBasis |
| 原有“两次 RandBasis”路径 | 原代码和失败断言保留；新测试重跑首个种子，仍在第二次 RandBasis 预算门拒绝 | 新通过结论没有覆盖、删除或改写旧失败 |

本轮仍使用预先固定的 `chkp-t2-chain-0` 至 `chkp-t2-chain-3`，不搜索成功种子、不失败重试、不换成较弱的采样宽度。每个变体每个种子一次，合计八次路径尝试。测试中的重复执行只用于回归，不增加独立样本数。

## 2. 论文与实现对应

主要来源为仓库 [CHKP 作者全文](../../../papers/2010_bonsai_trees_cash.pdf)（2011-06-14，36 页），[作者公开版本](https://sites.cc.gatech.edu/fac/cpeikert/pubs/bonsai.pdf)。这里只核对相关算法段落，不宣称本轮重新阅读全文或完成安全证明。

| 来源 | 原文/规格要求 | 本轮实现及边界 |
|---|---|---|
| §5.2，PDF 20，GENHIBE.Extract 后注 | 最大深度叶节点无需生成用于后代委派的基 | 一级仍随机化；二级从扩展父基抽取原像，不调用二级 RandBasis |
| 同页 Extract 的 SampleD 行 | 从扩展的父基生成本级原像 | 二级仍用 `ExtBasis(S1,A2)` 和原有 `s2`；不是先得到 S2 再采样 |
| §5.2 多比特说明，PDF 20 | 每位对应 syndrome 和原像 | 本轮只枚举小参数的两个目标 `(0,)`、`(1,)`，不是身份哈希或完整多比特实例 |
| §5.3，PDF 22 | 重复身份须返回相同解封装向量 | 本轮未实现身份地址及持久缓存，不把重新用相同种子跑实验当作该要求已完成 |
| [R1 HIBE 规格](../2026-10-08-r1/两套HIBE实施规格.md) §1–2 | 允许叶基省略；懒生成另有采样宽度和尺寸要求 | 仅实现固定目标集合的研究批次，不改变冻结的 derive/decrypt 接口 |

“省略叶基”是原论文已有选项，不是密码学原创。一级输出仍经过 RandBasis 和既有可选后处理；未随机化扩展父基只在采样内部使用，绝不作为叶对象输出。返回对象只含公开矩阵、目标、短向量和研究标记，不含父基、叶基、采样器或随机源。它还不是可序列化的 `HIBELevel2SecretKey`。

## 3. 参数、随机性与资源

- AP09 研究配置沿用 `n=1,q=2,m1=2,m2=8,random_rows=2,hadamard_scale=4`；根/一级/二级维数为 10/20/30。
- 宽度约定仍为质量 `exp(-pi*||x||²/s²)`；`s1²=9064`、`s2²=15952640`，不是方差。
- `epsilon_bits=16` 是有限采样证书输入，不是安全等级。标量 OnlineOptions、一般基 GPV、RandBasis、LLL 实现与原上限均不修改。
- 根与两个扩展块仍使用原实验的确定性测试流；目标枚举 0、1，不实现 H/G。身份、消息长度不适用。本轮没有加密、解密或高斯统计新实验。
- 新批次函数另设最多 32 个目标及整批 256 MiB 随机带预算，均为研究资源限制，不是已确认的消息容量，也不能保证 32 个目标对所有采样器都获准。全部输入和整批预算在抽样前检查。
- 原 GPV 中止、随机源异常直接传播，不外层重试、不返回部分批次、不拒绝零原像。记录范数但不按范数筛选样本。

| 二级开销项 | 数值 | 解释 |
|---|---:|---|
| 单次 SampleD 的最坏情况随机带预算 | 9,406,400 B | 沿用原证书 |
| 本轮两个固定目标的整批预算 | 18,812,800 B，约 17.94 MiB | 小于新批次沿用的 256 MiB 上限 |
| 原 K=50 的二级 RandBasis 预算 | 470,320,000 B，约 448.53 MiB | 本路径不执行；旧路径仍拒绝 |
| 叶对象保存的原像整数个数 | 2×30=60 | 不含公开上下文和对象开销，不是序列化字节数 |

以上是最坏情况随机字节消费上界，**不是实测内存占用或运行时长**。新路径仍要承担所有所需原像的采样成本；未来 L 个位位置需要约 `3mL` 个原像整数，不能由两目标实验推断完整签名载荷可用。

四个种子的叶原像范数平方如下，均低于本次记录的参考界 `s2²×30=478579200`：

| 种子后缀 | 目标 0 | 目标 1 |
|---|---:|---:|
| 0 | 53731476 | 96500136 |
| 1 | 74344791 | 76589995 |
| 2 | 73453104 | 80588154 |
| 3 | 39619243 | 82548110 |

这是样本观察，不是对所有输出的范数证明。JSON 中的 `leaf_batch_tv_upper_including_abort` 仅是给定已准入二级采样器时，两次调用的条件式有限误差账本；不包含根生成、一级随机化、LLL 或其他资源拒绝的整链预算，也不能解释为八个测试样本的失败率。

## 4. 实现与回归检查

新增：

- `experiments/research/chkp_leaf_reference.py`：固定目标原像批次；输入/预算预检、精确模方程复核、原异常传播、仅原像返回。
- `experiments/research/chkp_leaf_audit.py`：与旧脚本相同的根、一级流程、种子及宽度；保留有/无 LLL 对照，单独记录最小路径验收。
- `tests/test_chkp_leaf.py`：原像及对象边界、只有一级 RandBasis、旧路径随机流差分、原坏基负例、非法目标、预算拒绝、零原像、算术错误、中止及退出码范围。
- 本文、JSON 和两份执行日志；更新本目录 README 索引。

完整修改文件清单（8 个）：

```text
experiments/research/chkp_leaf_reference.py
experiments/research/chkp_leaf_audit.py
tests/test_chkp_leaf.py
docs/research/team-chkp/README.md
docs/research/team-chkp/T2-leaf-path-audit-2026-10-10.md
docs/research/team-chkp/T2-leaf-evidence-2026-10-10.json
docs/research/team-chkp/T2-leaf-execution-2026-10-10.log
docs/research/team-chkp/T2-leaf-validation-2026-10-10.log
```

关键差分测试把每次 RNG 请求长度及输出送入摘要，确认首个固定种子在新路径完成时与旧路径抵达二级 RandBasis 拒绝前的随机消费完全相同，并比较两级输入代数证书、宽度、SampleD 证书和原像方程。另对全部四个种子监测 RandBasis 构造，确认只调用一次、维数为 20。

首轮新增测试：**28 passed in 58.03s**。随后上述 CHKP/采样相关 13 个文件回归：**489 passed in 68.74s**；两次均退出码 0，无失败/跳过。详见 [执行日志](T2-leaf-validation-2026-10-10.log)。`git diff --check` 通过；原采样器、LLL、双基审计及其失败测试相对基点无改动。

独立审查发现一项失败分类问题：执行期随机源返回错误字节数触发 `ValueError`，原新审计会误记成准入拒绝，不会造成假成功但会污染失败归因。已增加叶批次专用 `LeafAdmissionError`，把一级 RandBasis 的准入/执行阶段分开；其他执行期 `ValueError` 记为 `execution_error`。新增四项回归：一级/二级真实短读 RNG 两项、一级 RandBasis 执行错误一项、叶批次预算准入一项。此次修正不改底层采样器，也不把错误计入“理想随机字节模型下的统计失败”。

**最终版本复跑：493 passed in 97.61s，退出码 0，无失败/跳过。**其中新增叶路径测试共 32 项，旧相关测试 461 项。修复后的审计重新生成 JSON，仍为有 LLL 4/4、无 LLL 0/4；源码指纹全部复核一致。独立审查另复跑四项故障测试：4 passed、28 deselected，确认上述问题已解决；其结果不叠加进 493 的计数。

运行命令（从仓库根目录，在指定 WSL 环境执行）：

```bash
PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m experiments.research.chkp_leaf_audit \
  --output docs/research/team-chkp/T2-leaf-evidence-2026-10-10.json

PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m pytest -q \
  tests/test_chkp_genbasis.py tests/test_chkp_gpv.py \
  tests/test_chkp_randbasis.py tests/test_chkp_tobasis.py \
  tests/test_chkp_t2_audit.py tests/test_chkp_basis.py \
  tests/test_chkp_basis_boundaries.py tests/test_chkp_t1_audit.py \
  tests/test_chkp_t2_conditions.py tests/test_online_sampling_reference.py \
  tests/test_chkp_basis_reduce.py tests/test_chkp_width_audit.py \
  tests/test_chkp_leaf.py --tb=short
```

审计命令退出码 **0** 只表示 `declared_leaf_sampling_gate_passed=true`；同时输出 `T2_complete=false`、`backend_admitted=false` 和 `security_claim=none`。旧整链脚本的 WIP/拒绝语义不变。本轮没有运行全仓库测试或正式 HIBE contract tests。

环境：Intel Core Ultra 7 255HX，20 核/20 逻辑处理器；Windows 上 WSL2，Sage 10.9、Python 3.13.15。精确 Linux 环境及源码/论文 SHA-256 见 [机器证据](T2-leaf-evidence-2026-10-10.json)，控制台摘要见 [审计日志](T2-leaf-execution-2026-10-10.log)。未使用专门硬件加速实现；计时包括代数/证书工作，不是公平性能基准。

## 5. 仍未完成、下一步与结论口径

1. **不能宣布完整正确性。** CHKP Lemma 5.1 的 q、噪声 α 和取整条件尚未满足/核验；当前 q=2 不是该宽度下的正式解密参数。没有噪声加解密实验，更没有端到端 IB-ME 验收。
2. **不能宣布整链失败概率已闭合。** 根矩阵分布、有限资源拒绝、一级随机化和 LLL 的全局预算仍需处理；成功样例不能抹掉这些条件。
3. **不能直接接任意字节载荷。** 下一步先冻结目标数量/载荷容量与成本，再落实同一公钥上下文、身份路径、位位置的固定原像缓存及保存恢复。只缓存已生成原像不需要叶基；自主生成新的原像则是另一条设计路径。
4. **不改变研究路线或归约模型。** 目标仍是 Wang 通用构造下的 CHKP 匿名 ROM HIBE；本轮不重做 CHKP 安全归约，不声称 QROM/标准模型或任何安全位数。

可汇报为：**原有一级基后处理配合论文允许的叶基省略，在四个固定小参数种子上走通了最小原像链；采样器及其上限未改。下一门槛转为有限容量、固定原像状态、噪声和整链参数验收，而不是先强行完成不一定需要的第二次 RandBasis。**

本轮按 `research-paper-code-study` 的来源—代码对应和 `paper-repro-python` 的最小复现/日志流程组织；不新建整篇论文复现项目或改写全仓库 README。材料同时保存到个人 outputs 副本；跨轮相对链接以仓库为准。当前仅本地提交，不推送或创建 PR。
