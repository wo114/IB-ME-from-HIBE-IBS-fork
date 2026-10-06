# 2026-10-06 更新汇总：Foo–Li 正确性核验与研究实现接入

这份 README 是本次 fork → PR 的统一阅读入口，概括今天的证明、代码、检查和组会材料更新。请先看本页，再按需要打开具体证据，不必逐个浏览全部 Lean 文件和日志。

**当前结论：已获得可复核的条件式正确性证明与研究级签验流程；完整实现级总正确性、安全归约和正式参数仍未全部完成。** 当前状态为 `partial_formal_closure`，`security_claim: none`。

- 对比基线：主仓库 `youzi258/IB-ME-from-HIBE-IBS:main`，发布前核对为 `800e4dd49790d0723b2a02be7698c713b93169f6`。
- 本日成果范围：`d683b05` 至 `5e1c5f5` 的 10 个提交，另加本 README 的交付汇总提交。
- 发布分支：`wo114/IB-ME-from-HIBE-IBS:docs/fooli-correctness-2026-10-06`；通过 PR 交给主仓库审查，不直接改写主分支。
- 构造方向不变：王老师的两层匿名 HIBE + IBS 通用构造；今天主要推进 Foo–Li IBS 正确性与 MP12 研究实现，不涉及 Boyen–Li 增强隐私。

## 1. 队友建议先看这三处

1. [今晚组会汇报](../../meetings/2026-10-06-组会汇报.md)：第 2 节可直接讲；第 4.2—4.4 节是今日成果，第 5—7 节是缺口与决策问题。
2. [最新机器核验汇总](../../research/2026-10-06-correctness/lean-total/README.md)：哪些定理通过 Lean、哪些仍有前提，以及形式模型的适用范围。
3. [条件式正确性定理与参数账本](../../research/2026-10-06-correctness/FooLi-条件式正确性定理与参数账本.md)：四个子引理、单次／预定批次结论、参数条件及失败概率预算，后续选参从这里逐项代入。

较早目录的“尚未接入”“仅本地提交”等文字反映该阶段的历史状态，不改写冻结记录。当前综合进度以本页及 `lean-total/README.md` 为准；本 PR 的发布也不等于此前未证前提已经解除。

## 2. 今天完成了哪些更新

| 工作 | 本次成果 | 主要入口与边界 |
|---|---|---|
| 正确性总账 | 整理 C1—C5 契约、L1—L4、T1 单次诚实流程、T2 预定批次、参数表与失败预算；完成多智能体审查和修订 | [正文](../../research/2026-10-06-correctness/FooLi-条件式正确性定理与参数账本.md)、[复核记录](../../research/2026-10-06-correctness/汇总与复核.md)；未定预算不能填零 |
| L1 代数形式化 | 主／用户陷门关系、整数签名到模方程、MP12 与 Foo–Li 负号适配、分块坐标展开 | [L1](../../research/2026-10-06-correctness/lean-l1/README.md)；方程成立不等于已证明短向量分布或安全 |
| L2 平滑条件传递 | 真正对偶格、陪集质量分解、无限和及从主矩阵到扩展签名矩阵的质量界 | [L2](../../research/2026-10-06-correctness/lean-l2/README.md)；保留主矩阵的初始平滑条件 |
| L3 委派质量 | 从 C2、C3 推出包含中止／非法关系／质量失败的条件式上界；补齐 Poisson、理想产品律及主关系到满秩的桥接 | [L3](../../research/2026-10-06-correctness/lean-l3/README.md)；“闭合”指前提蕴含结论，不是实际采样器已获认证 |
| 采样契约对照 | 核对维度、平方宽度、负号、原始输出 TV、有限带、失败与重试规则；保存 12 组探针 | [采样器对照](../../research/2026-10-06-correctness/sampler-alignment/采样器与证明契约对照.md)；不直接把旧后端的拒零／重试套入新证明 |
| L4 签名范数 | 明确随机性／失败契约，构造理想陪集高斯并将 C2、L2、原始 C4 接入签名失败界；建立有限均匀带的数学模型 | [L4](../../research/2026-10-06-correctness/lean-l4/README.md)、[契约](../../research/2026-10-06-correctness/lean-l4/契约与证明边界.md)；均匀带模型不是 SHAKE 的随机性证明 |
| 实际接入与初始化 | 在研究适配器连接五域地址、真实 MP12 调用、固定身份分支、持久用户种子、原始签验、失败缓存与保存／恢复；给出初始化符号条件和调试证书 | [实际接入](../../research/2026-10-06-correctness/runtime-integration/实际接入与初始化证据.md)；尚非生产 IBSBackend 或安全密钥库 |
| SHAKE 模型 | 区分理想熵源＋RO、实际 SHAKE、实际系统随机源；增加可注入的懒采样块模型，核验复用语义及条件式事件概率迁移 | [SHAKE 说明](../../research/2026-10-06-correctness/shake-model/SHAKE模型边界与正确性迁移.md)；未证明实例化差值可忽略 |
| 初始化与阶段合成 | 完整形式化理想主陷门的 I3 径向尾界；检查 I1／I2／I4 的条件式推导，并调用 L3/L4 完成阶段合成；L1 提供代数接受条件 | [总包](../../research/2026-10-06-correctness/lean-total/README.md)；MP12 几何和实际程序分布对应仍有未证前提 |
| 组会材料 | 更新开头结论、口头稿、今日成果／证据表、老师待确认问题、后续任务和答疑 | [组会稿](../../meetings/2026-10-06-组会汇报.md)；保留历史负面对照，不将功能检查表述为安全结论 |

本次交叉审查还修正了一个形式模型问题：坏委派后原本仍可能继续调用任意签名核。现用 `stopOnBad` 使委派中止、关系不合法或质量不合格立即计为失败，并加入控制命题重新核验。这不是新的密码攻击，也不是修改了生产后端。

## 3. 已保存的核验结果：按批次看，不累计相加

| 检查批次 | 结果 | 证据及解释 |
|---|---|---|
| 正确性账本复核 | 251 项研究测试通过；64 次固定流原像采样重放通过 | [核验 JSON](../../research/2026-10-06-correctness/核验记录.json)；重放不增加独立样本，也不是 64 次真实 IBS 端到端签验 |
| 采样器契约检查 | 66 项既有测试、12 组探针通过；复用原固定流重放 | [契约核验 JSON](../../research/2026-10-06-correctness/sampler-alignment/verification.json)；与其他批次有重叠 |
| 实际生命周期接入 | 189 项测试通过；3 次主生成、9 次发钥、36 次签验、36 次磁盘重放；另有 3 次新进程重放一致 | [运行 JSON](../../research/2026-10-06-correctness/runtime-integration/verification.json)；固定预定尝试全部保留，重放不计作新样本 |
| 最新模型与实现回归 | 195 项通过 | [回归 JSON](../../research/2026-10-06-correctness/shake-model/verification.json)；6 项模型＋41 项生命周期＋66 项在线采样＋82 项编码，覆盖上面的 189 项 |
| 最新 Lean 总包 | 397 项公共声明核验，其中 314 项定理；最新总包新增 51 项声明、44 项定理；3 个故意错误命题均被拒绝 | [最终机器记录](../../research/2026-10-06-correctness/lean-total/verification/run-20261006-171904/verification.json)、[交付清单](../../research/2026-10-06-correctness/lean-total/delivery.json)；含复用源码及基础引理，不是 397 个独立密码学结论 |

旧组会稿中的 366 项是 10 月 5 日第十轮记录，不是今天新增数量。以上 pytest、Lean 声明、探针和重放的对象不同且有交集，不能相加。多智能体交叉审查也不替代导师或外部专家审查。

Lean 固定为 **4.34.1**，mathlib 固定提交 **d13f23b723b8a846827a245b89c10fc7d3f11612**。最终总包没有占位证明或新增数学公理，传递公理限于 `propext`、`Classical.choice`、`Quot.sound`；仍须审查定理的显式前提。

研究代码使用规定的 WSL Sage 环境，今日运行记录为 Sage 10.9／Python 3.13.15。实际生命周期实验使用 $q=3,n=\bar m=1$ 的调试参数和固定测试种子，身份长度 5／3／6 字节、消息长度 0／5／6／2 字节；64 次原像重放使用历史大模数调试配置。两者不合并成同一参数的实验。没有新增算法性能基准、RSS 测量、硬件加速结论或正式安全位数。

## 4. 本次文件范围与审阅建议

```text
docs/deliveries/2026-10-06/README.md         本次统一交付入口
docs/meetings/2026-10-06-组会汇报.md          更新后的组会稿
docs/research/2026-10-06-correctness/        账本、分阶段 Lean 包、审查与冻结证据
experiments/research/foo_li_initialization.py
experiments/research/foo_li_runtime_reference.py
experiments/research/foo_li_runtime_audit.py
experiments/research/foo_li_oracle_model.py  四份独立研究实现／审计代码
tests/test_foo_li_runtime_reference.py
tests/test_foo_li_oracle_model.py            新增生命周期与模型测试
```

改动文件较多主要因为各阶段保留了可单独复核的 Lean 源码副本、依赖锁、检查脚本和原始日志。复用代码不计作新增研究结果；历史 WIP 与后续成功记录并存，当前结论以最后一轮的范围和前提为准。没有包含 `.lake`、编译缓存、生产密钥快照或临时运行目录。

未修改 `src/ibme/`、正式参数、现有生产协议接口或旧后端。其他人的 `docs/交接说明与安全发现.md` 未提交修改保留在本地，不纳入此次 PR。既有公开伪造／密文篡改反例不因本次研究成果而被认定已修复。

### 复核方式

先读冻结结果，再按需要在隔离目录复跑。不要直接覆盖已保存的 JSON／日志，也不要运行 `lake update` 改动依赖版本。

- **数学证明：**[总包 Verify.ps1](../../research/2026-10-06-correctness/lean-total/Verify.ps1)；按总包 README 配置对应 Lean／依赖，本地原运行目录为 `D:\Lean\projects\fooli-total`。交付源码不包含工具链和缓存。
- **最新 195 项回归：**在仓库根目录的指定 WSL 环境运行下列命令。它不覆盖冻结回归报告；输出是本次复跑的新证据。

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src ~/miniconda3/envs/sage/bin/python \
  -m pytest -q -p no:cacheprovider \
  tests/test_foo_li_oracle_model.py tests/test_foo_li_runtime_reference.py \
  tests/test_online_sampling_reference.py tests/test_encoding.py
```

- **只读账本与固定流复核：**[verify_ledger.py](../../research/2026-10-06-correctness/verify_ledger.py)，运行时 `--repo .` 指向仓库；这是旧流重放，不是新增随机样本。
- **实际流程原始结果：**直接打开运行 JSON 的 `all_attempts`、`counts`、`fresh_process_replays`、`source_sha256`，核查全部预定尝试、恢复结果和来源指纹。

## 5. 剩余任务与今晚需要确认的事情

1. **解除数学前提：**完成 gadget 核格基、MP12 基提升及 Gram–Schmidt 到主矩阵对偶质量界的形式化，解除 `hMP12`；若数值证书继续取两种尾界的最小值，还需补坐标尾界分支。
2. **建立真实分布对应：**把实际有限采样证书、变长字节消费、初始化及公共哈希状态与 Lean 概率实验逐项连接。实际 SHAKE 的跨进程重放已有测试，理想 RO 表恢复目前只检查了同进程同一对象，不能混写。
3. **形成候选参数准入表：**分别核对正确性质量条件、公开近均匀／熵条件、归约误差、完整 SIS 提取范数与难度，以及资源可执行性。队长负责最终选择；我们提供约束、核验和成本反馈，不必等参数最终确定才工作。
4. **请老师审查安全路线：**今天没有修复或继承原文的紧 QROM／强不可伪造定理。需复核原分支关联问题与经典补充归约，明确量子对手模型、用户／签名／哈希查询规模和可接受失败预算。
5. **继续完整系统和性能验收：**HIBE 匿名性、解密与载荷适配，IB-ME 的身份／消息／密文绑定、篡改拒绝、真实批量测试，以及不同实例的尺寸、耗时、峰值内存和优化收益仍需补齐。

对应[官方赛题验收基准](../../research/2026-09-30/IBME-赛题验收基准/2026-09-27/赛题验收基准.md)，本次为 A02／A04／A09／A10 等提供 IBS 子组件的局部证据，不直接判定整项或全题通过。至少一种完整 LWE/SIS 实例是明确要求；128 位安全、Ring-SIS 或固定速度不是本 README 新增的官方门槛。

## 6. 今日提交索引

| 提交 | 内容 |
|---|---|
| `d683b05` | 条件式正确性定理、参数和失败账本 |
| `98119b3` | L1 代数形式化 |
| `edf82ab` | L2 对偶质量与平滑传递 |
| `1b3a79e` | L3 阶段性 WIP |
| `4e63f2d` | 补齐条件式 L3 的解析、产品律和主关系连接 |
| `e150ee4` | 采样器与证明契约对照 |
| `28c24e3` | 明确契约并完成条件式 L4 |
| `5e4ca8d` | 实际生命周期接入与初始化证据 |
| `6b54848` | SHAKE 模型、初始化和条件式总失败界核验；整体状态仍为 WIP |
| `5e1c5f5` | 更新今晚组会材料 |

本 README 汇总冻结结果，不将整理文档视为新证明或新实验。科研写作检查用于区分成果、假设和计划，不是数学证据。outputs 同内容副本仅作归档；相对链接和复跑入口以仓库版本为准。

发布前复核：按 §4 命令重新运行 4 个相关测试模块，结果为 **195 passed in 5.91s**；检查 24 处本地资料链接、最新交付清单的 95 个文件指纹、PR 文件范围及 Git whitespace。没有在本次发布准备中重跑 Lean，机器结论沿用已核对源码／日志的冻结记录；没有覆盖旧实验报告。
