# CHKP 与 Luo 统一交付：已经做成什么，还差什么

日期：2026-10-12。本页面向队员同步，详细公式、代码和运行记录从文末进入；全项目当前安排仍以 [PROJECT_STATUS](../../PROJECT_STATUS.md) 为准。

## 1. 先看结论

**Luo 模格 IBS 的本版本研究工作已收尾；真实 CHKP 与 Luo 的组合已经跑通。** 现在不只是“两个接口能接上”：已经实际生成根、父和叶密钥，完成加解密、错误身份与篡改检查，并通过命令行读写保存后的状态。此次交付包含代码、测试、复现入口和脱敏证据，不只有这份说明。

**但这不是一套已获得安全等级的成品。** CHKP 当前使用 n=2 的研究小参数，公开攻击确实恢复到了测试种子；Hybrid 包装不能补救这个保密性问题。Luo 的 C64B 也只是明确选定、经过核验的研究候选，不能给整个组合贴上“128位安全”标签。所有入口保持 `security_claim=none / backend_admitted=false / parameters_are_formal=false`。

本次的 `chkp` 后端采用 MP12 生成根，再走 CHKP 完整基的父委派与叶采样；上游已有的 `mp12-chkp-reference` 是另一个 MP12 紧凑委派变体，保留其入口和证据，不能把两个后端的实验混算。

## 2. 正确性、安全性、性能分别做到哪里

| 方面 | 已经完成、可以写进报告 | 暂时不能写的结论 |
|---|---|---|
| Luo 正确性与可用性 | 算法、舍入和 Hint 条件与实现对应；C64B 54次正常签名、315次尝试全部成功，108次双格式验签；固定身份密钥缓存和保存恢复核验。另有指定理想模型/调用预算下的条件式生命周期中止界 `<2^-153` | 该界不是安全位数，不是整个 IB-ME 的失败率，也不是实际执行了65536次签名；不声称真实SHAKE无条件等于理想随机源 |
| CHKP 正确性与实现 | 根→父→四个叶地址的真实路径完成，每个叶地址256个索引原像，用于32 B种子；实际噪声封装、恢复、缓存复用通过，失败和受限恢复过程保留 | 小参数成功不证明大参数一定可跑；充分条件与有限测试不等于所有输入永不失败 |
| 安全依据 | Luo 按原论文经典ROM下的MLWE/MSIS分析引用，另列参数攻击成本估计；CHKP/MP12/Wang的条件与实现边界分别记录。组合层实际检查身份、签名和字节绑定 | 没有新写完整Luo归约、没有QROM声明、没有NIST等级；本次CHKP的公开恢复攻击说明当前组合不具备所需保密强度 |
| 尺寸与效率 | 已测签名、密钥对象、原始胶囊和完整密文尺寸；记录实际发钥、叶采样、组合及CLI耗时 | 尚未完成同安全目标的跨方案排名、隔离环境的稳定均值、硬件加速比较或生产可用性评估 |

Luo 中止界适用于一次 Setup、`QE≤64 / QS≤65536 / QH≤2^64`及其理想经典XOF、随机源、好矩阵与正常状态假设；缓存越限、存储故障、回滚等不由该界覆盖。精确 LowBits 联合分布仍未知，但已有鲁棒接受集推导不需要先求出它。[推导与证书](../../research/2026-10-11-luo-abort-bound/README.md)、[C64B参数与安全引用条件](../../research/2026-10-11-luo-c64b-handoff/参数决定与安全引用条件.md)给出具体边界。

## 3. 真实组合已经检查了什么

选定组合为 **CHKP + Luo C64B compact + Hybrid + BYTEAUTH**。CHKP 参数为 `n=2, q=1099511627791, m=127`，根/父/叶维度127/254/381，`qα=4`；Luo完整17字段见[固定参数文件](../../research/2026-10-11-luo-c64b-handoff/profile.json)。应用消息最大3924 B，内层只加密32 B种子，双方身份编码各86 B；顺序固定为 `(rcv, phi)`。

- [44项组合检查](../../research/2026-10-12-chkp-closure/evidence/combination/checks.json)：诚实解密，三种身份错配，空消息、最大消息及超限，截断/追加/重复字段，签名消息与身份绑定，恢复后缓存复用，以及有效外层一次性签名下的旧IBS伪造拒绝。
- [CLI导入状态验收](../../research/2026-10-12-chkp-closure/evidence/cli/imported.json)：15个实际命令、59项检查；重复发钥、解密与拒绝路径禁止重新采样，并核对密钥及元数据字节不变。
- [CLI新建实例检查](../../research/2026-10-12-chkp-closure/evidence/cli/setup.json)：另一个新状态的2个命令、8项检查。它与上面的导入状态**不是同一次从CLI新建到最终解密的实验**。
- 分层负对照保留：裸CPA胶囊的低位改动可能仍解出同一个种子，但 Hybrid 对完整胶囊的AAD认证拒绝该修改；不能要求裸CPA自身承担外层认证职责。

12个必要阶段指4个生命周期阶段、6个组合阶段和2类CLI阶段；不是12次独立重复实验。归档中的恢复历史也不额外计成新生成。历史回归批次有重叠和明确跳过项，不能简单相加为“总共新增多少测试”。

## 4. 尺寸与耗时：现在能直接引用的数据

以下来自本次实际组合收据，字节数按当前序列化格式计算。密钥包含上下文及其当时缓存，不能当成论文中的裸向量尺寸。

| 对象 | 字节数 | 证据/说明 |
|---|---:|---|
| 组合系统公钥 | 251,412 | [prepare快照](../../research/2026-10-12-chkp-closure/evidence/combination/prepare.json) |
| 组合主密钥 | 921,004 | 同一prepare时刻；后续发钥会改变缓存 |
| Alice发送密钥 | 313,695 | 同一prepare快照 |
| Bob接收密钥 | 1,329,891 | 同一prepare快照，已含Alice叶缓存；不与无缓存对象混比 |
| Luo C64B compact签名 | 16,383 | reference为29,455；同一数学签名的两种编码，不是两套算法 |
| 原始CHKP胶囊 | 3,919 | 只负责32 B种子，不是完整IB-ME密文 |
| 完整密文：空消息 / 16 B消息 | 119,038 / 119,054 | [真实组合收据](../../research/2026-10-12-chkp-closure/evidence/combination/checks.json) |
| 完整密文：3924 B最大应用消息 | 122,962 | 已包含Hybrid与BYTEAUTH开销 |

C64B compact相对reference减少13,072 B（约44.38%），只是编码压缩收益。旧默认compact的16,063 B、旧教学ABB10胶囊大小和旧参数耗时不能填入这张表。

实际记录：首个成功父委派约4606.80 s；第二个父约3821.84 s；四个叶地址各约282.37–347.73 s。CLI三次加密命令各约2.43–3.02 s，三次解密各约8.29–8.83 s，**包含新进程启动、对象读取等CLI开销**。这些是共享开发机上的单次观察，不是纯算法基准，也不能用两次父委派的差值宣布优化加速。[阶段收据与完整说明](../../research/2026-10-12-chkp-closure/README.md)可追溯每个数字。

环境为 Core Ultra 7 255HX、约32 GiB主存、WSL Ubuntu 24.04、Sage 10.9 / Python 3.13.15；真实实验使用系统CSPRNG。[环境记录](../../research/2026-10-12-chkp-closure/environment.json)说明并发负载和测量限制。记录有峰值RSS的仅特定生命周期阶段，未测得独立整链峰值；没有恒定时间或侧信道保证。

## 5. 本次材料在哪里

| 材料 | 入口 |
|---|---|
| Luo实现、显式C64B配置、两种编码 | [IBS源码](../../../src/ibme/ibs/)、[配置](../../../src/ibme/ibs/luo_module_profiles.py) |
| Luo可用性推导、候选参数与估计输入 | [中止界证据包](../../research/2026-10-11-luo-abort-bound/README.md) |
| Luo参数选择、论文映射、跨版本交接 | [C64B交接包](../../research/2026-10-11-luo-c64b-handoff/README.md) |
| Luo终验收、DeepSeek复核及保留的纠错 | [最终验收包](../../research/2026-10-12-luo-final-acceptance/README.md) |
| 旧参数单体性能与原始CSV（明确作为历史） | [生命周期包](../../research/2026-10-11-luo-lifecycle/README.md) |
| CHKP后端与共享格工具 | [HIBE源码](../../../src/ibme/hibe/chkp/)、[格工具](../../../src/ibme/lattice/chkp/)、[接口契约](../../specs/chkp-hibe.md) |
| CHKP真实生命周期、组合、CLI、参数/资源、公开攻击 | [收尾包](../../research/2026-10-12-chkp-closure/README.md)、[源码和证据清单](../../research/2026-10-12-chkp-closure/source-manifest.json) |
| 复跑入口与测试 | [生命周期](../../../experiments/research/chkp_lifecycle.py)、[组合](../../../experiments/research/chkp_combination.py)、[CLI](../../../experiments/research/chkp_cli_acceptance.py)、[测试目录](../../../tests/) |

本次没有上传私钥、实际种子、真实密文、运行状态、私密几何缓存、私人任务书或记忆。公开证据只含结果、计数、耗时、尺寸、允许公开的参数/源码与哈希。因私密状态不发布，公开包可新建研究实例并审查来源链，但不能凭这些收据重新播放同一个历史密钥实例。

## 6. 后续重点

下一步的主要门槛不是继续重复Luo单体测试，而是：给CHKP找到同时满足困难性、正确性、采样和资源条件的可用参数，或在统一框架下比较其他合格HIBE；再按同安全目标、相同输入长度与计时边界做横向实验。参数或组合改变时补做受影响的验收。

报告现在可以写“已完成研究实现、实际整链接入及分层验收”，并列出上述尺寸和运行观察；不能写“已完成可部署抗量子IB-ME”“整体达到某安全位数”或“优于所有候选”。Luo无需为此次收尾自动重写基础论文的完整归约。

## 7. 发布前复核：与原始实验分开记录

先拉取上游，再在独立工作树合并：上游基点`14f1163`，CHKP固定交付`4ea086e`。发布前再次拉取，确认上游未出现新提交。保留上游MP12变体、安装规则和新分工，不纳入原目录6项既存未提交内容。Luo终验收40项材料与CHKP的130份源码/48份材料均按原Git对象逐项核对；12个阶段的收据语义与恢复来源链另行检查。

原CHKP清单针对`48e5c19`，**不应改写成在合并版本上重新做过实验**。与该清单相比，本次保留上游的`pyproject.toml`，并在原注册器末尾保留MP12变体登记；CHKP/Luo算法源码不变。旧清单在新工作树直接运行会正确指出这两处版本差异，因此使用本轮[只读发布核对器](verify_publication.py)检查原Git对象、原证据和限定的集成差异，而不是放松旧检查器。

| 本轮实际复核批次 | 结果 | 范围与证据 |
|---|---|---|
| Windows集成回归 | 237通过 / 1跳过 | CHKP交付检查、装配/噪声门/CLI工具、主状态、公共装配与C64B；[JUnit](evidence/windows-integration.xml)。只跳过Windows符号链接权限用例 |
| Sage集成回归 | 186通过 / 0跳过 | 收据/受限恢复、标量执行域、采样等价、后端和装配；[JUnit](evidence/sage-integration.xml) |
| Windows公共API兼容 | 88通过 / 3跳过 | 上游MP12入口、Luo独立性、CHKP运行时；[JUnit](evidence/windows-public-api.xml)。跳过项需要Sage |
| Sage公共API兼容 | 101通过 / 0跳过 | 上述三文件完整执行；[JUnit](evidence/sage-public-api.xml) |
| 清单/数值复核 | 通过 | [发布核对结果](evidence/publication-audit.json)；Luo既有交付审计25项及参数判定28项通过，未重跑估计器或签名批次 |

上述批次重叠，不累计成独立场景数。独立审查最初发现一条“CHKP未实现”的过时测试断言，两个环境各失败1项；[失败记录](evidence/compatibility-before-fix.json)保留。现在分别检查已交付状态、Sage依赖以及两后端的ID/版本/参数类/工厂/解码器不混用，修改测试后完整回归通过。没有为通过验收修改密码算法或降低条件。

从仓库根运行：

```text
python -B docs/deliveries/2026-10-12-chkp-luo/verify_publication.py
python -B experiments/research/audit_luo_c64b_delivery.py
python -B experiments/research/audit_luo_c64b_selection.py --repo .
```

后两条先设置`PYTHONPATH=src`。各测试文件与计数可从JUnit逐项检查；实际新采样命令见CHKP收尾包，非本轮发布审计执行的操作。本轮未重新构建/安装wheel，也未重跑昂贵父/叶历史实验；安装入口保留上游已审版本，发布回归不冒称完整安装验收。公开材料清单与各文件SHA见[发布清单](MANIFEST.json)，不包含该清单自身。
