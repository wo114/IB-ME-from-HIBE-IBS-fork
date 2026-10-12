# CHKP 交接与验收入口

更新：2026-10-12。此处汇总 CHKP 模块的证据位置；项目全局状态以[当前进度](../../PROJECT_STATUS.md)为准，公共接口以[统一规范](../../../IMPLEMENTATION_SPEC.md)和[CHKP 专属契约](../../specs/chkp-hibe.md)为准。最新实现、真实执行与未闭合条件统一见[本轮收尾记录](../2026-10-12-chkp-closure/README.md)。

## 1. 当前状态与来源边界

| 来源 | 已有内容 | 尚不能据此宣称 |
|---|---|---|
| 当前checkout，`ec0783e`、`cdba26f`及后续修订；执行域修复`0765304`、显式恢复`3c53df1` | 六方法、对象及公开绑定、共享采样运行时、独立选择与状态事务已实现；真实CHKP + Luo C64B compact + Hybrid + BYTEAUTH完成生命周期、组合和CLI的12个必要阶段验收 | 研究功能已收尾；n=2实例已被公开数据唯一恢复seed，正式困难参数、资源可用性和组合归约仍未闭合。原失败及根父复用来源完整保留 |
| 仓库外第七步 Codex 修订包 | 规范集合／持久状态／执行器／收据修复；实际采样与资源问题的研究工具 | A/D 尚需接线；第七步同叶目标帽 32 不满足 32 B 种子的 256 位置需求；F 的成功是教学 ABB10 + Luo 路径 |
| 已并入本 checkout 的 `first_suite` | H/G、固定 256 位置、根/父/叶状态、有限 CSPRNG 和种子 KEM；[DelTrap 原交付](../2026-10-11-first-suite-compact/README.md)记录真实父陷门、同叶 256 原像及两枚带噪声种子的 512 位恢复 | 原执行参数n=1可公开恢复种子；独立MP12 DelTrap不等于原CHKP RandBasis，该历史profile尚无独立公开HIBE后端。研究合同见[first_suite专属规范](../../specs/first-suite-research.md) |

第七步研究包保持其原有 `T2_complete=false`、`T3_complete=false` 历史状态，不回写旧结果。当前后端的算法/测试/运行证据单独发布，仍声明 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。

## 2. 历史仓库外交付

以下路径属于当前机器的交付区，**不是本仓库内容**；团队交换时需另行取得对应包。根目录定位：`C:/Users/A/.dsh/deliverables/`。

| 相对该交付区的路径 | 用途与状态 |
|---|---|
| `CHKP-step7-codex-rework/report.md` | 第七步 Codex 主审与直接修复报告；其中新增修订经该轮定向回归，不能据此声称 DeepSeek 已独立验证后续全部差异 |
| `CHKP-step7-codex-rework/source_manifest.json` | 清单列 465 个文件；本次核对该清单文件 SHA-256 与发布值一致，未将此表述为本轮重跑全部测试 |
| `DEEPSEEK-CHKP第八步-加量任务书-参数闭合真实采样与整链并行实现-2026-10-11.md` | 历史任务 v2：参数／真实采样／状态／生命周期／同叶 256／公共适配器；用户后续要求由 Codex 直接实施收尾 |
| `CHKP-step8-package/` | 原预定包名，不作为当前代码是否完成的判据；当前交付随 Git 和本轮收尾记录发布 |
| `CHKP-taskbook-history/第八步-v1-修订验证状态接线与参数证书-2026-10-11.md` | 历史 v1；冻结第七步包内的 `next_step8.md` 也是 v1，由上面的 v2 替代 |

第七步清单文件 SHA-256：

```text
6e20806345024e92f1e9fe259439ac461f2ddfe7e194db597dce9ddbdc950790
```

`first_suite` 已随 `bc22c9c` 并入本 checkout；Luo 第二十二/二十三步已随 `7b9e8a7` 集成，第二十四步终验收以 `c336a51` 纳入。旧交付区的 `CODEX-step22-luo-integration/report.md` 当时报告“公开后端缺失”，该结论只适用于原版本；不能覆盖当前已实现的 CHKP 后端，也不能被当前后端存在自动改写成原时点已完成。

### 第七步修订的证据边界

- A：17 项 wire／集合检查；cap8 的强制范围为单一所有者实例，不提供防回滚。
- D：S1—S4 共 4/4，含真正子进程恢复；故障 17/17，子进程失败／超时守卫 2/2。状态机与 A 集合尚未完成统一接线。
- F：完整 HEAD 校验、15 项脱敏检查、24/24 reference/compact smoke 与 13 项独立收据检查；smoke 使用现有教学 ABB10 + Luo，不是 CHKP。
- E：5 项执行器回归、raw 层 6/6、E-26 的状态检查 21 项；没有在该修订轮重新跑完整 26 场景。
- C1：Windows／WSL 的 7 个输出逐字节一致；旧包换行失配保留为历史问题，没有重写旧清单掩盖差异。

以上为第七步报告及相应收据的范围摘要。历史通过数不累加为当前全量测试数。

## 3. 当前验收范围

1. 当前执行参数为n=2、q=1099511627791，MP12根转完整基、原CHKP RandBasis一级、最大深度SampleD叶的127/254/381维路线。Bob/Carol × Alice/Eve四个真实叶各有256目标，内层身份86/86 B、seed 32 B。旧AP09根173的矩阵TV充分上界1仍仅表示旧证书无信息。
2. 12个必要阶段收据齐全：生命周期4阶段、组合6阶段、CLI 2阶段。根和Bob父来自r3已成功对象；原叶零熵准备失败在源目录保留墓碑、pending和收据。`2^88`固定标量执行域修复没有改变实际宽度、概率质量或随机读取；显式恢复没有重新GenTrap、RandBasis或LLL，复制setup/parent按原来源统计。
3. [组合44项](../2026-10-12-chkp-closure/evidence/combination/checks.json)覆盖四种身份匹配、对象恢复、固定缓存复用、实际IBS拒绝、raw低位修改仍同seed时的Hybrid AAD拒绝、有效新OTS下完整BYTEAUTH到达IBS层拒绝，以及空/最大消息。执行的是两个真实研究后端，没有用教学ABB10或mock代替。
4. [CLI独立setup](../2026-10-12-chkp-closure/evidence/cli/setup.json)通过8项检查、2个实际命令；[CLI导入状态](../2026-10-12-chkp-closure/evidence/cli/imported.json)通过59项检查、15个实际命令。后者复用已完成组合的主/发送/接收对象，验证重发、0/21/3924 B消息及拒绝行为；不是CLI再次生成根父叶。
5. 原始胶囊3919 B，C64B compact签名16383 B，应用消息上限3924 B；组合16 B消息的完整密文119054 B，最大消息完整密文122962 B。单次实例与分阶段耗时见原收据，不由这些结果推断总体性能。
6. [公开恢复负控](../2026-10-12-chkp-closure/evidence/lifecycle/roundtrip.json)从5329个公开误差组合中唯一恢复匹配真实seed的候选。因此`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`保持不变；正式困难参数、对应资源与组合前提不因功能通过而完成。

公开源码、脱敏收据及清单统一放在[本轮收尾目录](../2026-10-12-chkp-closure/README.md)，旧报告按原版本保留。本地私密执行状态分别位于被Git忽略的`test-results/chkp-lifetime-2026-10-12-r3-resumed/`、`test-results/chkp-combination-2026-10-12/`、`test-results/chkp-cli-2026-10-12/`；原r3目录继续保留失败现场。私钥、缓存及原始进程日志不进入公开提交。本次入口更新只核对既有收据，没有重跑实验。

执行采用 G-run／G-chain／G-formal 分层：合法真实调用可以标为研究诊断，正式参数未闭合不阻止全部功能工作；数学采样前提、正式安全与功能结果各自留证。第八步 v2 已把可并行内容合并，不继续按旧 T1—T5 串行等待。

## 4. 历史证据索引

下列材料保留当时的输入、命令、结果与限制；其中“下一步”“本轮”按原日期理解，不覆盖当前任务或公共规范。

### 2026-10-10：参数、叶路径和缓存

- [论文参数预筛](T2-论文参数候选预筛-2026-10-10.md)、[预筛机器证据](T2-paper-preflight-toy-2026-10-10.json)、[正确性筛选参数 v1](T2-正确性筛选参数-v1-2026-10-10.md)：静态筛选与后续生成／质量／资源条件分开。
- [最大深度叶路径契约](T2-leaf-path-contract-2026-10-10.md)、[叶路径核查](T2-leaf-path-audit-2026-10-10.md)、[叶机器证据](T2-leaf-evidence-2026-10-10.json)：最大深度使用扩展后的一级基 SampleD，不要求第二次 RandBasis；四个固定种子的有限结果不代表正式参数。
- [固定叶原像缓存与恢复](T3-leaf-cache-restore-2026-10-10.md)、[缓存机器证据](T3-leaf-cache-evidence-2026-10-10.json)、[执行日志](T3-leaf-cache-execution-2026-10-10.log)：原组件的恢复测试；后续崩溃窗口和存储语义修订见仓库外报告。原快照不自带认证、事务或防回滚保证。
- [宽度与基后处理核查](T2-width-basis-audit-2026-10-10.md)、[宽度机器证据](T2-width-evidence-2026-10-10.json)：保留双基路径失败、可选 LLL 和预算限制；旧第二次 RandBasis 开销不是终止层叶路径必需成本。
- [真实采样实现与未闭合项](T2-真实采样实现与未闭合项-2026-10-10.md)、[早期整链记录](T2-chain-evidence-2026-10-10.json)、[ToBasis 来源补充](../../../papers/chkp-t2-source-supplement-2026-10-10.json)。

### 2026-10-09：算法契约与 T1 修复

- [算法来源与有限采样契约](T2-算法来源与采样契约-2026-10-09.md)、[T2 当轮交付](T2-交付与验证-2026-10-09.md)：当日为准备与条件检查，真实实现的后续进展见 10 月 10 日证据。
- [T1 正确性核验与修复](T1-正确性核验与修复-2026-10-09.md)、[验证记录](T1-验证记录-2026-10-09.md)、[公开机器证据](T1-exact-evidence-2026-10-09.json)：限定研究域中的完整格代数及测试证据，不代表完整 HIBE 或安全验收。
- [2026-10-08 原始交接](HANDOFF-2026-10-08.md)：保留当时的 14 passed / 2 failed，后续 T1 修复已处理这两项失败。
