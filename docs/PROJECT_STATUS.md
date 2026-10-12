# 当前进度与并行任务

更新：2026-10-12。本文是**唯一的当前进度和任务排序入口**。根规范负责长期契约；带日期的研究报告、交付记录与旧任务书只证明各自版本的事实，不继续发布全项目“下一轮”指令。

## 1. 已确认的组织方式

采用**一个 IB-ME 框架、独立 HIBE 模块、独立 IBS 模块、兼容组合的统一装配和验收**。协议、编码、持久状态、命令行和评测复用；每个原语由自己的负责人完成算法、对象、参数、采样及单体测试。

- 任一原语的阻塞只阻塞依赖它的组合。其它原语、组合预检和公共框架可以同时推进。
- 最终选择三组具有实际场景优势的完整组合；分别记录 HIBE 假设、IBS 假设、算法和组合数。参数变化、压缩格式和换采样器不自动算新方案。
- 用户已放宽第三套 HIBE 必须覆盖 Module-LWE 的限制。普通 LWE、环格、模格、SIS、Ring-SIS、NTRU 用于描述覆盖情况，不为凑分类把 IBE 当作 HIBE。
- 可选组合必须满足两层匿名 HIBE、IBS 安全游戏与固定密钥服务等具体前提。接口能连接、功能能运行、正式安全条件成立分别记录。
- 按用户给出的约 11 天窗口压缩交付轮次；80—140 天是估计工作量，不是日程。独立工作合并并行，发现实现问题直接修复，再由 DeepSeek 核验。

## 2. 代码与证据状态

本地已合并文档整理 `2868cf5`（含 `upstream/main` 的 `bc22c9c`）及框架检查点 `0bf0855`，状态整合为 `f61eb57`，最终装配边界修订为 `ccf34b6`，框架与三人分工交付为 `f98de52`。2026-10-12 又将 Luo 已提交分支截至 `e5e0b97` 的四个提交合入当前框架分支。上游 `first_suite`、接收状态事务、Luo C64B helper 与恢复入口现均在本地；没有重跑全部历史密码实验。框架原轮证据见[框架交付](deliveries/2026-10-11-framework/README.md)，本次同步及定向验证见[同步记录](deliveries/2026-10-12-local-sync/README.md)。

| 模块/产物 | 已有内容 | 尚缺内容及范围 |
|---|---|---|
| 统一框架与协议 | `assembly` 已实现后端注册、独立选择/参数快照、能力/容量预检；复用 Baseline/BYTEAUTH/Hybrid；CLI 与真实组合驱动共用装配入口 | 本轮已补齐用户要求的三项框架工作；候选原语须各自实现并通过单体/组合验收，静态预检不等于安全准入 |
| 可选 CLI / 状态 | `--hibe/--ibs` 和两边参数独立；v2 状态绑定完整配置、公钥摘要及对象类型；旧预设保留 | 摘要是存储一致性检查，没有外部认证或反回滚保证；持久化按所选公开对象保存，不改原语算法 |
| HIBE 公共接口 | 六个 HIBE 方法、规范对象；Hybrid 使用独立的公开密钥绑定验证能力 | 接口存在不等于每个候选已实现 |
| 教学 ABB10 + 教学 SIS | 实际代码、CLI、历史攻击与回归 | 教学参数及公开认证反例；不能计入已准入安全组合 |
| Luo 矩阵 IBS | 本地真实研究算法、适配器与历史参数筛查 | 当前暂停继续扩网格，保留为比较实例 |
| Luo 模格 IBS | 本地真实四算法、NTT/Hint、固定状态及 reference/compact 格式；通用框架允许显式完整参数；第二十三步 C64B helper、研究入口恢复及证据已合入 | 默认参数未改；引用条件和正式参数准入仍未全部完成；各批测试来源和执行版本见下表 |
| 现有完整研究接线 | **真实 CHKP + Hybrid + Luo 模格 C64B compact + BYTEAUTH** 已完成真实组合及 CLI 验收；教学 ABB10 接线继续作为历史对照 | 两条接线分别留证；当前 CHKP 的 n=2 参数已有公开种子恢复攻击，功能完成不等于保密性或组合安全准入 |
| CHKP 本仓库 | 六方法研究后端、共享运行时、六对象 wire、固定状态及统一装配已实现；原 CHKP RandBasis 父委派、四个真实叶各256目标、32 B种子和实际噪声封装/恢复均通过；[专属契约](specs/chkp-hibe.md)区分 MP12 根和原 CHKP RandBasis | 本轮研究功能已收尾，12个必要阶段的收据及原失败来源见[本轮记录](research/2026-10-12-chkp-closure/README.md)。正式困难参数、对应资源和组合归约仍未闭合 |
| CHKP 第七步外部包 | Codex 直接返工包及该轮定向验证，原输入与清单保留 | 作为当前实施的历史输入；第八步由 Codex 直接收尾，不以收到同名外部包作为完成条件；后续新增改动不能冒称已获 DeepSeek 再验 |
| 本地 `first_suite` 独立研究原型 | 已并入根/H/G/主父叶状态、有限 CSPRNG 采样、共享前导种子 KEM及 MP12 DelTrap；[固定交付](research/2026-10-11-first-suite-compact/README.md)记录 83/166/249 维 n=1 配置的真实父采样、同叶 256 原像、512 噪声位恢复与跨进程恢复 | 与第七步 cap32 不同版本；DelTrap 是独立 MP12 profile，不能改名当作原 CHKP RandBasis。n=1 可公开恢复种子；该历史 profile 没有独立公开后端，当前原 CHKP 后端及其验收另列 |
| 本地 CLI 接收状态事务 | [接收状态证据](research/2026-10-10-receiver-persistence/README.md)：锁、pending、保存后输出及已有研究接收密钥复用 | 提供同 OS 本地进程失败后的保守阻止；不宣称防回滚、硬断电或跨 OS 分布式事务 |
| 其它候选 | [候选基础包](research/2026-10-10-foundations/README.md)、Yu 同态、SRGG 代数/采样等部分实现 | 每项按实际算法和测试单独计数；不把候选卡或公开方程计作完整后端 |

### CHKP 本轮真实研究验收

Codex 已完成并核验生命周期4阶段、组合6阶段、CLI 2阶段，共 **12个必要阶段收据**。生命周期的根和Bob父基来自原r3成功结果，显式零熵恢复保留原失败叶墓碑、pending及来源收据；复制的setup/parent没有计为重新生成。恢复本身另留来源收据，不新增一次密码实验。

| 证据 | 已完成范围 | 来源边界 |
|---|---|---|
| [真实生命周期及恢复](research/2026-10-12-chkp-closure/evidence/lifecycle/roundtrip.json) | 127/254/381维根、父、叶路线；真实同叶256目标与32 B seed；对象恢复和无熵缓存复用 | 根/父保留原执行版本；原零熵准备失败和修复后第一次叶采样分别记录 |
| [真实组合44项](research/2026-10-12-chkp-closure/evidence/combination/checks.json) | Bob/Carol × Alice/Eve共四叶；四种身份匹配、对象恢复、实际IBS拒绝、Hybrid低位同seed的AAD拒绝、有效新OTS下旧IBS拒绝及空/最大消息 | 显式C64B compact + Hybrid + BYTEAUTH；没有使用教学HIBE或mock替代 |
| [CLI独立setup](research/2026-10-12-chkp-closure/evidence/cli/setup.json) | 8项检查、2个实际命令，独立生成setup状态并检查catalog | 该阶段未新发父/叶密钥 |
| [CLI导入状态验收](research/2026-10-12-chkp-closure/evidence/cli/imported.json) | 59项检查、15个实际命令；重发密钥复用、空/小/3924 B消息、错误身份和篡改拒绝，缓存字节保持不变 | 导入已完成的真实组合对象；不是由CLI再次生成根、父和叶 |

实测容量：内层86/86 B身份、32 B seed；原始胶囊3919 B，C64B compact签名16383 B；组合应用消息上限3924 B。16 B消息的完整密文119054 B，最大消息的完整密文122962 B。这些结果属于当前单次研究实例，不是性能总体估计。

n=2负控已从公开数据枚举5329个误差组合，**唯一恢复与真实seed匹配的候选**。因此全部入口保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。本次文档更新核对既有脱敏收据，没有重跑密码实验；公开证据统一归档于[收尾目录](research/2026-10-12-chkp-closure/README.md)，私密状态留在被忽略的`test-results/`。

### Luo 已合入工作与后续外部工作

| 来源 | 当前可使用的事实 | 验收边界 |
|---|---|---|
| Luo 历史提交 `c43c232`、`f079ce10fb6b3d2877465b308caaa30276d9e6f9` | 已合入验收、计时和生命周期材料；负责人记录 54 次 Sign、528 次 attempt、108 次两格式验签、212 项选定测试 | 历史执行证据；合入文件不等于本次重跑这些实验 |
| Luo 第二十二步，提交 `886fc127304479b87ef210836757004818e5b6ea` | 已合入鲁棒接受集/随机矩阵二阶矩条件式中止界、C49/C64B 研究候选及攻击成本估计。负责人记录 C64B 54 次 Sign／315 次尝试／108 次双格式验签，选定回归 269 passed | 本次复跑候选参数算术与证据检查；未重跑估计器/网格/全部历史回归。条件式可用性界不是安全位数，正式参数仍未准入 |
| Luo 第二十三步，提交 `e5e0b97752f9291ce7621dd830d665baff86aef8` | 已合入 `c64b_params()` 完整 17 字段 helper 与专属研究入口恢复；负责人此前交付 122 项定向/19 项工具测试，以及框架 `0bf0855` 上 25 项 C64B 检查 | 本次重跑范围见[同步记录](deliveries/2026-10-12-local-sync/README.md)。此前最大 3924 B 应用消息/20415 B 外载荷的 25 项装配收据仍归原执行版本，见[原收据](deliveries/2026-10-11-framework/luo-c64b-owner-receipt.json)；不计 CHKP 完成或正式参数 |
| Luo 第二十四步终验收 | 负责人固定交付 `c043c4b` 已以 `c336a51` 纳入当前分支；[验收记录](research/2026-10-12-luo-final-acceptance/README.md)包含复跑与独立审查 | 没有改变默认参数或正式安全标记；其中教学 ABB10 接线与本轮 CHKP 实跑分别计数 |
| `CODEX-step22-luo-integration/report.md` | 原版本的静态及公共接口预检指出首阻塞 `CHKP_PUBLIC_BACKEND_MISSING` | 负责人当时后续复跑26项检查及18项公共边界，均作为历史预检保留；当前后端及上列真实CHKP+Luo结果已另行交付，不回写原报告 |

第二十二步显式 C64B 候选的 compact 签名由负责人测得16383 B，本次真实CHKP组合再次核对该尺寸；默认参数对应的16063 B保持原状。inner输入为86/86/32 B；显式C64B没有改成全局默认，其它配置仍需分别核算容量。

第二十二步固定入口现为本地[中止界与参数材料](research/2026-10-11-luo-abort-bound/README.md)，第二十三步入口为[C64B 交付](research/2026-10-11-luo-c64b-handoff/README.md)。后续独立工作树位于 `C:/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS`。C64B 的 κ=64、γ1=190000、γ2=60000000000、γ3=(q−1)/10，两项重试帽各4096。负责人在理想随机源／理想 XOF 及明确查询预算下给出正常调用总中止上界 <2^-153；MSIS 模型成本指数为经典188.340／量子170.925。以上是该固定交付的条件与结果，未授予整个 IBS 或组合相应安全等级。

目前相关研究组合保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。这些标识约束安全表述；可执行的真实研究配置仍可进行功能接入和测量。

公共框架最终定向回归为 **122 passed / 3 skipped**，3 项跳过需要 Sage 的真实缓存；历史教学攻击回归为 **4 passed / 2 strict xfailed**。开发期 9 个配置共 274 检查通过，三种实际 IBS 与一个教学 HIBE 的多包装/格式不能计为九种独立密码算法。最终源码定向实跑、版本边界与逐项收据见[本轮交付](deliveries/2026-10-11-framework/README.md)。

## 3. 当前并行包与完成条件

| 并行线 | 本轮要交付的实物 | 依赖与停止边界 |
|---|---|---|
| 公共框架 | 已有[独立选择与测试入口](FRAMEWORK_USAGE.md)；维护新原语登记、容量/能力声明和其真实组合收据 | 不等待 CHKP；不重复开发协议；新增接口语义逐项协调 |
| CHKP | 本轮真实研究后端、根→父→固定256目标叶、32 B种子、对象加载、C64B组合及CLI均已收尾 | 后续范围是正式困难参数、资源可用性和组合前提；沿用已完成结果，旧[模块任务卡](workplans/2026-10-08/队友任务-CHKP与格工具.md)不要求重复根父实验 |
| Luo IBS | 条件与参数对应、总中止/LowBits 问题处置、真实生命周期证据 | 负责人独立推进；不重复重写已发表基础归约，不把 sketch 升级成完整定理 |
| 其它 HIBE/IBS | 每个认领模块的来源、对象、算法、真实最小实例和单体契约 | 与首套并行；优先有合法源码/明确有限参数的路线，复杂或条件不明的列储备 |
| 组合与交付 | 接入已具备研究契约的真实原语，四种匹配、错误输入、字节篡改、固定状态恢复、尺寸/时间/内存 | 原语未到可做预检；诚实端到端及对应攻击必须用该真实组合执行，不用 mock 顶替 |

验收分为研究执行与安全结论两层：前者要求算法对应、诚实功能、明确错误处理及真实收据；后者还要求所用版本的参数、分布、引用条件和组合前提成立。一个模型或参数的通过不自动传给其它组合。

### 三位队员的执行分工

用户确认按队员 A/B/C 编排。完整任务卡、文件边界、11 天相对日程、交付包和组合验收见 [三人方案分工与统一框架交付](workplans/三人方案分工与统一框架交付.md)：A 负责 CHKP HIBE 并对接现有 Luo；B 负责环 HIBE 主线；C 负责 BNN-Falcon 转换 IBS。每人新增一个主要原语，复用其它负责人的伙伴模块，最终按证据选择三组完整组合。Ring-SIS 与原生 NTRU 的研究支线不强塞进三人的同时开发主线，未闭合就如实保留缺口。

## 4. 当前入口与证据定位

- [总体架构](../ARCHITECTURE.md)、[公共接口与验收](../IMPLEMENTATION_SPEC.md)、[协作流程](../AI_WORKFLOW.md)、[通用任务模板](../DELEGATION_PROMPTS.md)。
- [框架使用指南](FRAMEWORK_USAGE.md)、[本轮框架交付](deliveries/2026-10-11-framework/README.md)、[三人分工](workplans/三人方案分工与统一框架交付.md)。
- [CHKP 交接入口](research/team-chkp/README.md)、[主 AI/IBS 与集成任务](workplans/2026-10-08/主AI任务-IBS集成与优化.md)。
- 本地首套研究版本：[公开代码/标量诊断](research/2026-10-11-public-reuse/README.md)、[原文噪声](research/2026-10-11-rounded-noise/README.md)、[固定种子/H-G](research/2026-10-11-first-suite-seed/README.md)、[主父树](research/2026-10-11-first-suite-tree/README.md)、[有限采样](research/2026-10-11-first-suite-finite/README.md)、[根与公开恢复攻击](research/2026-10-11-first-suite-root/README.md)、[有限 DelTrap/资源筛查](research/2026-10-11-first-suite-compact/README.md)。对应合同见 [first_suite 专属契约](specs/first-suite-research.md)。各报告统计属于各自原执行版本，不合计为本次复跑。
- [Luo 模格路线决策](research/2026-10-11/IBS版本决策-模格版主线.md)、[已知漏洞与历史 CI](KNOWN_SECURITY_GAPS.md)。
- [现行算法总表](ALGORITHM_CATALOG.md)（8 条 HIBE / 11 条 IBS 候选及模型路线）、[论文库](../papers/index.md)、[历史重建记录](history/PROJECT_RESTART-through-2026-10-10.md)。

本机外部交付根为 `C:/Users/A/.dsh/deliverables/`。可移交时需带包本身及其清单，不能只发送本机路径：

- `CHKP-step7-codex-rework/report.md`、`source_manifest.json`；清单 SHA-256 `6e20806345024e92f1e9fe259439ac461f2ddfe7e194db597dce9ddbdc950790`。
- CHKP 第八步研究功能由Codex直接完成收尾，[本轮记录](research/2026-10-12-chkp-closure/README.md)统一代码、真实12阶段证据及未闭合的安全条件。旧任务书和冻结包内`next_step8.md`保留为历史输入。
- `CODEX-step22-luo-integration/report.md`：外部接入预检，按上表范围使用。

更新本文时同时标出提交/包版本、核验者和已运行范围；不在 README、AGENTS 或旧报告末尾再追加第二份“最新进度”。
