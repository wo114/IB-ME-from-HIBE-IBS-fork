# 当前进度与并行任务

更新：2026-10-12。本文是**唯一的当前进度和任务排序入口**。根规范负责长期契约；带日期的研究报告、交付记录与旧任务书只证明各自版本的事实，不继续发布全项目“下一轮”指令。

## 1. 已确认的组织方式

采用**一个 IB-ME 框架、独立 HIBE 模块、独立 IBS 模块、兼容组合的统一装配和验收**。协议、编码、持久状态、命令行和评测复用；每个原语由自己的负责人完成算法、对象、参数、采样及单体测试。

- 任一原语的阻塞只阻塞依赖它的组合。其它原语、组合预检和公共框架可以同时推进。
- 最终选择三组具有实际场景优势的完整组合；分别记录 HIBE 假设、IBS 假设、算法和组合数。参数变化、压缩格式和换采样器不自动算新方案。
- 用户已放宽第三套 HIBE 必须覆盖 Module-LWE 的限制。普通 LWE、环格、模格、SIS、Ring-SIS、NTRU 用于描述覆盖情况，不为凑分类把 IBE 当作 HIBE。
- 可选组合必须满足两层匿名 HIBE、IBS 安全游戏与固定密钥服务等具体前提。接口能连接、功能能运行、正式安全条件成立分别记录。
- 按用户确认的时间充分条件，以验收阶段推进，不从旧 PR 推定截止日期。2026-10-12 用户要求先完成 PR 审查、路线排序、三人分工和统筹安排，再推进 A 的实现目标；发现已授权范围的实现问题直接修复，固定版本独立核验。

## 2. 代码与证据状态

2026-10-12 用户授权审查所有 PR 并直接合并合格者：#11（包含 #10）、#9、#12、后新增的 #13 均已合入远端 `main`，本批接收基点 `94f2168`。本节按合入源码描述；精确 head/合入提交、测试和未完成范围见[本轮审查记录](deliveries/2026-10-12-pr-review/README.md)。旧[分工审查说明](workplans/2026-10-12/PR审查与分工修订说明.md)保留当时尚未合并的版本事实。

已接收文档整理 `2868cf5`、框架修订 `57a02e5`、Luo `e5e0b97`、A研究后端 `7795719` 和安装入口/隔离测试修订 `3c8441f`。历史框架实验单列于[原交付记录](deliveries/2026-10-11-framework/README.md)，本轮不重新累加历史计数。#9—#12 固定源码审查350个唯一 pytest 用例最终通过，另25项 C64B assembly 实跑；该批合入源码与验证树相同。#13 另验173 passed/2明确skip、55 Sage passed、真实安装/CLI和两组远端检查；测试交叠不相加，失败/复跑均保留。

| 模块/产物 | 已有内容 | 尚缺内容及范围 |
|---|---|---|
| 统一框架与协议 | `assembly` 已实现后端注册、独立选择/参数快照、能力/容量预检；复用 Baseline/BYTEAUTH/Hybrid；CLI 与真实组合驱动共用装配入口 | 本轮已补齐用户要求的三项框架工作；候选原语须各自实现并通过单体/组合验收，静态预检不等于安全准入 |
| 可选 CLI / 状态 | `--hibe/--ibs` 和两边参数独立；v2 状态绑定完整配置、公钥摘要及对象类型；旧预设保留 | 摘要是存储一致性检查，没有外部认证或反回滚保证；持久化按所选公开对象保存，不改原语算法 |
| HIBE 公共接口 | 六个 HIBE 方法、规范对象；Hybrid 使用独立的公开密钥绑定验证能力 | 接口存在不等于每个候选已实现 |
| 教学 ABB10 + 教学 SIS | 实际代码、CLI、历史攻击与回归 | 教学参数及公开认证反例；不能计入已准入安全组合 |
| Luo 矩阵 IBS | 本地真实研究算法、适配器与历史参数筛查 | 当前暂停继续扩网格，保留为比较实例 |
| Luo 模格 IBS | 真实四算法、NTT/Hint、固定状态及 reference/compact；已合入 C64B 完整17字段 helper、研究入口 profile 绑定/恢复，最新公共 assembly 的 C64B 25项真实检查通过 | 默认参数不变；C64B 仍显式选择，引用条件和正式参数准入未全部完成，历史与本轮证据分列 |
| 既有内置完整研究接线 | **教学 ABB10 + Hybrid + Luo 模格 + BYTEAUTH** | 可以验证工程流程；HIBE 不是 CHKP，不能记为真实 CHKP 组合完成 |
| CHKP 本仓库 | `experiments/research/chkp_*` 的格基、采样、叶路径和缓存研究模块与测试 | 无 `src/ibme/hibe/chkp.py` 完整公开后端；T2/T3 与真实 32 B 接入未闭合 |
| CHKP 第七步外部包 | Codex 直接返工包及定向验证，原输入与清单保留 | 第八步加量任务已发；本次目录检查未收到 `CHKP-step8-package/`；第七步新增改动不能冒称已获 DeepSeek 再验 |
| 旧 `first_suite` 独立研究原型 | 已并入根/H/G/主父叶状态、有限 CSPRNG 采样、共享前导种子 KEM及 MP12 DelTrap；[固定交付](research/2026-10-11-first-suite-compact/README.md)记录 83/166/249 维 n=1 配置的真实父采样、同叶 256 原像、512 噪声位恢复与跨进程恢复 | 与第七步 cap32 不同版本；n=1 可公开恢复种子。旧组件不等于原 CHKP 或新计算型 MP12 完整后端；新后端单列，不能由旧“未实现”描述否定它 |
| A 的 MP12 变体公开研究后端（已合入） | [第一批](research/team-a-delivery/2026-10-12-hibe-reference/README.md)：计算型 `[I\|Â]` 根、真实 DelTrap/固定256叶，六方法/五类对象/绑定、自定义 registry；原交付21项组合收据，本轮独立48项Sage测试无skip；安装接入单列 | n2/q549755813911 不安全，原交付8649次公开枚举恢复明文；原 CHKP theorem 不能直接继承。正式参数/模型、原 CHKP 和 ABB-ROM 仍待，不升级已准入数 |
| A 的公共安装入口（PR #13 已合入） | [第二批](research/team-a-delivery/2026-10-12-installed-api/README.md)：公共HIBE/格工具、单一 provider、wheel与默认可选登记；审查173 passed/2明确skip、55 Sage passed，仓库外安装Windows3/Sage10项，独立实际CLI8步通过 | 无Sage明确unavailable；新根/新接收者需要显式本地engine，旧状态可无engine恢复；原n2公开攻击和none/false保持；正式大尺寸部署/模型仍待 |
| 本地 CLI 接收状态事务 | [接收状态证据](research/2026-10-10-receiver-persistence/README.md)：锁、pending、保存后输出及已有研究接收密钥复用 | 提供同 OS 本地进程失败后的保守阻止；不宣称防回滚、硬断电或跨 OS 分布式事务 |
| 其它候选 | [候选基础包](research/2026-10-10-foundations/README.md)、Yu 同态、SRGG 代数/采样等部分实现 | 每项按实际算法和测试单独计数；不把候选卡或公开方程计作完整后端 |

### 外部交付与接收记录

| 来源 | 当前可使用的事实 | 验收边界 |
|---|---|---|
| 邻居 Luo 工作树 `luo-acceptance-evidence`，历史提交 `f079ce10fb6b3d2877465b308caaa30276d9e6f9` | 负责人已核的上一批 54 次 Sign、528 次 attempt、108 次两格式验签、212 项选定测试 | 保留历史基点与原统计；后续源码接收按下列固定提交和本轮审查记录 |
| Luo 第二十二步，提交 `886fc127304479b87ef210836757004818e5b6ea` | 鲁棒接受集/随机矩阵二阶矩条件式中止界、C49/C64B 候选及攻击成本估计，已随 #9 接收。负责人原记录 C64B 54次 Sign／315次尝试／108次双格式验签、269项回归 | 原54次性能批次没有在本轮重跑，相关条件式证书与证据工具已独立验；条件式可用性界不是安全位数，正式参数仍未准入 |
| Luo 第二十三步，提交 `e5e0b97752f9291ce7621dd830d665baff86aef8` | 已合入 helper 与专属入口。原交付122/19项及`0bf0855`的25项收据保留；本轮在最终联合 assembly 独立重跑25项，compact 最大3924 B应用消息/20415 B外载荷真实往返、全对象/profile恢复与错配拒绝 | 新25项的 reference 是容量预检、compact 是实际运行；研究专用入口两格式另有实际 pytest 回归。原性能统计不相加，不计原 CHKP 完成或正式参数 |
| `CODEX-step22-luo-integration/report.md` | 静态及公共接口预检报告指出首阻塞 `CHKP_PUBLIC_BACKEND_MISSING` | 负责人后续已复跑 26 项检查及 18 项公共边界；本对话未复跑，仍不是实际 CHKP+Luo 加解密结果 |

第二十二步显式 C64B 候选的 compact 签名由负责人测得 16383 B（默认仍为 16063 B），inner 输入仍为 86/86/32 B；该候选尚未改变本仓库默认参数，未来组合按所选配置重新核算外层容量。

第二十二步固定入口为上述外部提交中的 `docs/research/2026-10-11-luo-abort-bound/README.md`；工作树位于 `C:/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS`。C64B 的 κ=64、γ1=190000、γ2=60000000000、γ3=(q−1)/10，两项重试帽各4096。负责人在理想随机源／理想 XOF 及明确查询预算下给出正常调用总中止上界 <2^-153；MSIS 模型成本指数为经典188.340／量子170.925。以上是该固定交付的条件与结果，未授予整个 IBS 或组合相应安全等级。

目前相关研究组合保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。这些标识约束安全表述；可执行的真实研究配置仍可进行功能接入和测量。

公共框架最终定向回归为 **122 passed / 3 skipped**，3 项跳过需要 Sage 的真实缓存；历史教学攻击回归为 **4 passed / 2 strict xfailed**。开发期 9 个配置共 274 检查通过，三种实际 IBS 与一个教学 HIBE 的多包装/格式不能计为九种独立密码算法。最终源码定向实跑、版本边界与逐项收据见[本轮交付](deliveries/2026-10-11-framework/README.md)。

## 3. 当前并行包与完成条件

| 并行线 | 本轮要交付的实物 | 依赖与停止边界 |
|---|---|---|
| 公共框架 | 已有[独立选择与测试入口](FRAMEWORK_USAGE.md)；维护新原语登记、容量/能力声明和其真实组合收据 | 不等待 CHKP；不重复开发协议；新增接口语义逐项协调 |
| CHKP | 合法研究参数与资源账本、真实根→第一层→叶采样、固定解封装、同叶 256 目标及 32 B 种子、公开后端和对象加载 | 按[CHKP 当前任务](workplans/2026-10-08/队友任务-CHKP与格工具.md)并行；失败给出具体首阻塞、收据与可继续项 |
| Luo IBS | 条件与参数对应、总中止/LowBits 问题处置、真实生命周期证据 | 负责人独立推进；不重复重写已发表基础归约，不把 sketch 升级成完整定理 |
| 其它 HIBE/IBS | 每个认领模块的来源、对象、算法、真实最小实例和单体契约 | 与首套并行；优先有合法源码/明确有限参数的路线，复杂或条件不明的列储备 |
| 组合与交付 | 接入已具备研究契约的真实原语，四种匹配、错误输入、字节篡改、固定状态恢复、尺寸/时间/内存 | 原语未到可做预检；诚实端到端及对应攻击必须用该真实组合执行，不用 mock 顶替 |

验收分为研究执行与安全结论两层：前者要求算法对应、诚实功能、明确错误处理及真实收据；后者还要求所用版本的参数、分布、引用条件和组合前提成立。一个模型或参数的通过不自动传给其它组合。

### 三位队员的执行分工

2026-10-12 按用户要求修订为**每人按原语族顺序完成若干方案**：A 负责 CHKP/明确标识的 MP12 变体、ABB-ROM 与矩阵陷门工具；B 负责现有 Luo 收尾及 Foo–Li/Wang+PW 等原生格 IBS；C 负责 LATTE/Lai 的结构 HIBE 核验与实施、共享认证转换的 ML-DSA/Falcon 对照、Xie NTRU 核验。现有文件 owner 先交接，不同时写入。

19 条路线均有 owner、优先级和下一步，公共 T0—T10 明确覆盖 PR 接收、装配、状态、全组合攻击、评测、展示、优化验证、报告和支撑材料。详见[总计划](workplans/三人方案分工与统一框架交付.md)、[A](workplans/2026-10-12/A-矩阵HIBE任务.md)、[B](workplans/2026-10-12/B-原生格IBS任务.md)、[C](workplans/2026-10-12/C-结构HIBE与工程IBS任务.md)和[任务登记](workplans/2026-10-12/tasks.json)。全部就绪且适配的配对纳入验收，最后按场景数据挑三个报告重点，不限制其它配对。这个分工是计划，不是新增后端的完成声明。

此前的[分工修订](workplans/2026-10-12/PR审查与分工修订说明.md)在 PR #11 工作树完成，当时没有合并。2026-10-12 本轮依用户授权完成 #9/#10/#11/#12 审查与合入，C64B 与 MP12 源码均已接收；没有改变密码算法或提升安全声明。后续按三人任务书推进，不把“代码已合入”写成“项目/正式参数已完成”。

A 随后按新任务书开始独立分支实施，新增 MP12 变体研究后端和真实单配对，范围/攻击/参数缺口见上表交付。A 目标仍 active：公开接口及安装工具已实跑，正式维度/两角色困难性/模型对应和大尺寸部署工具未闭合；A2研究接口/codec已交，正条件完整生命周期仍WIP；AR储备说明已交（见下方2026-10-13批次）。新结果不覆盖原型/旧报告或其它未测组合。

A 第二批已补[可安装公开 API 与默认 CLI](research/team-a-delivery/2026-10-12-installed-api/README.md)：Windows/Sage 均在仓库外验证 provider 来自安装包；Sage 无native/无熵重放原四种匹配，新安装CLI真实8步通过，55项Sage回归通过。默认入口在无Sage时明确 unavailable；缺native只阻止新根/新receiver，并在地址写入前拒绝。原n2攻击/none/false、原CHKP/ABB、正式维度/模型与双角色困难性仍待，不能称A完成。

A2 已有[SampleR/BasisDel原语批次](research/team-a-delivery/2026-10-12-abb-primitives/README.md)：整矩阵Gaussian条件采样、变换子格的完整格补全、真实随机化、非交换两层及直接产品核验。24项新Sage测试/57项含相关回归通过，保存私有84维输入复用成功；旧偏斜基准入失败保持，未调旧guard。随后[AP09根/原文位加解密批次](research/team-a-delivery/2026-10-12-abb-root-bits/README.md)补真实TrapGen族、208维核验、同一248维真实根的八比特恢复及公开n1攻击，33项新测试纳入116 Sage pass/3旧私有witness skip；三组同输入资源/宽度筛查明确不可执行项。仍无完整ABB两层后端/codec/组合，none/false和已准入数保持；正式域与共享委派/宽Gaussian工具继续。原CHKP最新PR #14已交研究整链，本A2分支尚未合入该PR，不重复编写其实现。

A3 已补[单源矩阵有限工具](research/team-a-delivery/2026-10-12-matrix-tools/README.md)：旧scalar/GPV/RandBasis/ToBasis兼容入口与显式宽profile共用数学源，实际257维GPV、2^192平方宽度及ABB双委派消费者测试通过；Sage168 pass/3旧私有witness skip、Windows116 pass/5 Sage skip，隔离安装调用通过。2026-10-13，同一248维真实AP09根/R的两次BasisDel/RandBasis、固定规约和最终SamplePre实际九阶段通过，约10.29小时/峰值RSS1184036 KiB；首轮中断与来源链保留。同组两层噪声界仍失败，没有身份oracle/五类对象/完整HIBE，宽profile和实现后处理不增加已准入数。

2026-10-13，A2交[研究后端/五类对象/固定状态与容量筛查](research/team-a-delivery/2026-10-13-abb-backend-wip/README.md)，独立BackendSpec可供统筹接入，默认registry/协议/CLI未改。真实q160和q104 Setup通过，父过程的中断/FAILED及零私有熵禁止重发证据保留，不能称完整HIBE通过；新q104单地址配置的4MiB capsule容量预检通过。[规范核格与精确三角计算](research/team-a-delivery/2026-10-13-abb-canonical-fix/README.md)相关Sage最终227 pass/3旧私有witness skip，仓库外隔离安装71个provider通过。正条件完整父/叶/256bit/Luo组合及正式域仍WIP；不得据接口或公开代数测试增加已准入数。

A 后续先完成[PR14/15/16固定版本复核](research/team-a-delivery/2026-10-13-pr-review/README.md)，再交[CHKP共享引擎配置与8文件接入提案](research/team-a-delivery/2026-10-13-chkp-shared-profiles/README.md)：当前A分支60 pass/7待接实际扩展消费者skip，独立候选副本1122 pass/4外部witness skip；未修改队友源码或默认registry，统筹仍需实际共享合并、安装/CLI与组合复核，不升级正式准入。ABB规范q104实例的进程已不在运行，仍是父pending且无完成收据；同一master只读恢复确认FAILED及重发私有熵0，终止原因和父总耗熵未知，不能继续写为正在运行或完整通过。

AR交[三个储备说明](research/team-a-delivery/2026-10-13-reserves/README.md)：固定原稿下GKR匿名LWE的LO缺口、ABB标准模型的选择性结论、CHKP标准模型的admissible hash/维度/归约条件；有限对象计数7项通过。完成的是模型/缺失模块/成本与重启材料，三项backend均未编码或登记。

## 4. 当前入口与证据定位

- [总体架构](../ARCHITECTURE.md)、[公共接口与验收](../IMPLEMENTATION_SPEC.md)、[协作流程](../AI_WORKFLOW.md)、[通用任务模板](../DELEGATION_PROMPTS.md)。
- [框架使用指南](FRAMEWORK_USAGE.md)、[本轮框架交付](deliveries/2026-10-11-framework/README.md)、[三人分工](workplans/三人方案分工与统一框架交付.md)。
- [CHKP 交接入口](research/team-chkp/README.md)、[主 AI/IBS 与集成任务](workplans/2026-10-08/主AI任务-IBS集成与优化.md)。
- 本地首套研究版本：[公开代码/标量诊断](research/2026-10-11-public-reuse/README.md)、[原文噪声](research/2026-10-11-rounded-noise/README.md)、[固定种子/H-G](research/2026-10-11-first-suite-seed/README.md)、[主父树](research/2026-10-11-first-suite-tree/README.md)、[有限采样](research/2026-10-11-first-suite-finite/README.md)、[根与公开恢复攻击](research/2026-10-11-first-suite-root/README.md)、[有限 DelTrap/资源筛查](research/2026-10-11-first-suite-compact/README.md)。对应合同见 [first_suite 专属契约](specs/first-suite-research.md)。各报告统计属于各自原执行版本，不合计为本次复跑。
- [Luo 模格路线决策](research/2026-10-11/IBS版本决策-模格版主线.md)、[已知漏洞与历史 CI](KNOWN_SECURITY_GAPS.md)。
- [现行算法总表](ALGORITHM_CATALOG.md)（8 条 HIBE / 11 条 IBS 候选及模型路线）、[论文库](../papers/index.md)、[历史重建记录](history/PROJECT_RESTART-through-2026-10-10.md)。

本机外部交付根为 `C:/Users/A/.dsh/deliverables/`。可移交时需带包本身及其清单，不能只发送本机路径：

- `CHKP-step7-codex-rework/report.md`、`source_manifest.json`；清单 SHA-256 `6e20806345024e92f1e9fe259439ac461f2ddfe7e194db597dce9ddbdc950790`。
- 当前 CHKP 任务是 `DEEPSEEK-CHKP第八步-加量任务书-参数闭合真实采样与整链并行实现-2026-10-11.md`。冻结包内旧 `next_step8.md` 不再驱动当前排序。
- `CODEX-step22-luo-integration/report.md`：外部接入预检，按上表范围使用。

更新本文时同时标出提交/包版本、核验者和已运行范围；不在 README、AGENTS 或旧报告末尾再追加第二份“最新进度”。
