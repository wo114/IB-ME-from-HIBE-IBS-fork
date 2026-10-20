# 当前进度与并行任务

更新：2026-10-20。接收基线为远端 main `102e35f`；本页只维护当前结论、负责人和下一步。逐轮提交、失败与复跑明细见各交付目录；整理前的全部文字保留在[历史快照](history/PROJECT_STATUS-through-2026-10-20.md)。找文件从[文档导航](README.md)进入。

## 1. 已确认的组织方式

- 一个公共 IB-ME 框架，HIBE／IBS 独立实现和选参；就绪且适配的组合进入真实验收，单个原语受阻不暂停其它工作。
- 报告三代表已经选定，详见[选型与参数冻结](deliveries/2026-10-19-report-three-selection/README.md)。三组不要求共同达到128位；各自保留论文目标、实际参数、模型和限制，不做跨目标性能排名。
- 按用户确认，以所选算法安全、HIBE 身份匿名为研发工作前提，理论说明引用原文；不新增基础安全性、匿名性或完整归约证明任务。实现偏差、参数估计和已知问题仍须记录。
- GKR、ABB标准模型、CHKP标准模型三条储备继续暂缓；Ext／ReExt 与 Boyen–Li 增强隐私不在范围。
- 当前报告直接编辑 LaTeX，以 PDF 交付；旧 Markdown、Word、作品报告和 PPT 保留为历史材料，后续不要求三种稿件同步修改。

## 2. 代码与证据状态

### 报告三代表

三份配置都绑定已有完整运行。预算为 Hybrid 内部载荷预算，不能当作应用消息容量；完整字段以链接中的 Suite 为准。

| 代表 | 冻结组合与预算 | 已有实物 | 当前边界 |
|---|---|---|---|
| A：主演示 | [LATTE＋BNN/ML-DSA-44，64 KiB](deliveries/2026-10-19-report-three-selection/suites/A-latte-mldsa44.json) | 三根重复基准、安装CLI、跨进程恢复、Web实跑和部署消融 | 新随机批量记录在PR69；本分支同机基准、精确安装与消息边界见PR72，均按PR分别接收；最终发布仍须复现 |
| B：原生IBS对照 | [LATTE＋SRGG论文PARAM-I compact，128 KiB](deliveries/2026-10-19-report-three-selection/suites/B-latte-srgg-I-compact.json) | 完整功能矩阵及三根重复基准 | 本分支PR72已交精确128 KiB安装、0／32／1024／65364 B、恢复和内层负例；同主题PR71在途，分别核验 |
| C：另一HIBE与环IBS | [Lai C2＋Sageloli RSIS v3 PARAM-I，8 MiB](deliveries/2026-10-19-report-three-selection/suites/C-lai-c2-sageloli-I.json) | 目标规模单根完整运行、四种身份情形及公开收据 | 本分支PR72补0／1024 B安装、恢复与有效外层下内层拒绝，4次真实未缓存委派；多根重复和3924 B诚实解密仍未做，无性能优势结论 |

三代表是2种HIBE、3种IBS、5个原语后端、3个完整组合。Web现有的LATTE＋ML-DSA／Falcon／Luo三预设是另一集合。当前相关组合保持 `none/false/false`；不因登记、有限测试或论文安全引用自动升级字段。

### 其它后端与研究材料

| 范围 | 已接收的结果 | 尚未由此完成的工作 |
|---|---|---|
| 公共框架／CLI／Web | 独立选参、能力和容量预检、规范wire、固定状态及真实组合工具；见[使用指南](FRAMEWORK_USAGE.md) | Web服务重启恢复仍未实现，持久恢复使用CLI；未测配对不算支持完成 |
| LATTE／Lai、SRGG论文档、Sageloli环v3 | LATTE的多IBS配对、Sageloli PARAM-I公共接入、Lai C2四个IBS组合均有实跑 | 各参数档的重复性能、安装和负例按实际覆盖分别验收；不把v2展开外推套到环v3 |
| ABB-ROM／CHKP／MP12各变体 | 已有小参数完整研究流程、对象和恢复；[3m原型](research/team-a-delivery/2026-10-18-3m-feasibility/README.md)与资源筛查保留 | 目标参数完整运行仍由队长安排的其它AI推进；本机资源受限不等于算法普遍不可行，暂不在本线程扩维 |
| Wang＋PW | 既有小参数五方法后端与服务；[PR67数值原型修订](deliveries/2026-10-19-pr66-67-review/followup/README.md)已合入 | n512数值采样记录尚非这组参数下的完整IBS；身份／消息绑定、PW、固定公开范数验签、恢复与完整组合仍待 |
| Luo模格／BNN-Falcon | 既有完整组合、重复基准、CLI／Web及恢复材料，作为辅助对照保留 | 不替换已冻结的三代表，不把参数或格式变化计为新算法 |
| Foo–Li／Yu／Sageloli矩阵SIS | 独立研究实现、实验与已知小参数问题保留；[Foo–Li估计修订](deliveries/2026-10-19-pr64-65-review/README.md)已接收 | 公共接入、容量或目标参数按各自限制继续记录；当前不为凑组合强行扩参 |
| Xie／Zhang等候选 | 原文核对、修订研究核或资格材料，见[候选总表](ALGORITHM_CATALOG.md) | 候选或方程实验不等于公共后端和完整组合完成 |

### 外部交付与接收记录

| 接收内容 | 当前可引用的入口 |
|---|---|
| PR72：报告第二项实验主表与必要补测（本分支待接收） | [同机A/B重复、三组精确安装、消息补测与公开证据](deliveries/2026-10-19-report-experiment-supplement/README.md)。保留PARAM-I与原Suite；原临时私有状态未能归档，公开记录保留，不能移交原状态 |
| PR66、68：报告内容修正、三代表选择、LaTeX／PDF迁移 | [2026-10-20接收记录](deliveries/2026-10-20-pr66-68-reception/README.md)。两PR已合并；旧Word渲染失败诊断不再阻塞PDF交付，报告仍为WIP |
| PR67：隔离数值研究原型 | [修复与23项实际测试](deliveries/2026-10-19-pr66-67-review/followup/README.md)。审定头`4fe3a93`合入`05373b2`；不记为Wang目标参数完成 |
| PR64：Lai C2四个新增配对 | [完整Suite、实测与收据](research/2026-10-19-lai-c2-combinations/README.md)。单根并发批次不当作公平重复基准 |
| PR62、63：Lai原始收据、Sageloli环v3公共接入 | [接收记录](deliveries/2026-10-19-pr62-63-review/README.md)、[Sageloli公共组合](research/2026-10-19-sageloli-ring-integration/README.md) |
| 更早交付、原参数反例和逐轮测试统计 | [整理前进度快照](history/PROJECT_STATUS-through-2026-10-20.md)、各日期的`deliveries/`和`research/`说明；原始数据不重新合计为本次实验 |

## 3. 当前并行包与完成条件

### 当前未完成项（按依赖推进）

| 顺序 | 交付物 | 完成判据 |
|---|---|---|
| 1 | 三代表冻结配置的证据接收 | PR71及本分支PR72已交相应材料，待审定接收；PR72含B精确128 KiB、C安装恢复和内层负例，逐份核对Suite与来源，不用旧预算替代 |
| 2 | 必要消息长度／边界、随机批次和有限重复 | PR69随机批次待审查；PR72已交A/B同机三根重复、三组必要长度和越界拒绝。均按PR接收后记入main；C仍无多根重复或最大消息诚实解密，不无限扩网格 |
| 3 | 三代表可解释比较 | 同环境、输入、计时和资源口径才能计算排名或收益；保留各组实际目标。C目前展示结构与资源边界，不虚构优势 |
| 4 | LaTeX报告正文与新三代表一致 | 原三组LATTE重复基线作为历史比较；更新现状、代表图表和补测结果，编译PDF并逐页检查 |
| 5 | 来源许可、提交模板及发布复现 | 整理引用／代码许可、本届模板和匿名信息；源码、Suite、演示、收据和报告对应同一发布版本 |
| 独立推进 | ABB10／CHKP／Wang的目标参数交付 | 由现负责人提交版本、参数、真实完整运行和资源数据；不阻塞已有三代表的作品收口 |

以上是工程与交付欠项，不新增安全证明任务，也不要求全部候选先完成目标参数才能交作品。

### 三位队员的执行分工

| 范围 | 当前责任与边界 |
|---|---|
| A及队长安排的接手AI | ABB10／CHKP与矩阵工具；按[接手执行标准](workplans/2026-10-18-ABB10与CHKP执行标准.md)各自认领，原3m成果保留，本线程不重复扩维 |
| B及IBS参数负责人 | 原生IBS、参数和单体数据；Wang大参数原型与既有小参数公共后端分别交接 |
| C及结构HIBE负责人 | LATTE／Lai、认证转换与原生依赖；各自交完整配置、安装和恢复证据 |
| 统筹 | 共享接入、固定版本审查、就绪组合、同条件评测、导航与报告材料衔接；共享文件先认领 |

原语分工和文件边界见[三人交付计划](workplans/三人方案分工与统一框架交付.md)及[协作流程](../AI_WORKFLOW.md)。旧任务书的首批顺序不覆盖本页当前排序。

### 在途PR

| PR | 在途范围与接收边界 |
|---|---|
| [PR69](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/69) | 主演示随机多身份批量验收；本批未审查或重跑该实验 |
| [PR71](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/71) | 报告B组128 KiB安装CLI与恢复；与PR72的同配置独立记录分别接收，不重复累计 |
| [PR72](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/72) | 本分支报告第二项：A/B同机基准、三组精确安装／长度／内层负例；公开收据可核对，原私有状态不可移交 |

以上PR均登记在途范围，不冒充远端main已经接收。接收后更新对应状态；本批不代替PR69／71的独立审查。

## 4. 当前入口与证据定位

- 找文件：[仓库与文档导航](README.md)；运行：[框架使用指南](FRAMEWORK_USAGE.md)、[Web演示](../src/ibme/webui/README.md)。
- 报告：[LaTeX／PDF说明](reports/2026-10-19-research-draft/README.md)；参数：[三代表完整Suite](deliveries/2026-10-19-report-three-selection/README.md)。
- 规范：[架构](../ARCHITECTURE.md)、[接口](../IMPLEMENTATION_SPEC.md)、[算法专属契约](specs/)、[复用指南](FRAMEWORK_REUSE_GUIDE.md)。
- 来源：[论文库](../papers/index.md)、[安全回归与历史反例](KNOWN_SECURITY_GAPS.md)；旧轮次状态：[历史快照](history/PROJECT_STATUS-through-2026-10-20.md)。

更新本页时替换对应状态和待办，给出来源链接；逐轮细节进入带日期的交付／研究记录。README维护导航，AGENTS维护长期规则，历史记录保存版本事实，避免再次并列多份“最新进度”。
