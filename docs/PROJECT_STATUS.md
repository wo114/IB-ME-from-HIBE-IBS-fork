# 当前进度与并行任务

更新：2026-10-15（补A0/A3具体误差预算和完整参数域排除，保留A默认接入/12组合及C/B各自版本）。本文是**唯一的当前进度和任务排序入口**。根规范负责长期契约；带日期的研究报告、交付记录与旧任务书只证明各自版本的事实，不继续发布全项目“下一轮”指令。

A0/A3最新：[具体有限账本与完整参数域](research/team-a-delivery/2026-10-15-finite-budget/README.md)。实际结构化SampleD证书已展开MP12卷积常数，并提供全树/服务模型累计工具。默认n2配置在2^20封装、各2^20个H地址/G路径的理想随机流与正确有向算术模型下，累计上界落在(2^-98,2^-97]，未达到2^-128；该指数不表示LWE安全位数，实际SHAKE/机器故障/安全归约仍另列。当前n2…128与2…61位模数的15240个乐观区间检查还证明完整H/G必要条件只容许n≤5，正式困难维度须改变实际实现域，A尚未完成。参数、wire、真实采样和协议没有因此改为其它算法，储备三线继续暂缓。

2026-10-15 A增量：[ABB默认框架与结构化H/G交付](research/team-a-delivery/2026-10-15-framework-and-structured/README.md)。真实 `abb-rom` 已进入默认registry/CLI；新增明确命名 `mp12-structured-hg`，保留完整m列H/G，使用真实结构化MP12 GenTrap/DelTrap、256目标固定叶和32 B实际噪声。原语同根双接收者四叶及恢复、两个HIBE分别与六种IBS的 **12配置404检查**、CLI与隔离安装均单列实物来源。最终Sage框架478 passed，结构化专项93 passed；Windows467 passed/5明确Sage skip。原语与框架树、固定测试流与系统随机、生成与验收修复后原树复放分别记账，不拼接成同一次无失败执行。n1/n2公开攻击仍成功，完整有限误差/正式参数/模型与公平基准仍待；GKR、ABB标准模型、CHKP标准模型按用户要求暂缓。PR31 Wang–PW持久服务已复核496项并合入，未重做其基础安全证明。

PR #15 固定 `0435285` 已经复核并合入远端 main（`010b75e`）：四项 CI 通过，本地330 passed/21明确skip，三项真实ABB实物契约全部执行，23个运行源码/工具指纹一致。A随后交[结构化MP12工具](research/team-a-delivery/2026-10-14-mp12-structured/README.md)：系统随机的两次DelTrap与新原像/恢复、独立n128/2432维真实采样已经通过；这是A3工具执行域的推进，没有替换已有HIBE或获得正式安全准入。下方带日期的B基础/旧PR状态保留各自版本事实。
2026-10-14 CI增量：新增[19条路线的通用目录、数据驱动测试和组合验收](deliveries/2026-10-14-catalog-ci/README.md)。框架不再按 Luo 名称猜参数或测试范围；公共框架、每条算法路线和明确选定的组合分别显示。Wang–PW、SRGG 已接入公共注册表并通过本地 Sage 单体测试，两个真实教学 ABB10+研究 IBS 组合也有独立收据；所有结果仍为功能/研究运行证据，security_claim=none，未升级为正式安全准入。

2026-10-13 B增量：本地分叉克隆完成，在已审PR14 `87deec2` 上新增 [Wang+PW完整研究签名链与交付](research/team-b-delivery/2026-10-13-wang-pw/README.md)，含真实MP12采样、PW转换、冻结五方法与严格恢复；debug参数仍none/false。SRGG相关扰动/提取按独立组件交付，不计完整IBS。上游PR15仍为WIP，B基础不包含它。

同日新授权完整SRGG：已完成 [SRGG完整研究IBS](research/team-b-delivery/2026-10-13-srgg-full/README.md)，含真实连续SampleF/随机舍入、Schur条件、XOF/H/挑战、四算法/五方法、固定身份缓存和恢复；组件批次与完整批次分别留证。正式安全与默认安装/真实HIBE配对未准入。

同日 Sageloli 已完成批次单独交付：[矩阵／环真实采样探针与原文规格](research/team-b-delivery/2026-10-13-sageloli-probes/README.md)，包含三进制陷门、8列矩阵／9列环委派、两条签名数学链和192-bit宽度区间核验；尚无完整IBS五方法、对象或服务，不计完整后端。两套调试参数仍none/false。

C1 按用户新授权优先实现较易落地的结构HIBE，已交[LATTE-3独立研究后端](research/team-c-delivery/2026-10-14-latte-hibe/README.md)，算法冻结`51c40f8`：N1024同根两次真正Delegate、四把终层密钥、32 B带噪声、2×2错配/篡改、五类对象与新进程恢复通过；116项相关Sage回归、13 provider隔离安装通过。新增的是单独HIBE，默认登记/CLI与真实IBS配对继续由统筹接入；匿名、修订后TV/RD和正式安全仍none/false/false。

C2 已交[认证转换ML-DSA独立IBS](research/team-c-delivery/2026-10-14-cert-mldsa/README.md)，初始实现 `a2ffb8c`、末次代码修订 `c61b8eb`：五方法、固定发钥/pending、对象与恢复完成；246项Sage无skip（含210官方向量），三参数实物与安装通过。现补[同一转换核心的Falcon独立IBS](research/team-c-delivery/2026-10-14-cert-falcon/README.md)，实现 `14c44a6`：固定Falcon v1.2作者代码与512/1024两档，237项专项无skip含200官方向量和Gaussian自检；两档各同根双用户/32份新签名/新进程零熵恢复通过，完整IBS签名2322/4447 B。仓库外34 provider、五份原实例160次零熵验签与5次恢复SK新签名通过。默认登记、真实HIBE配对、强UF/量子模型映射及正式准入仍待，none/false/false；参数档不多计算法。

C1/C3本批新增：[Lai精确资格反例](research/team-c-delivery/2026-10-15-lai-qualification/README.md)15项无skip，确认标签单位与委派类型仍需澄清，没有新增Lai HIBE；[Xie修订方程研究核](research/team-c-delivery/2026-10-15-xie-study/README.md)实现 `7c139f4`，53项无skip，两个教学域各同根双身份/32新签名/原对象零熵恢复及仓库外安装通过。实际默认参数的公开零挑战伪造与模q平移反例均保留，修订核不冒充原稿复现或共同IBSBackend，不登记可用组合；原稿/正式参数/整体误差和模型仍WIP，none/false/false。

2026-10-15 C与统筹接入：[LATTE＋两类认证IBS统一框架交付](research/team-c-delivery/2026-10-15-c-framework/README.md)，实现`37a124d`、首批`9c9fd5a`、最终选参门槛`30aebdf`。默认登记和CLI已接通；10个配置（一个HIBE×六种IBS算法，参数/格式不多算）338检查全部通过，最终C专项545 passed/0skip，Windows框架437 passed/5明确skip。首批五档认证IBS各完成15条系统随机CLI命令及原状态零熵恢复，最终安装再逐档验证只含所选引擎时可恢复、只含其它档时拒绝；仓库外安装重放原5份状态、121 provider与209份源码核对通过。匿名/修订采样/转换模型和正式参数仍未准入。CR另交[Zhang类型与模数资格](research/team-c-delivery/2026-10-15-zhang-qualification/README.md)，未补造Derive或实现HIBE。

同批[PR27—29审查记录](deliveries/2026-10-15-pr-review/README.md)：Foo–Li、Yu共同五方法/对象/固定服务已合入，分别定向294/550项Sage无skip，默认登记/实际HIBE组合及安全准入仍待。PR29接收Lai与Xie研究材料；自审和回归不等于独立密码学安全审查。

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

后续统一交付另行接收 Luo终验收 `c336a51`（原工作树`c043c4b`同树）及CHKP完整链最终提交`4ea086e`，并与上游`14f1163`集成；[通俗README及材料入口](deliveries/2026-10-12-chkp-luo/README.md)区分两种HIBE和原始执行版本。原CHKP真实根/父/四个256目标叶、44项组合检查、CLI新建8项与导入59项已通过；没有重跑昂贵历史采样，发布回归单列。n=2公开恢复攻击成功，正式参数、安全等级与公平横向基准仍未完成。

| 模块/产物 | 已有内容 | 尚缺内容及范围 |
|---|---|---|
| 统一框架与协议 | `assembly` 已实现后端注册、独立选择/参数快照、能力/容量预检；复用 Baseline/BYTEAUTH/Hybrid；CLI 与真实组合驱动共用装配入口 | 本轮已补齐用户要求的三项框架工作；候选原语须各自实现并通过单体/组合验收，静态预检不等于安全准入 |
| 可选 CLI / 状态 | `--hibe/--ibs` 和两边参数独立；v2 状态绑定完整配置、公钥摘要及对象类型；旧预设保留 | 摘要是存储一致性检查，没有外部认证或反回滚保证；持久化按所选公开对象保存，不改原语算法 |
| HIBE 公共接口 | 六个 HIBE 方法、规范对象；Hybrid 使用独立的公开密钥绑定验证能力 | 接口存在不等于每个候选已实现 |
| LATTE-3研究HIBE | [独立C1](research/team-c-delivery/2026-10-14-latte-hibe/README.md)六方法/五对象、真实2×2与恢复；[本轮公共接入](research/team-c-delivery/2026-10-15-c-framework/README.md)默认registry、Hybrid/BYTEAUTH、CLI/安装与10个配置338检查通过 | 原作者ID-IND-CCA不自动提供匿名性；修订采样有限误差/中止和正式映射未准入，none/false/false |
| ABB-ROM独立完整研究后端 | [A本轮交付](research/team-a-delivery/2026-10-14-abb-complete/README.md)：真实AP09、两次BasisDel/高斯RandBasis、同组86/86 B身份及32 Bseed、256新SamplePre；同公钥2×2多地址和Luo+C64B+Hybrid+BYTEAUTH完整攻击验收已通过 | q26/n1被公开输入恢复全部256比特，none/false/false；正式参数/规范化条件化/矩阵RO/工作区失败界未准入；本批已接入默认registry/CLI、六种IBS202检查及原状态安装复放；旧q104/q80中止仍单列 |
| A3 结构化 MP12 工具 | [本批交付](research/team-a-delivery/2026-10-14-mp12-structured/README.md)：分块gadget、精确低秩扰动、Algorithm3/4、固定地址状态与安装；n2同根22→40→58两次真实委派及16次批次原像/零熵恢复；独立n128根/2432维4原像/恢复，无全维核格基 | 旧批为H=I/nk列扩展；本批新增完整m列H/G结构化后端、32 B实际噪声和六种IBS共同验收；n128/q65537旧根角色比较成本约21.608/19.610，参数未安全准入；具体卷积总误差和正式参数仍WIP；本批新profile不新增论文算法或困难假设计数 |
| 教学 ABB10 + 教学 SIS | 实际代码、CLI、历史攻击与回归 | 教学参数及公开认证反例；不能计入已准入安全组合 |
| Luo 矩阵 IBS | 本地真实研究算法、适配器与历史参数筛查 | 当前暂停继续扩网格，保留为比较实例 |
| Luo 模格 IBS | 真实算法、NTT/Hint、固定状态及reference/compact；C64B完整17字段、正确性条件/中止界、原文安全引用映射和第二十四步终验收收尾；实际CHKP组合已核对compact16383 B | 默认参数不变、C64B仍显式选择；研究候选不是正式安全等级，不自动补写完整基础归约/QROM；版本变化定向复核 |
| Wang+PW IBS | [完整研究五方法](../experiments/research/candidates/wang_pw/)、真实采样/恢复；默认已登记，本轮LATTE+Hybrid+BYTEAUTH公共组合32检查通过 | q17调试参数不安全；正式参数/根近均匀、固定服务安全映射及其它未测配对仍待，不计已准入安全组合 |
| Foo–Li IBS | [PR27独立共同后端](research/team-b-delivery/2026-10-15-foo-li-backend/README.md)：完整五方法/四对象、固定发钥/pending/持久服务、可选descriptor；统筹294项Sage无skip并核对固定head后合入 | q3/n1公开伪造及错误上下文负控保留；默认registry/真实HIBE配对、模型和正式参数未准入 |
| SRGG IBS | [完整研究后端](../experiments/research/candidates/srgg/backend.py)、真实SampleF/Schur/挑战、固定cache与恢复；默认已登记，本轮LATTE公共组合34检查通过 | ζ factor2、连续数值总TV、HNF/强前提未证；n8公开伪造负控保留；正式参数与其它未测组合不自动通过 |
| Sageloli SIS／RSIS | [已完成数学验证批次](research/team-b-delivery/2026-10-13-sageloli-probes/README.md)：复合模数三进制Gaussian、根／委派／一次签名原像、环旋转结构与两块范数、Table2/4宽度核验；可重放源码和公开收据 | 尚无H1/H2／盐／规范对象／完整五方法／恢复与组合；环采用明确block-Schur数值解释，总TV与固定服务模型待核；调试范数约束过弱，不授安全等级 |
| 既有内置完整研究接线 | **教学 ABB10 + Hybrid + Luo 模格 + BYTEAUTH** | 可以验证工程流程；HIBE 不是 CHKP，不能记为真实 CHKP 组合完成 |
| CHKP 本仓库 | `src/ibme/hibe/chkp/`公开六方法、`src/ibme/lattice/chkp/`有限工具；原CHKP父RandBasis/ToBasis与同叶256目标真实运行、保存/恢复、Hybrid+C64B+BYTEAUTH及CLI完成 | MP12仅用于此后端根生成；n2/q1099511627791可公开攻击，G-formal未准入，状态无外部防回滚保证 |
| CHKP 历史第七步外部包 | 原输入、返工和清单保留供追溯；现行功能收尾由[完整交付](research/2026-10-12-chkp-closure/README.md)替代 | 不因旧第八步目录名未出现否定新的固定提交；历史未执行/失败/恢复不能改写为同一次全新成功 |
| 旧 `first_suite` 独立研究原型 | 已并入根/H/G/主父叶状态、有限 CSPRNG 采样、共享前导种子 KEM及 MP12 DelTrap；[固定交付](research/2026-10-11-first-suite-compact/README.md)记录 83/166/249 维 n=1 配置的真实父采样、同叶 256 原像、512 噪声位恢复与跨进程恢复 | 与第七步 cap32 不同版本；n=1 可公开恢复种子。旧组件不等于原 CHKP 或新计算型 MP12 完整后端；新后端单列，不能由旧“未实现”描述否定它 |
| A 的 MP12 变体公开研究后端（已合入） | [第一批](research/team-a-delivery/2026-10-12-hibe-reference/README.md)：计算型 `[I\|Â]` 根、真实 DelTrap/固定256叶，六方法/五类对象/绑定、自定义 registry；原交付21项组合收据，本轮独立48项Sage测试无skip；安装接入单列 | n2/q549755813911 不安全，原交付8649次公开枚举恢复明文；原 CHKP theorem 不能直接继承。正式参数/模型仍待；ABB-ROM默认接入和新的结构化profile见本批交付；原CHKP新增成果在上行单列，不升级已准入数 |
| A 的公共安装入口（PR #13 已合入） | [第二批](research/team-a-delivery/2026-10-12-installed-api/README.md)：公共HIBE/格工具、单一 provider、wheel与默认可选登记；审查173 passed/2明确skip、55 Sage passed，仓库外安装Windows3/Sage10项，独立实际CLI8步通过 | 无Sage明确unavailable；新根/新接收者需要显式本地engine，旧状态可无engine恢复；原n2公开攻击和none/false保持；正式大尺寸部署/模型仍待 |
| 本地 CLI 接收状态事务 | [接收状态证据](research/2026-10-10-receiver-persistence/README.md)：锁、pending、保存后输出及已有研究接收密钥复用 | 提供同 OS 本地进程失败后的保守阻止；不宣称防回滚、硬断电或跨 OS 分布式事务 |
| Yu IBS 独立研究后端 | [PR28交付](research/team-b-delivery/2026-10-15-yu-backend/README.md)：真实PRF/陷门/采样及完整共同五方法/对象、固定issuer/恢复和条件审计；统筹550项Sage无skip、110项源码检查后合入 | q3公开伪造；1—4 B容量不够Wang帧，descriptor明确阻止组合；主线程Sage限制、NC1/Lemma7/模型和正式参数待核，none/false/false |
| 其它候选 | [候选基础包](research/2026-10-10-foundations/README.md)、SRGG 代数/采样等部分实现；此行未重新审查后续远端PR | 每项按实际算法和测试单独计数；不把候选卡或公开方程计作完整后端 |

### 外部交付与接收记录

| 来源 | 当前可使用的事实 | 验收边界 |
|---|---|---|
| 邻居 Luo 工作树 `luo-acceptance-evidence`，历史提交 `f079ce10fb6b3d2877465b308caaa30276d9e6f9` | 负责人已核的上一批 54 次 Sign、528 次 attempt、108 次两格式验签、212 项选定测试 | 保留历史基点与原统计；后续源码接收按下列固定提交和本轮审查记录 |
| Luo 第二十二步，提交 `886fc127304479b87ef210836757004818e5b6ea` | 鲁棒接受集/随机矩阵二阶矩条件式中止界、C49/C64B 候选及攻击成本估计，已随 #9 接收。负责人原记录 C64B 54次 Sign／315次尝试／108次双格式验签、269项回归 | 原54次性能批次没有在本轮重跑，相关条件式证书与证据工具已独立验；条件式可用性界不是安全位数，正式参数仍未准入 |
| Luo 第二十三步，提交 `e5e0b97752f9291ce7621dd830d665baff86aef8` | 已合入 helper 与专属入口。原交付122/19项及`0bf0855`的25项收据保留；本轮在最终联合 assembly 独立重跑25项，compact 最大3924 B应用消息/20415 B外载荷真实往返、全对象/profile恢复与错配拒绝 | 新25项的 reference 是容量预检、compact 是实际运行；研究专用入口两格式另有实际 pytest 回归。原性能统计不相加，不计原 CHKP 完成或正式参数 |
| `CODEX-step22-luo-integration/report.md` | 历史静态预检当时指出 `CHKP_PUBLIC_BACKEND_MISSING` | 当时结果不算真实组合；该缺口现由`4ea086e`真实组合收据关闭，旧文档不覆盖当前状态 |
| Luo第二十四步/CHKP本轮固定交付 | [Luo终验收](research/2026-10-12-luo-final-acceptance/README.md)、[CHKP完整材料](research/2026-10-12-chkp-closure/README.md)及[统一说明](deliveries/2026-10-12-chkp-luo/README.md) | 原始收据、Git版本及发布集成分别记录；正式安全仍none/false/false |

第二十二步显式 C64B 候选的 compact 签名由负责人测得16383 B，本次真实CHKP组合再次核对该尺寸；默认参数对应的16063 B保持原状。inner输入为86/86/32 B；显式C64B没有改成全局默认，其它配置仍需分别核算容量。

第二十二步固定入口现为本地[中止界与参数材料](research/2026-10-11-luo-abort-bound/README.md)，第二十三步入口为[C64B 交付](research/2026-10-11-luo-c64b-handoff/README.md)。后续独立工作树位于 `C:/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS`。C64B 的 κ=64、γ1=190000、γ2=60000000000、γ3=(q−1)/10，两项重试帽各4096。负责人在理想随机源／理想 XOF 及明确查询预算下给出正常调用总中止上界 <2^-153；MSIS 模型成本指数为经典188.340／量子170.925。以上是该固定交付的条件与结果，未授予整个 IBS 或组合相应安全等级。

目前相关研究组合保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。这些标识约束安全表述；可执行的真实研究配置仍可进行功能接入和测量。

公共框架最终定向回归为 **122 passed / 3 skipped**，3 项跳过需要 Sage 的真实缓存；历史教学攻击回归为 **4 passed / 2 strict xfailed**。开发期 9 个配置共 274 检查通过，三种实际 IBS 与一个教学 HIBE 的多包装/格式不能计为九种独立密码算法。最终源码定向实跑、版本边界与逐项收据见[本轮交付](deliveries/2026-10-11-framework/README.md)。

## 3. 当前并行包与完成条件

| 并行线 | 本轮要交付的实物 | 依赖与停止边界 |
|---|---|---|
| 公共框架 | 已有[独立选择与测试入口](FRAMEWORK_USAGE.md)；维护新原语登记、容量/能力声明和其真实组合收据 | 不等待 CHKP；不重复开发协议；新增接口语义逐项协调 |
| CHKP | 本轮真实研究后端、根→父→固定256目标叶、32 B种子、对象加载、C64B组合及CLI均已收尾 | 后续范围是正式困难参数、资源可用性和组合前提；沿用已完成结果，旧[模块任务卡](workplans/2026-10-08/队友任务-CHKP与格工具.md)不要求重复根父实验 |
| Luo IBS | 本版本研究级收尾：C64B、原文引用/数值对应、条件式中止界、实现与交接材料齐备 | 精确LowBits联合分布非现有界的必要输入；不自动开启下一轮，只对参数/版本/目标变化定向验证 |
| 其它 HIBE/IBS | 每个认领模块的来源、对象、算法、真实最小实例和单体契约 | 与首套并行；优先有合法源码/明确有限参数的路线，复杂或条件不明的列储备 |
| 组合与交付 | 接入已具备研究契约的真实原语，四种匹配、错误输入、字节篡改、固定状态恢复、尺寸/时间/内存 | 原语未到可做预检；诚实端到端及对应攻击必须用该真实组合执行，不用 mock 顶替 |

验收分为研究执行与安全结论两层：前者要求算法对应、诚实功能、明确错误处理及真实收据；后者还要求所用版本的参数、分布、引用条件和组合前提成立。一个模型或参数的通过不自动传给其它组合。

### 三位队员的执行分工

2026-10-12 按用户要求修订为**每人按原语族顺序完成若干方案**：A 负责 CHKP/明确标识的 MP12 变体、ABB-ROM 与矩阵陷门工具；B 负责现有 Luo 收尾及 Foo–Li/Wang+PW 等原生格 IBS；C 负责 LATTE/Lai 的结构 HIBE 核验与实施、共享认证转换的 ML-DSA/Falcon 对照、Xie NTRU 核验。现有文件 owner 先交接，不同时写入。

19 条路线均有 owner、优先级和下一步，公共 T0—T10 明确覆盖 PR 接收、装配、状态、全组合攻击、评测、展示、优化验证、报告和支撑材料。详见[总计划](workplans/三人方案分工与统一框架交付.md)、[A](workplans/2026-10-12/A-矩阵HIBE任务.md)、[B](workplans/2026-10-12/B-原生格IBS任务.md)、[C](workplans/2026-10-12/C-结构HIBE与工程IBS任务.md)和[任务登记](workplans/2026-10-12/tasks.json)。全部就绪且适配的配对纳入验收，最后按场景数据挑三个报告重点，不限制其它配对。这个分工是计划，不是新增后端的完成声明。

此前的[分工修订](workplans/2026-10-12/PR审查与分工修订说明.md)在 PR #11 工作树完成，当时没有合并。2026-10-12 本轮依用户授权完成 #9/#10/#11/#12 审查与合入，C64B 与 MP12 源码均已接收；没有改变密码算法或提升安全声明。后续按三人任务书推进，不把“代码已合入”写成“项目/正式参数已完成”。

A 随后按新任务书开始独立分支实施，新增 MP12 变体研究后端和真实单配对，范围/攻击/参数缺口见上表交付。2026-10-14的A2真实完整生命周期、2×2及Luo组合已通过（见上表新交付）；正式维度/两角色困难性/模型对应和大尺寸部署工具仍未闭合，AR储备说明已交。下方按日期的WIP/中止保留为历史，不覆盖新结果或其它未测组合。

A 第二批已补[可安装公开 API 与默认 CLI](research/team-a-delivery/2026-10-12-installed-api/README.md)：Windows/Sage 均在仓库外验证 provider 来自安装包；Sage 无native/无熵重放原四种匹配，新安装CLI真实8步通过，55项Sage回归通过。默认入口在无Sage时明确 unavailable；缺native只阻止新根/新receiver，并在地址写入前拒绝。原n2攻击/none/false、ABB、正式维度/模型与双角色困难性仍待；原CHKP本轮功能收尾不替代A后续范围，不能称A全部完成。

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
- CHKP 第八步研究功能由Codex直接完成收尾，[本轮记录](research/2026-10-12-chkp-closure/README.md)统一代码、真实12阶段证据及未闭合的安全条件。旧任务书和冻结包内`next_step8.md`保留为历史输入。
- `CODEX-step22-luo-integration/report.md`：外部接入预检，按上表范围使用。

更新本文时同时标出提交/包版本、核验者和已运行范围；不在 README、AGENTS 或旧报告末尾再追加第二份“最新进度”。
