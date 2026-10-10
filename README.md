# IB-ME from HIBE + IBS

本项目的目标是实现基于两层格基 HIBE 和格基 IBS 的身份基匹配加密（IB-ME）。

[已知漏洞回归与基础 CI](docs/KNOWN_SECURITY_GAPS.md)：自动记录教学实例的公开伪造和单字节篡改问题；XFAIL 表示未修复，不表示安全通过。

2026-10-09 [密文字节认证修复](docs/research/2026-10-09-byteauth/README.md)：CLI 默认使用 BYTEAUTH/1，对临时认证公钥作内层 IBS 绑定并签完整外层密文字节，原 c1 低位篡改和接收者换认证密钥重签均拒绝；旧未认证密文仅显式 `--legacy-baseline` 研究开关访问。原公开 IBS 伪造及冒名仍未修复，也在新包装中保留真实反例，教育参数和整体系统仍 `security_claim: none`。本轮目标批次 28 passed、2 xfailed，完整协议/CLI 回归 175 passed；旧三个 XFAIL 已变为两个未修复目标及一个无标记通过目标。

## 当前重建路线 2026 年 10 月 10 日

2026-10-10 用户更新顺序：**全部候选先做基础准备 → 首套完整实现 → 继续其它候选并比较 → 选择三组场景代表 → 联合优化**。已建立 [候选基础包](docs/research/2026-10-10-foundations/README.md)，7个HIBE/10个IBS条目及17份来源，逐项给出算法/接口/参数状态、复用资产和队友任务；3个公共代数探针、2套已有IBS最小实跑及Sageloli单位计数已完成。条目数不等于实现数，未预定获选三套；其余路线也保留为重要比较材料。原先继续压缩/跑分的安排已后置，正式安全组合仍未准入。GKR、SRGG、Yu全文由用户补齐并原样归档。

最新 [Yu同态基础单元](docs/research/2026-10-10-yu/README.md)已实现gadget分解、NAND/匹配电路和公开/私有整数关系；47项检查跨环境通过，Sage独立核对32组输入及152个位原像。它供后续PRF/发钥/签名接手，当前仅完成同态代数部分，论文的完整范数保证、真实PRF及Yu IBS仍待实现，全部none/false；未做新的压缩/性能优化。

本轮 [SRGG代数与几何基础](docs/research/2026-10-10-srgg/README.md)进一步完成带误差原像、HNF首块重建、签名承诺恢复和精确正定/Schur条件；51项检查跨环境，Sage独立核对36个挑战、72个恢复修改及9组形状。高斯采样/XOF/哈希与完整IBS仍未实现，gadget/ζ宽度映射及强结论条件保留，全部none/false；不计新增完整实例，不进行性能优化。

后续 [SRGG随机gadget参考](docs/research/2026-10-10-srgg-sampling/README.md)已实现有误差界的离散高斯原像，40项Sage检查、36,864次抽样及27个联合PMF核验；仿射宽度映射明确，陪集归一化偏差单独计入。完整相关扰动、密钥分布/范数、哈希和IBS仍WIP，全部none/false。

当前[工作优先级](docs/workplans/2026-10-10/首套系统关键路径与优先级.md)已转回首套系统：先核验现有Luo IBS/组合条件、接CHKP真实HIBE并完成攻击验收；候选深入和独立优化后置。仓库尚未收到可集成CHKP，现有完整研究组合仍使用教学HIBE，安全获准组合为0。

首套接入已完成[固定状态与参数快照修复](docs/research/2026-10-10-mainline/README.md)：实际复现并修复并发同身份不同钥/不同身份丢缓存、HIBE参数漂移，补齐线程快照、原子密钥发布和跨配置覆盖保护。Luo数学算法/参数/wire不变；CHKP未交接，整体准入仍none/false。

首套接入第二轮已修复[HIBE密钥/公钥与私钥方程绑定](docs/research/2026-10-10-key-binding/README.md)：协议调用原语验证器，拒绝同参数不同公钥混钥、坏方程、身份替换及非法新产物。新增28项、每环境134项回归通过；算法/参数/wire保持，CHKP未交接、整体仍none/false。

总体规格与分工以 [R1](docs/research/2026-10-08-r1/README.md)为基础：队友实施 CHKP 两层匿名 ROM HIBE；主 AI 已形成 Luo 矩阵正确性参考，当前进一步实现模格 IBS，进度见下文 M2-B2。理论以原文定理引用和实现/参数对应为主。后续工作分为 [主 AI 的 IBS/集成/优化清单](docs/workplans/2026-10-08/主AI任务-IBS集成与优化.md)和 [队友的 CHKP/格工具任务书](docs/workplans/2026-10-08/队友任务-CHKP与格工具.md)。正式参数和完整安全实例仍未放行，`security_claim: none`。

M1/M2-A 已完成 [真实矩阵参考](docs/research/luo-reference/README.md)与 [IBSBackend 接入](docs/research/2026-10-09-m2/README.md)，公开小参数伪造和一列主秘密的 LLL 恢复保留为负面对照。M2-B1 完成 [联合选参与精确模格参数](docs/research/2026-10-09-m2b/README.md)：40 行矩阵研究搜索、统计分布检查、保守范数界及 7 组模格参数对照。上一轮最低 LWE 成本来自区分攻击，现已与秘密搜索分开；原 Theorem 1 与事件 E 的范数界差异也明确记录。

M2-B2 已实现 [Luo 模格 IBS 四算法及独立 Sage 核验](docs/research/2026-10-09-module/README.md)：degree=256、(k,l)=(11,10)、κ=64、q=274877844481 的真实签验、精确 NTT/Hint、规范对象和固定密钥恢复。68 项新检查跨 Windows/WSL 通过，Sage 独立核验 24 个真实参数签名；当前基础批次 464 passed、2 xfailed。参考签名 29455 B，完整 Wang/BYTEAUTH 载荷至少 29563 B；当时超出现有 HIBE 的 489 B 容量，已由下述 M3-A 继续完成接线。正式参数、安全组合和旧教育目标的状态须分别记录，均 `security_claim: none`。

当前已完成 [大载荷适配与真实研究组合](docs/research/2026-10-09-hybrid/README.md)：`--params luo-module-research` 接 ABB10 教学 HIBE + Luo 模格 IBS + BYTEAUTH，底层只加密 32 B 种子，AEAD 承载完整签名/消息。修复身份长度泄漏及跨命令身份缓存；新组合 Windows/WSL 均 67 passed，公开新格式猜测、完整冒名及持接收密钥重签对照均拒绝。应用消息上限 3924 B，完整密文约 2.58 MB；未做全系统加速宣传。默认 education 保留两个认证反例，正式参数/安全 HIBE 与安全默认入口仍待准入，全部 none/false。下一轮集中处理模格 MSIS/Hint 条件与成本，队友继续 CHKP。

[M2-B3 参数/引用复核](docs/research/2026-10-09-admission/README.md)已明确 Hint 恢复误差、两分支 MSIS 矩阵/块界及条件式非零论证；4 个输入和 144 个固定扫描点的经典/量子最低对照为196.808/178.610。κ=64 的泛型量子挑战搜索指数133.783，κ=49 对照112.673不通过本轮128搜索线。结论是保留当前研究参数继续工程；不是完整安全位数或 QROM 证明，参数/算法未改变，none/false保持。新增20项检查跨环境通过；后续规范压缩见下文，队友继续可信 HIBE。

最新 [M2-B4 规范无损压缩](docs/research/2026-10-09-compact/README.md)已保持数学值和完整哈希输入，签名29455→16063 B（减少45.466%），完整密文实测每包减少13392 B、约0.52%；HIBE胶囊仍为2452065 B。`setup --params luo-module-research --signature-format compact` 显式启用，参考格式仍默认，两种严格解码器不互相回退。新增96项检查跨环境通过、两环境公开数据一致，基础CI选择本地559 passed、2 xfailed。此项不计新算法或 A+B<C，不提升安全声明；下一轮建立完整系统冷/热与内存基线。

已合并 PR #5（`37e7031`）；本地基础检查 182 passed、3 xfailed，严格模式 3 failed；合并后的主仓库基础 CI 成功。三个 XFAIL 是保留的旧教学漏洞，不是修复或安全通过。R1 新增 24 项公开参数/容量检查，不生成新密钥或密码性能结果。

团队固定王老师的两层匿名 HIBE + IBS 通用构造，不实施 Boyen–Li 增强隐私。已整合队友 PR #3 的条件式正确性和研究签验/恢复流程；195 项相关回归复跑通过，95 个交付及 34 个复用源码指纹一致。Lean 总包保持 `partial_formal_closure`，几何及实际随机模型前提未全部解除，本机没有重跑 Lean。

有限参数预筛检查 36 个矩阵 SIS 点：13 个通过所列解析检查，其中 6 个被标准 LLL 上界排除；9 个预定公开 SIS 对照均找到短关系。所有点均超过当前参考实现至少一项上限，没有准入安全后端。参数扫描不计新算法或假设实例；全查询预算、真实采样误差与 SIS 难度仍待收紧和估计。

组合优化曾实现保持完整输入的 Core SHAKE 前缀准备及显式研究适配器，219 项相关检查通过。合成 1 MiB 联合上下文、128 块的子环节中位数从 196.45 ms 降至 15.44 ms（12.73 倍），包含首次准备成本且输出逐字节相同；这不是完整 IBME 跑分。随后 BYTEAUTH 已修复默认外层字节篡改目标；公开 IBS 伪造和冒名仍待真实替换及完整验收，`security_claim: none`。

2026-10-06 用户向老师进一步确认：多实例同时覆盖不同困难假设和不同算法。围绕矩阵 LWE/SIS、环格、模格调查假设扩展，也核验 Foo–Li、Wang + Pan–Wagner 等具体算法实例；同族算法不增加假设类别，参数扫描和采样实现调整不增加算法方案。混合组合分别标注 HIBE/IBS 的依赖。所有完整实例均须原语与参数准入，当前范围修订不表示已交付这些后端。

先前 ABB10 分别搭配 Foo–Li、认证型 ML-DSA/Falcon 的三组是历史候选。按用户反馈，当前优先采用直接原语论文，认证型方案退为储备；具体条件与下一轮以 R1 为准。联合编码与混合包装保持明确依据，组合额外收益须在相同安全目标下实测。

- [重建工作记录](docs/PROJECT_RESTART.md)：已确认范围、阶段进度及下一任务；
- [三组优先组合与联合优化路线](docs/research/2026-10-08-integration/三组优先组合与联合优化路线.md)：具体原语、认证型 IBS 的原文依据、参数容量与准入门槛；
- [组合上下文复用优化与公平基线](docs/research/2026-10-08-integration/组合上下文复用优化与公平基线.md)：字节等价实现、子环节实测和完整绑定包装草案；
- [Foo–Li 有限参数预筛与成本](docs/research/2026-10-06-parameters/FooLi有限参数预筛与成本审计.md)：近均匀有限界、完整归约范数、公开 SIS 对照和资源模型；
- [队友 10 月 6 日统一交付](docs/deliveries/2026-10-06/README.md)：条件式 Lean、真实研究签验和 SHAKE 模型的冻结证据；
- [多困难假设与多算法实例化口径](docs/research/2026-10-06/多困难假设实例化口径与验收.md)：老师确认后的范围、分别统计、混合组合及完整实例准入；
- [第十轮任意中心在线采样与 MP12 扩展](docs/research/2026-10-05-round10/任意中心在线采样与MP12扩展核验.md)：统一有限误差、整类位数与随机带证明、一般大模数连通及公开恢复负面对照；
- [第十轮核验记录](docs/research/2026-10-05-round10/第十轮核验记录.json)与[完整结果](docs/research/2026-10-05-round10/online-sampling-results.json)：66 项新增检查、全部尝试、独立无限目标对照、重放与安全边界；
- [第九轮生成、委派与统一准入](docs/research/2026-10-05-round9/MP12生成委派连通与统一准入核验.md)：实际陷门链、逐点质量失败、整类资源／有限误差，以及公开近均匀和 SIS 门槛失败；
- [第九轮核验记录](docs/research/2026-10-05-round9/第九轮核验记录.json)与[连通结果](docs/research/2026-10-05-round9/mp12-trapdoor-chain-results.json)：全部尝试、实际教学陷门、前四次完整证书、重放及测试；
- [第八轮完整 SampleD](docs/research/2026-10-05-round8/MP12完整SampleD有限误差与随机带核验.md)：非球形扰动、精确协方差、统一有限误差、随机带及 Foo–Li 代入边界；
- [第八轮核验记录](docs/research/2026-10-05-round8/第八轮核验记录.json)与[采样结果](docs/research/2026-10-05-round8/mp12-sampled-results.json)：完整无限目标对照、去扰动反例、环境、测试与交付文件；
- [第七轮 Foo–Li 证明补全与修复顺序](docs/research/2026-10-04-round7/FooLi经典ROM证明补全与修复路线.md)：两个联合引理、模块化定理、MP12 条件映射及旧反例的修复责任；
- [第七轮核验记录](docs/research/2026-10-04-round7/第七轮核验记录.json)：精确有限控制、测试、文件范围及未交付内容；
- [第六轮 Foo–Li 条件归约](docs/research/2026-10-04-round6/FooLi固定密钥经典ROM条件归约草案.md)：两个固定分支模拟器、签后腐化、SIS 提取及有限后验熵条件；
- [第六轮核验与交付记录](docs/research/2026-10-04-round6/第六轮核验记录.json)：实验、精确结果、测试命令、文件范围及未闭合条件；
- [第五轮一般模数 gadget](docs/research/2026-10-04-round5/一般模数gadget采样与有限误差核验.md)：完整格基、条件中心、统一误差及资源边界；
- [第五轮核验与交付记录](docs/research/2026-10-04-round5/第五轮核验记录.json)：文件范围、环境、测试、参数及已知限制；
- [第四轮采样参考实现](docs/research/2026-10-04-round4/离散高斯与gadget陪集采样参考实现.md)：分布约定、有限误差界、实验结果及与完整采样链的缺口；
- [第四轮核验与交付记录](docs/research/2026-10-04-round4/第四轮核验记录.json)：文件范围、参数、环境、测试命令与已知限制；
- [第三轮固定密钥接入审查](docs/research/2026-10-04-round3/Wang与PanWagner固定密钥接入审查.md)：Wang + PW 候选的完整字段、参数依赖及条件准入判断；
- [固定密钥转换条件归约草案](docs/research/2026-10-04-round3/固定密钥转换条件归约草案.md)：安全实验、两个模拟器、查询损失与未闭合条件；
- [第二轮结论与实现门槛](docs/research/2026-10-04/第二轮选型结论与实现门槛.md)：ABB10 与 Foo–Li 的审查及精确核验；
- [修订后的重建研究报告](docs/research/2026-10-03/IBME项目现状与完整重建研究报告.md)：现状证据与完整路线；
- [原语选型第一轮核验](docs/research/2026-10-03/原语选型第一轮核验.md)：组合前提及首轮历史判断，候选优先级以重建工作记录为准；
- [固定版本论文库](papers/index.md)：ABB10、Foo–Li、MP12、Wang 与 Pan–Wagner 原文及指纹。

推荐把一个主 AI 作为架构、集成和最终报告负责人，把其他 AI 限定在明确的模块边界内。主 AI 不需要把整篇论文反复发给每个实现者，只需给它们以下三个文件和对应任务提示：

- [ARCHITECTURE.md](ARCHITECTURE.md)：系统分层、组件关系和安全声明边界；
- [IMPLEMENTATION_SPEC.md](IMPLEMENTATION_SPEC.md)：唯一接口规范和验收标准；
- [DELEGATION_PROMPTS.md](DELEGATION_PROMPTS.md)：可直接复制给其他 AI 的任务提示词；
- [AI_WORKFLOW.md](AI_WORKFLOW.md)：并行开发、交接、合并和审计流程。

主线构造是指导论文第三章的：

$$
\text{两层匿名 HIBE} + \text{自适应安全 IBS}.
$$

发送者身份为 $\phi$，接收者身份为 $\rho$，加密时指定 `rcv`，解密时尝试 `snd`。正确匹配条件为：

$$
\rho = rcv \quad\land\quad \phi = snd.
$$

978-3-031-51476-0_21 的 Boyen–Li 论文保留为隐私定义的背景资料。其增强隐私不属于本项目开发与安全声明范围。

## 建议执行顺序

```text
Core 编码/哈希/类型
    -> 格工具
    -> HIBE contract 与实现
    -> IBS contract 与实现
    -> Baseline IB-ME
    -> 正确性/篡改/性能审计
    -> 同一通用构造下不同困难假设和不同算法的实例与优化评测
```

第一版使用 Python + SageMath；需要 Sage 的代码在 WSL 中使用：

```text
~/miniconda3/envs/sage
```

（绝对路径随各自机器的 WSL 用户名不同，统一用 `~` 写法。）

## 旧原型进度与安全口径 2026 年 9 月

M1（core/格工具）、M2（HIBE/IBS 原语）、M3（基线 IB-ME 组合 + CLI + 基准）已合并并通过功能测试：`python -m pytest -q`。目录 `src/ibme/`（core/lattice/hibe/ibs/protocol/cli）与 `experiments/`、`params/` 已包含实现代码。

> **本项目目前是演示原型（demo）。未完成安全性证明与正确性证明，不得用于生产部署，也不得用于承载任何真实秘密数据。**

### 参数自查结论（2026-09，实测）

**在当前教学参数下，方案的两个核心安全性质均不成立。** 以下结论全部由实际运行代码得出，复现脚本见 `experiments/attacks/`，完整记录见 [交接说明与安全发现](docs/交接说明与安全发现.md)。

- **SIS-IBS 可被平凡伪造，IB-ME 强可认证性不成立。** 验签范数界 `beta = 789.04` 超过模数 `q = 257`，`F_id·z = h2 (mod q)` 退化为普通线性方程组。实测：不持有任何签名密钥即可伪造出通过 `verify()` 的签名，并据此端到端伪造出接收者正常解密、且归因于被冒充发送者的密文。LLL 可将伪造范数压至 **6.71**，而诚实签名实测落在 **184.7–784.7**，因此**不存在任何验签界能同时接受诚实签名并拒绝伪造**。
- **HIBE 的 LWE 实例约 2^33。** `lattice-estimator` 对 `n=8, q=2^19, σ=1.0, m=473` 给出 usvp/bdd ≈ 2^33.1（同一环境对 Kyber512 给出 2^143.8，与公开基准吻合）。

复现：

```text
python experiments/attacks/forge_ibs.py
```

**边界：** 这是**实例化参数选择**的缺陷，不是指导论文构造 3.3.1 / 3.4.1 的缺陷。论文要求 `q` 相对范数界足够大，本项目的参数恰好相反。

### 其余既有限制

- TrapGen/SamplePre 为简化采样链（无 MP12 扰动采样），未达证明级分布——这正是诚实签名范数过大、迫使验签界放宽到 `beta > q` 的直接原因；
- HIBE 身份矩阵与 IBS 的 H1/H2 是 SHAKE-256 的 ROM 风格工程哈希，HIBE 哈希未绑定 mpk，非标准模型构造；
- 所有参数集均为极小教学参数（`security_claim: none`）；
- IBS 自适应转换和正式参数尚未完成，不能把基本方程实现当作完整安全后端；
- 功能测试与基准不替代任何安全性证明——本次自查即为实例：全量 333 项测试通过的同时，方案可被伪造。

后续重建里程碑见 `docs/PROJECT_RESTART.md`。修复须覆盖算法、采样、自适应转换与参数；仅调整范数界不构成完整修复。旧作品报告、演示与答辩材料是历史成果，重新核验后才能用于新项目交付。

## M3 交付材料

- [IB-ME 作品报告（比赛提交版）](docs/IBME_作品报告.md)：摘要、背景、设计、实现、测试、基准、贡献和安全边界；
- [M3 内部代码审查记录](docs/M3_CODE_REVIEW.md)：仅供项目内部审查，不作为比赛提交材料；
- [M3 方案流程图、算法说明与安全边界](docs/M3_FLOW_ALGORITHM_SECURITY.md)：Mermaid 流程图、算法公式和比赛统一安全口径；
- [全国密码技术竞赛演示与答辩材料](docs/COMPETITION_DEMO_AND_DEFENSE.md)：CLI 演示命令、5 分钟讲解顺序和高频问答。
