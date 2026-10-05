# IB-ME from HIBE + IBS

本项目的目标是实现基于两层格基 HIBE 和格基 IBS 的身份基匹配加密（IB-ME）。

## 当前重建路线 2026 年 10 月 5 日

团队已固定王老师的两层匿名 HIBE + IBS 通用构造，不实施 Boyen–Li 增强隐私。第七轮补上 Foo–Li 的经典隐藏种子桥接、目标槽位联合论证及模块化 SIS 归约；第八轮实现完整 MP12 SampleD；第九轮连接真实高斯主生成、独立列委派与用户采样，并给二进制单列参数类补上全部合格陷门的资源和有限误差界。128 次尝试保留 2 次质量拒绝，前四次共 512 个用户输出方程正确；这组小参数的公开分布距均匀约 0.4602，SIS 范数区间失败，仍为数学研究样例。下一项解除全中心预计算瓶颈；大模数可用性、实用参数与正式后端仍为 WIP，不默认转向另一套 IBS。ABB10 保持 HIBE 参考候选。旧公开伪造和外层密文篡改仍由后端替换、认证包装解决；当前生产密码代码与教育参数未改。

- [重建工作记录](docs/PROJECT_RESTART.md)：已确认范围、阶段进度及下一任务；
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
\text{两层匿名 HIBE} + \text{SIS-IBS}.
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
    -> 同一通用构造的多实例与优化评测
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
