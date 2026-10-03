# IB-ME from HIBE + IBS

本项目的目标是实现基于两层格基 HIBE 和格基 IBS 的身份基匹配加密（IB-ME）。

## 当前重建路线 2026 年 10 月 3 日

团队已固定王老师的两层匿名 HIBE + IBS 通用构造，不实施 Boyen–Li 增强隐私。下一阶段先核验 HIBE、IBS 的具体算法、安全前提、采样与参数，再建立可靠实例、认证封装和公平评测。当前密码代码仍是教学原型，已有伪造与篡改反例尚未修复。

- [重建工作记录](docs/PROJECT_RESTART.md)：已确认范围、阶段进度及下一任务；
- [修订后的重建研究报告](docs/research/2026-10-03/IBME项目现状与完整重建研究报告.md)：现状证据与完整路线；
- [原语选型第一轮核验](docs/research/2026-10-03/原语选型第一轮核验.md)：组合前提、候选准入与进一步精读任务。

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
