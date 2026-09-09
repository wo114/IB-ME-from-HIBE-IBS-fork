# IB-ME from HIBE + IBS

本项目的目标是实现基于两层格基 HIBE 和格基 IBS 的身份基匹配加密（IB-ME）。

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

978-3-031-51476-0_21 的 Boyen–Li 方案作为增强版扩展，额外使用匿名 IBE、`Ext` 和 `ReExt`。基线版和增强版的安全声明不能混用。

## 建议执行顺序

```text
Core 编码/哈希/类型
    -> 格工具
    -> HIBE contract 与实现
    -> IBS contract 与实现
    -> Baseline IB-ME
    -> 正确性/篡改/性能审计
    -> Enhanced privacy（可选）
```

第一版使用 Python + SageMath；需要 Sage 的代码在 WSL 中使用：

```text
/home/youzi/miniconda3/envs/sage
```

## 当前进度与安全口径（2026-09 更新）

M1（core/格工具）、M2（HIBE/IBS 原语）、M3（基线 IB-ME 组合 + CLI + 基准）已合并并通过功能测试：`python -m pytest -q`。目录 `src/ibme/`（core/lattice/hibe/ibs/protocol/cli）与 `experiments/`、`params/` 已包含实现代码。

**当前状态是功能参考原型，不是可宣称安全级别的密码方案实现**，具体限制：

- TrapGen/SamplePre 为简化采样链（无 MP12 扰动采样），未达证明级分布；
- HIBE 身份矩阵与 IBS 的 H1/H2 是 SHAKE-256 的 ROM 风格工程哈希，HIBE 哈希未绑定 mpk，非标准模型构造；
- 所有参数集均为极小教学参数（`security_claim: none`），未做任何 LWE/SIS 格安全估计；
- Boyen–Li 增强隐私版（Ext/ReExt，M4）尚未实现，基线版只对应指导论文第三章的原始隐私与强可认证性口径；
- 功能测试与基准不替代任何安全性证明。

后续里程碑：M4 增强隐私版（须记录 ROM 假设与身份熵条件）、全面审计（任务 G）。

## M3 交付材料

- [M3 代码审查与作品报告](docs/M3_CODE_REVIEW_AND_WORK_REPORT.md)：摘要、背景、设计、实现、测试、基准、贡献和限制；
- [M3 方案流程图、算法说明与安全边界](docs/M3_FLOW_ALGORITHM_SECURITY.md)：Mermaid 流程图、算法公式和比赛统一安全口径；
- [全国密码技术竞赛演示与答辩材料](docs/COMPETITION_DEMO_AND_DEFENSE.md)：CLI 演示命令、5 分钟讲解顺序和高频问答。
