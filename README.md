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

第一版建议使用 Python + SageMath；需要 Sage 的代码在 WSL 中使用：

```text
/home/youzi/miniconda3/envs/sage
```

当前目录只包含论文和设计文档，尚未包含方案实现代码。实现 AI 开始前，应先按规范建立 `src/ibme/`、`tests/` 和 `experiments/` 目录。
