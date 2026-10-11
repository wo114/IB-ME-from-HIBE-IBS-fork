# IB-ME from HIBE + IBS

一个共享的身份基匹配加密框架，独立实现 HIBE 和 IBS，再装配满足条件的组合。统一使用王老师的两层匿名 HIBE + IBS 通用构造；身份顺序固定为 `(rcv, phi)`。

## 从这里开始

| 要了解什么 | 唯一入口 |
|---|---|
| 当前进度、负责人、外部交付与下一步 | [PROJECT_STATUS](docs/PROJECT_STATUS.md) |
| 模块结构与组合方式 | [ARCHITECTURE](ARCHITECTURE.md) |
| 公共接口、兼容预检与验收 | [IMPLEMENTATION_SPEC](IMPLEMENTATION_SPEC.md) |
| 分工、交接与提交 | [AGENTS](AGENTS.md)、[AI_WORKFLOW](AI_WORKFLOW.md) |
| 交给实现者的任务模板 | [DELEGATION_PROMPTS](DELEGATION_PROMPTS.md) |
| 文献与候选基础 | [论文库](papers/index.md)、[候选基础包](docs/research/2026-10-10-foundations/README.md) |
| 已知漏洞与历史记录 | [安全回归](docs/KNOWN_SECURITY_GAPS.md)、[重建历史](docs/history/PROJECT_RESTART-through-2026-10-10.md) |

## 框架与当前能力

```text
HIBE 模块 ─┐
           ├─ 组合配置与兼容检查 ─ 共享 IB-ME 协议 ─ CLI / 统一验收与评测
IBS 模块 ──┘
```

现有协议已经支持注入 HIBE/IBS 对象和分别传入参数。通用后端注册、独立选择命令和自动组合矩阵是接下来的实现项；本文整理没有实现这些功能。

当前可运行的研究预设使用**教学 ABB10 + Hybrid + Luo 模格 IBS + BYTEAUTH**。真实 CHKP 公开后端和正式安全组合尚未完成；仓库外的新成果及尚未合并的提交见当前进度表。`security_claim=none`，功能测试不等于安全证明。Boyen–Li 增强隐私不在开发范围。

HIBE/IBS 可以由不同成员同时实现，一项阻塞不暂停其它模块；每个模块通过自己的单体契约后进入对应组合的功能测试。正式安全结论另按论文、参数和组合前提核验。

## 环境与运行入口

Python 项目位于 `src/ibme/`，测试位于 `tests/`，研究原型位于 `experiments/research/`。已配置依赖的环境可先查看：

```text
python -m ibme.cli --help
```

现有 CLI 按预设选择，具体命令以实际帮助为准。需要 Sage 的研究代码统一使用 WSL 环境 `~/miniconda3/envs/sage`。新的安装或环境变更单独确认。

## 保留的历史参数反例

下面保留已有的 2026-09—10 反例说明。文中的旧交付日期对应历史证据；当前修复与剩余问题以 [PROJECT_STATUS](docs/PROJECT_STATUS.md)及[安全回归](docs/KNOWN_SECURITY_GAPS.md)为准。BYTEAUTH 已处理当前包装的字节篡改目标，旧教学认证反例仍保留。

### 参数自查结论（2026-09，实测）

**在当前教学参数下，方案的两个核心安全性质均不成立。** 以下结论全部由实际运行代码得出，复现脚本见 `experiments/attacks/`，完整记录见 [交接说明与安全发现](docs/交接说明与安全发现.md)。

- **SIS-IBS 可被平凡伪造，IB-ME 强可认证性不成立。** 验签范数界 `beta = 789.04` 超过模数 `q = 257`，`F_id·z = h2 (mod q)` 退化为普通线性方程组。实测：不持有任何签名密钥即可伪造出通过 `verify()` 的签名，并据此端到端伪造出接收者正常解密、且归因于被冒充发送者的密文。LLL 可将伪造范数压至 **6.71**，而诚实签名实测落在 **184.7–784.7**，因此**不存在任何验签界能同时接受诚实签名并拒绝伪造**。
- **HIBE 的 LWE 实例约 2^33。** `lattice-estimator` 对 `n=8, q=2^19, σ=1.0, m=473` 给出 usvp/bdd ≈ 2^33.1（同一环境对 Kyber512 给出 2^143.8，与公开基准吻合）。

复现：

```text
python experiments/attacks/forge_ibs.py
```

**边界：** 这是**实例化参数选择**的缺陷，不是指导论文构造 3.3.1 / 3.4.1 的缺陷。论文要求 `q` 相对范数界足够大，本项目的参数恰好相反。
