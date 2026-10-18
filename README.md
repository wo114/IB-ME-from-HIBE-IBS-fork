# IB-ME from HIBE + IBS

一个共享的身份基匹配加密框架，独立实现 HIBE 和 IBS，再装配满足条件的组合。统一使用王老师的两层匿名 HIBE + IBS 通用构造；身份顺序固定为 `(rcv, phi)`。

## 从这里开始

| 要了解什么 | 唯一入口 |
|---|---|
| 当前进度、负责人、外部交付与下一步 | [PROJECT_STATUS](docs/PROJECT_STATUS.md) |
| CHKP与Luo本轮完成内容、尺寸与证据 | [2026-10-12统一交付README](docs/deliveries/2026-10-12-chkp-luo/README.md) |
| 模块结构与组合方式 | [ARCHITECTURE](ARCHITECTURE.md) |
| 公共接口、兼容预检与验收 | [IMPLEMENTATION_SPEC](IMPLEMENTATION_SPEC.md) |
| 分工、交接与提交 | [三人方案分工](docs/workplans/三人方案分工与统一框架交付.md)、[AGENTS](AGENTS.md)、[AI_WORKFLOW](AI_WORKFLOW.md) |
| 分别选择 HIBE / IBS、预检和运行 | [框架使用指南](docs/FRAMEWORK_USAGE.md) |
| 通用构造、公共框架与算法专属适配怎么分 | [其他队员复用说明](docs/FRAMEWORK_REUSE_GUIDE.md) |
| 交给实现者的任务模板 | [DELEGATION_PROMPTS](DELEGATION_PROMPTS.md) |
| 算法、代码与论文 | [现行算法总表](docs/ALGORITHM_CATALOG.md)、[论文库](papers/index.md) |
| 已知漏洞与历史记录 | [安全回归](docs/KNOWN_SECURITY_GAPS.md)、[重建历史](docs/history/PROJECT_RESTART-through-2026-10-10.md) |

## 框架与当前能力

```text
HIBE 模块 ─┐
           ├─ 组合配置与兼容检查 ─ 共享 IB-ME 协议 ─ CLI / 统一验收与评测
IBS 模块 ──┘
```

统一装配已经支持独立选择 HIBE、IBS 及各自参数，并在发钥前检查版本、能力和容量。CLI 提供 `list-backends`、`check`、`matrix` 与独立选择的 `setup`；真实组合测试由共用驱动执行，静态预检与实际结果分别记录。

除**教学 ABB10 + Hybrid + Luo 模格 IBS + BYTEAUTH**外，真实CHKP完整基研究后端及其Luo C64B组合已完成本轮功能验收；独立MP12紧凑委派变体的可安装入口同时保留。两个HIBE的小参数均有公开攻击，正式安全组合仍未完成。`security_claim=none`，功能测试不等于安全证明；具体版本、数据和边界见统一交付及当前进度表。Boyen–Li增强隐私不在开发范围。

HIBE/IBS 可以由不同成员同时实现，一项阻塞不暂停其它模块；每个模块通过自己的单体契约后进入对应组合的功能测试。正式安全结论另按论文、参数和组合前提核验。

## 环境与运行入口

Python 项目位于 `src/ibme/`，测试位于 `tests/`，研究原型位于 `experiments/research/`。已配置依赖的环境可先查看：

```text
python -m ibme.cli list-backends
python -m ibme.cli check --hibe abb10 --ibs luo-module --transport hybrid --signature-format compact
```

新 CLI 可分别选择原语，也保留旧预设。未安装 editable package 时先设置 PowerShell `$env:PYTHONPATH = 'src'`；完整调用见[使用指南](docs/FRAMEWORK_USAGE.md)。需要 Sage 的研究代码统一使用 WSL 环境 `~/miniconda3/envs/sage`。新的安装或环境变更单独确认。

## 保留的历史参数反例

下面保留已有的 2026-09—10 反例说明。文中的旧交付日期对应历史证据；当前修复与剩余问题以 [PROJECT_STATUS](docs/PROJECT_STATUS.md)及[安全回归](docs/KNOWN_SECURITY_GAPS.md)为准。BYTEAUTH 已处理当前包装的字节篡改目标，旧教学认证反例仍保留。

### 旧参数自查与安全反例（2026-09—10，区分实测与估计）

**旧教学实例已有公开伪造及密文篡改接受反例，不应宣称安全。** 复现脚本见 `experiments/attacks/`；证据保留在[重建研究报告](docs/research/2026-10-03/IBME项目现状与完整重建研究报告.md)与[原始核验记录](docs/research/2026-10-03/核验记录.json)。当前研究成果和待办见[10 月 6 日统一更新汇总](docs/deliveries/2026-10-06/README.md)，不再单独维护旧交接说明。

- **旧 SIS-IBS 的公开伪造已实测成功。** 对模 257 的 8×152 身份矩阵，若选到 8 个线性无关列，中心化稀疏解满足 `||z||₂ ≤ 128√8 ≈ 362.04 < beta ≈ 789.04`。历史脚本找到此类解，通过验签并完成冒充发送者的端到端伪造。依据是列满秩条件、维度相关范数界和接受记录，不是单凭 `beta > q`。旧 LLL／诚实样本的范数对照不能证明任何调参都无效，也不能替代一般安全定义。
- **密文字节篡改拒绝存在独立缺口。** 10 月 3 日记录了单个 `c1` 系数加 1 后仍恢复原消息的反例；消息签名有效不等于外层所有密文字节已经认证。新 IBS 正确性进展不代表该反例已修复。
- **历史 LWE 估计不等于实测破解。** 旧记录给出 usvp/bdd 的 `rop ≈ 2^33.1`，尚须固定工具版本、分布、成本模型和样本映射重新校准；不能据此换算墙钟时间或断言已恢复明文。v2 每个比特使用新秘密，`c2[j]` 有 472 个标量方程；扣除已知或猜定的比特后才可将 `c1[j]` 计入第 473 个方程，不能将全部比特并成同秘密实例。

复现：

```text
python experiments/attacks/forge_ibs.py
```

**边界：** 以上针对旧教学实现及参数，不是否定论文有效参数构造或新 Foo–Li 候选。`beta < q` 不是充分安全条件；采样分布、正确性、安全归约、正式参数和实现分别验收。当前仍为 `security_claim: none`。
