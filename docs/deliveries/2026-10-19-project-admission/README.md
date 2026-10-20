# 已完成方案的默认安全口径

2026-10-20，用户明确要求“就认为是安全的，不是本项目准入”“默认已经做好的都是安全的”，并要求同步AGENTS.md。已完成方案按安全方案处理，安全性与HIBE身份匿名性依据选定原文和已确认前提，不再等待补充安全证明或完整归约。本文修正原PR73使用的项目内部准入说法。

当前统一值为：

```text
security_claim = secure
backend_admitted = true
parameters_are_formal = true
```

公共registry列出已完成并冻结采用的精确preset，当前清单如下。

| 角色 | 后端 | 已完成参数 |
|---|---|---|
| HIBE | `latte` | `seed32`、`framed32` |
| HIBE | `lai-ideal-hibe` | `target-research` |
| IBS | `cert-ml-dsa` | `ml-dsa-44`、`ml-dsa-65`、`ml-dsa-87` |
| IBS | `cert-falcon` | `falcon-padded-512`、`falcon-padded-1024` |
| IBS | `luo-module` | `research`、`c64b` |
| IBS | `srgg2025-paper` | `PARAM-I`、`PARAM-II`、`PARAM-III` |
| IBS | `sageloli-rsis` | `PARAM-I`、`PARAM-II` |

其中主演示 `LATTE-3 + BNN/ML-DSA-44 + Hybrid + BYTEAUTH` 的Suite及BNN参数快照均输出 `secure/true/true`。LATTE-3采用原论文80-bit目标表中的作者参数，ML-DSA-44采用FIPS 204基础签名参数；各自实际目标和模型分别引用，不额外声称完整IB-ME获得NIST认证。

以下对象不因实现代码存在而自动准入：mock、教学参数、`debug-small`、已知 q3/q17/n1/n2 公开攻击负控、只完成估计或资源投影而没有目标运行的参数，以及尚未交付公共后端的路线。它们继续使用 `none/false/false`。

Luo矩阵版的`research`也属于已知反例：实际为n=4、m=8、η=1的M2 functional配置，仓库[原参数筛查](../../research/2026-10-09-m2/README.md)已记录其等效主秘密恢复和有效伪造。它保留可运行研究接口，标记为`none/false/false`；Luo模格版的`research`和`c64b`为另两份配置，不受此例外影响。

旧提交中的实验收据、Suite摘要和哈希不改写。当前 `make_suite` 输出上述安全元数据；旧 `none/false/false` Suite仍可按原摘要加载和复核，不能把改变标记写成新增密码实验。未完成配置和已知反例不能伪造安全字段绕过按profile校验。

实现与回归入口：

```text
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_project_admission.py
```

该测试逐项核对准入清单、主演示和其它完成组合、Lai C2 与小 A 点的区分、负控不升级、伪造准入字段拒绝，以及旧 Suite 的兼容读取。

原PR73修订前的作者核验记录（Nix环境，不计作本轮WSL复测）：

- registry／CLI／Web／旧状态兼容等共同回归：`205 passed`；
- 认证 IBS、SRGG、Sageloli、Lai 真实生命周期和 Luo 两档专项：`241 passed, 26 skipped`；跳过项是未配置相应可选原生引擎的既有显式 skip；
- 研究报告构建与逐格一致性：`188 checks passed`；
- 历史主演示批次保持可复核：`60` 个批量结果、`405` 个源码/provider 绑定及 `5` 个负控全部通过。

本机执行使用 Nix 提供的 Sage/Python，没有调用仓库中记录的旧 Sage 绝对路径。上述测试验证元数据、接口、兼容与既有功能证据，不新增外部标准认证结论。
