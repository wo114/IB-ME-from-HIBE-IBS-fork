# 已完成方案的项目准入

2026-10-19，用户决定不再以额外安全证明闭合作为项目准入前置条件。准入依据固定为：论文或标准中的安全结论、项目已确认的 HIBE 身份匿名性工作前提，以及真实实现、完整参数快照、公共接入和所需组合验收均已完成。

当前统一值为：

```text
security_claim = project-admitted
backend_admitted = true
parameters_are_formal = true
```

公共 registry 按精确 preset 授权，当前清单如下。

| 角色 | 后端 | 准入参数 |
|---|---|---|
| HIBE | `latte` | `seed32`、`framed32` |
| HIBE | `lai-ideal-hibe` | `target-research` |
| IBS | `cert-ml-dsa` | `ml-dsa-44`、`ml-dsa-65`、`ml-dsa-87` |
| IBS | `cert-falcon` | `falcon-padded-512`、`falcon-padded-1024` |
| IBS | `luo-matrix` | `research` |
| IBS | `luo-module` | `research`、`c64b` |
| IBS | `srgg2025-paper` | `PARAM-I`、`PARAM-II`、`PARAM-III` |
| IBS | `sageloli-rsis` | `PARAM-I`、`PARAM-II` |

其中主演示 `LATTE-3 + BNN/ML-DSA-44 + Hybrid + BYTEAUTH` 的 Suite 及 BNN 参数快照均输出 `project-admitted/true/true`。LATTE-3 采用原论文 80-bit 目标表中的作者参数；ML-DSA-44 为 FIPS 204 基础签名参数。这里记录的是项目对完整实现的准入，不把完整 IB-ME 写成单独的外部标准认证对象。

以下对象不因实现代码存在而自动准入：mock、教学参数、`debug-small`、已知 q3/q17/n1/n2 公开攻击负控、只完成估计或资源投影而没有目标运行的参数，以及尚未交付公共后端的路线。它们继续使用 `none/false/false`。

旧提交中的实验收据、Suite 摘要和哈希不改写。当前 `make_suite` 生成新准入元数据；旧 `none/false/false` Suite 仍可按原摘要加载和复核，但不能反向把未列入清单的 profile 提升为准入。

实现与回归入口：

```text
PYTHONPATH=src:. nix shell nixpkgs#sage -c \
  sage -python -m pytest -q tests/test_project_admission.py
```

该测试逐项核对准入清单、主演示和其它完成组合、Lai C2 与小 A 点的区分、负控不升级、伪造准入字段拒绝，以及旧 Suite 的兼容读取。

本次最终核验结果：

- registry／CLI／Web／旧状态兼容等共同回归：`205 passed`；
- 认证 IBS、SRGG、Sageloli、Lai 真实生命周期和 Luo 两档专项：`241 passed, 26 skipped`；跳过项是未配置相应可选原生引擎的既有显式 skip；
- 研究报告构建与逐格一致性：`188 checks passed`；
- 历史主演示批次保持可复核：`60` 个批量结果、`405` 个源码/provider 绑定及 `5` 个负控全部通过。

本机执行使用 Nix 提供的 Sage/Python，没有调用仓库中记录的旧 Sage 绝对路径。上述测试验证元数据、接口、兼容与既有功能证据，不新增外部标准认证结论。
