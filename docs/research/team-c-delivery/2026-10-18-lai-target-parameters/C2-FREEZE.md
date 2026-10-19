# Lai C2 研究目标实现冻结

日期：2026-10-19  
代码冻结提交：`f797685`（随机源修复）；此前实现提交 `bb2ddd3`、`2b339aa`、`775d5ad`、`c484eb5`、`dcd0309`。  
状态：**算法实现冻结，可继续做组合/交付层；不是正式安全准入。**

## 1. 冻结对象

`lai-ideal-hibe` / `lai-a-256-v1` 的显式 `target-research` preset：

```text
n=2048, q=274877976577, k=39, l=2, p=2, sigma=2, sigma_r=1
identity_bytes=86, max_message_bytes=32
```

默认 preset 仍为 A 点的 `hybrid-research` / `direct-research`；C2 不自动替换默认。

## 2. 冻结内容

- 参数：C2 常量、5 字节系数 codec、`q<2^40`、参数快照 q u64；
- 随机源：64 KiB 缓冲的 OS CSPRNG（`SecureRandom`），无 Mersenne Twister；`DeterministicRandom` 仅测试；
- 对象：PK/MSK/SK1/SK2/CT 严格 `to_bytes/from_bytes`；
- 引擎：两级 setup/extract/derive/encrypt/decrypt、Klein/GPV、`ringDelTrap`、Babai；
- 目标 preset：`target-research`；
- 目标负测试：wrong-child、wrong-parent（HIBE 层）、h/u/v tamper、非单位 tag、截断/追加；
- 外层 BYTEAUTH：context/signature/inner/truncate/append 拒绝；
- 目标 CLI/state：CSPRNG 完整生命周期已重跑。

## 3. 证据摘要

| 项目 | 结果 |
|---|---|
| 完整 GSA 攻击集 | C2 **169.94 / 154.23 bit**（经典/量子成本模型）；C3 164.10 / 148.93 |
| 生命周期（4 个确定性种子） | 4/4 通过；derive 622–645 s |
| 生产 CSPRNG HIBE 探针 | 2.08/33.20/540.93/106.76/17.41 s，通过 |
| 目标 CLI CSPRNG 生命周期 | 8/57/6/110/632 s；14 B → 1,357,049 B；解密一致；state 26 MB |
| HIBE 错误身份 | wrong-child、wrong-parent → None |
| 外层 BYTEAUTH tamper | 5/5 拒绝 |
| CI | Lai 套件 **57 passed**；hybrid/assembly **65 passed** |
| 后端测试 | backend **14 passed**；P1 **22 passed** |

## 4. 明确不在冻结范围

- 正式安全/匿名性证明；`security_claim=none`；
- NIST category 或形式化 HIBE 安全等级；
- LGSA C2 的 hybrid 路径（estimator math-domain error）；完整集用 GSA；
- 逐种子残差/容差统计；
- perturbation / 证明级 `ringSampleD`；
- 外层 wrong receiver/sender 与 replay（组合/应用层，未单独测）；
- 性能优化、默认 preset 切换、P3/P4 完整组合攻击矩阵。

## 5. 冻结规则

- 冻结后不再向 `src/ibme/hibe/lai/` 增加算法功能；如需改参数、采样、随机源或对象编码，开新任务并重新评审。
- C2 仍是显式 `target-research`；默认 A 点不变。
- 现有 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false` 不变。
- 组合层、性能、报告材料可以使用本冻结版本，但必须引用上述限制。

相关报告：[目标参数筛选](README.md) · [security-estimate.json](security-estimate.json) · [Lai 契约](../../../../docs/specs/lai-hibe.md)。
