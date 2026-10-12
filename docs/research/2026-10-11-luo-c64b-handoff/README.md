# 第二十三步：把 C64B 变成能明确选择、保存和接入的候选

本轮是在第二十二步参数与条件式中止界之上做交付，不重新做 Luo 全套安全归约，不承担 CHKP 实现。

## 这次具体解决什么

1. **参数不用再手抄。** `c64b_params()` 固定全部 17 个参数和资源限额，稳定名称为 `luo-module-c64b-v1`。它与第二十二步 `availability-k64` 逐字段相同。
2. **修复生成和恢复不一致。** 旧研究入口的恢复器只认旧默认参数。现在必须显式选 C64B，生成与恢复绑定同一参数快照；错误选择在采样前被拒绝。旧入口、旧签名格式和旧数据的默认解释保持不变。
3. **分开选参和安全结论。** C64B 作为下一阶段可复现实验的固定候选；不宣称已经是正式安全参数。经典 ROM 引用依据、参数估计、条件式可用性界和程序测试分别记录。

状态仍为 `security_claim: none`、`backend_admitted: false`、`parameters_are_formal: false`。这些状态不阻止合法功能测试，也不表示算法存在已证实的安全漏洞。

## 接入方式

```python
from ibme.ibs.luo_module_profiles import C64B_PROFILE_ID, c64b_params
from ibme.protocol.luo_hybrid import make_research_runtime, RESEARCH_HIBE_PARAMS

p = c64b_params()
protocol, readers = make_research_runtime(ibs_params=p, signature_format="compact")
public, master = protocol.setup(RESEARCH_HIBE_PARAMS)  # 自动使用选定的 p
```

这里的 HIBE **仍是教学 ABB10 + Hybrid**，不是 CHKP。要交接通用框架，只需把 `p` 交给真实 `LuoModuleIBSBackend` 或 `LuoModuleCompactIBSBackend`，并保存明确的 profile 与签名格式。不得仅把旧 state 的名字改成 C64B：参数参与公钥上下文，已有密钥应按原快照读取；新参数需要新系统状态。

调用方省略 `ibs_params` 时保持旧默认；默认格式仍是 `reference`。显式 setup 参数必须与运行入口选定值相同。签名加载器不自动跨格式降级。此次没有改 CLI 或其他对话负责的装配模块。

## 能报告什么，不能报告什么

| 项目 | 本轮结论 |
|---|---|
| 参数数值 | 固定 C64B，全部 17 字段；未改旧默认 |
| 签名尺寸 | reference 29455 B、compact 16383 B；较旧 compact 多 320 B |
| 最大组合外载荷 | compact 的 16383+108+3924=20415 B；教学Hybrid已实测，不是 CHKP 实测 |
| 内层 HIBE 要求 | 两层身份各 86 B、种子 32 B；CHKP 是否具备由其分支验收 |
| 可用性 | 第二十二步已给理想随机模型下的条件界；精确 LowBits 联合分布不是该界的前提 |
| 安全等级 | 没有宣布 128/153/192 位或 NIST 等级；中止概率指数不等于安全位数 |
| 新框架 | 公共接口与源版本分别核对；本目录不是另一套注册器或 CLI |

具体决定见[参数决定与安全引用条件](参数决定与安全引用条件.md)，运行范围见[验收记录](验收记录.md)。122项定向回归、19项工具测试通过；共享框架0bf0855上的25项C64B装配检查也已通过，实际测得教学Hybrid外载荷20415 B。没有将这些结果称为CHKP完成。

## 证据入口

- [第二十二步参数与估计](../2026-10-11-luo-abort-bound/参数选择与安全边界.md)：数值、模型、权衡与限制。
- [第二十二步可用性推导](../2026-10-11-luo-abort-bound/鲁棒接受集与中止界.md)：概率界的准确模型和预算。
- [Luo 原文](https://icics2024.aegean.gr/wp-content/uploads/2024/08/150570198.pdf)：§4.1–4.3 为算法和正确性依据，§4.4 为安全归约草图；不继承其 Table 1 的等级与性能数字。

本轮使用 Scientific Critical Thinking 的“主张—证据—边界”检查流程，不以 Skill 作为密码学证据。方法工具引用：Timothy Kassis, Vinayak Agarwal, Yuhuan He, Darshil Patel, Aubrey M. Brueckner (2026), [Scientific Agent Skills: A Library of Procedural Knowledge for Research Agents](https://doi.org/10.48550/arXiv.2609.00065)。作者与当前记录已核对。
