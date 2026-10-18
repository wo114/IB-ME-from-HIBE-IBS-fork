# SRGG 独立 IBS 原论文续审总览（WIP）

范围：仅 Jia、Liu、Tang、Wang 的独立 IBS，不涉及 HIBE、公共组合或正式安全准入。来源为仓库冻结的 [论文 PDF](../../../../papers/2025_efficient_ibs_jia.pdf)，SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`；出版版 DOI [10.1049/ise2/6684889](https://doi.org/10.1049/ise2/6684889)。本轮以 `ac5d442` 为起点，九个范围内提交依次为 `ccc3d1b`、`ab61558`、`b7b6f44`、`88d53d4`、`73e80e7`、`3650eb4`、`5d31fba`、`8b9765c`、`c54b68f`。原 Table 4 的三行、两种明确标记的 Gaussian 解释、既有源后端及优化路线均未被改写。

| 可复核结果 | 当前成立的范围 | 证据入口 |
|---|---|---|
| 原顺序有限 Schur 链 | 数值式使用门限 64 和根无关常数；六个**冻结 Setup 根**是已运行见证。表标准差解释给非平凡条件界，字面 density 解释的替代 Fourier 矩界非平凡但弱。此旧包未实施覆盖所有可接受根的 guard。 | [有限链](../2026-10-18-srgg-finite-chain/README_zh-CN.md) |
| Setup 接受 | 原分布的**数学**正定拒绝每次上界为约 0.2055／0.09513／0.04667；实际数值后端通过条件的质量差仍没有有用上界。 | [数学门](../2026-10-18-srgg-setup-acceptance/README_zh-CN.md)、[后端缺口](../2026-10-18-srgg-setup-backend-gap/README_zh-CN.md) |
| 原参数首次发钥与历史 | 六行各有一次固定根真实发钥回执。标准差解释下，在同根容量 3／2／1 个身份内，自适应**发钥专属**历史 TV 各至多 `2^-24`。冻结 Alice 的同一把密钥，两次自适应消息签名界依次为 `2^-18`／`2^-17`／`2^-17`。两项不能相加成随机发钥后签名的整体界。 | [首次发钥](../2026-10-18-srgg-source-issuance/README_zh-CN.md)、[历史界](../2026-10-18-srgg-history-law-followup/README_zh-CN.md) |
| 原文记号与验签代数 | 论文形式定义的 `η_ε(Z^10240)` 在 `(2.9077794,2.9077796)`，却印作 `r≈1.16`；仅额外假设未写出的物理标准差转换才接近 1.16。验签映射在模 `2Q` 的像／核已精确算出，不是短向量成本。 | [平滑宽度](../2026-10-18-srgg-smoothing-eta/README_zh-CN.md)、[验签映射](../2026-10-18-srgg-verification-image/README_zh-CN.md) |
| 结构成本与原生 strong | 原表 `Q=15,744,063<2γ`，`Qe_i` 对界为 `2γ` 的无限制整数 Q-MSIS 是零 BKZ 成本短核见证。另六种原表配置的真实首签中有 5 种通过公开 `±Q` 单基修改得到同消息、不同规范签名且验签接受；默认 PARAM-I 的一次探针未命中。两者都不等于新消息伪造概率或总体强度估计。 | [结构成本](../2026-10-18-srgg-structural-cost/README_zh-CN.md)、[strong 游戏](../2026-10-18-srgg-strong-game/README_zh-CN.md) |

原参数共同部分为 `n=512,p=16383,b=31,w=2,Q=15744063,d=2/3/4`；`γ=42086491.7/63653172.0/86573930.5`。论文 Theorem 1 的奇数模数 `q>2γ` 与三行中自然映射的 `Q` 不相容；Table 3 的扰动减 `r²WWᵀ` 与 Algorithm 7 经 `ζζ*=2` 后的 `u` 形状存在相对因子 2；Theorem 2 文字写 strong，但其 G0 新消息条件不覆盖同消息替换。保留这三项来源与实例对应问题，不自行改 `γ`、采样宽度、验签规则或安全游戏。不满足论文定理的充分条件本身并不能推出所有安全目标都失败；上述真实替换则直接反驳“这五份实际签名拒绝所有同消息不同签名”的说法。

失败时按用户澄清的边界处理：主路线失败后最多换两条路线，再失败就保存数值、资源和前提缺口，转做下一项。字面 density 整链和实际 Setup 后端缺口都已按此规则留下证据。尚未闭合的事项统一包括所有接受根上的有限链与根分布、随机发钥后签名及故障历史、原文 Gaussian／`ζ`／定理前提的统一对应、实际 Ring-HNF／CRT／子域攻击成本、native strong 的真实随机成功概率与可适用归约、服务终身熵／RAM／时间。论文作者的 C/ANS 和 1000 次性能数据尚未在本 Python/Sage 实现中复现，单次研究运行不可与之作同安全强度性能比较。HIBE 选择不作为修改上述独立参数的理由。

验证：规定 WSL Sage 10.9／Python 3.13.15 运行 `PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg*.py`，在九个提交中的前六个之后得到 **1813 passed、0 failed/error/skipped**（467.78 秒）。后三个提交仅新增各自的源码、测试与证据，没有修改既有后端；三包联合定向回归 **42 passed**（39.16 秒）。[验证记录](validation.json)列明两次运行的 HEAD 与命令；[总校验回执](package-verification.json)记录九个分包各在普通和 `-O` 模式通过，总共 18 次，可用 [`verify_all.py`](verify_all.py)复核。测试种子用于复现，不证明生产熵或密码学安全。

本批结论始终为 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。原论文声称、代码功能、有限实验、条件概率界和正式安全证明分别验收。本段是原本地 WIP 检查点；本次发布范围及冻结回执的基线差异另见[SRGG 集成说明](../2026-10-18-srgg-pr-integration/README.md)。DeepSeek 的 guarded/v1 改写不在本次交付中。
