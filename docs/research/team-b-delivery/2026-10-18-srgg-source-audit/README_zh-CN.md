# SRGG 独立 IBS 来源与安全结论续审（WIP）

此批只核 Jia–Liu–Tang–Wang 独立 IBS 的冻结原文、当前 Table 4 代码和条件安全结论。论文为 `papers/2025_efficient_ibs_jia.pdf`，SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。开发基线 `cd31389`，隔离分支 `codex/srgg-source-audit-2026-10-18`；旧 SRGG worktree 的两份未追踪草稿与主检出均未修改。本批不推送或创建 PR。

| 新增审计 | 已得到的限定结论 | 仍缺什么 |
|---|---|---|
| [H1/H2 地址与经典有限拒绝耦合](../2026-10-18-srgg-hash-address-mapping/proof.md) | 固定单公钥、经典理想独立地址模型下，至多 `N` 个互异 H1 地址的完整自适应 transcript `TV≤N*d*n*((2^24−Q)/2^24)^256`；H2 直接取 512 位。代码地址包含完整公钥和规范长度前缀。 | 真实 SHAKE 到 RO、QROM 编程及跨公钥全局 `H(id)` 联合游戏。不能用“全程无失败条件同分布”替代耦合。 |
| [Algorithm 1 每列密钥恢复格](../2026-10-18-srgg-key-recovery-mapping/proof.md) | `Âs_j+e_j=F_j−B_j mod Q`；三档 `D=2049/3073/4097`、`det=Q^m`。作者 p.9 印出 `I_n`，本批明示维数一致的 `I_m` 修正。CBD1 支持范数与作者 β 判据的输入敏感性已复算。 | 接受根的条件范数及联合分布、实际 primal/BKZ 和 Ring-HNF/CRT/子域成本；Table 5 安全位数仅为作者自报。 |
| [Theorem 2 抽象验证接口](../2026-10-18-srgg-theorem-interface-mapping/proof.md) | p.8 的概括性 SIG 验签调用按字面缺少与 `(a,H(id))` 对应的验证公钥；具体 Algorithm 8 与代码的身份目标、承诺恢复、消息挑战逐项对应。 | 底层 SIG 验签与 `H̄` 共享 oracle 的精确游戏接线，以及实际/QROM 归约。 |
| [§5.2.3 伪造仿射格输入](../2026-10-18-srgg-forgery-input-mapping/proof.md) | 固定承诺 `w`、挑战 `c` 的目标为 `M_hz=w+Qjc mod 2Q`；目标可达当且仅当 `w` 在已证验签像中，整数核格行列式为 `Q^(dn)·2^256`。原表三档维数和范数门已映射。 | 短陪集向量的存在／求解成本、从作者通用 `Q`-ary 公式到实际 `2Q` 格的变换，以及 Table 5 伪造位数复现。 |

数值复算入口是 `python -m experiments.research.candidates.srgg.paper_key_recovery_mapping` 与 `python -m experiments.research.candidates.srgg.paper_forgery_input_mapping`；均先校验冻结 PDF 哈希。前者的 `author_table5_security_bits_reproduced`、`actual_primal_attack_cost_bits`、`complete_ring_hnf_crt_subfield_attack_cost` 保持 `null`；后者的 `actual_short_solution_or_attack_cost` 保持 `null`。密钥恢复测试用非零 CBD1 **支持** fixture 检查三档所有 `B` 列及每个系数，不把 fixture 说成通过 Setup 的随机根。哈希测试复用已有拒绝预算及来源符号测试；伪造输入测试只查格像与恢复等式，不求短解。

验证记录：

| 命令（仓库根；WSL 指定 Sage 环境） | 本批结果 |
|---|---|
| `PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_oracle_budget.py tests/test_srgg_paper_source_symbol_mapping.py` | 25 passed，0 failed |
| `PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_key_recovery_mapping.py tests/test_srgg_paper_backend.py` | 56 passed，0 failed |
| `PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_forgery_input_mapping.py tests/test_srgg_paper_verification_image.py` | 20 passed，0 failed |
| `python -m experiments.research.candidates.srgg.paper_key_recovery_mapping` | 三行 JSON 正常生成，冻结 PDF 哈希匹配 |
| `python -m experiments.research.candidates.srgg.paper_forgery_input_mapping` | 三行格输入 JSON 正常生成，冻结 PDF 哈希匹配；未复现作者伪造位数 |
| `git diff --check`、提交前 `git diff --cached --check` | 通过 |

WSL 启动时报告过 Windows `E:\Service\DBus\bin` 路径翻译警告，但上述测试进程退出码均为 0。此批没有新的随机密码学实验，随机重复次数 0；新增伪造输入测试只用固定 14 字节身份和 13 字节消息。审计对象的代码入口分别限制身份 1–4096 字节、消息 0–65536 字节。经典理想 oracle 是显式条件模型，不是实际 SHAKE 或 QROM 的运行声明。既有 Table 4 参数保持 `n=512,p=16383,b=31,w=2,Q=15744063,d=2/3/4`，两种 Gaussian 解释未改，作者 C/ANS/1000 次基准未复现。代码功能测试不能替代正确性、困难性或安全归约证明。

本机定向复核环境：Intel Core Ultra 7 255HX、Windows build 26200；测试在 WSL2 Linux 6.18.33.2、指定 conda 环境的 Python 3.13.15 / Sage 10.9 执行。这不是论文作者的 C/gcc 8.3.0/Deepin 20.9 性能环境，不作速度对比。

依[原论文续审总览](../2026-10-18-srgg-independent-followup/README_zh-CN.md)，所有接受 Setup 根、随机发钥与故障历史属于另一类待核链，此批没有接手。Theorem 1 的 `q=Q` 门、`η`、`ζ` 因子、G0 fresh-message 与同消息 Q-shift 也已封存，不重复运行或改变判据。现在依然是 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`；不存在已核准的 NIST 等级或完整原论文安全映射。
