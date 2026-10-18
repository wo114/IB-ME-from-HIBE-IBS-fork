# SRGG 独立 IBS 来源与安全结论续审（WIP）

此批只核 Jia–Liu–Tang–Wang 独立 IBS 的冻结原文、当前 Table 4 代码和条件安全结论。论文为 `papers/2025_efficient_ibs_jia.pdf`，SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。开发基线 `cd31389`，隔离分支 `codex/srgg-source-audit-2026-10-18`；旧 SRGG worktree 的两份未追踪草稿与主检出均未修改。本批不推送或创建 PR。

| 新增审计 | 已得到的限定结论 | 仍缺什么 |
|---|---|---|
| [H1/H2 地址与经典有限拒绝耦合](../2026-10-18-srgg-hash-address-mapping/proof.md) | 同一经典理想 XOF 下，至多 `M` 个 matrix、`N` 个 H1 有效地址的自适应 transcript `TV≤(Md²n+Ndn)*((2^24−Q)/2^24)^256`；原始 XOF 预查询计入地址预算，H2 直接取 512 位。诚实 Setup 先确定公钥；若先看候选 H2 再选公钥，固定公钥重命名会失效。重命名只覆盖代码可接受的身份/消息域。 | 真实 SHAKE 到 RO、QROM 编程及跨公钥全局 `H(id)` 联合游戏；论文全比特串域与代码长度上限须显式区分。此界不证明接受根分布或整个服务 law。 |
| [Algorithm 1 每列及多目标密钥恢复格](../2026-10-18-srgg-key-recovery-mapping/proof.md) | `Âs_j+e_j=F_j−B_j mod Q`；单列三档 `D=2049/3073/4097`、`det=Q^m`。同一公开矩阵的 `k=wd` 个目标及全部环旋转另给 `D=2m+k`、`D=4m` 两种输入，行列式均为 `Q^m`；三档完整环输入维数 `4096/6144/8192`。作者 p.9 印出 `I_n`，本批明示维数一致的 `I_m` 修正；短核向量不自动等于原始主密钥列。 | 接受根的条件范数及联合分布、这些不同格的实际 BKZ 和 Ring-HNF/CRT/子域成本；Table 5 安全位数仅为作者自报，不能按行列式直接迁移。 |
| [Theorem 2 抽象 SIG 与 [33] QROM 引用](../2026-10-18-srgg-theorem-interface-mapping/proof.md) | 固定单公钥下，实际 Sign/Verify 可计算上因子化为候选 `(P,H1_P(id))` SIG 调用；`H̄_P` 在经典理想模型可作地址重命名。p.8–9 的概括性验签调用及 G2 `H(x)=pk` 有类型缺口。[33] IBE 明数 `q_H+q_E+1` 次 H 查询，且另以 Claim 1 处理依赖秘密集合 `X` 的成功事件；Jia 的 `ℓ(q_H,q_S,q_E)` 和 `ℓ(q_H,4q_S,q_E)` 是待证扩展，G1 排除 Extract 身份却写 `q_S`。 | [33] Appendix D 全证明未核；SRGG 的 Sign/Extract 联合回答、内部 H1 查询账本、H2 与底层 SIG 接线、抽样与公钥联合分布、真实 SHAKE/共享 oracle 及原生 strong 前提均未闭合。候选解释不能冒充原文证明。 |
| [§5.2.3 伪造仿射格输入](../2026-10-18-srgg-forgery-input-mapping/proof.md) | 固定承诺 `w`、挑战 `c` 的目标为 `M_hz=w+Qjc mod 2Q`，整数核格行列式为 `Q^(dn)·2^256`。受限 `w=0,z=(x,c)` 子问题精确等价于 `Ax=hc mod Q`，其核格行列式为 `Q^(dn)`、范数预算为 `floor(γ²)−wt(c)`；定向测试含正反两侧。 | 短向量的存在／求解成本、作者通用公式究竟对应哪种子问题，以及 Table 5 伪造位数复现。 |
| [Table 4 裸尺寸与用户对象维数](../2026-10-18-srgg-table4-storage-mapping/proof.md) | `mpk=(32B seed_A,B)` 用每模 `Q` 系数 3 字节，`msk=R` 用每 CBD1 系数 2 位，三档均精确得到作者表中 `mpk/msk` 字节数；Algorithm 2/7 与代码的用户密钥 tail 和签名响应维数亦对应，三档系数数分别为 `3072/4608/6144` 与 `4608/6656/8704`。 | `mpk/msk` 是一种与表格一致的编码假设；`sk_id/sig` 的预像熵、ANS、作者 C wire 与本实现 JSON 长度仍未对应。 |
| [Table 5 β 到位数换算](../2026-10-18-srgg-table5-bit-conversion/proof.md) | 作者六个 β 代入 §5.2.1 的 `0.292β`、`0.265β` 并按最近整数取整，精确得到十二个表内经典／量子位数。 | β 的实际格输入、攻击模型、成功率与成本未复现；此算术不赋予当前实现安全等级。 |

数值复算入口是 `python -m experiments.research.candidates.srgg.paper_key_recovery_mapping` 与 `python -m experiments.research.candidates.srgg.paper_forgery_input_mapping`；均先校验冻结 PDF 哈希。前者的 `author_table5_security_bits_reproduced`、`actual_primal_attack_cost_bits`、`complete_ring_hnf_crt_subfield_attack_cost` 保持 `null`；后者的 `actual_short_solution_or_attack_cost` 保持 `null`。密钥恢复测试用非零 CBD1 **支持** fixture 检查三档所有 `B` 列及每个系数，不把 fixture 说成通过 Setup 的随机根。哈希测试复用已有拒绝预算及来源符号测试；伪造输入测试只查格像与恢复等式，不求短解。

验证记录：

| 命令（仓库根；WSL 指定 Sage 环境） | 本批结果 |
|---|---|
| `PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_oracle_budget.py tests/test_srgg_paper_source_symbol_mapping.py` | 25 passed，0 failed |
| `PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_key_recovery_mapping.py tests/test_srgg_paper_backend.py` | 56 passed，0 failed |
| `PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_backend.py tests/test_srgg_paper_source_symbol_mapping.py` | 本次扩展定向 67 passed，0 failed；与旧行测试有重叠，不合计 |
| `PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_forgery_input_mapping.py tests/test_srgg_paper_verification_image.py` | 20 passed，0 failed |
| `python -m experiments.research.candidates.srgg.paper_key_recovery_mapping` | 三行 JSON 正常生成，冻结 PDF 哈希匹配 |
| `python -m experiments.research.candidates.srgg.paper_forgery_input_mapping` | 三行格输入 JSON 正常生成，冻结 PDF 哈希匹配；未复现作者伪造位数 |
| 标准库 `fractions.Fraction` 逐个计算六个 β 的 `292β/1000`、`265β/1000` | Table 5 十二个位数全部匹配；β 来源未核 |
| `python -c` 读取 `paper_profiles.profiles` 并断言 Algorithm 2/7 的三档 tail／响应／挑战裸维数 | `(3072,4608,64)/(4608,6656,64)/(6144,8704,64)`；作者压缩字节不作断言 |
| `git diff --check`、提交前 `git diff --cached --check` | 通过 |

WSL 启动时报告过 Windows `E:\Service\DBus\bin` 路径翻译警告，但上述测试进程退出码均为 0。此批没有新的随机密码学实验，随机重复次数 0；新增伪造输入测试只用固定 14 字节身份和 13 字节消息。审计对象的代码入口分别限制身份 1–4096 字节、消息 0–65536 字节。经典理想 oracle 是显式条件模型，不是实际 SHAKE 或 QROM 的运行声明。既有 Table 4 参数保持 `n=512,p=16383,b=31,w=2,Q=15744063,d=2/3/4`，两种 Gaussian 解释未改，作者 C/ANS/1000 次基准未复现。代码功能测试不能替代正确性、困难性或安全归约证明。

本机定向复核环境：Intel Core Ultra 7 255HX、Windows build 26200；测试在 WSL2 Linux 6.18.33.2、指定 conda 环境的 Python 3.13.15 / Sage 10.9 执行。这不是论文作者的 C/gcc 8.3.0/Deepin 20.9 性能环境，不作速度对比。

依[原论文续审总览](../2026-10-18-srgg-independent-followup/README_zh-CN.md)，所有接受 Setup 根、随机发钥与故障历史属于另一类待核链，此批没有接手。Theorem 1 的 `q=Q` 门、`η`、`ζ` 因子、G0 fresh-message 与同消息 Q-shift 也已封存，不重复运行或改变判据。现在依然是 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`；不存在已核准的 NIST 等级或完整原论文安全映射。
