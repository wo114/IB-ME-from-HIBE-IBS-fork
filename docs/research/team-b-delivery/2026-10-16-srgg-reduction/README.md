# SRGG 原生 strong 安全归约：本批条件证明与证据

2026-10-16。用户已明确选择继续 SRGG 的安全归约，保留 **native strong** 目标。本批把原文的目标身份签名缺口、混合密钥下的交互签名分布、经典签名模拟和 strong 提取分成可审查的证明义务；给出条件引理、反例和精确成本工具。**实际 SRGG 的完整安全归约、QROM 和正式安全准入仍未完成。** 六项联合目标保持 active/WIP。

算法、哈希、参数、采样器和上一批真实 n512 收据均未更改；不采用编译层替换原生 strong，不修改已冻结的 [bridge 交付](../2026-10-16-srgg-bridge/README.md)。本批的证明是文稿推导及独立审查，不是机器形式化证明；有限代数与概率测试是辅助证据。

## 这批具体解决了什么

| 问题 | 本批可审查结论 | 入口与适用边界 |
|---|---|---|
| 原文目标身份 Sign 直接中止 | 允许转发目标签名；给完整 strong 游戏、跨身份重放反例和条件经典 single-index 转移；半常数分区不能直接对编程后的自适应 transcript 因子化 | [target-signing.md](target-signing.md)：完美分布、经典 H1 等前提显式列出，未证明量子版本 |
| 混合/HNF 密钥是否破坏签名模拟 | 对任何满足关系和范数条件的固定 y 完成平方；ζ 像格 all-center 平滑给完整 `(W,c,z)` 交互 law 的 TV；不要求 y 为纯 Gaussian | [native-sig.md](native-sig.md)：独立交互挑战，不能直接当 FS 定理 |
| 最坏 key bound 太松 | 分析 `GoodKey: ||y||²<=Ucap/4`，坏事件按首次发钥计；运行时不筛根、不筛密钥、不重发 | [native-sig.json](native-sig.json)：真实发钥 TV 与理想 tail 分别计入 |
| 承诺熵缺失 | full-cap 理想 P1 承诺最小熵下界 **36351 位**，用条件 head Gaussian 的 Schur 补及 Q 格陪集 atom 界 | [native-sig.md §6](native-sig.md#6-承诺-min-entropy-的条件充分界)：不是实际有限 sampler 的同等熵声明，也不是密钥熵或安全等级 |
| 不同挑战 fork 可能给零差分 | `eta(c)=c_low XOR c_high` 只有 `n/2` 位；给明确零差分反例，证明不同 eta 才保证非零 | [strong-games.md](strong-games.md)、[strong-structure.json](strong-structure.json)：n2/4/8 穷举及 n512 反例，未跑大参数搜索攻击 |
| 旧消息的新签名如何提取 | 已返回签名的同一哈希 entry 走 CUR；free entry 走可重放经典 fork；未查询 entry 付完整 n 位猜测项。失败编程点不能冒充已返回签名 | [strong-games.md §5.2/8.1](strong-games.md)：无覆盖编程、完整记录、全局 bad/abort 等条件必要 |
| 如何把这些分布用于 FS | 给逐历史碰撞、交互 law、norm 与失败的经典模拟论证，并分析隐藏目标猜测与误差累计的次序 | [classical-fs.md](classical-fs.md)：实际 IBS/矩阵分布及量子组合的条件另列 |
| 归约成本是否能忽略 | 精确计算 owner/fork 成功率下界与理想承诺碰撞账本；区分 fixed-key SIG 优势与 IBS 优势 | [classical-cost.json](classical-cost.json)：输入优势和完整模拟距离均是假设，未填入实际困难性 |

## 当前数字应怎样理解

沿用上一批固定研究点：`n=512,d=2,p=16383,b=31,w=8,r²=64,Q=13972913866395903,L=16`；公开目标 `signature_squared=22159188660729268928705`，`user_norm_cap=338122385570209792`。参数来源是已有研究筛选和谱/采样算术，**不是正式安全参数**。deep 数值选项、所有 shape/范数门及原始大维执行见冻结 bridge。

全允许密钥类的交互 HVZK 充分界约 `2^-135.0355`，按 `2^40` 次签名、最多16次尝试累计约 `2^-91.0355`，这个充分界不够。GoodKey 分析给每次交互 TV `<=4667/2^256`；理想坏 key 每次 `<=2^-256`。加入已有最终整数/发钥/范数项后，`qE=qS=2^40` 的**条件统计账本**约 `2^-134.3759`。这些查询数是上界输入，没有实跑 `2^40` 次服务。

完整 FS、身份像均匀性、服务失败和困难性归约不能被上述算术自动替代。尤其 `qE` 必须计入所有相关的首次发钥，H1-only 查询造成的像分布替换也须在完整 IBS 归约单独计入。代码中 `FS_or_QROM_simulation_proved=false` 与 `total_distance_is_a_composition_hypothesis=true` 均保留。

另已核有限 H1/XOF 层：当前7字节余数拒绝的单次失败率为 `rho=(2^56-5Q)/2^56<1/32`；每系数最多256次尝试给单次 H1 失败 `<2^-1270`，一次根矩阵展开 `<2^-1269`，read budget 足够。成功余数精确均匀，失败仍须按查询数纳入完整归约。这是理想 XOF 模型内的源码/算术结论，不能解决公开 seed 的困难性嵌入。

例如，仅**假设** fixed-key SIG 攻击优势为 `2^-128`、完整模拟距离由上面统计项加碰撞项控制，且所有 free H2 entry 不超过 `2^40`，成本工具给公平 owner 求解器的短核成功率保守下界约 `2^-299.035`。这是条件提取概率下界，不是攻击优势上界或“299位安全”；若要据它证安全，必须有与该概率、运行时间和矩阵分布匹配的困难性结果。IBS 的身份猜测损失尚须另外施加，不能把这里的 epsilon 当成原 IBS 优势。

同一算术例子的理想承诺碰撞项小于 `2^-423`；工具只用了已证36351位中的512位来控制有理数长度。有限采样 TV 先在整场 hybrid 支付，不再乘哈希表大小。`n/2=256` 仅是有效挑战商的位数，不授予 NIST 等级。经典重放证明也不能代替 QROM 重绕或改编定理。

## 验证、来源与复现

最终指定 WSL Sage 10.9 / Python 3.13.15 回归 **704 passed、0 failed/errors/skipped**；Windows Python 3.14.7 新增三个文件合计 **62 passed**。独立审查另跑 native 28项、strong structure 14项、classical cost 20项；这些集合与回归重叠，不相加为独立实验次数。精确命令、环境、JUnit 和公开转换记录见 [validation.json](validation.json)。

新增检查包括 n2/4/8 全部二元挑战的商类、独立 schoolbook 环运算、全 bottom 范数门、非独立 head/tail 的 Schur 补、接受筛选反例，以及含编程的可重放小预言机。后者明确要求 fork 下界严格为正，另验统一 owner 界的正值、重复查询、owner 不可更改、碰撞及 norm 失败。独立审查发现早期模型下界恒零，已修成这些非平凡情形；最终版本的检查通过。

本批没有生成新的主密钥、用户密钥、签名或身份/消息；没有重跑 n512 生命周期或估计正式困难性。小模型使用公开精确有理数穷举，实际取熵为0；不把它称为密码攻击实验。硬件为 Intel Core Ultra 7 255HX，WSL2可见20逻辑CPU，未固定亲和性/频率。旧生命周期的37B身份、32B消息和单次系统熵结果仅在冻结 bridge 中引用。

主要来源是冻结 SRGG 论文 *Constructing Efficient Identity-Based Signatures on Lattices*，[DOI 10.1049/ise2/6684889](https://doi.org/10.1049/ise2/6684889)，SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。本批定向核 p.4、p.8–9 及相应算法/游戏。KLS 正式开放版定向阅读定义、Theorem3.3 和 §4.5；完整证明被转引至 full version，本批没有声称读完或重证。各文稿列具体来源和阅读范围。原文事实、项目条件推导、有限实验和未证假设分别列出。

只读核对，不运行随机采样：

```text
python experiments/research/srgg_reduction_delivery_check.py
python -O experiments/research/srgg_reduction_delivery_check.py
```

必要时向新输出目录复现，避免覆盖原始收据：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_*.py tests/test_primitive_spec_audit.py --junitxml=build/outputs/srgg-reduction-recheck/sage.junit.xml
python -m experiments.research.candidates.srgg.native_sig --output build/outputs/srgg-reduction-recheck/native-sig.json
python -m experiments.research.candidates.srgg.strong_structure --output build/outputs/srgg-reduction-recheck/strong-structure.json
python -m experiments.research.candidates.srgg.classical_cost --output build/outputs/srgg-reduction-recheck/classical-cost.json
```

清单见 [MANIFEST.json](MANIFEST.json)；原始收据留在 `build/outputs/srgg-reduction-2026-10-16/`。公开 JSON 按字节复制，JUnit仅删除hostname并序列化为LF，转换均登记。冻结 bridge 清单也由新检查器只读重核。所有本批修改形成独立 Git 提交并更新现有 PR37，不合并上游或覆盖主目录其它工作。

## 下一阶段的实质义务

1. 把公开 seed/XOF 的真实矩阵分布合法嵌入困难性归约。保留 seed 却独立换成均匀 Ahat 可被公开重算立即区分；普通 PRG 口号不能修复它。条件 uniform-Ahat 的 Module-LWE 逐列 hybrid/HNF-MSIS 结果不能直接冒充实际 seeded 后端。
2. 完成真实完整 IBS 游戏的身份像替换、固定发钥、失败、侧信息和经典模拟的总拼接，给运行时间及精确损失。条件分布恒等式不自动证明这个完整归约。
3. 分别闭合 H1 的量子身份嵌入和 H2 的 QROM FS/native-strong 转移，不能把经典 lazy-query/fork 搬到叠加查询；不得默认 KLS 已覆盖所有本实现条件。
4. 在确切困难假设、复合模数、矩阵维度、分布、范数及归约损失固定后做正式估计，才能讨论教师要求的 Kyber/ML-KEM、NIST 对标。新大维 namespace 的公共五方法/严格对象/持久服务仍未完成。

```text
security_claim=none
backend_admitted=false
parameters_are_formal=false
nist_security_category=null
```

功能测试、有限负控、Gaussian 分布界、经典条件证明和正式安全归约各自承担其证据范围，不互相替代。
