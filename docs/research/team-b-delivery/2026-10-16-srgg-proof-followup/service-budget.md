# 结构化固定发钥服务的条件预算对应

本项把冻结 `query-bounded-deep` 证书与 `ibme.ibs.srgg.structured` 的公共五方法、固定身份缓存和持久服务对应。工具 `experiments/research/candidates/srgg/service_budget.py` 仅读取公开 JSON/源码、检查证书之间的完整参数和已声明源码哈希，再做 `Fraction` 精确运算；不导入 Sage、随机源、采样器或私有状态，不生成根、密钥或签名。不修改冻结证书及算法。以下数值是带前提的算术上界，不能替代服务游戏的完整耦合证明或密码学困难性估计。

## 1. 固定研究点和来源

完整参数来自冻结 `2026-10-16-srgg-bridge/integrated-bridge.json` 的 deep 行，与 `structured-execution-n512-d2w8.json`、`2026-10-16-srgg-reduction/native-sig.json` 和 `2026-10-16-srgg-classical-rom/seeded-xof.json` 完全一致：

```text
n=512, d=2, p=16383, b=31, w=8, r²=64, L=16
Q=13972913866395903
s_master²=1031865954433
s_signature²=22159188660729268928705
Rcap=169060917974302720
Ucap=338122385570209792
Bsig=238255596480161099521436160
```

公开模拟器 U/z/E0/c 的费用读取 `2026-10-16-srgg-classical-rom/reduction-samplers.json`。`native-sig.json`、`seeded-xof.json` 还须绑定同一份 integrated JSON 的 SHA-256。工具核对所有输入收据已声明的源码哈希；另记录所选当前接口、服务、预算和归约文稿的哈希。所选文件哈希不是全 Python 运行环境的依赖闭包，也不认证外部库、硬件或未记录配置。

上述点已有研究运行证据；本次不重复运行。现有困难性对照不支持正式参数或 Kyber/ML-KEM、NIST 等级主张。这里不把参数规模、通过测试或 `<2^-128` 的某个误差分量当作整体128位安全。

## 2. 服务操作与收费次数

`N_K` 只数第一次实际发钥的不同身份，包含 Sign 内部首次发钥的服务模型；`q_S` 数整个会话的新签名请求，`N_S≤q_S L` 数所有范数重试。相同身份取已发缓存、恢复主状态、恢复用户密钥或重启后再取同一密钥，都不新增发钥采样。恢复后产生的新签名仍计入 `q_S`。失败身份和失败服务保持阻断，不把重试解释成新的独立成功机会。

对持久服务，这一对应以可信合作写者、互斥排序、原子保存/结束事务及无基础设施故障为条件。工程测试能检查若干运行路径；它们不自动给崩溃、断电、IO、恶意回滚或运行库故障分配概率，也不建立任意并发历史的完整分布耦合。

`Q_I` 数有效 H1 点的首次触及，包括没有发钥的公开查询、内部首用和最终 Verify；`M_H` 覆盖全部相关 H2 点，包含签名尝试和负向测试。重复解码同一身份、公钥种子或 H2 点，读取相同固定 XOF tape，不重复收 hash 失败概率。partial/offset 请求也属于同一点的首次触及规则，完整归约的 bounded overlay 合成另列。

| 场景 | N_K | q_S | L | N_S 上界 | Q_I 上界 | 额外 H2 点 | M_H 上界 |
|---|---:|---:|---:|---:|---:|---:|---:|
| 当前审计生命周期 | 2 | 3 | 16 | 48 | 4 | 6 | 54 |
| 两把固定钥匙、目标查询预算 | 2 | 2^40 | 16 | 2^44 | 2^40 | 2^40 | 17·2^40 |
| 2^40 个新身份的抽象算术行 | 2^40 | 2^40 | 16 | 2^44 | 2^40 | 2^40 | 17·2^40 |

第一行对应父进程两个新身份和两次签名，加子进程恢复后的第三次签名；错误身份验签增加两个 H1 点。两次错误身份、两次错误消息、两次随机伪造尝试最多增加六个 H2 点。诚实验签、对象恢复和缓存读取不增加独立 oracle 点。消息长度为32 B、65536 B及恢复消息的32 B，实际新身份长13 B、11 B；身份容量4096 B，消息容量65536 B。`q_F` 可保守取 `max(1,M_H)`，不能只数外部显式哈希请求。

后两行是预算假设，没有执行2^40次实验。第三行超过当前最多64个身份和2 MiB快照限制，不能用于声称一台当前服务支持2^40个用户；第二行也不代表已验证运行时长、磁盘寿命或2^40次签名的吞吐能力。

## 3. 有限采样、范数门与 abort

记 `a_M`、`a_G`、`a_P`、`a_u` 分别为 SampleF-master、有限 gadget 标量批、SampleF-sign 和 u 标量批到其各自理想完整 law 的 TV，上界均包含其算法采样 abort。冻结 `sampling_query_certificate` 的原式为：

```text
δfinite = min(1, N_K(a_M+a_G) + q_S L(a_P+a_u)).
```

这里 gadget 的目标仍是理想递推，尚未把递推的 fiber bias、卷积、HNF、范数门或安全游戏并进去。新工具的2^40个新身份行与冻结该函数的原 JSON 分数精确相等，未从后 HNF 的 TV 反推前 raw law。

`per_call_sampling_abort_upper` 另列 gadget/u、公有 U/z/E0/c 的原 abort 上界。SampleF 的完整 law 比较到非 abort 理想目标，因此在正确算术前提下，可以用它的完整 TV 保守控制算法 abort 原子；这不涵盖任意 MPFR/运行库故障。`finite_sampling_abort_union_only_excluding_norm_hash_and_infrastructure` 只累计这些采样 abort。**这些 abort 已在 TV 里，不再加一遍 TV。**

设 `δ_E` 为 integrated 收据的 `complete_issuance_to_common_hnf_gate_reference_tv_upper`，`t_R=2^-256` 为理想 union 的逐目标 raw 尾界，`δ_S` 为 `sign_attempt_finite_tv_upper`。当前确定性条件

```text
Ucap ≥ 2 Rcap + 2dn(p−1)²
||Y||² ≤ 2||U||² + 2dn(p−1)²
```

保证 raw 门通过后 repaired final 门也通过。因此 final 门的**额外**失败费用为0；raw 失败、整个发钥失败及坏成功密钥都不是0。按 [direct-ibs §2](../2026-10-16-srgg-classical-rom/direct-ibs.md) 的保守桥：

```text
δ_lat ≤ min(1, δ_E+t_R).
δ_common = min(1, N_K δ_E + N_S δ_S).
δ_latent_known = min(1, N_K δ_lat + N_S δ_S + β_matrix + Q_I β_H).
```

`δ_latent_known` 只填 `Delta0` 的已知算术部分，未赋值完整 `Delta0`。`δ_E` 已计实际 raw 门到仅共同 final 门参考的变化，再到 latent 双门参考还需额外 `t_R`，不能仅改字段名省去费用。

冻结条件算法 abort 界记为 `a_K`；理想签名范数拒绝 `η=2^-255`，实际单次范数拒绝可保守用 `r=δ_S+η`。在每个可达历史上统一成立、使用新鲜独立熵的条件下：

```text
a_sign ≤ min(1, L δ_S + r^L).
a_algorithm ≤ min(1, N_K a_K + q_S a_sign + β_matrix + Q_I β_H).
```

数值/熵失败立即传播，只有公开范数门按原算法重试。`r^L` 依赖逐历史统一界，不是从一次成功运行或实测失败率外推。完整服务 abort 尚有 IO、服务阻断和运行库，JSON 保持 `full_service_abort_upper=null`。第7节单独证明当前审计生命周期的额外全局 cap 不会触发，不把该结论移植给2^40次实验或任意其他调用计数。

## 4. 经典归约费用的已知部分

沿用 [direct-ibs 式(7)](../2026-10-16-srgg-classical-rom/direct-ibs.md)；以下是分子中的独立项目，不是总优势上界：

| 项目 | 保守费用和含义 |
|---|---|
| 诚实完整游戏→参考 | `Delta0_known=N_K δ_lat+N_S δ_S+β_matrix+Q_I β_H`；尚有未建模部分 |
| 目标跳过底层 raw 门 | `Delta_issue≤N_K t_R` |
| GoodKey 失败 | `Delta_bad≤N_K·2^-256`；按新 key 收一次，不按签名次数重复收 |
| 身份 alias | `Delta_alias≤Q_I(Q_I−1)/(2Q^(dn))` |
| image / 公共 Dom | `Q_I(ε_image+δ_U+δ_E0)`，其中 `ε_image=1/(2^256−1)` |
| H2 程序化碰撞 | `N_S M_H·2^-36351`，仅用理想 commitment 的统一熵界 |
| GoodKey 内 joint-TV | `N_S·4667/2^256`，不乘 `M_H` |
| 理想 Sign 首拒绝 | `N_S·2^-255` |
| 公开 Sim 的有限采样 | `N_S δ_z`；挑战 c 的有限实现精确均匀，费用0 |
| 非目标 known-key Sign 第二端 | `N_S δ_known`，本对应取 `δ_known=δ_S` |

有限公有 U/z/E0 的完整 law 含 bounded abort，分别来自冻结 `reduction-samplers.json` 的精确分数。public Dom 施加确定性 latent 门不放大其 TV。计入第一端诚实→理想 Sign 后，公开程序使用有限 known-key Sign 仍需理想→有限第二端；本工具明确保留，不能因为第一端已付就省略。按 `N_S` 累计公开 Sim 是保守收费，即使某具体实现每请求只用一次 Sim。

GoodKey 是分析事件 `||Y||²≤Ucap/4`，不新增运行时密钥筛选。`36351` 只适用于声明类中的理想 Gaussian commitment，未声称有限 commitment 也有相同 min-entropy。所有完整法则桥和两端费用需对同一可达历史、同一参数及同一固定服务语义有效；这里只组合既有数值前提。

## 5. Hash 与剩余 overlay

在理想 byte-XOF 模型中，`ρ=2193024705948421/72057594037927936`，每系数最多256轮，宽度7 B。精确联合上界可按因式表示再精确计算：

```text
β_matrix ≤ 2048·ρ^256 ≤ 2^-1278
β_H      ≤ 1024·ρ^256 ≤ 2^-1279.
```

byte budget 覆盖所有256轮路径；重复解析相同固定 tape 不是独立失败事件。此处已把 matrix 一次、每个首次 H1 点一次收费到 `Delta0_known`，不在 `Delta_overlay` 再重复加同一 decode 失败。

有限 conditional-prefix 生成器本身的 law/成本，以及它与公开 Dom、H2 owner、重绕和整个 adaptive reduction 的合成，需要对应独立实现与证明。就算已有某个局部 kernel，也不能把整项自动填0。本 JSON 对剩余 overlay、完整 adaptive composition 和完整提取器的 hardness overlay 保持 null。种子预查询的经典数值 `2^40/2^256=2^-216` 另列作为有前提的局部项，未加成“完整 overlay 已闭合”；不把 SHAKE 的真实字节当成已可编程的理想 oracle。

## 6. 当前数值与未闭合总量

以下为精确分数的最小 dyadic 上界 `≤2^e`。JSON 使用十六进制整数分子/分母，避免 `Q^(dn)` 巨大分母触发 Python 十进制位数限制；不改系统限制、不用浮点近似。

| 场景 | 有限采样 TV | 共同 final 门参考 TV | 条件算法 abort | 式(7)已知分子部分 |
|---|---:|---:|---:|---:|
| 2把钥匙、3次签名 | 2^-172 | 2^-172 | 2^-172 | 2^-170 |
| 2把固定钥匙、2^40次签名 | 2^-134 | 2^-134 | 2^-134 | 2^-132 |
| 2^40个新身份的抽象行 | 2^-134 | 2^-134 | 2^-134 | 2^-132 |

最后一列是已知数值项目的部分和。由于完整 `Delta0`、remaining overlay、真实 SHAKE→理想模型及困难性优势没有全部实例化，JSON 的 `direct_ibs_complete_numerator_error_upper`、`p0_or_IBS_advantage_bound`、`backend_admitted` 等没有据此升级；没有输出总 IBS 安全位数或 NIST 类别。QROM 相干访问、程序化与提取也不由这些经典预算覆盖。

## 7. 局部采样 cap 与审计的全局 cap

固定服务本身不加入 `CountingEntropy` 的进程级总 cap；审计脚本使用独立 `AuditEntropy` 包装，父进程512 MiB、子进程256 MiB，单次 read 请求仍不超过256 MiB，冻结算法及局部 sampler 的上限不变。预算工具用只读 AST 解析驱动的 `PARENT_ENTROPY_CAP` / `CHILD_ENTROPY_CAP` 整数常量，不导入或执行驱动。不可仅从每个局部 sampler 适配256 MiB推出整个审计的额外中止概率为0，还需以下完整计数。

| 项目 | 所有允许路径的字节上界 |
|---|---:|
| Setup 的原始请求 | 32,800 |
| 每个新身份：SampleF+gadget | 18,155,707 |
| 每个签名尝试：SampleF+u | 11,663,274 |
| 父进程两次随机伪造候选 | 22,528 |
| 父进程：Setup+2次发钥+2次签名各16轮+伪造候选 | 409,591,510 |
| 子进程：恢复缓存+1次签名最多16轮 | 186,612,384 |

父进程包络409,591,510 B低于536,870,912 B，子进程包络186,612,384 B低于268,435,456 B。因此在各局部 cap、无额外熵读取和上述计数对应成立时，两者的**额外**全局 cap abort 均有确定性上界0，无需实测失败率或额外尾界。测试也保留256 MiB父 cap的负对照：409,591,510 B超过旧总 cap时不能推出费用0，更不能由保守包络超限反推实际审计必然失败。局部 sampler 自身的已计 abort、IO、真实 OS/运行库异常均未因此消失。JSON继续将运行库/文件系统故障概率保留为null。

驱动因此只对n512设置 `extra_global_entropy_cap_abort_probability_certified=true`、`extra_global_entropy_cap_abort_upper=0`；较宽的 `extra_audit_abort_probability_certified` 仍为false，不把IO等其他审计中止一并认证。

## 8. 验证与复现

Windows Python 和指定 WSL Sage 均运行同一套精确算术检查；两次运行不算两组不同算法测试。测试覆盖冻结查询证书精确一致、第二端 Sign 没有漏费、每 key 的 GoodKey/raw 收费、巨大分母无浮点往返、完整父/子包络及旧 cap 负对照、未闭合项保持 null、参数/源码/法则错配拒绝、AST只读常量与动态/布尔/重复声明拒绝，以及禁止导入 Sage/随机模块和调用 `os.urandom` 的新进程执行。它们验证预算工具和证据绑定，不证明密码学游戏安全。

```text
python -m experiments.research.candidates.srgg.service_budget --output build/outputs/srgg-structured-service-2026-10-16/service-budget-final.json
python -m pytest -q tests/test_srgg_service_budget.py --junitxml=build/outputs/srgg-structured-service-2026-10-16/service-budget-windows-final.junit.xml
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_service_budget.py --junitxml=build/outputs/srgg-structured-service-2026-10-16/service-budget-sage-final.junit.xml
```

最终两端均 **45 passed**，没有 failed/error/skip。normal 与 `python -O` 分别生成同一冻结源码下的 JSON，逐字节相同；独立显式 `if ...: raise` 核输入/源码哈希、额外cap为0、取熵0和安全标志。早期驱动metadata调整前的原始 JSON 保留在 ignored 输出目录，不作为最终同源收据。

本项随机重复次数0，实际取熵0 B，没有重新选择成功根或密钥；实验身份/消息仅引用服务审计的计数，未读取私有 payload。生成 JSON 会记录本次 Python/platform、输入和所选源码哈希；Sage 不是此工具的执行依赖。安全口径保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。
