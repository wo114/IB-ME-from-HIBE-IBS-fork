# SRGG：保留 raw 门与失败的公开身份—密钥 pair

2026-10-16。本文补全直接 IBS 归约所需的参考分布，不能把它读成已实现公开发钥器或完整安全证明。沿用已冻结的 [mixed-domain 恒等式](../2026-10-16-srgg-bridge/mixed-domain.md) 与 [integrated bridge](../2026-10-16-srgg-bridge/integrated-bridge.md)；不修改运行算法、参数或旧收据。后者已经明确支付移除 raw 门的 tail，本批没有将该旧结论判错。

## 1. 先固定潜变量，再定义 pair

在系数空间取 `A=[I_H,A_tail] mod Q`，`J` 嵌入前 H 个坐标，`C_Q` 仅中心化 head，`1<=p<=Q`。固定公开、与 A 的陷门及目标无关的 raw law μ。取

```text
U ~ μ, E uniform {0,...,p−1}^H independently;
Y = C_Q(U+JE), h=AY=AU+E mod Q;
K = Y if ||U||²<=R and ||Y||²<=Buser, otherwise bottom;
P_A = law(h,K).
```

这是一次全局采样，h 先确定；失败输出 `(h,bottom)`，不能丢掉 h、重抽同身份、条件于成功或把失败 pair 变成另一个身份。实际执行只需保存 K 或失败状态，不需永久保存潜变量 U/E；**分析时**在两个门处理完之前不能消去 U。

这里的理想公开采样器取 μ 的 Gaussian law，尚须给有效有限算法及其距离/运行成本。`public_pairs.py` 只是有限有理概率模型；不把它作为实际 Gaussian 实现。μ 可以独立于 A，但 forward h 使用当前 A，因而 P_A 一般依赖 A；Module-LWE hybrid 必须继续实际计算该 forward。

## 2. 条件 law 连同 bottom 恰好匹配

对给定 h，令

```text
e_h(u) = (h−Au) mod Q，取非负规范代表；
S_h = {u : e_h(u) in {0,...,p−1}^H};
alpha_h = Pr_P[h] = μ(S_h)/p^H.
```

每个 u 的可用 E 至多一个，故在 `alpha_h>0` 时

```text
law(U,E | h) = law(U~μ|S_h, E=e_h(U)).
```

对这个等式应用同一确定映射：先检查 U 门，作 `Y=C_Q(U+JE)`，再检查 Y 门；失败保留 bottom。于是

```text
law_P[K | h] = law(conditional raw issuer output, including bottom) =: K_h.
```

head aliases 的质量由推前相加。这个恒等式不要求修复单射，也不要求 norm gate 是 Y 的函数。Gaussian μ 全支持时每个 fiber 的质量为正；有限模型缺失 fiber 会显式拒绝定义 K_h，不补造一个条件分布。

定义诚实均匀目标参考 `R_A(h,k)=Q^(−H) K_h(k)`。因两边相同 h 使用同一规范概率核，且 h **保留在输出中**，得到精确等式

```text
TV(P_A,R_A)
 = (1/2) sum_h sum_k |alpha_h−Q^(−H)| K_h(k)
 = TV(law_P[h], Uniform).
```

即使全部 key 都 bottom，该等式仍成立。若把所有失败压成一个不带 h 的 bottom，TV 可能严格变小，不能再用这个缩小的数估计已公开 H1 值的完整 transcript。像近均匀性来自已验证的 kernel-coset smoothing，不来自 norm gate 或有限模型。

## 3. 为什么不能只给 D_mix 的 Y 加一个门

确切反例取 `Q=3,p=1,H=N=1,A=1`，raw law 为 `U=0` 和 `U=3` 各半。两者都修复为 `Y=0,h=0`。raw/user 范数平方门均为 0 时，真实结果一半 key0、一半 bottom。任何只依赖 Y 的确定门都要么接受两者，要么拒绝两者，与真实 law 的 TV 均为 1/2。

源码 `structured_execution.Execution.key_extract` 先检查 raw 范数，再由 tail 重构规范 full key 并检查 user 范数，正是这个先后顺序。此前 integrated bridge **已经**用 raw tail 支付移除前一个门的距离；本批的潜变量参考提供另一种保留两个门的写法。

令 `t_R` 是每个目标条件下 `Pr_{μ|S_h}[||U||²>R]` 的统一上界；构造参数要求 `Buser>=2R+2H(p−1)²`。因为

```text
||Y||² <= 2||U||²+2H(p−1)²,
```

raw 门通过即 user 门通过，所以本潜变量参考每身份首次发钥失败至多 t_R。旧公开 Y 门参考与本参考的 TV 也至多 t_R。若仅使用旧公开证书的 `δE`，保守三角界为

```text
TV(actual issuer, latent-gated reference) <= δE+t_R.
```

不能把旧 δE 不加说明直接移用。若从已证明的 raw union bridge 出发，再对两门作共同映射，可避免为移除/恢复 raw 门重复付账；这是另一个源级组合选择，不能从两个保守上界相减而得到更紧证书。本批不重写旧数字。

## 4. 固定状态、目标失败与 hash bytes

公开非目标 pair 可以在身份首次分配时预采，缓存成功 key 或失败。重复 Extract/Sign 必须复用该状态；若失败后再采，分布已变化。反例中两个请求的正确缓存 law 只有 `(key0,key0)` 与 `(bottom,bottom)`，重新独立采样则另有两种混合结果，TV=1/2。

目标 h 由外部均匀挑战给出，模拟器没有目标 U，通常不能决定真实 raw 门是否失败。故目标首次 IssueOnce 失败是另外的分析坏事件，每身份一次付 t_R 或完整适用 bound；不能因为目标不被 Extract 就忽略内部 Sign 所需的首次发钥。GoodKey 的“坏的成功 key”tail 不含 bottom，二者分开。具体隐藏目标耦合和成功概率见 [direct-ibs.md](direct-ibs.md)。

若攻击者可访问原始 XOF 字节，不能先返回身份点的一段 bytes，之后才按公开 pair 的 h 改哈希。须在该规范点第一次被触及时分配身份、固定 pair 及与 h 一致的完整拒绝采样 prefix，保留 suffix/cache 一致性；或者明确使用只暴露复合 H1 的较弱接口。对应的条件 prefix law 与失败见 [seeded-xof.md](seeded-xof.md)。

原始 XOF 层看到的是 h 的条件 byte law，不应看到私有 U/E。在相同 h 上，两边都从同一条件 byte law 取样，因此它是同一 Markov kernel，TV 仍不超过像距离；不能把与 h 不一致的真实 uniform prefix 和另抽的 pair 拼起来。

## 5. 本批实现和验证范围

新增纯 Python 工具 `experiments/research/candidates/srgg/public_pairs.py`；复用已冻结的 `mixed_domain.py` 的严格输入/布局检查。有限状态最多4096，向量最多64坐标，不收浮点概率或未归一化 law。对每个目标，独立 raw-union 路径和全局 latent-pair 路径核验条件 key/bottom law、`μ(S_h)=p^H alpha_h`，并核对 pair-TV 的精确等式。

测试包含 Q2/3/4/5、p1/pQ、奇偶中心化、两维 head、aliases、全失败、真正非均匀像、丢 h 的反例、固定失败与重抽差别、零 fiber 和资源边界；输入均为公开合成有理 law，不使用真实身份、消息、Gaussian 或随机采样。新增21项测试在 Windows Python3.14.7通过；最终联测与环境以本目录 validation/JUnit 为准。

```text
python -m pytest -q tests/test_srgg_public_pairs.py
python -m experiments.research.candidates.srgg.public_pairs --output build/outputs/srgg-classical-rom-recheck/public-pairs.json
```

确定性例子只核有限概率实现，本文一般恒等式来自条件化和数据处理证明。实际效率、完整服务状态、所有 oracle 预算、Module-LWE/HNF-MSIS 分布归约及 QROM 分别另核。保持 `security_claim=none, backend_admitted=false, parameters_are_formal=false, nist_security_category=null`。
