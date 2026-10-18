# SRGG：混合域代入原文定理的一页义务映射

日期：2026-10-16。**建议保留独立 SRGG 的 native strong 研究目标；混合域已消除一个真实分布障碍，但还不能调用原文安全结论。最小剩余主障碍是实际 key-generation law 的底层 SIG 强安全，以及允许目标身份签名的 IBS/QROM 归约。** 本项为只读、定向理论审查，不修改算法、参数、哈希或接口；`security_claim=none, backend_admitted=false, parameters_are_formal=false`。

来源边界：本地冻结 SRGG PDF（[DOI 10.1049/ise2/6684889](https://doi.org/10.1049/ise2/6684889)，SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`），本轮定向重读 p.4 Theorem 1/Definition 3、p.8–9 Theorem 2/模拟器；本地 GPV 全文 `papers/2008_gpv_trapdoors_full.pdf`（SHA-256 `7e747881cddd16b7dcf82893682cb9b4c788d7cec5712f80aa4193f2bd30a5b3`）§5.3.1/Theorem 5.9。本轮只沿用[已有来源审查](../2026-10-16-srgg-qualification/source-eligibility.md)对 KLS2018 Theorem 3.3 的定向核验；未取得完整 G+G 证明或重证 KLS/Zhandry。

| 来源义务 | 混合域后的精确位置 | 当前结论与最小后续 |
|---|---|---|
| GPV PSF：固定域、forward、近均匀像、条件 preimage | `D_mix=C_Q(U+JE)`, `f_A(Y)=AY mod Q`，µ 和公开 Σ 不依赖目标/陷门 | **条件分布恒等式已证**，包含 aliases；kernel smoothing 给近均匀像和每像概率下界。有限 sampler/去分母误差另加；见 [mixed-domain.md](mixed-domain.md)。这部分不需新困难假设 |
| GPV PSF：可有效识别的短域及统计松弛 | 不能把未限范数的混合 Gaussian 全支持当安全域 | 若域不限制范数，首块 I 使 `(center_Q(h),0)` 成为公开逆像，one-wayness 不成立。必须明确短域 D，并核全局域外率、每目标范数失败及成功条件化。GPV 明确允许统计松弛，但不能省略它们的概率 |
| GPV collision-resistant PSF：每像条件熵 | 原来的“wrap耦合再除以很小像概率”可换成直接 aliases 求和 | **一般充分界可由当前数学完成。** 对 isotropic Σ=sI、N 偶数，`max_y D_mix(y)<= (1+sqrt(s)/Q)^H/s^(N/2)`；由 coset ε 得条件 atom `<=min(1,(Q+ceil_sqrt(s))^H/s^(N/2)*(1+ε)/(1−ε))`。norm 成功条件化还须除每目标成功下界。熵不证明 one-way/碰撞困难；完整 PSF 名义还需这些性质，SRGG 模拟中实际使用哪些性质应逐项标出 |
| 原文 Theorem 1：真正底层 SIG 的 key-generation、分布及模数条件 | 需要证明的是 `(pk,sk)=((a,f_A(Y)),Y)` 且 `Y~D_mix` 对应的 SIG | 原文 Theorem 1 只声明 **EUF-CMA**，并要求奇 q、`q>2γ` 等；它未给“任意混合 Gaussian secret 都适用”的定理。ζ factor2、离散响应联合 law、真实 public-A 分布仍须对应；不能把纯 Gaussian 的已有安全定理直接继承给 mixed law。允许重新推导或作已核验的分布变换；否则必须明确额外假设 |
| KLS2018 Theorem 3.3：底层 native sEUF | no-abort HVZK、commitment min-entropy、UF-NMA、CUR 以及有限尝试/采样误差 | 精确 ζ、Gaussian smoothing、范数/熵预算可以继续数学闭合；**响应范数尾界不等于 HVZK 联合模拟**。CUR pair 差分到真实 Abar 的短核关系已知，但实际矩阵分布到所估计 MSIS/MLWE 的归约及 UF-NMA 仍须补证。源 Table 4 有公开 CUR 对；当前 `Q>2γ` 仅排除已知 Qe pair，不能删除 CUR 项 |
| 原文 Theorem 2：完整 IBS strong 游戏与签名模拟 | G0 排除任何已签 `(id*,µ*,.)`；p.9 模拟器对 X 中身份的 signing query 直接 abort | **独立的新/修正归约义务。** strong 应允许旧消息的新签名；连 ordinary EUF 也允许目标身份先签其它消息。若该目标在 X，现写模拟器会中止，不能仅改 G0 一行便引用其成功界。需真实 SIG signing-oracle 转发、适当游戏界及最终新鲜性证明 |
| 原文 Theorem 2：分区身份、QROM、固定发钥和多查询 | 多个 X 身份被半常数 oracle 映到同一 SIG pk；当前 `hashing.py` 明确 Hbar 不含身份 | 转发不能自动保留底层“未返回过该消息/签名”的条件；须处理跨身份查询和输出，不能假设身份已进入 challenge。固定服务应复用同一 SampleDom tape/key。近均匀单像 TV 和经典 oracle 账本不自动给 QROM reprogramming 损失；需核 [33] 量子归约及失败模型。未经协调不改哈希来掩盖这一义务 |

上述 entropy 的 aliases 界无需 wrap 假设：对每个 head 坐标和固定 e，单峰 Gaussian 的格点和不超过 `peak+integral/Q=1+sqrt(s)/Q`；其余坐标权重至多 1，E 的平均不增上界；Poisson 零项给 `rho_(sI)(Z^N)>=s^(N/2)`。若 `ε<=1/3,L=floor(log2 s),B=ceil(log2(Q+ceil_sqrt(s)))`，则条件 atom 至多 `min(1,2^(BH−LN/2+1))`。这是显式条件下的数学界，不是现有参数熵、安全等级或 source SIG 对应的自动证书。

推荐推进顺序：先将 mixed law、短域/每目标 norm 与 aliases 熵接进现有全局采样账本；随后明确该 key-generation 下的 HVZK/commitment entropy 及 CUR/UF-NMA 归约；并行重写 Theorem 2 中目标身份签名与 strong 新鲜性部分。后两项需要**原文未提供的适用性证明或新归约**，不能用更多功能测试、直接扩大参数或假设另一 HIBE 来代替。若必须额外假设，应显式列名和适用分布，而不称原文已证明。保留 native strong 目标及所有负控，不在本项自行改成编译层或降级目标。

审查不运行密码学实例，无新消息/身份采样或攻击成功率实验；仅定向文本核验、现有代码读取和上面的一般推导。没有新安全定理、正式参数或 NIST 等级声明。
