# SRGG Theorem 2 抽象 SIG 接口与实际验签的对应（WIP）

范围为独立 IBS 的**原文接口解释与代码对应**。来源是冻结 `papers/2025_efficient_ibs_jia.pdf`（SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152），PDF p.8 的 Algorithm 7–8、Theorem 2 与页底 PSF/SIG 改写，p.9 的 oracle 模拟器。已封存的 [模数、平滑宽度与游戏审计](../2026-10-18-srgg-source-symbol-mapping/proof.md)、[经典目标签名条件归约](../2026-10-16-srgg-reduction/target-signing.md)和[哈希地址审计](../2026-10-18-srgg-hash-address-mapping/proof.md)不在这里重证。

## p.8 抽象接口的类型缺口

论文在 Theorem 2 前把底层 `SIG.Gen` 的验证公钥写为 `(a,f_a(sk))`，并令 IBS 的 `mpk=a`、身份目标 `H(id)`。因此若把 IBS 直接解释为该 SIG 的身份派生实例，一个类型正确的底层验签调用至少要知道 `a`、`H(id)`、消息 `μ` 和签名。p.8 末尾的抽象 `IBS.Vrfy` 条目却把 SIG 验签输入写成 `(id,μ,sig)`，其中原始 `id` 是字节串而非上文的 `(a,f_a(sk))` 型验证公钥；该条目的左侧参数又未列出 `μ`。按页面**字面**读，两个调用类型均不闭合。

这可能是省略或排版笔误，不是已发现的算法攻击。若作“底层公钥是 `(a,H(id))`”的**候选修复解释**，仍需证明实现的近似 `SamplePre` 关系、底层 SIG 验签关系及公钥分布满足该解释；不能默默把候选修复当作原文已证明的定理。论文同页 Algorithm 8 的具体版本明确接收 `(mpk,id,μ,sig)`，使用身份目标和消息挑战，因而是本次源码映射的直接算法依据。

**G2 的另一处字面类型缺口。** 论文 p.8 页底把 `SIG.Gen` 的公钥写为一对 `(a,f_a(sk))`，p.8 的 Game G2 却令被编程身份的 `H(x)=pk`，p.9 再写 `H(id*)=pk`；Table 3（p.6）把 `H` 的输出声明为单个 `R_Q^d` 向量。若 `pk` 仍指整对，赋值按字面不属于 `H` 的值域。可供后续证明尝试的**候选解释**是固定同一个公开 `a`，只把挑战公钥的像分量 `h*=f_a(sk)` 编程进 `H`；这不是论文已写出的类型正确游戏，更不自动解决多身份共用 `h*`、目标 Sign 转发或 QROM 模拟。

## 固定公钥下可提取的候选 SIG 计算

固定一份在 H1/H2 查询前确定的规范公钥 `P`。把其完整公开描述符当作候选底层参数 `a=P`，令 `f_P(y)=A(P)y mod Q`，其中 `A(P)=[I_d|Â|B]`，并记 `h=H1_P(id)`。`paper_objects.SigningKey.full` 和 `structured_execution.reconstruct` 使实际发出的完整用户向量 `y` 满足 `f_P(y)=h`。这只核**关系**；`y` 的条件分布、接受 Setup 根与论文 PSF/SIG key generation 的联合 law 不由关系推出，且属于另行核验的分布链。

对同一未篡改后端配置及相关缓存状态（尤其 `series_options`、`scalar_options`、`sign_max_attempts`）、同一初始随机带与 oracle 状态，固定 `P,y,h,μ` 后，`paper_backend.sign` 的 `PaperSampleF` 计划由 `y` 构造，后续承诺、`H̄_P` 挑战、中心采样、响应、范数重试及末次自检只经这些固定项与 `P,y,h,μ`；`key.identity` 在此处只用于重新计算 `h`。若把遥测计数也计入完整路径，其初值也须固定。因而成功、重试或中止的路径可以**计算上**写成候选 `SIG.Sign(P,y,h,μ)`。`paper_backend.verify` 则只经 `P,h,μ,z,c` 检查 context、形状、二元挑战、范数，计算 `w=M_hz−Qjc mod 2Q`（`M_h=[2A(P)|Qj−2h]`），再检验 `c=H̄_P(w,μ)`。于是可提取候选 `SIG.Vrfy((P,h),μ,(z,c))`；同一固定 `P` 下若两个身份有同一个 `h`，对相同规范签名的验签结果相同。这是算法因子化，不是已有独立 SIG 后端、底层 sEUF 定理或原文归约的成立声明。

实际 `H̄_P` 的有效地址为长度分帧的 `(DOMAIN,"message",P.to_bytes(),canonical(w),μ)`。对固定 `P`，规范承诺 `w` 与字节消息 `μ` 到该地址是单射；若**额外假设**一个经典、独立的理想 oracle，可把这些地址连同重试中的自适应查询一致地重命名为论文的 `H̄(w,μ)`。实际 SHAKE-256 并不因此等于理想 oracle；论文的量子查询、底层 SIG 实验共享同一 `H̄` 状态及跨公钥全局地址也不由此闭合。[H1/H2 地址核验](../2026-10-18-srgg-hash-address-mapping/proof.md)另列有限 H1 拒绝耦合与多公钥差异。

对于固定 `P`，实现 `Signature` 把论文 `(z,c)` 附上固定 `SHA256(P.to_bytes())` context，并以规范 JSON 字节编码；解码拒绝重复字段及非规范重编码，`IBSSignature.__eq__` 按规范字节比较。因此在**可接受对象域**上，`(z,c)` 到实际签名字节是单射，给 [经典目标签名条件归约](../2026-10-16-srgg-reduction/target-signing.md)所需的精确 strong 新鲜性一个代码级包装映射。它不能补足实际底层 SIG 的 strong 安全；已记录的同消息 Q-shift 有效替换仍需正面处理。

## 具体 Algorithm 8 与代码

| 论文 Algorithm 8 p.8 | 实现位置 | 对应边界 |
|---|---|---|
| 用 `H(id)` 形成末列 `Qj−2H(id)`，构造模 `2Q` 的验签矩阵。 | `paper_backend.py:208` 调 `identity_target`；`structured_execution.py:245–250` 的 `signing_matrix`。 | 同一公钥、规范身份和原表 `Q` 上的代数对应；H1 的真实 SHAKE 到 RO 距离仍未知。 |
| 从 `(z,c)` 恢复 `w=Āz−Qcj mod 2Q`。 | `structured_execution.py:262–269` 的 `recover`。 | 仅核代数计算；范数、wire 和固定服务仍须按各自层验收。 |
| 检验 `c=H̄(w,μ)` 及 `||z||≤γ`。 | `paper_backend.py:201–210`；`paper_algebra.py:43–49`。 | H2 代码地址附带规范完整公钥 `P`，论文抽象地址只写 `(w,μ)`；固定单公钥可作经典理想 oracle 地址重命名，跨公钥联合游戏另核。 |

这里不声称底层 SIG 的 `SIG.Vrfy` 已作为独立对象实现，也不声称 IBS 调用与论文抽象 SIG 游戏在分布上相同。特别是原文 p.8 的 Theorem 2 给定底层 **sEUF-CMA** 前提，p.8 的 G0 却采用新 `(id,μ)` 对条件；实际五次同消息替换及原 Theorem 1 `q>2γ` 不满足的证据已有以上冻结审计。本页只闭合固定单公钥的**计算与编码对应**，并记录抽象接口和 G2 的字面类型缺口。

## 两个 oracle 的游戏接线义务

Table 3 定义身份哈希 `H` 与签名挑战哈希 `H̄`。Theorem 2 的 G0 文字明示量子查询身份随机 oracle `H`，而 p.9 模拟器列出 `O1/O2` 以构造半常数 `H`；这几段没有逐项规定 `H̄` 的查询能力、它与底层 SIG 安全实验共享的 oracle 状态，以及目标身份签名转发时怎样保持同一 `H̄` 回答。底层 SIG 定理也许承担部分挑战 oracle 工作，但要套用到**这份实现**，仍须给出同一公钥下 `H̄_P(w,μ)` 与底层实验 oracle 的明确接口和查询预算；在 QROM 下还须相干模拟。H2 本身直接取 512 位，不存在模 `Q` 拒绝中止；若把有限服务中止纳入同一实验，应另列服务失败耦合。这是缺少可核映射的义务，**不等于宣称不存在可修复证明**。

**[33] 的实际适用对象与查询数。** Jia 所引 [33] 是 [Zhandry 2012 ePrint 2012/076](https://eprint.iacr.org/2012/076)，不是后来的博士论文版本。[33] §4 的 Corollary 4.3 给一张半常数 `SC_λ` 随机 oracle 表：仅有至多 `q` 次量子 oracle 查询时，输出分布与均匀表的距离至多 `(8/3)q⁴λ²`。§5.1 的 IBE Theorem 5.1 明确把对手直接查 `H` 的 `q_H` 次、Extract 内部的 `q_E` 次，以及挑战加密内部的 1 次并成 `q_H+q_E+1`，而不是只数对手界面上的 `q_H`。其 Game 1 排除所有已 Extract 身份，给 `λ(1−λq_E)`；Game 2 的成功判断又依赖秘密植入集合 `X`，所以作者另列 **Claim 1** 的 `ℓ(q_H,q_E)λ²` 界，说明仅用 Corollary 4.3 比较输出边缘分布不足，完整论证置于 Appendix D。这些文字从 [33] PDF 的搜索索引正文逐段核得；本次直接读取该 PDF 返回 403，**Appendix D 全证明未核**。作者的 [博士论文 §4.2](https://mzhandry.github.io/files/Thesis.pdf#page=50) 是另一版本，其中 Corollary 4.8 的常数不能代替 [33] Corollary 4.3；博士论文 §5.4 又采用 small-range hybrid，不是这里可直接替换的同一 Claim 1。

**Jia 的三变量界是待证扩展。** Jia p.8 写 `ℓ(q_H,q_S,q_E)`，p.9 改为 `ℓ(q_H,4q_S,q_E)`；[33] 上述 IBE Claim 1 只有 `q_H,q_E`，没有 Sign oracle 或 `4q_S` 的直接结论。Jia p.8 的 Game G1 文字同样排除所有已 Extract 身份，却在概率式写 `δ(1−δq_S)`；与 [33] 对应的 `λ(1−λq_E)` 也不一致。这里仅标出**原文字面缺口**，不擅自替作者换下标或填写新常数。要把 Claim 1 用于 SRGG，须计入 Extract、Sign、内部验证以及最终验签的 `H1` 查询，说明重复查询与量子查询如何计数，证明联合 Sign/Extract 回答及依赖 `X` 的成功谓词仍可由同一 oracle 实验模拟；还须说明 `H2` 与底层 SIG 实验如何接线。`4q_S` 的来由不能仅由 [33] 推定。

**实现 H1 调用账本。** 以下只数现有成功代码路径上的 `identity_target` 方法调用，不把调用数直接当作 [33] 模拟器的量子 oracle 查询数；固定同一 `P,id` 时重复调用落在同一地址。

| 路径 | paper 后端 | structured 后端 | 代码定位与边界 |
|---|---:|---:|---|
| 首次成功 Extract | 2 | 3 | `paper_backend.py:158,163`：显式求目标一次，`paper_objects.SigningKey.__post_init__` 行 110–111 重算一次；`structured_execution.py:519` 与 `Key.__post_init__` 行 330 各一次，`structured_backend.SigningKey.__post_init__` 行 138–141 再构造一个 `raw.Key`，故多一次。两种封装的 issued 缓存命中为 0；早期拒绝也可能为 0。 |
| 成功 Sign | 2 | 2 | `paper_backend.py:178,191,208`、`structured_execution.py:536,552,567`：循环前求目标一次，首次范数通过后的内部 Verify 自检再查一次；范数重试不再查 H1，耗尽或早期中止可少于 2。 |
| 有效形状的 Verify 正常路径 | 1 | 1 | `paper_backend.py:208`、`structured_backend.py:350`：前置校验后各查一次；校验早退为 0。最终伪造验签若执行此路径，也须入账。 |

两个后端的 `DOMAIN` 不同，上表是**并列候选实现**，不能把调用数跨后端相加成同一安全游戏。失败路径也不同：paper Extract 在采样后才到 `paper_backend.py:158` 的 H1；structured Extract 在 `structured_execution.py:519` 先查 H1、后采样和检查，故后续采样失败已有一次调用。issued 缓存命中两者都不重查。

这份账本还不能推出 `4q_S` 或 [33] 的 `ℓ` 可直接使用：经典确定性 SHAKE 会对同一地址重新计算，理想 oracle 模拟器可缓存经典回答，但 QROM 的相干查询、Sign/Extract 联合回答与隐藏 `X` 的条件成功事件需在**同一**实验中证明。H2 挑战在每次签名范数尝试中另有查询，不能从 H1 的上述计数中消去。

**联合回答边界的独立反例。** [33] Corollary 4.3 比较的是一张 `H` 表的查询输出，不能自动覆盖一个额外泄露隐藏植入值的相关回答通道。取 `|Y|≥2`，两个实验都先取 `y←Y` 并经同一假想侧通道泄露；均匀实验的 `H` 独立于 `y`，半常数实验以 `y` 为植入值。对手一次查询固定 `x` 并测试 `H(x)=y`。均匀实验命中概率 `1/|Y|`，半常数实验为 `λ+(1−λ)/|Y|`，差 `λ(1−1/|Y|)`，是一阶而非上述 oracle-only 二阶 `λ` 界。这是**适用范围反例**，不是声称 SRGG Sign 实际泄露 `y`，也不是对 [33] Claim 1 的反例。

因此若修复 p.9 目标身份 Sign 中止而向底层 `SIG.Sign` 转发，须显式证明 Extract/Sign 回答在两实验中可由同一 `H` oracle、独立随机性及计入预算的内部查询模拟，或另给联合 hybrid。代码 `paper_backend.py:178–210` 的 Sign 与末次自检/Verify 会重复取 H1，重试及验证也重取 H2；固定公钥的经典理想表可一致回放这些值，但 [经典地址耦合](../2026-10-18-srgg-hash-address-mapping/proof.md)没有量子查询账本或上述联合回答结论。实际底层 SIG 实验仍须单独核对。

本次仅作原文 pp.6、8–9、[33] 可检索正文局部、Zhandry 博士论文 §4.2 与现有代码只读核对；没有新根、身份、消息或签名样本，重复试验 0。参数沿用 Table 4 的 `n=512,w=2,Q=15744063,d=2/3/4`；不声称 ROM/QROM 归约、正式强度或 HIBE 组合。`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。
