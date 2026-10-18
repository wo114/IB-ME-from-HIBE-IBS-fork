# SRGG Theorem 2 抽象 SIG 接口与实际验签的对应（WIP）

范围为独立 IBS 的**原文接口解释与代码对应**。来源是冻结 `papers/2025_efficient_ibs_jia.pdf`（SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152），PDF p.8 的 Algorithm 7–8、Theorem 2 与页底 PSF/SIG 改写，p.9 的 oracle 模拟器。已封存的 [模数、平滑宽度与游戏审计](../2026-10-18-srgg-source-symbol-mapping/proof.md)、[经典目标签名条件归约](../2026-10-16-srgg-reduction/target-signing.md)和[哈希地址审计](../2026-10-18-srgg-hash-address-mapping/proof.md)不在这里重证。

## p.8 抽象接口的类型缺口

论文在 Theorem 2 前把底层 `SIG.Gen` 的验证公钥写为 `(a,f_a(sk))`，并令 IBS 的 `mpk=a`、身份目标 `H(id)`。因此若把 IBS 直接解释为该 SIG 的身份派生实例，一个类型正确的底层验签调用至少要知道 `a`、`H(id)`、消息 `μ` 和签名。p.8 末尾的抽象 `IBS.Vrfy` 条目却把 SIG 验签输入写成 `(id,μ,sig)`，其中原始 `id` 是字节串而非上文的 `(a,f_a(sk))` 型验证公钥；该条目的左侧参数又未列出 `μ`。按页面**字面**读，两个调用类型均不闭合。

这可能是省略或排版笔误，不是已发现的算法攻击。若作“底层公钥是 `(a,H(id))`”的**候选修复解释**，仍需证明实现的近似 `SamplePre` 关系、底层 SIG 验签关系及公钥分布满足该解释；不能默默把候选修复当作原文已证明的定理。论文同页 Algorithm 8 的具体版本明确接收 `(mpk,id,μ,sig)`，使用身份目标和消息挑战，因而是本次源码映射的直接算法依据。

## 具体 Algorithm 8 与代码

| 论文 Algorithm 8 p.8 | 实现位置 | 对应边界 |
|---|---|---|
| 用 `H(id)` 形成末列 `Qj−2H(id)`，构造模 `2Q` 的验签矩阵。 | `paper_backend.py:208` 调 `identity_target`；`structured_execution.py:245–250` 的 `signing_matrix`。 | 同一公钥、规范身份和原表 `Q` 上的代数对应；H1 的真实 SHAKE 到 RO 距离仍未知。 |
| 从 `(z,c)` 恢复 `w=Āz−Qcj mod 2Q`。 | `structured_execution.py:262–269` 的 `recover`。 | 仅核代数计算；范数、wire 和固定服务仍须按各自层验收。 |
| 检验 `c=H̄(w,μ)` 及 `||z||≤γ`。 | `paper_backend.py:201–210`；`paper_algebra.py:43–49`。 | H2 代码地址附带规范完整公钥 `P`，论文抽象地址只写 `(w,μ)`；固定单公钥可作经典理想 oracle 地址重命名，跨公钥联合游戏另核。 |

这里不声称底层 SIG 的 `SIG.Vrfy` 已作为独立对象实现，也不声称 IBS 调用与论文抽象 SIG 游戏在分布上相同。特别是原文 p.8 的 Theorem 2 给定底层 **sEUF-CMA** 前提，p.8 的 G0 却采用新 `(id,μ)` 对条件；实际五次同消息替换及原 Theorem 1 `q>2γ` 不满足的证据已有以上冻结审计。本页只新增**抽象验签调用类型与具体代码**的对应缺口。

## 两个 oracle 的游戏接线义务

Table 3 定义身份哈希 `H` 与签名挑战哈希 `H̄`。Theorem 2 的 G0 文字明示量子查询身份随机 oracle `H`，而 p.9 模拟器列出 `O1/O2` 以构造半常数 `H`；这几段没有逐项规定 `H̄` 的查询能力、它与底层 SIG 安全实验共享的 oracle 状态，以及目标身份签名转发时怎样保持同一 `H̄` 回答。底层 SIG 定理也许承担部分挑战 oracle 工作，但要套用到**这份实现**，仍须给出同一公钥下 `H̄_P(w,μ)` 与底层实验 oracle 的明确接口、查询预算和失败耦合；在 QROM 下还须相干模拟。这是缺少可核映射的义务，**不等于宣称不存在可修复证明**。

本次仅作原文 p.8–9 与现有代码只读核对；没有新根、身份、消息或签名样本，重复试验 0。参数沿用 Table 4 的 `n=512,w=2,Q=15744063,d=2/3/4`；不声称 ROM/QROM 归约、正式强度或 HIBE 组合。`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。
