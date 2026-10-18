# SRGG：目标身份签名转发、跨身份新鲜性与经典分区损失

日期：2026-10-16。**结论：目标身份的签名请求可以转发给底层 SIG signing oracle；必须允许它们，不能像原文模拟器那样全部中止。排除其它已签身份落入 X 的最终事件可保证 ordinary/strong 新鲜性，但分区概率只能先在与分区独立的诚实 transcript 上计算。半常数编程后的自适应 transcript 不能直接因子化。** 下文给出条件命题、一个明确反例、可完成的经典 RO 损失及单目标猜测对照；不是 SRGG 或 QROM 的完整安全证明。

本项保留 native strong 目标，不修改哈希、原语、参数、冻结的 `srgg-bridge` 包或公共接口。`security_claim=none, backend_admitted=false, parameters_are_formal=false`。

## 1. 来源与两个安全实验

冻结 SRGG 来源：*Constructing Efficient Identity-Based Signatures on Lattices*，[DOI 10.1049/ise2/6684889](https://doi.org/10.1049/ise2/6684889)，PDF SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。核对范围为 p.4 Definition 3、p.8 Theorem 2/G0、p.9 的半常数 H 与模拟器。其模拟器在 `O2(id)=1` 时中止 signing query；这不能覆盖以下允许的查询。既有 source/PSF 义务见 [theorem-obligations.md](../2026-10-16-srgg-bridge/theorem-obligations.md)。本项不声称已经核准其引用的 Zhandry 量子定理。

令 T 为完整经典交互 transcript，最终输出为 `(f,m*,sigma*)`。记：

- E(T)：曾成功向 extraction oracle 请求的不同身份集合；合法伪造要求 `f notin E(T)`。
- S(T)：曾向 signing oracle 请求的不同身份集合，允许包含 f；重复请求同一身份只计一次。
- L(T)：signing oracle 实际返回的规范三元组 `(id,m,sigma)` 的集合。
- ordinary 赢法：验证接受且 `(f,m*)` 未向 signing oracle 请求；f 可以签过其它消息。
- strong 赢法：验证接受且 `(f,m*,sigma*) notin L(T)`；相同 `(f,m*)` 可以曾返回其它签名。

这里先采用不 abort 的理想实验。实现中的 failed/pending、有限尝试、范数拒绝和 oracle 异常不能删去；它们须由另一个完整 law/失败模型桥接。强实验中的“精确签名”必须采用同一个规范对象/字节定义，不能忽略 wire aliases。

## 2. 归约依赖的精确前提，而非已证 SRGG 事实

以下命题限定于**经典查询的身份 oracle H1**。设公开 a 的分布、底层 SIG key generation 及共享其余 oracle 满足：

1. `SIG.Gen` 的挑战 pair 为 `((a,h*),sk*)`，其中公开可执行的 SampleDom 抽取 `U~D_a`、`h=f_a(U)`，且 `h` 恰均匀于有限像 R。给定 a 后，不同 SampleDom 样本独立。
2. 固定 H1(id)=h 后，理想 IBS 发钥 law 恰为 `D_a | f_a(U)=h`。同一身份从第一次需要密钥起固定一把 key；重复 Sign/Extract 使用同一把。
3. 身份只通过 H1(id) 进入相应的 SIG 验签关系；对同一 h、同一公开 a，IBS 的签名请求 `(id,m)` 能由 `SIG.Sign(sk,m)` 回答，使用完全相同的共享 H2/上下文/编码。若实际底层消息是规范变换 `M(id,m)`，则必须相应重写下文消息新鲜性，不能自行忽略它。
4. 从底层 oracle 返回的规范签名到 IBS 返回对象的变换固定；对于固定最终身份 f，若要得到 strong 结论，这个变换在可接受签名域上须为单射，且验签对应。这排除“仅改变包装字段就出现新 IBS 字节，但底层还是旧签名”的情况。
5. reduction 可以访问底层 SIG signing oracle 及其真实共享其余 oracle，并公开运行 SampleDom 与持有已知 key 的 Sign；不需要主陷门。底层安全实验允许这些公开算法和相关但由 reduction 自行生成的辅助 key。

这些是假设，不是由 mixed-domain 的条件 law 恒等式自动建立的。特别是前提 1 的 key-generation law、底层 SIG 的实际普通/strong 安全及经典或量子 oracle 接口仍须分别证明。近均匀像、有限 sampler、norm 和服务误差在第 7 节另列。

## 3. 新鲜性命题：允许所有 X 身份 Sign，最终只接受一个相关身份

独立为每个身份设隐藏位 `b(id)~Bernoulli(delta)`，`X={id:b(id)=1}`。模拟器持有底层挑战公钥 `(a,h*)`，对新身份懒惰设定：

```text
if b(id)=1:  H1(id)=h*;
else:        U_id <- SampleDom; H1(id)=f_a(U_id); cache U_id.

Extract(id): if b(id)=1 abort; else return cached U_id.
Sign(id,m):  if b(id)=1 forward m to SIG signing oracle;
            else sign with cached U_id.
```

**不能在线中止其它 X 身份的 Sign**：此时还不知道最终 f。应记录返回结果，在最终检查事件

```text
Good(T,X) = { f in X, E(T) cap X is empty,
              (S(T) minus {f}) cap X is empty }.
```

模拟器可在最终不满足 Good 时输出失败。Extract 的早期中止不影响 Good 分支，因为该分支排除了所有 X-extraction。这里的 Sign 转发仅有普通底层 message m；没有暗改 H2 加入 id。

**命题 1（条件新鲜性）。** 在第 2 节的精确映射成立时，若 IBS 输出是 ordinary/strong 有效伪造且满足 Good，则 `(m*,sigma*)` 是相同类型的底层 SIG 有效伪造。

证明：Good 使所有向 SIG oracle 的实际 signing query 都来自唯一身份 f。ordinary 情形中 m* 没有在身份 f 上请求过，故底层未请求过 m*；f 的其它消息请求完全合法。strong 情形中，底层已经返回过的每个 `(m*,sigma)` 都对应 L 中身份 f 的相同规范签名。由单射前提，若最终底层 `(m*,sigma*)` 已返回过，则 IBS 的精确三元组也已返回过，矛盾。不同于原文中止策略，本命题允许目标身份任意多次请求、也允许 strong 的同消息多签。证毕。

Good 是一个**充分事件**，不是证明所有不满足 Good 的 transcript 都无法转移；有些额外 X-sign query 也未必撞到最终底层签名。归约可以保守地只接受 Good，而不能假称跨身份新鲜性本来就自动保持。

## 4. 独立诚实 transcript 的自适应分区概率

**引理 2。** 先完整运行诚实实验（允许攻击者适应性选择身份、消息和最终 f），得到与隐藏独立分区 X 无关的 T。对每个成功且未提取 f 的 T，设

```text
k(T)=| E(T) union (S(T) minus {f}) |.
```

则恰有

```text
Pr_X[Good(T,X) | T] = delta*(1-delta)^k(T).
```

证明：固定 T 后，f 与上述并集不交。Good 恰要求一个独立身份位为 1，并要求 k(T) 个其它不同身份位为 0。攻击者在 T 形成过程中如何自适应选择这些身份不再影响条件计算；Extract 与 Sign 集合重叠的身份只计一次。**f 属于 S 时不多乘一个 `(1-delta)`。** 证毕。

若成功概率为 epsilon，且所有成功 T 满足 `k(T)<=K`，则

```text
Pr_R[success and Good] >= delta*(1-delta)^K * epsilon,
K <= q_E + q_(S,distinct).
```

更紧时直接使用并集数；当 f 已签过，`k<=q_E+q_(S,distinct)-1`。K>=1 时 `delta=1/(K+1)` 最大化这个**独立分区因子**，值为 `K^K/(K+1)^(K+1)>=1/(e*(K+1))`；K=0 时因子为 delta，可取 1。这个优化并未计入编程造成的分布损失，不是下面真实 reduction 的最优 delta。

## 5. 半常数编程后不能直接套该引理：精确反例

考虑第 2 节完美、不失败的模型，像大小为 M>1。攻击者固定两个不同身份 i0,i1，查询两者 H1；相等时给 i0 的消息 m 请求一次签名，并将它作为 i1 上 m 的伪造。身份在 verify 中只通过 H1 进入，故这在 honest H1 碰撞时是 ordinary 和 strong 的合法成功：i1 从未签过或提取过。

在诚实随机 H1 中，成功率为 `1/M`。在半常数模拟中，两身份若都在 X 则必定碰撞，故

```text
Pr_SC[success] = delta^2+(1-delta^2)/M,
Pr_SC[success and Good] = delta*(1-delta)/M.
```

第二式中只能有 `i1 in X,i0 notin X`；另一身份的 off-X 均匀像还需恰好等于 h*。因此对 M>1、0<delta<1，

```text
Pr_SC[success and Good]
  < delta*(1-delta)*Pr_SC[success].
```

例如 `delta=1/4,M=1000` 时，三者分别为 `203/3200`、`3/16000`、`609/51200`（最后是错误因子化得到的数）。这是不依赖底层伪造能力的有限反例，直接说明**编程后的 T 与 X 相关**。底层 oracle 先为 i0 签过 m 后再输出同一 `(m,sigma)`，不构成底层新鲜伪造；不能遗漏 Good 或以“两个身份不同”解决它。

这不是对真实大像 SRGG 的非忽略攻击；诚实 H1 碰撞只有 `1/M`，且没有实例化其实际参数。反例的作用是推翻不合法的证明步骤。

## 6. 可完整证明的经典 RO 分布修正与损失

在第 2 节的**完美分布/经典 H1**前提下，可另外给出一个保守、显式的半常数分布耦合。不引用原文的量子改编结论。

令 Q>=1 是一轮中所有 H1 查询、Extract/Sign 内部 H1 首次使用及最终验证涉及的不同身份总数的确定上限；例如可取 `q_H1+q_E+q_S+1`，重复身份不增加计数。固定公开 a 后，为新出现的身份抽独立位。在比较实验 R 和 SC 中：

1. off-X 身份共享同一新 SampleDom pair `(h,U)`。
2. 第一个 X 身份共享同一挑战 SIG pair `(h*,sk*)`；由前提 1，它与普通新 SampleDom pair 同 law。
3. 在出现第二个 X 身份前，两边 H1、固定 key、所有签名和其它共享 oracle 都可完全耦合。第二个 X 身份出现时标 Bad，之后不再要求一致；SC 将复用挑战 pair，R 则用新的独立 pair。

新身份的隐藏位在第一次触及时仍是 fresh Bernoulli(delta)，即使身份由此前回复自适应选择。若实际少于 Q 个身份，可用未公开的全新 dummy 身份补到 Q，故

```text
TV(joint transcript and encountered labels in R, SC)
 <= Pr[at least two X bits among Q fresh identities]
 = beta_Q(delta)
 := 1-(1-delta)^Q-Q*delta*(1-delta)^(Q-1)
 <= binom(Q,2)*delta^2.
```

Q=1 时 beta=0。耦合还包括相同身份的所有重复 key/sign 回复，而非仅比较单个 H1 输出。实际 reduction 不知道 sk*，但可用 SIG oracle 生成与持有该固定 key 相同 law 的签名回复；分析中的 sk* 是合法挑战实验的隐藏变量，不是给 reduction 的额外输入。Extract-X 被实际中止，只有在虚拟全程实验里才定义其回复；目标 Good 事件不包含这些中止历史，故不影响以下成功下界。

**条件命题 3（经典半常数归约）。** 若第 2 节全部满足、底层 ordinary/strong 与 IBS 类型一致、攻击者的理想 honest 优势为 epsilon，则上述转发归约存在 B 满足

```text
Adv_SIG(B) >= delta*(1-delta)^K*epsilon - beta_Q(delta),
q_(SIGsign,B) <= q_S.
```

证明：先对 R 使用引理 2，再用联合 transcript/标签 TV 比较同一个 `success and Good` 事件；最后命题 1 将 SC 中该事件转换为有效底层伪造。负下界当然只给零信息。这里 K、Q 不同：只在 hash 过但未签/提取的 X 身份也可能引起半常数相关性，所以不能把分布损失中的 Q 偷换成 K。证毕。

若已知 `epsilon>=epsilon_0>0`，可选 `delta=epsilon_0/(2Q^2)`。因 `K<=Q`，Bernoulli 不等式给 `(1-delta)^K>=1/2`，且 beta 至多 `Q^2 delta^2/2`，于是

```text
Adv_SIG(B) >= epsilon_0^2/(8Q^2).
```

这是保守二次损失，不是声称最紧。归约需要一个可用的 epsilon_0（或标准多项式下界猜测）；不能在实现中假装知道攻击者真实优势。除攻击者本身外，时间成本还包含最多 Q 次公开 SampleDom、最多 q_S 次本地已知-key Sign、分区采样与状态记录。仅给 query 次数不能代替总运行时间。

### 对照：经典 single-index 猜测可避免半常数相关性

仍在完全相同的完美分布、经典 H1 前提下，另有更直接的条件 reduction：均匀猜一个 `J in {1,...,Q}`；按首次触及身份的次序，仅第 J 个身份绑定挑战 h*，其它身份各自产生独立 SampleDom pair。对第 J 个身份 Sign 转发，Extract 中止；最后仅接受最终身份恰为第 J 个的成功伪造。

可定义不提前中止的虚拟实验：每个身份的 pair 仍然是独立、同 law 的 SIG key pair，故完整 honest T 的 law 与 J 无关。固定任何成功 T，其最终身份的首次出现序号 j(T) 唯一；`Pr[J=j(T)|T]=1/Q`。该分支无目标提取而不会早停，所有 SIG signing queries 只来自最终身份，命题 1 保证普通/strong 新鲜性。因此

```text
Adv_SIG(B_index) >= epsilon/Q.
```

这只是经典 RO 下的对照归约；不要求改 H2/身份绑定。它说明“必须拒绝所有 X-target Sign”并不是经典模型里的根本障碍，也不说明可以将单索引的在线身份次序搬进 QROM。最终身份未曾显式 H1-query 时，在最终验证处建立其新 entry，因此 Q 中的 `+1` 不可省略而无需强迫攻击者提前查询。

## 7. 与近似 PSF、真实 sampler 及 QROM 的分界

若已独立证明真实 honest 服务到上面完美实验的**完整 transcript**距离至多 Delta_real，并证明实际模拟器到上面的理想 SC simulator 距离至多 Delta_sim，数据处理可保守写成

```text
Adv_SIG(B_actual)
 >= delta*(1-delta)^K*(epsilon_real-Delta_real)
    - beta_Q(delta) - Delta_sim.
```

可用更松 `delta*(1-delta)^K*epsilon_real-beta_Q-Delta_real-Delta_sim`。这些 Delta 不能凭单次有限采样 TV 填入：还须包含 image/keygen 对应、抽样失败、逐目标 norm、固定服务和全部相应查询。若底层挑战 keygen 本身改变，其安全假设也需相应改写。此处只是已有完整距离一旦获得后的传播式。

**QROM 尚未证明。** 上述 fresh-label/lazy-entry 操作依赖 H1 的经典单点查询记录。对叠加查询不能测量/枚举其身份，也不能以“第二个 X 被触及”为经典停止时刻；single-index 顺序也不存在相同的直接解释。KLS 的底层 QROM strong 定理即使适用，也不自行填补 IBS 的这一层。需要定向核对源 [33] 的 semi-constant lemma、可相干计算的采样 tape、目标 Sign 转发、跨身份新鲜性及完整量子 hybrid 损失。单像 TV、经典分区公式或上面的 beta_Q 不能直接宣称量子版本成立。

在这些义务完成前，本文件只闭合**明确前提下的经典普通/strong 转移机制**，没有证明实际 SRGG 的底层 SIG 已安全，也没有证明最终组合或授予 Kyber/NIST 等级。

## 8. 证据与审查收据

本轮未下载论文、未修改哈希/生产代码、未运行密码学实例。反例分数以 Python `Fraction` 单次精确算术复核：`delta=1/4,M=1000` 得 `SC_success=203/3200,good=3/16000,naive=609/51200`。本文件的一般引理/命题由上面的条件化、耦合和新鲜性推导承担，有限算术检查不代替证明。没有新增实现测试或安全攻击成功率。
