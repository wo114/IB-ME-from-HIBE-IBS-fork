# SRGG：直接 uniform-H1 目标的经典 native-strong 归约

2026-10-16。本文给出**明确前提下**的直接 IBS→短核路线：保留真实目标身份的均匀 H1 值，非目标身份用公开 mixed-domain 样本回答，不经过一个 image-distributed `SIG.Gen`。随后对整个公开短核提取器做 shared-Ahat 的 16 列 Module-LWE hybrid。此处证明的是条件耦合、oracle 接口和代数分布对应；不是实际 SRGG 已完成的安全定理，也不处理 QROM。安全标志保持 `security_claim=none, backend_admitted=false, parameters_are_formal=false`，native strong 赢法不降为 fresh-message EUF。

不修改哈希、参数、冻结的 bridge/reduction 批次或公共后端。HIBE 的选择不进入以下对象。Kyber/ML-KEM 与 NIST 是后续比较目标，不能据此给本 IBS 授予等级。

## 1. 来源、固定游戏和记号

固定来源为 *Constructing Efficient Identity-Based Signatures on Lattices*，[DOI 10.1049/ise2/6684889](https://doi.org/10.1049/ise2/6684889)，PDF SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。这里不直接引用原文 Theorem 2 来补足 strong 赢法或目标签名；其具体差异已列在 [strong-games.md §2–3](../2026-10-16-srgg-reduction/strong-games.md)。

采用同文件 §2 的完整 native-strong 游戏：合法显式 Extract 请求记入 E；Sign 的内部 IssueOnce 不记入 E；仅实际成功返回的规范三元组 `(id,mu,sigma)` 记入 L。获胜要求目标身份未被显式 Extract、Verify 接受、且确切三元组不在 L。允许重复请求同一身份、同一消息，以及在输出时自适应选择目标。规范对象到签名字节必须单射。

令 `R_Z=Z[X]/(X^n+1)`，`R_Q=R_Z/Q R_Z`，n 是 2 的幂，Q 为奇数。记

```text
H = dn,                 M = (2+w)d,
N = Mn,                 D = (M+1)n,
A = [I_d | Ahat | B] in R_Q^(d by M),
H1(mpk,id) = h in R_Q^d,      K = |R_Q^d| = Q^H.
```

这里 K 是像空间大小，不是密钥缓存。`Q_I>=1` 是一轮中有效身份 H1 点的首次触及数上界，包括显式查询、Extract/Sign 内部首用、最终 Verify 首用；原始 byte-XOF 接口下还包括第 7 节的 partial/offset 首触及。`N_K` 是实际第一次调用 IssueOnce 的不同身份数，`N_S<=q_S L` 是实际签名尝试数上界。不能把 `N_K` 只写成攻击者显式 Extract 次数。

H2 的完整规范输入为 `(mpk,W,mu)`，**不含 id**。整个游戏中至多已有 `M_H` 个相关 H2 entry；其数量包含公开调用、已知密钥签名和失败重试，不只是外部 q_H。`q_F>=1` 是整个公开提取程序一轮中 fresh free-owner H2 entry 数的确定上界。所有预算还需覆盖重放和 raw-XOF 访问的字节/运行成本。

## 2. 保留 raw 门的 latent mixed-domain pair

以下固定同一个公开 A；原始 trapdoor setup 的秘密 witness 不属于公开采样器输入。令 `J_H:Z^H→Z^N` 嵌入首 H 个系数；`C_Q` 只将这 H 个系数化为中心规范剩余类。取固定公开、与 A 的秘密 witness、目标和历史无关的 law

```text
mu = D_(Z^N),s_master I,
U <- mu,
E0 <- Uniform({0,...,p-1}^H), independent of U,
Y = C_Q(U+J_H E0),
h = A Y mod Q = A U+E0 mod Q.
```

保持 latent `(U,E0,Y)`，不只保留 Y。公开发钥门是

```text
G(U,Y) = [||U||^2 <= Rcap and ||Y||^2 <= Ucap],
key = Y if G(U,Y), otherwise bottom.
```

tail/full key 的确定性规范变换和身份包装也属于同一映射。失败时仍保留 h 并缓存该身份的失败；不能先重抽到 G 成功再设置 H1。实际代码在 `structured_execution.key_extract` 中先检 raw U 范数，再由 `Key` 检 HNF 修复后的 full Y 范数；只写 `Gate(Y)` 会漏掉第一个门。

令 `alpha_h=Pr[A Y=h]`。对每个 h 定义

```text
e_h(u) = nonnegative_mod_Q(h-Au),
S_h = {u : e_h(u) in {0,...,p-1}^H}.
```

当 `alpha_h>0`，有 `mu(S_h)=p^H alpha_h`，且

```text
law(U,E0,Y | A Y=h)
 = law(U, e_h(U), C_Q(U+J_H e_h(U))) for U~mu|S_h.       (1)
```

这是 [mixed-domain.md §2](../2026-10-16-srgg-bridge/mixed-domain.md) 的 latent 版本；head 相差 Q 的 aliases 按推前自动求和，不要求修复映射单射。对 (1) 两边施加相同 G，包含 bottom 的条件 key law 仍恰相同。raw 门不能被当作 Y 的函数，但在 latent pair 上是同一个确定函数。

**引理 1（完整 pair 距离）。** 设 `P_A` 为公开抽取 `(h,U,E0,Y,key)` 的 law；`R_A` 先取均匀 h，再按 (1) 抽 latent 条件样本、施加同一门。则在施加门前

```text
TV(P_A,R_A) = TV(alpha,Uniform(R_Q^d)) =: epsilon_image(A).
```

证明：对每个 h，两边具有相同条件 law `P_A(.|h)`；联合质量分别为 `alpha_h P_A(.|h)` 与 `K^-1 P_A(.|h)`。逐 h 求绝对值并求和，得到等式。保留 h、施加 raw/final gate、规范 key/失败包装或同一个条件 raw-prefix kernel 后，数据处理给同一上界。这里只比较 h 边缘而丢掉 latent/失败会不足以使用该引理。证毕。

**旧证书的对应。** 冻结 `integrated-bridge.json` 的 `hnf_common_gate_comparison.complete_issuance_to_common_hnf_gate_reference_tv_upper`（记 `delta_E`）比较的是仅公共 Y 门参考；其源码已明确 raw 门不是 Y 谓词，并先付 raw-tail，旧结论没有忽略这点。本文件的新 latent 双门参考可保守使用

```text
delta_lat <= delta_E+t_R,                                  (2)
t_R = raw_union_norm_reject.probability_upper.
```

因为仅 Y 门与双门参考的距离至多 `Pr[||U||^2>Rcap|S_h]<=t_R`。不能直接把旧 delta_E 字段改名为 latent 误差，也不能靠从数值上界相减来声称更紧结果。另一路是从 `issuance_pre_raw_finite_and_recurrence_tv_upper` 加 `convolution.ideal_raw_to_union_gaussian_tv_upper_exact`，然后对同一个 latent→双门映射用数据处理；使用它前必须逐项核真实 raw-law 对应和所有 abort。

当前 n512 参数满足 `Ucap>=2 Rcap+2H(p-1)^2`，而 `||Y||^2<=2||U||^2+2H(p-1)^2`。因此理想双门参考每目标 bottom 概率至多 t_R。该 bottom 不能并入“坏成功密钥”后忘记：目标无密钥模拟器无法判断未知 U 是否过 raw 门，必须另外付这个差异。

## 3. 直接目标模拟器及固定状态

公开算法 `Run(A,h_star,J; tape, free_H2_replies)` 的输入只有公开 A、一个独立均匀 `h_star in R_Q^d`、隐藏索引 `J uniform {1,...,Q_I}` 和独立随机带。mpk、seed/matrix-XOF 初始化和其它对外初态不得依赖 h_star；h_star 不另行暴露给 IBS 攻击者。

```text
TouchIdentity(id):
    已有 entry 则复用；否则分配下一个首次触及索引 i。
    if i=J:
        H1(id) := h_star; status := target-unissued。
    else:
        公开抽 (U,E0,Y)，设 h:=AY，保留 h。
        缓存 latent gate 后同一 key 或 blocked/bottom；不重抽。

Extract(id):
    检查规范身份；TouchIdentity(id)；记录合法显式请求。
    if index(id)=J: 整次归约失败。
    else: 返回缓存的同一 key 或规定的失败。

Sign(id,mu):
    TouchIdentity(id)。
    if index(id)!=J: 按缓存 key/失败运行原 known-key Sign。
    else:
        不抽/不恢复目标 key，不读取主陷门；仅用公开 Sim(A,h_star)。
        独立抽 c uniform {0,1}^n，z~D_(Z^D),Sigma_public。
        计算 W=Rec_hstar(c,z)，令 x=(mpk,W,mu)。
        若 norm 失败、x 已触及、采样/熵/状态异常：整局失败。
        否则在 fresh x 编程 c，记录 sign owner 和实际返回的规范签名。

Finish(id,mu,sigma):
    对最终合法身份先 TouchIdentity，再验证。
    仅保留 native-strong 获胜且 index(id)=J 的结果。
```

norm/碰撞失败前不得留下可被计作成功签名的 owner；基础设施异常也不能留程序后继续套 CUR。原真实 Sign 的 norm 重试和模拟器首拒绝整局失败之间的距离按第 5 节支付。目标第一次 Sign 跳过真实 IssueOnce，故目标底层发钥失败须另付；重复 Sign 不再重复收首次发钥失败或 GoodKey 费用。

这个算法描述的是安全实验中的固定缓存，不宣称新的 n512 持久服务已实现。要对应真实恢复/并发版本，IssueOnce 的 pending/failed/committed、并发排序、原子保存、恢复前已发 key 和全部错误结果必须进入同一因果状态机。仅有一把 key 的 snapshot 恢复不自动建立这个前提。

## 4. 与隐藏 J 无关的母空间及事件耦合

构造完整诚实参考 R：A 仍来自原 trapdoor setup；每个新身份 h 均匀，隐藏 latent key 按 (1) 固定一次；服务/Sign 使用同一失败和缓存语义。先在一个与 J 无关的母空间上生成其完整轨迹 T，以及下述所有潜在耦合随机性，再独立抽 J。

证明中可令隐藏 `h_star=H1(T 的第 J 个身份)`。联合 law 等价于先给归约独立均匀 h_star、再将它放在第 J 个身份：首次触及前所有输出不依赖 h_star，新的诚实 H1 值条件于既有历史仍均匀。**不能一面把外部 h_star 当作已条件化的公开辅助信息，一面宣称 T 与 J 独立。** 在母空间中 h_star 是后定义的隐藏变量；攻击者初态/公开 mpk 不包含它。

为 R 中每个新身份 i，附一个 honest latent pair 与公开 pair 的最大耦合。潜在缺陷 `C_i` 是这两个 pair 不同；其联合 coins 与 J 无关，并在每个共同历史中满足 `Pr[C_i|history]<=epsilon_image`。对每次真实 Sign 附一个同样与 J 无关的理想真实/公开 Sim transition 耦合，潜在缺陷概率至多 d_t。这里 transition 包含 H2 表、完整 owner、实际返回记录和失败，而不是只有 z 的边缘分布。

对固定 J，仅 i≠J 使用附带的公开 pair；目标 Sign 使用附带 Sim transition。在首次相关缺陷前，两条可见轨迹及缓存相同；首次缺陷后可按各自条件 law 完成游戏。每步目标/非目标 kernel 的边缘必须正确，不能先按存活事件或最终伪造身份筛样本。

设 `Success(T)` 是 R 中获胜事件，`f(T)` 是最终身份的首次触及索引。固定完整的 T 和全部潜在耦合 coins，恰有 `Pr[J=f(T)]=1/Q_I`。所以

```text
Pr_R[Success and J=f and exists i!=J:C_i]
 <= (1/Q_I) sum_i Pr_R[C_i]
 <= Q_I*epsilon_image/Q_I.                                (3)
```

这里先逐轨迹选 `J=f`，再对可能相关的所有缺陷求并集；不是声称混合实验的 transcript 与 J 独立。不能一般把分子的 Q_I 收紧成 Q_I−1，因为最终身份可根据历史自适应选取。

第 t 个 Sign 的身份索引 i_t 是 R 轨迹的函数。令 Bad_global 包含第 5 节先扣掉的坏事件；签名 tiny-TV 仅在 GoodKey 历史上要求成立。同样可得

```text
Pr_R[Success,J=f,not Bad_global, first relevant Sign defect at t]
 <= Pr_R[J=f=i_t,not Bad_global,SignDefect_t]
 <= E_R[1{GoodKey_t}*d_t]/Q_I.                             (4)
```

式 (4) 中 d_t 在 GoodKey 类上取统一界；坏 key 上不主张这个 tiny-TV，可以把该项定义为零而由 Bad_global 支付全部坏事件。先丢掉“此前仍耦合”的非负指示，再使用与 J 无关母空间；不要对未中止/最终猜中条件化后重新宣称 J 均匀。目标 Extract 的实际早停可以先在虚拟 R 中回答隐藏 key；`Success and J=f` 从未显式提取目标，所以实际早停与该接受分支一致。这里的目标 key 只是证明 ghost 变量，归约不接收它。

**必要反例。** 若直接在混合实验中用独立 J 猜中率，会出错。取 Q_I=2、H1 范围 `{0,1}`，目标准均匀，非目标 `Pr[h=0]=1/2+e`。攻击者读两个 h，优先选 h=0 的身份作最终身份，平手选第一个，则混合实验中最终身份恰是 J 的概率为 `1/2-e/2`，不是 1/2；e=1/2 时只有 1/4。式 (3) 把这类相关性计入 image 费用。

另取 `A=[1] mod3`，U=0，E0 均匀于 `{0,1,2}`，故像恰均匀；若门只接受 Y=0，先重抽到成功再设 h 会令 h 恒零。即使未过滤 image 误差为零也产生 TV=2/3。第 2 节保留 h/bottom 的构造避免这个错误。

## 5. 统计费用、目标 bottom 和跨身份别名

令 Delta_0 是从实际诚实完整游戏到 R 的**已证明的**距离。它可保守包含每个首次发钥的 delta_lat、真实签名 finite→ideal、有限 hash 失败、完整状态/资源模型等；必须先在与 J 无关的诚实游戏中支付。对现有证书，只能在其数学、MPFR 和运行条件成立时使用数值；不能将未建模的全局 cap/基础设施异常当作概率零。

另在 R 中标记以下全局坏事件：

- `IssueFail`：某次真正首次 IssueOnce 的 latent gate 返回 bottom；充分界 `Delta_issue<=N_K t_R`。这是目标 Sign 跳过未知 raw 门的保守费用；非目标仍实际保留门。
- `BadKey`：成功 key 不满足签名模拟所需 GoodKey；逐 key 费用只收一次。使用 `||Y||^2<=Ucap/4` 时，现有理想逐目标坏成功 key 界 `delta_bad<=2^-256` 给 `Delta_bad<=N_K delta_bad`，不是按 Sign 次数重收。
- `Alias`：任意两个不同有效身份具有相同 h。诚实 uniform-H1 参考内，即使自适应触及，fresh h 条件于以前仍均匀；用未公开 dummy 点补足 Q_I，得到

```text
Delta_alias <= min(1, Q_I(Q_I-1)/(2 Q^(dn))).               (5)
```

H1-only 点及最终 Verify 首触及都计入 (5)。此处保守去掉所有别名；没有把真实偶然碰撞与半常数归约人为制造的多身份同值混为一谈。先在 R 中去掉 Alias 再用 (3) 转移，故不需要在 mixed transcript 上声称相同生日界。

H2 不含 id，**即使去掉 h 别名，跨身份也可能访问同一个 `(mpk,W,mu)`**。owner 永久取第一次建立该 entry 的来源：非目标 known-key 签名的内部 H2 是 free；只有目标 Sim 新建且实际返回的签名是 sign。非目标命中 sign entry 只读取它，不改 owner。最终 owner=sign 时，该见证来自本轮唯一目标身份；规范 strong 新颖性迫使最终响应不同。最终 owner=free 时一律交重放 fork；不能因它曾由其它身份签名而把它误计成目标已返回记录。故式 (5) 是清楚的充分剔除，不代替这套 owner 规则。

GoodKey 内的逐历史 ideal FS 模拟界来自 [classical-fs.md §3](../2026-10-16-srgg-reduction/classical-fs.md)：

```text
d_t <= M_H*2^-alpha + delta_zk_good + eta_sign.             (6)
```

全 cap 理想 commitment 的 `alpha=36351`、GoodKey 内 `delta_zk_good=4667/2^256`，以及 `eta_sign<=2/2^256` 各有独立前提。先付真实 commitment 已有 entry 碰撞，再对整个 independent interactive joint 经同一个 gate/program/log 映射，joint-TV **只支付一次**；不能乘 M_H。有限实际公开 Sim 再另付每调用 `delta_sim`。若 R 的 Sign 已换成理想 Gaussian，而 Run 的非目标 known-key Sign 使用有限实现，还要另付每尝试 `delta_known`；Delta_0 里支付过诚实→理想，不能据此省去理想→公开非目标有限程序的另一端桥。对每个诚实 Sign 附与 J 无关的 known-key 有限 transition 耦合，沿式 (3) 同样可将此费用置于分子。用 N_S≤q_S L 保守收费；若非目标 Sign 在 R/Run 中已经完全相同，取 `delta_known=0`。

若实际公开 Dom 相对理想 latent Dom 的完整 law 距离（含采样 abort）至多 `delta_pub`，可将每身份 honest/public pair 最大耦合上界放宽为 `epsilon_image+delta_pub`；raw-prefix overlay 的收费按第 7 节另列。所有这些上界须对同一公开参数、相应可达历史统一有效。

**条件命题 2（直接目标签名伪造概率）。** 在上述完整 law、因果 kernel、规范编码及 oracle 前提下，实际公开 Run 的目标 strong 成功概率 p 至少为

```text
p0 = max(0, [epsilon_IBS - Delta_0 - Delta_issue - Delta_bad
             - Delta_alias - Q_I*(epsilon_image+delta_pub)
             - N_S*(M_H*2^-alpha+delta_zk_good+eta_sign
                     +delta_sim+delta_known)
             - Delta_overlay] / Q_I).                     (7)
```

这里 Delta_overlay 只填尚未在 Delta_0/pair/Sign 中支付的完整 raw-prefix/cap 费用，不能重复计项。证明：先在独立 R 上扣全局坏事件并取正确猜测 1/Q_I，再用 (3)(4) 转移成功事件；实际目标 Extract 不发生于接受分支。坏 key、目标 bottom 和所有 finite 桥按各自层收费。若只有“每个固定 J 的通常 transcript TV≤D”而没有此共同母空间，只能扣未缩放 D，不能套 (7)。证毕。

## 6. 从 native strong 到同一个短核矩阵

对 Run 的每个目标成功，按输出前完整 H2 表分类。设最终 entry 是 sign 的无条件概率为 a，free 的为 b，尚未触及的为 u。sign-owner 有已经实际返回的同目标、同消息、同 W 的合法签名，故 native strong 新颖性产生不同响应；free-owner 采用可重放有效挑战 fork；未触及点须猜中完整 n 位 c，故 `u<=2^-n`。注意 fork 的非零性只需、也必须排除 `eta(c)=eta(c')`，其中

```text
eta(c) = c_low XOR c_high in F_2^(n/2).
```

原理及完整二阶矩证明见 [strong-games.md §5.2/8.1](../2026-10-16-srgg-reduction/strong-games.md)。所有非 free-H2 随机性放入独立固定带；重跑从空表和同一初态开始，保留前 I−1 个 free 回复，重采第 I 个及以后回复。不能复用第一次运行的后缀状态。

提取器 E 公平选择 direct-owner 或 fork。给定公开 A 和固定 h_star，其成功率至少

```text
(a+max(0,b^2/q_F-b*2^(-n/2)))/2
 >= F_(q_F,n)(p),
t=max(0,p-2^-n),
F_(q,n)(p)=max(0,t^2/(8q)-t*2^(-n/2)/4).                  (8)
```

这里 (8) 先对固定公开实例 `omega=(mpk,A,h_star)` 的成功率 `p_omega` 使用，J 和其它执行熵仍在该实例内部随机。第 5 节的 p0 是对原 setup/独立均匀 h_star 平均后的下界，不能仅凭 F 的单调性将它代入固定实例。所用 F 在 `p<=2^-n+2q*2^(-n/2)` 时为零，之后为凸递增二次函数，交点右导数非负，故全区间凸且非减。Jensen 给

```text
Pr[E succeeds] >= E_omega[F_(q_F,n)(p_omega)]
                >= F_(q_F,n)(E_omega[p_omega])
                >= F_(q_F,n)(p0).
```

每次成功输出

```text
C_h = [I_d | Ahat | B | -h_star] in R_Q^(d by (M+1)),
Delta in R_Z^(M+1),
Delta!=0,      C_h Delta=0 mod Q,
||Delta||_2^2 <= 4 Bsig.
```

当前门 `Q^2>4 Bsig` 进一步保证 Delta 非零模 Q，不会只得到 Q 倍数的平凡核。欧氏界蕴含逐系数 `||Delta||_infinity<=floor(sqrt(4 Bsig))`。这不是任意均匀标量矩阵 SIS：展开后是负循环块矩阵，应明确叫所选环/模数/范数版本的 HNF-MSIS。

重放后第 J 个身份的名称可能随自由后缀改变；两次成功都要求最终身份索引 J，因此两次最终 h 都是同一个固定 h_star。重放索引 I 的完整 H2 输入保持相同，给相同 W、mu，已足够做同矩阵差分；不要求把两次最终身份名称额外固定。

## 7. 原始 byte-XOF 的首次触及 overlay

主命题若只给复合 H1/H2 随机 oracle，必须明确攻击者无独立 raw-XOF 通道。若采用实现所用的三域原始 XOF，则采用以下 classical overlay；不能在攻击者已经读过某点 1 B 后再覆盖其完整 h 或 c。

域由长度前缀编码的 `matrix / identity / message` 分离。对于固定有效 mpk，canonical identity 点的任何首次非空 raw 输出请求（包括 prefix 或 offset）立即调用 TouchIdentity，分配完整 bounded decoding tape/latent pair。不同有效 mpk、无效身份/消息/commitment、非规范 frame 等点按事先固定规则服务独立 raw stream；不得与有效点混为同一 entry。若把无效点也分配索引或计入资源，必须在预算中保持同一规则。

对 H1 的每个 Q 系数，候选为 7 B、`T=2^56`，接受区间 `[0,kQ)`，`k=floor(T/Q)=5`，每系数最多 l=256 轮。`rho=(T-kQ)/T`。1024 系数完整解码成功率 `s_H=(1-rho^l)^1024` 与目标 h 无关；失败率

```text
beta_H=1-s_H <= 1024*rho^256 < 2^-1270.
```

需要公开的 fixed-target raw kernel `G_h`：给定目标系数 r，每次候选保持原拒绝/接受判定；拒绝候选在 `[kQ,T)` 均匀；首次接受候选在 `{r,r+Q,...,r+(k-1)Q}` 均匀；保留 256 轮失败，并给未消费字节/任意后续 suffix 独立均匀字节。拒绝次数服从同一个截断几何 law，故成功/失败概率与 r 无关。均匀 h 的 `G_h` 混合恰为真实 uniform raw tape 的完整 law；成功条件 kernel `K_h=G_h|success` 满足 `Uniform_h K_h=raw|success`。

非目标先公开抽 latent pair→h，再接同一 K_h，按引理 1 联合距离仍至多 epsilon_image；成功条件 raw 到完整 raw 的桥再付 beta_H。或用保留失败的 G_h 直接构造同一扩展实验，并将 wrapper 解码失败全部标作 bad。攻击者只读取部分 bytes 时，其分布是完整 tape 的边缘，距离不增加。这里失败概率是每个新身份点一次，不按 prefix/offset 查询次数重复支付。可让游戏继续返回既定原 bytes，只在证明的成功事件中去掉 hashbad；不必提前用一个可观察 abort 改变 raw 查询行为。

因此，在没有重复计入其它项时可保守使用 `Delta_overlay,H1<=Q_I beta_H`，再加真正 finite conditional-prefix 实现的 cap/TV。对应 exact 有限模型接口见 `experiments/research/candidates/srgg/seeded_xof.py` 的 `conditioned_target_trajectory_law`、`raw_trajectory_law` 和 `observed_prefix_law`；有限模型不是 n512 采样器的运行时间证书。

message 域同样在一个 canonical `(mpk,W,mu)` 的首次 raw 触及时生成**完整 n 位挑战**，即使只读一部分或只读后续 suffix，也固定 free owner。多余未使用高位和后续 bytes 来自独立固定带。目标 Sim 只可编程完全未触及的点；重查 sign/free 点只读取。fork 在第 I 个 free 点首触及时重采其完整 n 位 c，保留独立 suffix 带；partial 读取不把同一点拆成多个可独立 fork 的挑战。

matrix 域的公开 32 B seed 不能凭空成为一个显式 Ahat 的逆像。必须将上述 fixed-target prefix kernel 用于**合法的 classical programmable matrix-XOF 嵌入**，含攻击者预查询、seed 抽取和冲突/有限失败的界。仅另给一个均匀 Ahat、保留未改的可重算 SHAKE seed 会被立即区分。该独立嵌入及其成本按本批 seeded-XOF 文稿核验；实际 SHAKE 是理想 XOF 的模型实例，不声称已证明 SHAKE 与 RO 的统计距离。

## 8. shared-Ahat 的 16 列 Module-LWE hybrid

设 Ahat 显式均匀于 `R_Q^(d by d)`；实际公开 seed 的条件嵌入须由第 7 节的独立构造提供。原 setup 的

```text
F = p gadget_b in R_Q^(d by wd),
R0,R1 <- CBD1^(d by wd), independently,
B = F-R0-Ahat R1 mod Q.
```

CBD1 每个系数的 law 为 `Pr[-1]=1/4,Pr[0]=1/2,Pr[1]=1/4`，各位置独立；这不是任意小噪声或 Kyber 已标准化的参数。每列 `v_j=Ahat s_j+e_j` 的 secret `s_j∈CBD1^d` 和 error `e_j∈CBD1^d` 相互独立，所有列共享同一个 Ahat。

定义 `H_j`（j=0,…,wd）：B 的前 j 列为独立均匀，余列为原 `F_k-Ahat s_k-e_k`。目标 h_star 在**所有** hybrid 中独立均匀，不是 `A SampleDom`；非目标 key、Sign 和所有状态均由第 3 节的公开 Run 程序现算。

每个标准单列 decisional Module-LWE 区分器具有以下可执行接口：

```text
D_j receives (Ahat, v), where
    LWE: Ahat uniform; v=Ahat s+e with independent CBD1 s,e,
    RAND: Ahat uniform; v uniform R_Q^d, independent of Ahat.
Generate:
    k<j: B_k uniform;
    k=j: B_j=F_j-v;
    k>j: own independent CBD1 s_k,e_k; B_k=F_k-Ahat s_k-e_k.
    h_star uniform R_Q^d; public seed/XOF overlay for Ahat;
Run entire public kernel extractor E(A,h_star), including its possible replay.
Output 1 iff E returns a nonzero Delta with C_h Delta=0 and norm^2<=4Bsig.
```

LWE 输入给 `H_(j-1)`，RAND 输入给 `H_j`，常数平移和取负保持均匀。因此

```text
|Pr[E succeeds in H_0]-Pr[E succeeds in H_wd]|
 <= sum_(j=1)^wd Adv_MLWE(D_j).                            (9)
```

**侧信息核对。** D_j 不接收未知 `s_j,e_j`、主 R、目标 key 或任何秘密 root 检查结果。其它列的 s/e 是区分器自己的独立随机性；非目标 latent U/E0、key/blocked 状态、恢复日志和签名也是从公开挑战矩阵和自己的随机带生成。它们可与 Ahat、B 强相关，但属于标准区分器的高效后处理，不是额外给予 MLWE 攻击者的未知秘密 oracle。公开 Sigma、范数 cap、sampler 参数必须固定于公开 pp；若它们读取真实 root witness 或目标 key，这个接口立即失效。

统计 smoothing/HVZK 只需在 H_0 的原 setup law 上建立。H_j 的公开程序对任意 A 仍有定义，known-key 样本总满足 AY=h，目标 Sim 的 Rec/program/范数检查仍公开有效；**无需**声称每个 uniform-B hybrid 也有原陷门或相同 smoothing 证书。式 (9) 在完整提取器之后应用，不将 MLWE 损失错误地再放进 fork 的平方。

`H_wd` 中 `U_hnf=[Ahat|B|-h_star]` 恰是独立均匀的 `d by ((1+w)d+1)` 环矩阵；所以 `C_h=[I_d|U_hnf]` 恰是所声明的 HNF-MSIS 实例。此分布结论不需在 uniform B 下重新证明 `A SampleDom` 近均匀，因为目标 h 从一开始就是独立均匀。

## 9. 确切实例、最终条件不等式与成本

本批沿用已有研究点，不是正式安全参数：

```text
n=512, d=2, w=8, p=16383, b=31, r^2=64,
Q=13972913866395903 = 3*43*127*31^8,
M=20, N=10240, D=10752, wd=16,
Bsig=238255596480161099521436160.
```

HNF-MSIS 挑战为 `C_h=[I_2|U]`，`U uniform R_Q^(2 by 19)`，即 `C_h∈R_Q^(2 by 21)`；目标为非零整数系数响应差分，`||Delta||_2^2<=953022385920644398085744640`，因而逐系数无穷范数至多 `30871060654286`。展开成系数空间为 1024 行、10752 列负循环块矩阵；其条目不能当作 1024×10752 个独立均匀标量。参数来源及 raw/final cap 见冻结 `integrated-bridge.json` 的 `query-bounded-deep`。

在完整实际 kernel 程序及 seeded-XOF 嵌入前提都满足时，(7)(8)(9) 给

```text
F_(q_F,n)(p0)
 <= Adv_HNF-MSIS(E) + sum_(j=1)^16 Adv_MLWE(D_j)
    + Delta_hardness_overlay.                             (10)
```

最后一项只放完整 E 的 seeded embedding、有限 oracle overlay 或计算 cap 中**尚未计入**的差异；若已经给完全同 law 的标准挑战嵌入则为零。不得把未经实例化的 Delta 写成零，也不能将 (10) 左边称安全强度。这里先在原 setup 上从 IBS 赢法得到公开 E 的短核成功率，再移动整个 E；它与“先移动伪造概率、再 fork”的另一种损失次序不能混用。

公开 sampler 已由本批独立 [effective-samplers.md](effective-samplers.md) 具体化：mu 是 N 个独立 `D_Z,s_master`；目标 Sim z 是 D 个独立 `D_Z,s_signature`，使用相应 `WideScalarGaussian` deep 选项、`batch_certificate(count=N or D,error_bits=192)` 和 `AggregateByteSource`。E0 的 H 个 `[0,p)` 均匀值用独立 bounded rejection，c 用 n/8 B。n512 deep 的 U/z 到各自理想 product law 的完整 TV 均 `<2^-177`，E0 的 bounded rejection abort/TV `<=2^-3574`，c 精确均匀。可以在其逐历史及独立熵前提下取 `delta_pub<=delta_U+delta_E0`、`delta_sim<=delta_z`；不是把它们设成零。有效硬字节 cap 分别为 U 11,104,872 B、z 13,744,738 B、E0 524,288 B、c 64 B；本批构造的是 n512 证书，没有执行 n512 抽样生命周期。

这些独立 batch 证书没有实现整个 adaptive reduction；尤其第 7 节 finite raw-prefix 条件生成器还须给 bounded 实现/成本，有限概率枚举不构成该 PPT 前提。每轮合成时也须真正使用上述 kernel，不能将它的证书移植给其它 sampler。

一次 Run 至多 Q_I 次公开 Dom、q_S 次目标 Sim/known-key Sign（已知 key Sign 含至多 L 次尝试），以及其全部 raw/H2 调用。E 最多两次完整 Run；每个 D_j 跑一次这样的 E。fork 固定一条 tape 但在新后缀下可能触及不同身份和消耗不同长度的 sampler，必须按最坏每轮预算收费；不能仅用第一次实跑时长或只数外部哈希查询。

## 10. 本项完成范围与待核前提

已给出：latent raw/final 门的完整 pair 恒等式与 TV；与 J 独立母空间上的事件费用缩放；目标 Sign/Extract 和失败语义；诚实参考内的全身份 alias 界及跨身份 H2 owner 处理；raw-first-touch 的 classical overlay 构造；整个 root-free 提取器的 16 列 MLWE 区分器接口；确切 HNF-MSIS 分布、环维数与范数。

公开 U/z/E0/c batch 的 bounded 实现和 n512 数值证书见 effective-samplers；仍须另行核验/实现：raw-prefix 条件生成器的 bounded kernel/成本；整个公开 kernel 到 adaptive reduction 的实际合成；真实服务/全局 cap 到独立诚实参考的完整 Delta_0；seed/matrix-XOF 嵌入及每层重复计费审查；所有 query/运行预算；该合数 Q、环与 CBD1 分布下的 MLWE/MSIS 具体困难性估计。本文不把旧 ledger 或有限合成概率检查当作这些完整前提的证明。QROM 相干首触及、重编程与重绕不由以上经典构造覆盖。

本项仅新增文稿，未执行密码学实例、未改生产代码或冻结证书。一次公开 Python 精确算术核对了 `Q=3*43*127*31^8`、4Bsig、整数无穷范数界、`Q^2>4Bsig`，并穷举 Q_I=2 的两位玩具例子，e=0/1/4/1/2 时分别得到猜中率 1/2、3/8、1/4。这不是密码学攻击或分布实验；一般推导不依赖这些有限检查。数学推导与代码运行/参数安全估计分开交付；由 root 统一审查与提交。
