# SRGG：经典 Fiat–Shamir 签名模拟与隐藏目标合成

2026-10-16。本文证明**显式前提下的经典逐历史 Sign 模拟距离**，并说明怎样与隐藏 single-index 目标合成。不是实际 SRGG、seeded 矩阵困难性、完整 IBS 或 QROM 的安全证明。保留 native strong 目标；不修改算法、哈希、冻结 bridge 包或参数；`security_claim=none, backend_admitted=false, parameters_are_formal=false`。

## 1. 固定前提、历史与两个 joint law

使用 [native-sig.md](native-sig.md) 的系数空间和密度 shape 约定。固定目标 h、一个满足 `Ay=h mod Q` 的真实密钥 y、公开 `Sigma` 和响应范数门 B。设 `M_h=Abar_h`，挑战空间为 `{0,1}^n`，恢复函数为

```text
Rec_h(c,z)=M_h*z-Q*J*c mod 2Q.
```

固定完整可达历史 F：当前公钥/身份、该次消息 mu、此前 H2 表、私钥和服务状态均已给定。新的扰动和签名熵独立于历史。H2 是经典 lazy-sampled 随机函数；查询的**完整规范输入**为 `x=(mpk,W,mu)`，下文的“已有 entry”包含攻击者、已知密钥签名及所有内部查询所建立的点，不只计外部 q_H。

需要两项逐密钥、逐历史界：

1. 理想真实第一阶段取 P 后的 `W=M_h P mod 2Q` 满足 `max_w Pr[W=w|F]<=2^-alpha`。native-sig §6 给 full-cap 理想类的 `alpha=36351`，不是有限实现的同等熵声明。
2. 对独立均匀交互挑战 c，理想真实 joint `I_y=(W,c,z)` 与无密钥 simulator 的 joint S 满足 `TV(I_y,S)<=delta_zk`。S 独立取 `c uniform {0,1}^n,z~D_(Z^D),Sigma`，再取 `W=Rec_h(c,z)`。两边均**尚未施加范数门**。

另记真实交互响应的逐历史拒绝率 `Pr[||z||^2>B|F]<=eta`。这些前提只在 GoodKey 时成立也可以，但坏密钥概率必须按第 5 节另付。本文不以只知 z marginal 的 TV 代替 joint TV，不以实验观测范数代替 eta。

## 2. 交互 HVZK 桥的独立核查

令 `Z=M(zeta), zeta=1+X^(n/2)`。`Z^T Z=2I`，故 `L_zeta=Z Z^n` 是旋转后的 `sqrt(2) Z^n`，行列式 `2^(n/2)`。`v=Zu+c` 的条件 law 是陪集 `c+L_zeta` 上 shape `nu I` 的离散 Gaussian，其中 **`nu=2r^2`**；不应漏掉 ζ 的 factor2。

对 `P~D_(Z^D),S_y`、`S_y=Sigma-nu T T^T`，完成平方的剩余矩阵恰为

```text
C=(nu^-1 I+T^T S_y^-1 T)^-1
 =nu I-nu^2 T^T Sigma^-1 T.
```

每个固定 c 的响应质量相对目标 Gaussian 的 tilt 是

```text
Pr[z|c]=D_Sigma(z)*Theta_C(c-a_z)/E_(Z0~D_Sigma)[Theta_C(c-a_Z0)].
```

这是真正归一化后的比值，不假定各 c 的 normalizer 相等。若所有实中心满足 `|Theta_C(t)/K-1|<=epsilon_C<1`，则 joint TV 的充分界为 `delta_zk=epsilon_C/(1-epsilon_C)`。ζ 对偶格的最短长度平方为 1/2，所以由 `C>=c_min I` 得到的标量 theta/smoothing 输入必须为 **`c_min/2`**。native-sig 中已经采用该因子；将 c_min 原样代入单位格会错误强化证书。

这些是点态的、与 key-generation law 无关的条件陈述；可以对任何同一真实 y law 积分。它们仅给**独立交互 c**，尚不能直接把 c 换成 FS 的 `H2(W,mu)`；第 3 节用 fresh-entry 条件建立这一步。不同挑战但 `eta(c)=eta(c')` 时可能有 `Delta z=0`；不在本节消去，已由 [strong-games.md §5/8](strong-games.md) 的 owner/商挑战提取单独处理。

## 3. 一次 classical FS Sign：只支付一次 joint-TV

设当前表大小至多 M。真实第一阶段在查 H2 前先生成 W。对固定 mu，能使 `x=(mpk,W,mu)` 已存在的 W 至多 M 个，故

```text
Pr_real[x already in table | F] <= M*2^-alpha.                 (1)
```

这里是理想真实 W 的点质量界，不是 simulator W 的经验熵；同一 entry 的重复查询只算一个点。

先定义一个证明用真实实验：若 x 已有则**整局 bad/abort**，不读取后覆盖；否则其 H2 回复是尚未抽取的独立均匀 c。因此 fresh 分支可以先运行独立 c 的完整交互 law，再处理表；不必条件于“W 未碰撞”后重新估计 HVZK。

对完整 joint 使用同一历史相关确定映射 `F_table`：

```text
input (W,c,z):
    if (mpk,W,mu) already exists: entire game bad/abort;
    if ||z||^2>B:                 entire game bad/abort;
    otherwise:
        insert a fresh entry ((mpk,W,mu),c), never overwrite;
        log the exact valid canonical signature (mu,z,c);
        set owner=sign for this target h;
        actually return the logged signature.
```

范数失败时**不编程、不建立 sign-owner、不继续游戏**。在真实 fresh RO 实验中可以把 table insertion 延迟到范数通过之后：失败被整个吸收成 bad/abort 后没有后续查询可见；成功分支与立即设定该 fresh 值完全相同。不能把此“整局失败”的分析便利偷偷改成“返回 bottom 后继续留着已编程点”。

对 I_y 与 S 应用同一个 `F_table`，由数据处理

```text
TV(F_table#I_y,F_table#S)<=delta_zk.                            (2)
```

碰撞检查、norm gate、programming、日志与 owner 都在同一映射内，故 (2) **不乘 M**。特别不能先给 simulator 的 W 一个 `2^-alpha+delta_zk` 的 atom 界，再对 M 点做并集；那会人为制造 M*delta_zk。

为了与原来可 norm-retry 的真实 FS Sign 比较，再把任何真实 norm 拒绝标记成整局 bad。该改编与真实执行只会在这些拒绝事件上分歧；按真实理想逐历史界支付 eta。结合 (1)(2)，一次尝试的保守距离为

```text
delta_sign(F)<=M*2^-alpha+delta_zk+eta.                        (3)
```

Sim 自身的碰撞/超范数概率可能比真实大 delta_zk，但已经由 (2) 包含，不另付 M*delta_zk 或第二个 delta_zk。若只比较真实/模拟双方**共同 norm-gated**的完整 law，可不另加 eta；这里加 eta 是为把实际 norm-retry/继续行为换成整局 bad，以保证 sign-owner 语义。

若 source 最多 L 次尝试、最多 q_S 次请求，使用 `A_sign<=q_S L` 为保守总尝试上界即可。证明用“首次 norm 拒绝整局终止”不意味着修改已冻结的运行算法；实验间差异全部计入 (3)。不能把实际 L 次重试的成功条件 law直接认作一次 S 的成功条件 law。

## 4. 整场 finite→ideal，再作 FS 模拟

先用已有完整逐历史 sampling 证书把整场有限真实执行换成理想 P、gadget/u 及明确的理想发钥参考。若有限 Sign 每尝试完整 TV 为 delta_fin，最多 q_S L 次，则此阶段只付

```text
Delta_fin,sign<=q_S L delta_fin.                              (4)
```

实际发钥、HNF、norm 和状态的其它距离仍按其自己的 ledger 加入。**只在完成 (4) 的理想实验中**使用 alpha 和 (1)，不把 finite TV 再乘每个 H2 点或 M。否则同一分布差异被重复放大。

若所有相关 ideal key 都满足 GoodKey，表大小逐次有界 M_t，则由停止于首次分歧的耦合及 (3)

```text
Delta_FS<=sum_(target-sign attempts t)
    (M_t*2^-alpha+delta_zk,t+eta_t).
```

只用统一上界可取 `q_S L*(Mmax*2^-alpha+delta_zk_good+eta)`。Mmax 必须包括已知密钥子程序、所有 retry 和模拟器本身产生的 H2 entries。公开 alpha=36351 很大也不能证明查询总数可忽略；计数是 reduction 的时间/查询契约。

## 5. GoodKey 和 owner/replay 的边界

native-sig §4 的 GoodKey 是分析事件 `||y||^2<=Ucap/4`，**不改变实际抽钥、密钥缓存或 hash 像 law**。其理想每目标坏成功输出 tail 为 `delta_bad<=2^-256`；当前完整发钥桥 delta_key 与它分开。一个正确次序是先按首次发钥付 delta_key，再对该理想抽钥标坏事件 delta_bad，之后在好 key 上逐 Sign 使用 delta_zk_good。不能每次重复签同一 key 都重新支付一次坏 key 概率，也不能只因本窗口没有 Extract 就漏掉先前发钥或 Sign 隐式发钥。

默认全类 alpha 是理想 P1 承诺的 full-cap 界，不靠 GoodKey 的高概率性提供它；GoodKey 只用于收紧 HVZK 项。不能成功条件化 KeyGen 后还沿用未条件化的 H1 像分布；保留 bottom 和分析坏事件最稳妥。

对程序重放，必须保留完整 canonical entry、首次 owner、实际返回的有效签名和全部公共状态。所有 Sign simulator 的随机性归入独立随机带 r；给定 r 和先前 free H2 回复，模拟器、碰撞检查、gate/program/log 均为确定程序。重跑应从空表和同一初态开始，不复用第一次的后缀表；变长 sampler 重新按程序消费同一带，不要求不同后缀消耗相同长度。该条件仍需算法具备多项式时间/熵上限；理想 Gaussian 的形式 law 本身不是有效算法证明。

在这些条件下，sign-owner 必须对应**同一目标 h、已实际返回**的有效规范签名。范数/采样失败不能留下可作 CUR 证据的 owner。free/sign/未查询 entry 的分支以及可重放签名编程的 fork，直接交由 [strong-games.md §5.2/8.1](strong-games.md)；本文不重做其二阶矩和商挑战计算。尚需把 (4)(3) 得到的完整模拟距离与其 fixed-pk 优势输入对应，不能用 IBS 优势直接替换为 fixed-pk SIG 优势。

## 6. 隐藏 single-index 与模拟误差次序

以下给一个可证明的**条件合成引理**，用于避免先除 Q_I 再扣未缩放的全部签名误差。Q_I 是 H1 首次出现身份数的确定上限，包含内部首用和最终验证。令 J 均匀取 `{1,...,Q_I}`，仅第 J 个身份使用未知挑战 key 的模拟 Sign；其它身份由公开 SampleDom key 真实执行，内部 H2 查询都计入 free-query 预算。

假设存在完整诚实虚拟参考 R：其所有身份 pair 独立同 law、固定服务/各 oracle 精确匹配，而且 R 的完整轨迹（包括隐藏的真实 key）与 J 独立。底层 Gen 的 h law 可以是 `f_A(SampleDom)` 的非均匀 image law；不需要这一步本身强迫 h 完全均匀。真实均匀 H1 到该 image-H1 的**经典**完整 hybrid，需另付至多 `Q_I*TV(image,uniform)`，且保持 conditional key law 同时匹配。

对 R 的第 t 个 Sign/尝试，设其身份首次索引为 i_t。即使身份是自适应选择，i_t 是 R 历史的函数，故

```text
Pr_R[i_t=J | full honest trajectory]=1/Q_I.
```

现在只替换 `i_t=J` 的签名 transition。若在每个尚未发生分歧的共同历史中，该替换可用一个**与 J 无关、对该历史/目标 key 类统一有效**的距离上界 d_t，则首次分歧耦合给

```text
Pr[first divergence]
 <= sum_t E_R[ 1{i_t=J} d_t ]
 = (1/Q_I)*sum_t E_R[d_t].                                  (5)
```

第一步可在诚实参考上丢掉“此前仍耦合”指示函数，因各项非负；**不能先对生存或最终猜中事件条件化**再声称 J 仍均匀。只要事件是点态/逐历史的，生存会泄露 J 并不破坏这个未条件化的上界。若 d_t 依赖模拟器才有的未耦合历史、未统一的未知 key，或 R 本身先按 J 筛 key，则此证明不适用。

若诚实参考成功率 epsilon_R，每条成功轨迹唯一最终身份 f，经典 single-index 的猜中成功率是 `epsilon_R/Q_I`。结合 (5)，在明确的完美 key-mapping/规范新鲜性前提下

```text
epsilon_SIG,sim >= (epsilon_R-sum_t E_R[d_t])/Q_I.
```

例如统一每目标理想签名尝试界 `d=Mmax*2^-alpha+delta_zk_good+eta`、尝试总数不超过 q_S L，可将这部分误差置于分子：

```text
epsilon_SIG,sim >= (epsilon_R-q_S L d)/Q_I.                  (6)
```

目标身份 Extract 的实际归约会提前中止；可在分析虚拟实验中回复隐藏的真实 key。最终合法伪造若猜中 J 就不曾提取该身份，因此实际归约与此虚拟实验在接受分支一致，不需把所有目标 Extract 中止作为额外 transcript TV 硬加。

**全局 key/finite hybrid 的处理。** 若先把整个 honest 实验换成一个与 J 无关的精确参考，距离为 Delta_global，则先用 `epsilon_R>=epsilon_IBS-Delta_global`，之后再除 Q_I。因此 (6) 可写

```text
epsilon_SIG,sim >=
 (epsilon_IBS-Delta_global-q_S L d)/Q_I.                     (7)
```

Delta_global 可包含已证明的完整 key/H1-image/finite 模型桥；不能以一个未认证的数值 ledger 代替该前提。GoodKey 若用 (7) 的全局坏事件处理，应在**与 J 无关的完整诚实参考**上按不同发钥执行计入，并以未条件化坏事件损失成功率；不重抽、不把成功 keygen law 改名为原 law。

如果只掌握“对每个固定 J，模拟距离至多 D”的通常界，而没有上述共同 R、点态耦合与独立 J 条件，那么只能保证 `epsilon_R/Q_I-D`，**不能**把 D 擅自除以 Q_I。当前 (7) 是清楚可核验的合成义务；它不是宣称实际服务、挑战 Gen 和全部有限资源状态已满足这些前提。

## 7. 有限 hash-rejection 层须另计

只读核对 `structured_execution.identity_target/public_matrix` 和 `wang_pw.hashing.uniform_values`：两者使用 `XOFStream`，每个系数最多 256 个 uniform candidates。当前 `Q=13972913866395903`，每次读 7 B，`floor(2^56/Q)=5`。在**理想独立 uniform XOF bytes**前提下，单 candidate 拒绝率为

```text
rho_hash=(2^56-5Q)/2^56
        =2193024705948421/72057594037927936 < 1/32.
```

故一次 H1 的 1024 个系数失败概率至多 `1024*rho_hash^256<2^-1270`；一次根 public-matrix 展开的 2048 个系数失败概率至多 `2048*rho_hash^256<2^-1269`。各接受剩余类的 candidate 数量完全相同，所以成功输出恰均匀；不能把失败质量静默删去。最坏读取 `count*7*256<count*4096`，不会先触发另一个 stream-read-budget 失败。完整经典 hash 层可按真正新输入/调用数给并集；重复固定输入的失败是同一确定结果，不会靠重复请求重新获得新 hash 熵。

这些项属于 finite hash 模型桥，可进入 Delta_global，**不属于** commitment entropy、delta_zk 或 GoodKey 的那一项。它们以精确有理数表示，不能把极小上界用 float 下溢成 0。SHAKE 到理想 XOF 仍是模型假设；公开 seed 诱导矩阵与一个可嵌入的 uniform/structured 难题矩阵之间的分布问题也没有因此解决。

## 8. 当前可用数字与未完成的对应

当前 native-sig 证书提供 full-cap 理想 alpha=36351；GoodKey 内 `delta_zk_good=4667/2^256`，坏 key/finite/norm 项按该文件和总 ledger 的独立字段使用。GoodKey 的坏概率按首次发钥，签名项按实际尝试；两者不互相替代。本文没有重新运行 n512 或制造新测试通过数；上述一般证明不是由少量样例建立。

当前已经可核验：factor2/ζ 格的全中心归一化、fresh FS point 上独立 c、一次 joint-map TV、norm/owner 的完整 bad 语义，以及明确条件下隐藏 J 的误差缩放。仍需完成或在总归约中显式假设：

- 实际 public/seeded matrix law、SampleDom/conditional key 与底层挑战 Gen 的有效对应；采样算法的时间/熵上限及全部固定服务状态。
- 总归约的 H1/H2 输入与预算、适用的完整 Delta_global，以及需要多次执行时真正的运行时间；没有将 H2 内部查询从 q_free 漏掉。
- owner/fork 所得非零短核到所选实际困难假设的分布归约；现有 planted/seeded 情况不能仅凭代数关系称 uniform MSIS。
- QROM 的相干签名模拟/重编程及量子查询损失。这里的经典表和隐藏首次序号不能直接搬入 QROM。

这批是原生 strong 的条件证明进展，不是正式参数、安全等级或 HIBE 选择的结果。
