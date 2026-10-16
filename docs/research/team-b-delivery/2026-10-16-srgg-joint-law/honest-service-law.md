# SRGG 完整诚实服务 law：根、固定发钥、签名和异常恢复

2026-10-16。本页将已有局部证书组合成**指定参考下的完整诚实服务轨迹界**，
而不再把所有已覆盖项合并为一个未定义的 Delta0。这里的“完整”指下文明确的
API 观察、经典服务调用、故障模型和密码学随机性模型；它不等于完整 IBS
安全归约、QROM 模拟器、生产 SHAKE 证明或正式参数准入。

`security_claim=none, backend_admitted=false, parameters_are_formal=false,
nist_security_category=null`。

## 1. 证据、固定参数和观察边界

本页只组合现有实现及冻结证书，不更改其算法、参数、采样过滤或失败处理。

| 来源 | 本页使用的事实 |
|---|---|
| [structured_execution.py](../../../../experiments/research/candidates/srgg/structured_execution.py) `Execution.setup/key_extract/sign` | seed 与 CBD1 根；一次发钥；raw 范数门；HNF 重构；最多 L 轮顺序签名；只有响应范数拒绝可重试 |
| [structured_samplef.py](../../../../experiments/research/candidates/srgg/structured_samplef.py) `StructuredSampleF` | 全 CBD1 支持类、全公开用户范数类的统一完整 law TV；局部有限上限及 abort 已包含 |
| [integrated_bridge.py](../../../../experiments/research/candidates/srgg/integrated_bridge.py) `execution_certificate` | 有限发钥、gadget 分母、raw 卷积、HNF/key law、签名顺序 Gaussian 和范数界的组合 |
| [integrated-bridge.json](../2026-10-16-srgg-bridge/integrated-bridge.json) deep 行 | 本页参数点的冻结局部数值；不是正式安全等级证书 |
| [mixed-domain.md](../2026-10-16-srgg-bridge/mixed-domain.md) | 全局 mixed domain、条件 latent law 和 HNF 推前恒等式 |
| [seeded-xof.md](../2026-10-16-srgg-classical-rom/seeded-xof.md) | 理想 byte-XOF 的有限解码、含失败的 raw prefix 和条件 prefix law |
| [service-law.md](../2026-10-16-srgg-bounded-runner/service-law.md) | 缓存、pending/issued/blocked、锁、恢复和带相同故障 kernel 的状态对应 |
| [service_budget.py](../../../../experiments/research/candidates/srgg/service_budget.py) | 五份输入参数核对、16 个声明源码哈希核对，以及精确 Fraction 预算 |

固定研究点为

```text
n=512, d=2, w=8, b=31, p=16383, r^2=64, L=16,
Q=13972913866395903,
s_master^2=1031865954433,
s_signature^2=22159188660729268928705,
Rcap=169060917974302720,
Ucap=338122385570209792,
Bsig=238255596480161099521436160.
H=dn=1024, N=(2+w)dn=10240, Dsign=N+n=10752.
```

数值 profile 为 `query-bounded-deep`：normal ticket 768 bit，series 精度
1024 bit，scalar 精度及向量 dyadic 为 384 bit；各有限 scalar/tape/aggregate 上限与冻结
证书完全一致。本页没有增加抽样、重新筛根或修改密钥范数门。

观察包括合法或非法 API 请求、规范返回字节、公开失败标签、调用/完成顺序、
缓存结果和重开结果；若有攻击者，也包括其 oracle 查询/回答及最终量子状态。
私有根、磁盘明文、Gaussian 内部轨迹、耗时、实际耗熵长度和其他侧信道不公开。
若要包括这些量，须重新给相应**联合** kernel 的界。

服务的确定状态按旧 `service-law.md` 保留完整根、已提交 map、事务阶段、
pending 值和存储 image。持久 `FixedIssuer` 自身没有 `sign` 方法；这里的
服务轨迹是调用方先 `IssueOnce(id)`，再对其原固定 key 调用
`Backend.sign(key,message)` 的组合。不能据此声称新增了持久签名 API。

## 2. 两个具体参考，避免混淆 hash 费用

### 2.1 保持同一 oracle 的参考 R_FA,F

先定义 actual finite execution `C_FA,F`。它使用实际 Setup/有限采样代码、
同一个固定完整 hash/XOF 函数 F、真实固定缓存和持久状态机。模型中 fresh
random bytes 独立均匀；Sage 整数环运算和已声明 MPFR/区间运算正确。
F 可以是一次固定的理想 oracle 表；同一 identity/commitment 的重复查询
保持同一值，任意先前 raw prefix 也不会在后续 H1 调用时被重选。

`R_FA,F` 仅作以下替换：

1. Setup 原样执行，包括 seed、CBD1 witness、矩阵 XOF 解码、失败和持久化。
2. 新身份解出同一 H1 目标 h 后，将一次有限发钥替换成 §3 的 latent 双门
   reference；所有成功 key 与失败都只缓存一次，保留相应公开失败标签。
3. 签名中将 finite SampleF 和有限 u scalar 换成其理想顺序 Gaussian。
   W 仍由本轮 perturbation 计算，c 仍等于**同一 F 的** H2(W,message)。
   不将 c 改成独立 interactive challenge；保留最多 L 轮范数重试和最终失败。
4. 规范序列化、范数门、容量、pending/issued、并发锁、重开及 §5 的故障
   kernel 保持同一语义；不将失败服务悄悄换成可重试的无状态服务。

因此该参考不要求 h 或公开矩阵在固定 F 下均匀，也不为 hash 解码失败另付费用。
它是整个有限实现到指定理想**采样**服务的比较，而非普通无故障 IBS 游戏。

### 2.2 经典理想 byte-XOF 的 decoded-uniform 参考 R_FA,U

在经典理想 byte-XOF 模型中，还可将公开矩阵扩展和每个 canonical H1 point
改为“均匀 decoded 值 + 与该值一致的完整条件 raw prefix”。令 G_h 为旧文中
保留解码失败的 raw kernel，K_h 为 G_h 条件于解码成功的 kernel。矩阵及身份
每个系数的有限 rejection 解码在成功条件下准确均匀，故

```text
sum_h Uniform(h) K_h = law(raw prefix | decode success).
```

必须保存条件 raw prefix，不能给出均匀 h 后另外暴露独立 raw bytes。prefix
之外的字节保持独立；首次请求 partial prefix、offset 或 H1 均建立同一个
point 的完整共同状态。首次 raw 查询早于 Extract 时，随后 Extract 使用已经
绑定的 h。`conditional_xof.py` 当前实现的是 G_h；K_h 在此是数学参考，
不声称新增了有界生产 K_h router。

若矩阵解码失败概率界为 beta_M、每个 H1 point 为 beta_H，则按**经典首次触碰**
耦合，在至多 Q_I 个不同 canonical identity point 上付 beta_M+Q_I beta_H。
这是保留全部失败的未条件化比较；不能从成功收据中免费删去失败。
这里 Setup 先于攻击者对本次 seed 的相关 oracle 查询；若有 setup 前 oracle
历史，需使用同目录 `seed-prehistory.md` 的明确量词和费用，不沿用这个简化前提。
本段的线性首次触碰证明不用于量子叠加 raw 查询；量子 row 替换另见
[quantum-row-switch.md](quantum-row-switch.md)。

实际 Setup 先读取独立 32 B seed 与 `2*d*d*w*n` 个 witness bytes，每字节
经 `(x&1)-((x>>1)&1)` 准确生成一个 CBD1 系数；然后扩展 Ahat，并由陷门
关系确定 B。它没有 SampleF、好根概率筛选或失败后重选。新鲜理想 XOF point
的矩阵解码成功概率不依赖 seed/witness，故**仅条件于该解码成功**时 witness
仍是原 CBD1 law、decoded Ahat 准确均匀。但 `initialize` 最终 API 成功还
要求目录、规范状态、保存与锁退出等成功；依赖根/存储内容的故障 kernel 可改变
这个成功条件分布。故不得把成功初始化收据当作未偏置 root-law 证书：保留
故障 reference，或另付未条件化故障事件，而非免费条件化整个初始化成功。

## 3. 发钥的完整 kernel，包括 HNF、失败和全根统一性

令 `A=[I_H,A_tail] mod Q`，J 嵌入前 H 坐标，C_Q 只将前 H 个整数系数
中心化，其余 tail 不变。公开固定 `mu=D_(Z^N),s_master^2 I`。取

```text
U~mu, E uniform {0,...,p-1}^H independent,
Y=C_Q(U+JE), h=AY mod Q.
```

对指定 h，`e_h(u)=nonnegative_mod_Q(h-Au)`，
`S_h={u:e_h(u) in {0,...,p-1}^H}`。mixed-domain 恒等式给出

```text
law(U,E,Y | AY=h)
 = law(U,e_h(U),repair_h(U)), U~mu|S_h,
repair_h(u)=C_Q(u+J e_h(u)).
```

引用实现确实使用这个 repair：`raw_from_values` 验证
`AU=h-error mod Q` 且 error 每系数在 `[0,p)`；`reconstruct` 保留原 tail，
把 head 设为 `center_Q(h-A_tail*tail)`，因此恰等于 `repair_h(U)`。
head aliases 的质量自动相加，不能将该输出称为未经证明的零中心 exact-fiber
Gaussian。其全局 latent mu 不依赖 h、私有 witness 或发钥历史。

reference 同时保留 `||U||^2<=Rcap` 和 `||Y||^2<=Ucap`；未通过时输出
同一 raw/final 失败类别而不重抽。公开不等式

```text
Ucap >= 2 Rcap + 2 H (p-1)^2
```

保证 raw 通过即 final 通过。它只消去**额外 final 门**，不把 raw 失败概率变零。

令 a_M 是完整 master SampleF law TV，a_G 是完整 gadget finite TV，
e_rec 是理想 gadget recurrence 到球形 fiber 的偏差，e_conv 是其 raw
卷积偏差。所有 finite abort 均保留。旧收据给出

```text
delta_E = complete_issuance_to_common_hnf_gate_reference_tv_upper,
t_R     = raw_union_norm_reject.probability_upper,
delta_I = min(1,delta_E+t_R).
```

delta_E 已包括 a_M、a_G、e_rec、e_conv 及该比较中删除 raw 门的费用；
再加 t_R 是恢复 latent 双门的保守比较。这个选取会保守重复支付 raw tail，
但不遗漏它，也不反向推断 HNF 前 TV。更紧的 raw 同门比较可直接用
`a_M+a_G+e_rec+e_conv`，须单独沿原 raw kernel 证明；本页数值一律使用
已在 `service_budget.py::components` 固定的 delta_I，不替换冻结收据。

deep 证书给出

```text
a_M <= 2^-178, a_G <= 2^-178,
e_rec <= 2^-277, e_conv <= 2^-276,
delta_E <= 2^-177, delta_I <= 2^-177, t_R=2^-256.
```

这些上界对**所有可达根、目标及共同历史**统一：Setup witness 的每个系数
准确服从 CBD1，support 为 `{-1,0,1}`；public support-class 谱界覆盖全部该
支持，不通过抽出好根建立参数。`integrated_bridge` 将同一全类 beta 传给
完整 A-kernel basis GSO，再传给全 coset smoothing 和卷积证书，允许任意 Ahat。
master SampleF 的公开计划/series/aggregate 也使用同一全类 beta。因此不是
只对冻结样例根或非自适应目标成立。正式的 Module-LWE public-key 隐藏性
不在这一统计比较中证明。

这里不支付 `GoodKey` 坏成功 key 的费用：参考保留所有公开 Ucap 内 key，
并未把它们筛成 GoodKey。GoodKey 只在后续 ZK/安全模拟需要该性质时支付。
同理，mixed image 到均匀的误差属于后续 identity-row 替换，不属于保持同 F
和同 h 的本节发钥替换。

## 4. 签名逐尝试 law 和经典接口的 cq 提升

对任何公开 norm-cap key y，sign SampleF 计划使用
`beta=1+(n/2) Ucap`，其 finite TV 对该公开类中所有 y 统一。设

```text
delta_S = sign_attempt_finite_tv_upper
        = sign SampleF complete TV + u batch complete TV <= 2^-178.
eta     = ideal_sequential_sign_attempt_norm_reject_upper = 2^-255.
```

按以下顺序 hybrid：先保持有限 P，将 u scalar 换为 ideal；对共同 P、固定 h、
message 和完整 H2 表，W 及 c=H2(W,message) 完全相同，scalar bound 对由该
自适应 c 得到的全部允许中心统一。再比较完整有限 P 与 ideal P，包括有限
采样失败；此时 exact ideal u 是两边共同的全域 kernel。这样无需假定无限支持
的 ideal P 满足有限 perturbation guard。耦合不匹配的尾部已包含在有限 TV 内，
不能另作免费丢尾。相同 response 函数、范数门及失败标签的推前因此给出
**完整一轮** `(W,c,response-or-failure)`
TV 至多 delta_S；不要求 c 独立于 P、identity 或 oracle 历史。
拒绝后下一轮 fresh coins 独立；按轮 hybrid 最多 L delta_S。实际停止轮是
自适应 stopping time；比较整个“第一次接受或 L 轮失败”law，绝不条件于最终接受。

理想每轮给定任意共同历史的范数拒绝概率至多 eta，故连续 L 次拒绝至多
eta^L。有限范数拒绝可用 delta_S+eta；一个保守的实际 sign-operation
algorithmic abort 上界为

```text
min(1, L delta_S + (delta_S+eta)^L).
```

这里 finite sampler abort 已含在 delta_S，不能再作为额外 TV 项相加。
上式不包括故障、坏熵源或额外全局资源 cap。

**引理 1（同一 oracle 下的 cq lift）。** 固定完整函数 F、私有 root 和
服务经典状态 s。假设 Issue/Sign 的输入是经典的，fresh sampler coins
独立于 F 及攻击者量子 reference；实际与参考的完整经典输出和新服务状态
kernel 对每个合法 `(F,root,s,input)` 的 TV 不超过 delta。则将服务改用
reference 后，扩展的 cq 状态 trace distance `T=||rho-sigma||_1/2`
至多 delta，即使攻击者此前已对 F 作量子查询。

证明：把 F、root、s、input 放在分析用的经典隐藏 register X 中，攻击者
reference 条件态记为 rho_E,x。一次 classical service call 的差为按 x、y
分块的算子，其 trace norm 等于各块标量差绝对值乘 rho_E,x 的 trace。
因此

```text
T <= sum_x p_x TV(P_x,R_x) <= delta.
```

丢弃隐藏 register 只会减小距离。后续针对**同一 F**的量子 oracle unitary、
攻击者任意通道和经典服务后处理均不增加距离；混合与自适应序列用 triangle
inequality 逐次累加。证毕。

根/历史可与 F 及攻击者 reference 相关，前提是逐条件状态的全类界成立，
而不是只证明一个平均样例。此处 §3–4 已给该统一性。该引理只替换 fresh
经典 sampler kernel，不改变随机 oracle law、不支持量子叠加 Extract/Sign，
也不自动提供 QROM 中 programming/reprogramming 的安全归约。

## 5. 缓存、持久化、故障和历史如何进入同一界

故障和调度满足旧 service-law 的假设 S：可信合作进程；相同文件/锁语义；
共同因果 kernel 可看 API 历史、事务阶段和共同存储 image，但不能读取未被
比较的 sampler 内部轨迹、耗时或耗熵。缓存命中先于容量检查，重开不抽样；
新身份只尝试一次，失败后不重选。

给两边相同完整 Issue/Sign 结果和故障 coins，则编码、写 pending、写 issued、
删除标记、阻断与重开逐点相同，包装增加 TV/trace distance 为零。这个零是
**相同故障下的包装距离**，不是故障概率为零。尤其保留以下实际边界：

- `_begin` 在内层 try 之前；标记创建前失败可仍 idle，但尚未采样。
- 已写 issued、未返回时退出，可留下调用者未收到的已提交 key；重开复用它。
- 锁退出异常可发生于内层 try 外，未必执行 `_block`；原 issued 状态仍保留。
- pending/failed、损坏状态、公钥或参数不匹配、容量满均按实现拒绝；不以
  “修复”为名丢弃原状态再重抽。

对初始完整历史状态另给距离 delta_hist；它包括固定已发 map、根、oracle
table、存储和攻击者 reference 的**联合** law。若两边从同一个真实历史
分布续跑，则 delta_hist=0 只证明续跑比较；不能据此宣称此前历史已经理想。
要与从 genesis 的理想服务比较，应将此前的发钥、签名和 hash 首次触碰计入
总调用数。一个来源不明的外部 snapshot 没有可认证的 delta_hist；规范解码
成功证明格式与数学关系，不能证明它具有正确生成分布。

设从比较起点起至多 N_K 次首次新身份发钥、N_S 次 sign attempt、q_S 次
签名请求，N_S<=L q_S；Sign 为未发身份取得 key 时也计入 N_K。缓存、只读
恢复和重复 H1 point 不增加 N_K 或相应首次触碰数。

**定理 2（完整同 F 诚实服务 law）。** 在 §1–5 的随机性、算术、接口和
故障前提下，任意自适应请求、共同历史以及上限内的并发/重开策略满足

```text
T(C_FA,F, R_FA,F)
 <= Delta_FA,F := min(1, delta_hist + N_K delta_I + N_S delta_S).
```

纯经典观察时 T 即 TV；有量子 reference 和相同 F 的量子查询时使用 trace
distance。证明：按实际锁次序/经典调用逐步 hybrid。每次首次发钥应用 §3
统一界和引理 1，缓存零费用；每次 sign attempt 应用 §4；确定包装及共同
故障按本节保持距离，停止和重开为共同后处理。以全历史初态距离起算并
triangle 累加。所有失败和未收到响应的已提交状态仍在比较内。证毕。

**推论 3（经典 decoded-uniform byte-XOF 参考）。** 再满足 §2.2 的前提时

```text
TV(C_FA, R_FA,U)
 <= Delta_FA,U := min(1, delta_hist + beta_M + Q_I beta_H
                           + N_K delta_I + N_S delta_S).
```

矩阵 beta_M 只付一次，每个 H1 point 的 beta_H 在首次 raw/API 触碰时支付；
此前已建表的相关历史由 delta_hist 或从 genesis 的 Q_I 覆盖。此推论仍保留
同一故障，并非普通无故障 IBS reference。

## 6. 精确可用的当前预算和运行上限

旧 hash 证书中每系数拒绝基数
`rho=2193024705948421/2^56`，每个 rejection cap 为 256。因此

```text
beta_M <= 2048 rho^256 <= 2^-1278,
beta_H <= 1024 rho^256 <= 2^-1279.
```

`service_budget.load_inputs()` 在本次组合时成功核对五份输入、deep 参数和
16 个声明源码哈希；以下表用其 `components()` 的**精确有理数**先求和再
向上取二进制幂，不用显示后的粗 dyadic 项再次相加。

| 假定总调用上限；fresh genesis，delta_hist=0 | Delta_FA,U 上界 |
|---|---:|
| N_K=2，q_S=3，N_S<=48，Q_I<=4 | 2^-172 |
| N_K=2，q_S=2^40，N_S<=2^44，Q_I<=4 | 2^-134 |
| N_K=64，q_S=2^40，N_S<=2^44，Q_I<=2^40 | 2^-134 |

第一行与既有 audit 的 2-key/3-sign 计数对应；本页仅重新组合冻结值，没有
重跑该 audit。后两行是次数上限下的数学预算，不是执行过 2^40 次，不是吞吐
或寿命测试，也不认证一个更大的文件容量。固定 issuer 的最大身份数仍是 64，
身份最长 4096 B、消息最长 65536 B、wire cap 2 MiB；恢复读取的是同一状态。

下游 `ExactRing.poly` 还检查每系数至多 256 bit，不能忽略一个未收费的
resource abort。对本参数点，从冻结 `series.scale_upper_exact` 和
`operator_vector_rounding_l2_error_upper`、ticket=768、scalar radius<=2^56
可作完全确定的 all-path 包络：

```text
noise_cap = scale_hi * (4 D (768+1) + operator_rounding_error),
Pcap      = ceil(noise_cap) + 2^56 + 2,
digitcap  = (b-1) + b*(2^56+2),
rawcap    = Pcap_master + wd*n*digitcap,
zcap      = Pcap_sign + n*floor(sqrt(Ucap))*(2*(2^56+2)+1).
```

其中 gadget scalar 中心绝对值<1，u scalar 中心绝对值<=1；negacyclic
系数卷积用 n 乘积上界，witness 系数绝对值<=1，用户 key 各系数绝对值
<=floor(sqrt(Ucap))。计算结果为

| 有限执行中该类值的绝对系数包络 | 上界 | bit 长度 |
|---|---:|---:|
| master perturbation | 72070358661009598 | 57 |
| sign perturbation | 2036153001601083941 | 61 |
| gadget digit | 2233785415175766108 | 61 |
| raw U | 18299242191478536966334 | 74 |
| sign response（范数门之前） | 42905866362142479417608744997 | 96 |

线性累加中的 partial sums 使用同一绝对和上界；公开模 Q/2Q matvec 每项
先约减，输入均在上述界内。因而有限算法的这些下游 256-bit guard 在本点不
增加 abort。最终签名范数门把系数进一步限制为 44 bit；后端 `signature_size`
使用同一公开范数 cap 给最坏规范 wire 包络。这里仍假设算术库正确；数值不变量
或库故障不能仅凭有限样例宣布概率零。

audit 外层的全局 entropy cap 与 kernel 的局部 cap 分开：旧
`entropy_envelope` 已证明当前 audit parent 最坏 409591510 B<512 MiB，child
最坏 186612384 B<256 MiB，故**这一固定调用配置**的额外全局 cap 不触发。
固定 issuer 自身不含该 audit CountingEntropy cap。后两条 2^40 表行不能
继承同一 512/256 MiB 包络；若调用方另加总 cap，须另作全路径包络、把它保留
为共同 reference gate，或付未条件化的 cap 事件费用。

## 7. 哪些距离仍不能置零

从本页 reference 进一步变成普通无故障 IBS 游戏，必须另行说明比较对象。
若只在 infrastructure fault 事件 F、额外总 cap 事件 C 之外与目标游戏相同，
可由共同 coupling 加 `Pr[F union C]`，取截断于 1；这里概率是未条件化的。
没有故障概率模型时，该数值未知，但不妨碍本页带相同故障 reference 的界。
只保存一份无故障成功收据不能估计它，也不能把它从 law 中条件化删掉。

| 尚未由本页建立的项 | 精确缺口或应接文件 |
|---|---|
| 生产 SHAKE/OS 熵源到理想随机模型 | 本页无计算安全替换或熵源测量；同 F theorem 是条件 sampler 比较 |
| setup 前 oracle 历史 | `seed-prehistory.md` 的 seed 碰撞/量词及采用的模型；不能只用普通成功 root |
| quantum random-row 的 law 替换 | `quantum-row-switch.md`；§4 cq lift 不会改变 oracle 分布 |
| 未知外部 snapshot 的生成分布 | 需要完整 delta_hist 或可信生成 provenance，格式/方程检查不足 |
| 依赖内部耗时/耗熵/轨迹的故障、侧信道 | 需要扩充完整 joint kernel，当前有限最终输出 TV 不覆盖 |
| 操作系统或硬件故障概率 | 需部署模型；当前 state-machine 对应不估计其概率 |
| GoodKey、image uniformization、ZK 模拟和 H2 programming | 属后续安全模拟，不重复记入同 F 的诚实 sampler Delta_FA,F |
| 原文 PSF/SIG 前提、HNF/CRT、FS/QROM、安全参数 | 需各专门文稿、定理和估计；本页不给安全准入结论 |

相应地，旧冻结 budget 文件中的 `Delta0_complete_service_to_reference_upper=null`
不由本页偷偷改写。现在可以明确填用的是定理 2/推论 3 的**指定参考与模型**；
如果“Delta0”特指无故障生产 IBS 或全部 QROM reduction 的入口，必须带上其余
未量化项后再命名。研究参数、单次功能测试和本页分布计算均不赋予 NIST 类别。
