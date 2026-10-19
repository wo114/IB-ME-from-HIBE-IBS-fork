# SRGG 原参数的固定根发钥分布桥

本说明只分析原论文参数命名空间中的一次首次发钥。结论条件于一个已经固定、实际采样计划通过检查的根；不改变根分布、参数、发钥或 HNF 算法，也不涉及 HIBE。它建立有限采样到明确数学参考的分布比较，不证明原文 PSF/SIG 定理已适用、native strong 安全性、ROM/QROM 归约或正式安全等级。

原论文为仓库冻结的 [Constructing Efficient Identity-Based Signatures on Lattices](../../../../papers/2025_efficient_ibs_jia.pdf)，SHA-256 为 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。Table 3/4 的输入和实现约定见 [SOURCE_MAP.md](../2026-10-16-srgg-paper-baseline/SOURCE_MAP.md)。以下推导明确采用代码的密度形状约定，不把作者的“标准差”解释争议视为已解决。

## 1. 固定对象和适用范围

令 `n=512`、`d∈{2,3,4}`、`w=2`、`b=31`、`p=16383`、`Q=p b^w=15744063`，并记

```text
H=dn, M=wdn, N=2H+M.
A=[I_H,Ahat,B] mod Q,
T=[R;I_M], AT=F mod Q,
F=p[I,bI,…,b^(w−1)I].
```

`R` 是已经固定的 CBD1 根见证的系数算子，`A` 是对应公开矩阵。实际环运算在系数空间中表示为整矩阵；转置 `*` 表示该实系数算子的伴随，而 Fourier 表示中为共轭转置。

全文使用**同一份当前实现的精确 shape**：

```text
κ=PaperParams.r_squared, s=√κ, ν=b²κ,
a1=PaperParams.master_first_squared,
a2=PaperParams.master_second_squared,
Σ=diag(a1 I_(2H), a2 I_M),
Σp=Σ−νTT*.
ρ_D(z)=exp(−π z*D⁻¹z).
```

在字面 density-width 解释下 `κ=1.16²`；在物理标准差解释下，各 shape 采用 `PaperParams` 明确记录的有理转换。后者是实现的有理 shape，不在本证明中悄悄换成精确实数 `2π` 倍。连续协方差为 shape 除以 `2π`。这里要求 `Σp` 正定，有限 `PaperSampleF` 还要求其剩余形状、数值、中心和资源检查通过。

`paper_backend.Backend._master_plan` 使用中心零的 `PaperSampleF`；`PaperGadget` 使用居中小余数。原 `key_extract` 不含优化命名空间的 raw/user 范数门。对象的坐标、编码、容量和状态检查仍是不同的实际条件，第 7 节单独处理。

## 2. 居中余数下的真实递归支持

定义

```text
E_c={−(p−1)/2,…,(p−1)/2}^H.
S_h={u∈Z^N : h−Au mod Q 有一个代表 e∈E_c}.
```

因为 `p≤Q` 且本批 p、Q 均为奇数，`E_c` 在模 Q 意义下单射；该代表若存在便唯一，记为 `e_h(u)`。`PaperGadget.sample_scalar` 对规范残差 `v∈{0,…,Q−1}` 取

```text
e=center_p(v), state_0=(v−e)/p,
a_i=state_i mod b ∈{0,…,b−1},
k_i ~ D_(Z,κ,−a_i/b),
x_i=a_i+b k_i,
state_(i+1)=(state_i−x_i)/b.
```

这恰在 `Σ_i b^i x_i ≡ state_0 mod b^w` 的 gadget fiber 上生成整数向量；最后的 carry 不要求等于零。全部系数的 digit 数是 `M`。有限实现与理想递归的区别在 `k_i` 的有限标量核和中止，本节先讨论无中止的理想核。

对任意整数向量对 `(P,x)`，令 `u=P+Tx`。给定 P 后，x 是相应 gadget fiber 的元素，当且仅当 `u∈S_h`。特别地，固定任意 `u∈S_h` 后，**所有** `x∈Z^M` 都对应合法的 `P=u−Tx`：

```text
h−A(u−Tx) ≡ e_h(u)+Fx mod Q.
```

右边的小余数仍为 `e_h(u)`。这一步保证第 4 节对 x 求和时没有省略支持限制，也没有额外假定 e 均匀。

## 3. 一次移除理想递归的联合分母

对一个 residue a，定义标量正规化量

```text
z_a=Σ_(k∈Z) exp(−π(k+a/b)²/κ).
```

理想 digit 输出的概率为 `ρ_(νI)(x_i)/z_a`，因为 `x_i=a+b k_i` 且 `ν=b²κ`。设 `Zp=Σ_P ρ_Σp(P)`。理想顺序联合 law 是

```text
L_rec(P,x)=1_(P+Tx∈S_h) · ρ_Σp(P)ρ_(νI)(x)
             / [Zp · Π_(j=1)^M z_(a_j)].
```

`a_j` 可以依赖 P 和先前 digits；无需它们独立。Poisson 求和及三角不等式给每一个中心同样的界

```text
|z_a/s−1| ≤ t_F,
t_F=2q_F/(1−q_F³), q_F≥exp(−πκ).
```

这里使用 `k²≥1+3(k−1)` 对正整数 k 的 theta 尾作几何上界。若 `x_F=M t_F<1`，则

```text
1−x_F ≤ (1−t_F)^M
        ≤ Π_j(z_(a_j)/s)
        ≤ (1+t_F)^M ≤ 1/(1−x_F).
```

第一项来自 Bernoulli 不等式；最后一项由二项式展开的系数不超过 `M^j` 得到。因此可直接定义规范化的联合 product law

```text
L_prod(P,x) ∝ 1_(P+Tx∈S_h) ρ_Σp(P)ρ_(νI)(x),
```

且 `L_prod = W L_rec / E_rec[W]`，其中 `W=Π_j(z_(a_j)/s)` 处于区间 `[1−x_F,1/(1−x_F)]`。

此范围给出

```text
TV(L_rec,L_prod) ≤ x_F/(2−x_F).
```

下面独立核对常数。若一个正 reweight W 位于 `[L,U]`，其均值为 m，则弦线界给

```text
TV(P, WP/EW)
 ≤ (U−m)(m−L) / [m(U−L)].
```

取 `L=c=1−x_F`、`U=1/c`，并用 `m+1/m≥2`，右边至多

```text
(1/c+c−2)/(1/c−c)=(1−c)/(1+c)=x_F/(2−x_F).
```

`x_F=0` 时 W 是常数，TV 恰为零，单独处理即可。该常数不需要数值平方根，也没有假定某个 residue 产生相同正规化量。

**这只付一次递归分母费用。** 路线是 `ideal recurrence → normalized joint product`，不经过“理想 spherical-fiber Gaussian”中间参考。`fiber_normalizers.normalizer_certificate` 的标量/乘积界可复用，但不能再叠加一次 spherical-fiber 的 `Z_F` 移除费用。相应地，有限费用须使用 `gadget.batch["scalar_kernel_tv_including_aggregate_exact"]`；不能先取已含 ideal recurrence bias 的 `total_fiber_tv_upper_including_abort`，再重复支付上述 `x_F/(2−x_F)`。

## 4. 配平方和全中心 C-theta 界

定义正定矩阵及中心

```text
C=(ν⁻¹I+T*Σp⁻¹T)⁻¹
 =νI−ν²T*Σ⁻¹T,
μ(u)=CT*Σp⁻¹u=νT*Σ⁻¹u.
```

Woodbury 恒等式给后一种表达；直接展开二次型得到

```text
ρ_Σp(u−Tx)ρ_(νI)(x)=ρ_Σ(u)ρ_C(x−μ(u)).
```

共同的原始中心为零，而配平方中心 `μ(u)` 一般不为零。因为第 2 节已证明对 x 的求和不另受约束，`L_prod` 的 raw marginal 恰为

```text
P_prod(u) ∝ 1_(u∈S_h) ρ_Σ(u) Θ_C(μ(u)),
Θ_C(c)=Σ_(x∈Z^M) ρ_C(x−c).
```

若一个已经验证的固定根下界满足 `C≥λI`，令

```text
q_C≥exp(−πλ), t_C=2q_C/(1−q_C³), x_C=M t_C<1,
ε_C=x_C/(1−x_C)<1.
```

Poisson 求和给**所有实中心 c**共同的界

```text
|Θ_C(c)/√det(C)−1|
 ≤ Σ_(z≠0) exp(−π z*Cz)
 ≤ (1+t_C)^M−1 ≤ ε_C.
```

因此相对于公开 Gaussian-union 参考

```text
Q_h = D_(Z^N,Σ) | (U∈S_h),
```

乘子在 `[1−ε_C,1+ε_C]` 之间；连同最终正规化可用保守界

```text
TV(P_prod,Q_h) ≤ min(1, ε_C/(1−ε_C)).
```

此处不再出现 gadget fiber 正规化误差。`C≥64I` 是可选择的固定粗证书门：在每个 negacyclic Fourier block 中，用有向区间 LDL 证明

```text
(1−64/ν)I − ν T(ω)*Σ⁻¹T(ω) > 0
```

便证明 `C>64I`。这不需要公开私有谱值或矩阵。未通过该分析门只表示该证书未得出结论，不允许为报告重抽根，也不证明实际 C 不平滑。该门没有被提升为对所有 setup 输出根都成立的条件。

## 5. 当前有限实现误差的顺序相加

固定同一个 root、目标 h、精确 shape、选项和已通过的计划。设

```text
δ_F ≥ TV(actual PaperSampleF complete law,
         D_(Z^N,Σp)),
δ_G ≥ sup_(reachable residual/history)
         TV(actual finite gadget complete kernel, ideal recurrence kernel).
```

两边的样本空间显式包含 `⊥`；无中止的理想 law 在该点质量为零。`δ_F` 须涵盖有限连续近似、数值、整数 rounding、标量核和其 batch 上限；`δ_G` 是有限标量/aggregate 费用。由于每个 gadget 的标量中心始终为 `−a/b`，有限核证书必须覆盖全部这些 residue 和实际自适应历史。新鲜独立均匀字节、MPFR/区间算术和计划的输入范围条件须保留；一次固定测试种子的诚实运行本身不是这些概率前提的证明。

先耦合扰动，再按相同扰动耦合条件 gadget，得

```text
TV(actual finite latent law,L_rec) ≤ min(1,δ_F+δ_G).
```

随后依次使用第 3、4 节，并对 raw 形成这一确定映射用 TV 收缩：

```text
δ_raw = min(1,
  δ_F + δ_G + x_F/(2−x_F) + ε_C/(1−ε_C)).

TV(actual complete raw-vector law,Q_h) ≤ δ_raw.
```

该公式只在各输入界和守卫条件确实成立时可用；没有通过的输入应保留为缺失或平凡界 1。不得把含 `QQ(RealNumber)` 端点问题的旧冻结 finite 证书当作修复后的 `δ_F`。需要当前源码和当前精确 shape 对应的新计划/证据；只修源码、不重验其证书不够。

## 6. tail、HNF 与居中全局 mixed-domain 参考

令 `π_tail(u)` 删除前 H 个系数，`D_h` 按 `(A,h)` 从 tail 恢复头部的居中模 Q 代表。对 `u∈S_h`，实际 HNF 恢复恰为

```text
F_h(u)=D_h(π_tail(u))=C_Q(u+J e_h(u)),
```

其中 J 将 H 维向量嵌入头部，`C_Q` 只规范化头部。无论原 head 有多少模 Q aliases，该恒等式都成立；压缩 tail 和恢复不是从 raw-TV 反推，都是已有 raw 比较之后的确定性后处理。

于是数学向量空间中有

```text
TV(F_h#actual finite law, F_h#Q_h) ≤ δ_raw,
```

并保留 `⊥`。这里不额外加 HNF 位移、head-wrap 或不存在的 raw/user 范数拒绝项。

为识别参考，另定义一次不接收目标或陷门的全局采样：

```text
U ~ D_(Z^N,Σ),
E uniform in E_c, independent of U,
Y=C_Q(U+JE), f_A(Y)=AY mod Q.
```

给定 u，事件 `AU+E=h` 可选的 E 在 `u∈S_h` 时恰有一个，否则没有。因此

```text
Pr[f_A(Y)=h]=Pr[U∈S_h]/p^H,
law(Y | f_A(Y)=h)=F_h#Q_h.
```

Gaussian 全支持保证该条件事件有正概率。推前自动汇总不同 u 的 aliases；不需要 F_h 为单射。这个数学参考的基础域不依赖目标或陷门，forward 才使用 A。

该恒等式不证明像近均匀。像概率、完整核格 smoothing、短域/条件熵和底层 SIG 适用性是独立任务，不能从固定根的 C 门推得。

## 7. 实际守卫、中止和成功条件化

上述 `Q_h` 及数学 HNF 向量参考总归一且不 abort；这不表示实际服务的所有异常概率为零。须分别处理以下情况。

1. 若有限采样成功的每一条实际路径都已由公开有限支持包络证明满足中间环输入、256-bit 坐标、对象编码/字节数等检查，那么实际数学输出就是对有限 latent law 应用未加额外拒绝的确定函数。**理想参考不必满足有限 wire 对象的支持约束**，因为此时比较是在数学向量加 `⊥` 空间上进行。这不要求给无界 Gaussian 另付 wire 尾概率。
2. 若没有上述实际所有路径证明，不能将实际 guard 默认设为不触发。可以在两条 latent law 上应用同一个包含 guard 的确定映射，保留 abort；该映射仍收缩 TV。若 guard 依赖中间 P/x，而不只是最终 u，其参考可能继续依赖 T，不能直接改名为第 6 节的公开 mixed-domain law。若还要比较未加 guard 的参考，需要另给对应 guard 拒绝率。
3. 若明确比较序列化后的共同受限参考，则应对理想参考同样执行该编码/guard 并保留其 abort；不要称它为“不 abort 的数学参考”。

公开支持/资源分析见 [paper_resource_audit.py](../../../../experiments/research/candidates/srgg/paper_resource_audit.py) 的 `object_coordinate_envelope_conditional_on_prepared_plans`、`wire_envelope` 等部分。其条件包括采样计划通过及 draws 成功；它们不是完整 Gaussian 尾、密钥范数准入或基础设施异常概率证书。首次身份容量、pending/failed 状态、身份/公钥及 hash 输入合法性应先作为本次调用的公开前置条件核对。缓存重复请求不是一次新采样。

在情况 1 下，若已建立实际完整发钥向量 law P 到第 6 节无中止参考 Q 的 `TV(P,Q)≤δ<1`，则

```text
Pr_P[success]≥1−δ,
TV(P | success,Q)≤δ.
```

第二式可由包含 abort 的共同成功事件直接证明：设成功率 α，条件重叠至少为 `Σ_success min(P,Q)`；因 Q 的成功率为 1，这个未条件化成功部分的重叠恰为 `1−TV(P,Q)`。亦是既有 `conditional_tv_upper(δ,α,1)=δ` 的特化。此处不需要再粗除 `1−δ`。若两边参考均有 guard abort，则只能使用它们实际的正成功率，例如共同筛选条件下的一般上界 `min(1,δ/max(α,β))`，不能把 β 偷设为 1。

文件系统、崩溃、库/硬件故障及不匹配源码恢复不是本项采样 law 的概率模型。若纳入完整服务，必须另给模型和费用；不能从成功测试、锁或 fsync 推出概率零。setup 的重试/条件分布也在本项固定根条件之外。

## 8. 本说明新增的对应和保留缺口

本批 `paper_issuance_bridge.py`、`paper_issuance_audit.py` 和本文只增加分布推导、证书及真实固定根的审计运行；没有修改 `paper_profiles.py` / `paper_parameters.py` 的 Table 4 输入，也没有修改 `paper_backend.py`、`paper_samplef.py`、`paper_algebra.py` 或 `paper_objects.py` 中既有算法语义。对应关系仍是：Algorithm 1 的 CBD1/setup 与公钥关系、Algorithms 3–4 的各向异性 master 扰动、Algorithms 5–6 的近似 gadget 递归、Algorithm 2 的 tail 发钥，以及 Algorithms 7–8 的 HNF 恢复与签验。这里认证的是当前有限 joint sampler 到所声明目标 law 的误差；它仍不等于原文逐层 Schur sampler 或作者 C 程序的逐随机位复现。

Table 4 的“Std. dev.”归一化、报告的近似 `r=1.16`、Algorithm 6 中模 p 的整数代表、HNF 中模 Q 的整数代表，以及 Table 3/Algorithm 7 的 ζ factor1/factor2 疑点继续按 [SOURCE_MAP.md](../2026-10-16-srgg-paper-baseline/SOURCE_MAP.md) 保留。新固定根发钥证书不解决这些来源歧义，不反向宣称原论文所有参数前提均成立。它只覆盖所记录解释下的精确实现 shape。

[mixed-domain.md](../2026-10-16-srgg-bridge/mixed-domain.md)、[psf-review.md](../2026-10-16-srgg-bridge/psf-review.md) 和 [convolution.md](../2026-10-16-srgg-bridge/convolution.md) 已给一般推前、条件化、配平方和参考选择的证明。这里不重复认领为新的安全结果；本说明的具体对应是：

- 原参数的两段各向异性 master shape，与实际居中 E 的递归支持；
- 从理想递归直接到联合 product 的一次分母移除，并独立核对 `x_F/(2−x_F)`；
- 同一固定根的全中心 C-theta 门、当前有限证据、数学 HNF 和实际对象 guard 的分层拼接；
- 原后端没有 raw/user 范数门时，明确数学无中止参考及成功条件化的适用条件。

没有某个固定根的实际认证收据时，本说明只给条件公式。即使一根通过，也不能外推到全部原 setup 分布、全部实际运行/恢复状态或所有身份历史。原文宽度归一化、q/Q/2Q、ζ、完整 PSF/SIG 对应、困难性、native strong、ROM/QROM 与正式参数仍独立保留。所有安全声明继续为 `security_claim=none`、`parameters_are_formal=false`、`backend_admitted=false`、`nist_security_category=null`。
