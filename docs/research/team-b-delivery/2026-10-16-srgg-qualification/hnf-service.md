# SRGG 发钥分布、HNF 与固定服务模型

本项依据冻结的 Jia 等 2025 论文（SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`）PDF p.4 Definition 3、p.5 §4.2、p.7 Algorithm 2、p.8 Algorithm 7/Theorem 2 及当前实际调用链。它闭合的是一般分布表达、若干可证明界和合成严格反例，不是实际 SRGG 的完整 PSF 分布或安全归约证书。

## 从实际调用链定义比较对象

`runtime.extract_tail` 先执行 `sample_geometry` 和 `GadgetSampler`，再由 `sampling.extract_with_gadget` 计算 raw 向量并仅返回尾部。`Backend.key_extract` 用 `SigningKey` 的构造器重建首块、检查范数；失败直接中止而不重抽。`runtime.sign_attempt` 使用的是重建后的 `key.full_vector`。这些步骤不能简化成“直接从 exact-preimage Gaussian 发钥”。

固定公开矩阵 `A=[I_d,A_tail]`、陷门 `R`、目标 `h=H(pk,id)`，令 `T=[R;I]`。记实际有限扰动 law 为 `P_R(p)`，残差 `v(p)=h-Ap mod Q`，实际条件 gadget law 为 `G_v(x)`。两个 law 均包含可观察的中止原子 `⊥`。则对任一非中止 raw 向量 u，精确表达是

```text
P_raw,R,h(u) = sum_p P_R(p) * sum_x G_v(p)(x) * 1[u=p+Tx].
```

这里的残差先规范到 `[0,Q)`，误差逐系数为 `e=v mod p ∈ [0,p-1]`；非中止支持必须满足 `Au=h-e mod Q`。所有扰动/条件 gadget 中止的质量相加得到 `P_raw(⊥)`。有限采样器的 law 包括票据、有限试验次数、表格近似及其相依条件；不能用删掉中止后重新归一化的 law 代替。

令 `π(u)=tail(u)`，`D_h(t)=(center_Q(h-A_tail*t),t)`。它的像为 HNF 规范代表，且 `A D_h(t)=h mod Q`。设用户范数准入事件 `E_B(t)=[||D_h(t)||²≤B]`，真实发钥 law 是

```text
P_issue(D_h(t)) = 1[E_B(t)] * sum_{u:π(u)=t} P_raw(u),
P_issue(⊥) = P_raw(⊥) + sum_{t:not E_B(t)} sum_{u:π(u)=t} P_raw(u).
```

`issuance_analysis.finite_raw_extraction_law` 和 `issuance_law` 对明确给出的有限有理 law 精确执行以上求和，验证陷门关系和每个 gadget 条件支持，保留中止质量。它们不是生产采样器；未声称能枚举真实后端全部票据路径。

## 实际理想卷积还缺哪些条件

以下在系数空间中书写，避免把环矩阵转置误作普通块转置。设
`N=(2+w)dn`、`m=wdn`、`T=[R;I]`、`AT=F mod Q`，
`σ²=b²r²`，主密钥目标形状为 `Σ`，扰动形状为
`Σp=Σ−σ²TTᵀ≻0`，并记 `ρ_M(z)=exp(−πzᵀM⁻¹z)`。
先单独考虑无中止的理想条件采样：

```text
P ~ D_{Z^N,Σp},
v = canonical_Q(h−AP), e = v mod p,
X | P ~ D_{ {x∈Z^m: Fx=v−e mod Q}, σ²I },
U = P+TX.
```

这不是已证明与 PSF 等价的采样算法。对可达 `s` 定义
`Z_F(s)=sum_{x:Fx=s mod Q} ρ_{σ²I}(x)`。
当 `u` 满足 `Au=h−e mod Q`、`e∈{0,…,p−1}^{dn}` 时，代入
`P=u−Tx`，得到精确边缘表达：

```text
Pr[U=u] = (1/Z_P) * sum_{x∈Z^m}
          ρ_Σp(u−Tx) ρ_{σ²I}(x) / Z_F(Fx mod Q),
Z_P = sum_{a∈Z^N} ρ_Σp(a).
```

其它 u 的概率为零；`Q=p b^w` 和 F 的系数都是 p 的倍数保证该支持条件。
要消去分母，须给出所有可达 fiber 的 `Z_F(s)` 相对同一常数的统一上下界。
现有 gadget 证书只比较递推输出与各自已正规化的 spherical fiber law，
不自动证明不同 fiber 的正规化量一致。

再令

```text
C = (σ^(-2) I + TᵀΣp^(-1)T)^(-1),
μ(u) = C TᵀΣp^(-1)u.
```

配平方恒等式给出
`ρ_Σp(u−Tx)ρ_{σ²I}(x)=ρ_Σ(u)ρ_C(x−μ(u))`。
因此即使 fiber 分母已足够均匀，还须控制
`sum_x ρ_C(x−μ(u))` 对所有相关中心的变化，例如为 `C` 给出足够的
`Z^m` smoothing 条件。仅有 `Σp≻r²I` 不构成该条件的核验。
也不能把秩仅为 m<N 的 `σ²TTᵀ` 直接当作冻结 Peikert Theorem 3.1
所要求的第二个正定形状；上面的辅助变量配平方或适用的陷门采样定理必须另行核对。

即使这两项都闭合，自然得到的参考仍是并集
`S_h={u:Au=h−e mod Q, e∈{0,…,p−1}^{dn}}` 上的 Gaussian，
尚不是单个 exact fiber。令 `J=[I_{dn};0]`，平移 `y=u+Je` 可修复等式，
但各误差分量的密度成为中心为 `Je` 的 Gaussian 密度；分量权重也须核对。
HNF 不会使这些平移密度自动等于某个指定的 exact-fiber 条件 Gaussian。
其尾部误差、压缩后的 head-wrap 和范数门仍是独立义务。
这给出了具体补桥条件，不是实际 SRGG 分布的反例或已建立的误差数值。

## 与 PSF 条件 law 的精确缺口

若拟用的数学 PSF forward map 是 `f_A(y)=Ay mod Q`，必须先指定一个与 h 无关的完整 witness 域 law `Q_dom`，再定义

```text
Q_h(y) = Q_dom(y) * 1[f_A(y)=h] / Pr_Qdom[f_A(Y)=h].
```

它是否是目标离散高斯、image 是否接近均匀、SamplePre 是否与该条件 law 接近，是不同义务。论文 p.8–9 的 PSF 叙述与“properly distributed”一句不能替代这些义务。有限分析工具 `condition_domain_on_image` 精确计算给定有限域的 image 概率及条件 law；无限高斯的 image 正则性在本项没有建立。

wire 保存 tail，而自然的 `Ay` forward map 作用于完整 y。引用 PSF 归约时必须区分数学 witness 与压缩表示。给定 h 后可从 tail 解码首块，但同一 tail 对不同 h 能补成不同完整向量；不能自动把 tail 当成原来那个、可直接代入 `f_A` 的 SampleDom 对象。若原文实际采用其它带舍入的 forward map，也需要明确其域、函数与条件 law，不能擅自补写。

以下一般界已经闭合：

1. **解码前的尾部 law 是关键。** 对同一 A、h，`D_h` 保留尾部，因此在包含 `⊥` 的扩展空间上是单射。于是
   `TV(D_h#π#P_raw, D_h#π#Q_h) = TV(π#P_raw, π#Q_h)`。
   raw 全向量的差异可以被丢首块彻底抹掉，反过来不能由某个方程或首块误差界推知尾部 law。
2. **压缩解码也需要处理 wrap。** 用同一个 `Y~Q_h` 耦合，`Y=D_h(π(Y))` 在首块本来居中时成立，故
   `TV(Q_h,D_h#π#Q_h) ≤ Pr_Qh[Y_head不在居中区间]`。
   `reference_decoder_comparison` 可对明确有限 reference 精确计算这个 wrap 概率与 TV。无限 Gaussian 的实际 wrap 尾界未在这里推得。
3. **HNF 代数范数界不等于分布界。** 若 `Au=h-e mod Q` 且 `0≤e<p`，则
   `||D_h(π(u))||₂≤||u||₂+(p−1)√(dn)`，无 no-wrap 假设；但这不识别恢复后 Gaussian、陷门独立性或 PSF 条件 law。
4. **共同准入是收缩映射。** 把同一范数门以不通过即 `⊥` 的方式应用到两边，完整 law 的 TV 不增加。若只比较成功后条件 law，成功概率为 α、β>0，则
   `TV(P|success,Q|success) ≤ min(1, ε/max(α,β))`，其中 ε 是共同过滤前的 TV 上界。不能不给成功率下界就把过滤前 ε 原样用于成功发出的密钥。

最后一式的证明：不妨 α≤β。条件 law 的重叠质量至少为 `sum_success min(P(x),Q(x))/β`，所以其差异至多为 `sum_success(Q(x)-P(x))_+/β≤TV(P,Q)/β`。实现返回可观察异常，因此优先比较包含 `⊥` 的完整 law，避免悄悄条件化。

## 两个精确反例及其作用范围

工具的第一例固定 `n=2,d=1,p=5,b=3,w=1,Q=15`、`A=[1,1,5]`（各项为常数多项式）。仅允许首块常数系数在 `[-5,5]`，第一尾块系数 t 在 `{0,1}`，其它系数全零；取满足 canonical approximate-fiber 条件的点，以 `2^(-||u||²)` 赋权并归一化。这是有明确有限条件事件的 Gaussian 密度，宽度满足 `s²=π/log 2`。

HNF 输出与同样两个尾部对应的 exact witnesses 上、同密度 `2^(-||y||²)` 的有限 Gaussian 不相同。两个尾部的 raw 权重分别为

```text
S0 = 1+2^-1+2^-4+2^-9+2^-16,
S1 = 2^-1*(2^-1+2^-4+2^-9+2^-16+2^-25),
```

exact witness 权重则为 `1` 与 `2^-2`。精确有理 TV 在 `1/25` 和 `1/20` 之间。因而“近似 fiber 上是 Gaussian → HNF 后就是 exact fiber Gaussian”不是一般恒等式。**该有限 law 并非实际 SRGG raw sampler 的已识别 law，不是实际 SRGG 安全反例，也不证明它不能获得小误差界。**

第二例用同样 Q 的 `A=[1,0,5]`，两个 law 共享质量 `1−ε` 的超范数点，各有质量 ε 的不同合格点。过滤前 TV=ε，保留 `⊥` 后 TV 仍是 ε，而成功条件 law 的 TV=1。这严格展示范数筛选能放大成功输出偏差，并使上述条件化界取等号；它也只是一般风险的合成证明。

## 固定服务的 query 与 abort 映射

Definition 3 的同身份首次发钥后复用，与内存 `Backend.key_extract` 和持久 `FixedIssuer` 的成功路径一致。安全模型中身份必须限定在同一个公开参数/主密钥 generation 与同一可信账本，合作进程使用同一锁。重复 extraction 不调用新随机采样，统计发钥调用数应计**首次身份数**，包含将来若增加的 signing-oracle 编排中首次为身份发钥的请求。当前 `FixedIssuer` 仅提供 extraction 服务；`Backend.sign` 接收已给定密钥。尚不能声称已经实现一个完整的游戏 signing-oracle wrapper。

发钥是一次尝试：已持久化 pending 后的任何失败均保留 failed/阻断，不能用独立重试成功后的条件分布替代。签名只对 Algorithm 7 的范数拒绝重试；采样异常直接中止，不能把采样失败也算成可重抽。

若对所有可达历史都有发钥中止上界 δE、每完整签名尝试的采样中止上界 δS、范数拒绝事件概率上界 ρ、最大尝试数 L，则一个可复核的宽松预算是

```text
Pr[any failure] ≤ min(1, q_new*δE + q_sign*(L*δS+ρ^L) + δ_infrastructure).
```

`ρ` 须是逐历史的上界，不能用平均经验拒绝率代替。此式不要求各 query 独立，使用联合界及连乘条件概率。`service_abort_upper` 要求调用方明确提供所有概率输入；本项没有为真实发钥范数失败、签名范数拒绝或文件故障填入未经证明的数。

若已有**每 query、逐历史、含中止的完整输出 law**与理想游戏 oracle 的 TV 上界 εE、εS，则逐步耦合给
`TV(transcript_real,transcript_ideal)≤min(1,q_new*εE+q_sign*εS+δ_infrastructure)`。
`transcript_tv_upper` 精确计算该条件性界；中止已计入 ε 时不能再加一次相同中止质量。

可信本地明文状态模型不自动处理恶意回滚、管理员篡改、独立克隆账本、网络文件系统、混合平台写入、硬断电或侧信道；`fsync`/原子替换及并发测试不产生这些事件的密码学概率。没有相应基础设施模型时，只能给条件于可信状态运行的界。有限身份槽、消息容量和调用预算还须反映到受限游戏中，不能直接声称等价于任意多项式查询的原文游戏。

## 状态与复现

真正闭合：有限 law 合成、HNF 与范数过滤、尾部 TV 等式、reference wrap 耦合界、成功条件化界、带明确假设的 query/abort 联合界，以及上述严格反例。

仍未闭合：实际无限/有限发钥 raw law 与 PSF reference 的 tail-TV，trapdoor independence，数学 forward map 与压缩密钥的正式对应，真实 norm 失败率及全服务泄漏模型。上游最终离散采样逼近证书只能把真实采样连到明确的 sequential ideal sampler；不能单独把它升级成 PSF 条件 law 或强不可伪造。

```powershell
python -m pytest -q tests/test_srgg_issuance_analysis.py
python -m experiments.research.candidates.srgg.issuance_analysis --output build/outputs/srgg-qualification-2026-10-16/issuance-analysis.json
```

本工具与测试不需要 Sage，不消耗生产随机性，全部合成概率使用精确 `Fraction`。保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。
