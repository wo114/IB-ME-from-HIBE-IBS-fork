# SRGG：HNF 修复的全局混合域参考与条件分布

日期：2026-10-16。本项给出一个固定、与目标和陷门无关的全局 SampleDom 参考，并证明其条件分布**恰好**等于理想 union law 的 HNF 修复推前。证明不需要把修复输出近似成零中心 exact-fiber Gaussian，因此不再使用此前约 0.52–0.73 的位移 TV 项。它尚未证明 SRGG 原文的 PSF/SIG 定理允许这个域，也不改变后端或正式参数。状态保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。

## 1. 固定全局 SampleDom 与 forward

设 `H=dn,N=(2+w)dn`；以下结论对任意有限正整数 H、N 也成立。令公开矩阵 `A=[I_H,A_tail] mod Q`，`J:Z^H -> Z^N` 将向量嵌入前 H 个坐标。令 `C_Q` 只将前 H 个整数系数化为区间 `[-floor(Q/2),ceil(Q/2)-1]` 中的规范剩余类，其余坐标不变。

取一个全局离散概率 law µ 于 `Z^N`，**不依赖目标 h、陷门 R 或发钥历史**。在 Gaussian 参考中可取 `µ=D_(Z^N),Σ`，但 Σ 必须为固定公开目标协方差；由秘密 witness 决定且未去除依赖的协方差不能直接代入此条件。

定义下列一次采样，无目标参数：

```text
U ~ µ;
E uniform in {0,...,p-1}^H, independent of U, with 1<=p<=Q;
V = U+JE;
Y = C_Q(V);
D_mix = law(Y),        f_A(Y)=AY mod Q.
```

`D_mix` 只依赖 µ、p、Q、H。其本身不需要 A；forward 才接收 A。由于 `AJ=I_H mod Q`，且 canonicalization 保持模 Q 像，`f_A(Y)=AU+E mod Q`。模数偶数时的规范端点取负半边，不影响证明。

## 2. 条件 law 恒等式，包括 head aliases

对固定 `h∈(Z/QZ)^H`，定义

```text
e_h(u) = canonical_nonnegative_mod_Q(h-Au),
S_h    = {u : e_h(u) in {0,...,p-1}^H},
repair_h(u)=C_Q(u+J e_h(u)).
```

因 `p<=Q`，对每个 u，满足 `Au+E=h mod Q` 的可用 E 至多一个；若 `u∈S_h` 则恰有一个。因此

```text
alpha_h = Pr[f_A(Y)=h] = µ(S_h)/p^H.
Pr[U=u,E=e_h(u) | f_A(Y)=h] = µ(u)/µ(S_h),  u∈S_h.
```

对这个条件联合分布应用确定函数 `(u,e)->C_Q(u+Je)`，得到**一般恒等式**：

```text
D_mix | (f_A(Y)=h) = (repair_h)_# (µ | S_h),  whenever µ(S_h)>0.
```

不同 u 可以因 head 相差 Q 的整数倍而映到同一个 y。上述推前将其质量相加；既没有忽略这些 aliases，也没有要求修复函数为单射。若 `µ(S_h)=0`，两边的成功条件 law 均未定义，不能补成任意 law。Gaussian µ 有全支持时每个目标可达；有限检查中的零像目标明确报错。

这是一个与 R 无关的全局参考，不是“对每个目标另外命名一个 PSF 域”。目标只用于条件化。它也没有将 E 固定为零。p=Q 时像恰均匀；一般 p<Q 时只有继承的近均匀界。

## 3. 与有限 SampleF / HNF 输出的误差拼接

若已独立建立某目标的理想 raw union 参考为 `µ|S_h`，实际 raw 输出 law P_h 与其 TV 至多 `epsilon_raw,h`，则确定性的 HNF 修复满足

```text
TV((repair_h)_# P_h, D_mix|f_A=h) <= epsilon_raw,h.
```

这里 epsilon_raw 必须包含实际适用的连续离散卷积桥、有限 normal/rounding、递归 gadget coset denominator removal、数值舍入、ticket/运行上限及其 abort 映射。`fiber-normalizers.md` 已给出的 denominator-removal 项仅承担自己的归一化步骤，不能独自代替整个 raw bridge。此恒等式所消去的是**选错零中心参考造成的额外修复位移项**，并未将已有采样误差变成零。

如果 P_h 已有 abort，应用一个固定映射保留 `⊥`，再比较同样扩展了 abort 的参考。不得把双方的失败自动删除后继续沿用同一个 TV。多查询归约还需按真正调用次数和依赖给出总预算；单次精确恒等式本身不完成整个归约。

## 4. 像近均匀性由 kernel smoothing 继承

若 Gaussian µ 的所有 A-kernel coset masses 满足同一个常数 c 的界

```text
c(1-epsilon)<=Z_h<=c(1+epsilon),  0<=epsilon<1,
```

则 `Pr[AU=h]=Z_h/sum_t Z_t`，并有充分界

```text
TV(law(AU),Uniform) <= epsilon/(1-epsilon),
(1-epsilon)/(Q^H(1+epsilon)) <= Pr[AU=h]
    <= (1+epsilon)/(Q^H(1-epsilon)).
```

对群上分布加独立 E 相当于卷积，是随机化映射；Uniform 在该映射下保持 Uniform，故 TV 只能收缩。点概率界也由对 h−e 的有限平均保留。因此同样的界适用于 `f_A(Y)`，不用支付零中心 Gaussian 的平移 TV 项。`spectral-bounds.md` 的有序 kernel-GSO 界和 `psf_bridge.py` 的 coset-smoothing 充分条件可以用于验证本节前提；它们仍须真正通过，不能因定义 mixed law 而省略。

API `image_uniformity_bound(epsilon)` 返回这些**条件于已验证输入前提**的精确有理数界；它不自行核验 Gaussian µ、kernel 基或 coset masses。

## 5. 范数门、abort 与全局成功条件化

令 G(y) 为与目标无关的公开范数谓词。对第 2 节双方应用 `y if G(y) else ⊥`，law 仍严格相同；若原有 TV 为 epsilon，TV 仍至多 epsilon。每个目标的成功质量 `b_h=Pr[G(Y)|f_A(Y)=h]` 也相同。

若源定义要求 SampleDom **总成功而先条件于 G**，则域应改为 `D_mix|G`。其像不再是第 4 节原像：

```text
Pr[f_A(Y)=h | G] = alpha_h*b_h / Pr[G].
(D_mix|G) | f_A=h = D_mix | (f_A=h,G),  provided alpha_h*b_h>0.
```

条件化可交换，但含 abort 的 SamplePre 与成功重抽的 SamplePre 是不同算法。若全局拒绝率 `delta_global=Pr[not G]<1`，由 `TV(D_mix,D_mix|G)=delta_global` 得像 TV 的充分上界 `epsilon_image+delta_global`。它**不证明每个目标的 b_h 有界**。测试中的精确反例：`Q=p=5,U=0,H=1` 的像均匀，只保留零向量时全局拒绝 4/5，成功条件化后的像变成零点质量，距均匀 TV=4/5，其余目标全部失败。

若必须比较单目标的成功条件 law，应另给 b_h 的正下界及条件化引起的误差放大；不得只引用 delta_global。Gaussian µ 下可从 per-target raw tail 推导 b_h，但本项尚未给出现有 n512 参数的成功率证书。

一个简单 norm envelope 是

```text
||Y|| <= ||U||+(p-1)*sqrt(H),
||Y||^2 <= 2||U||^2+2H(p-1)^2.
```

因为中心规范化逐坐标不增加整数绝对值，三角不等式和 `(a+b)^2<=2a^2+2b^2` 立即给出。这个 envelope 可将**已证明的条件 raw tail**传到输出；它没有自动证明 per-target tail。对 Gaussian 的全局 tail，仅除以 alpha_h 的通用条件界可能很松，必须显示该损失。

## 6. 可用但尚未实例化的条件熵充分界

设 µ 的最大点质量至多 M。V 为平移混合，因此 `max_v Pr[V=v]<=M`。设 canonical-head 回绕事件 `C_Q(V)!=V` 的概率至多 delta_wrap。由同一 V 上的耦合，`TV(law(V),D_mix)<=delta_wrap`，故

```text
max_y D_mix(y) <= M+delta_wrap.
```

若第 4 节给出 `alpha_h>=alpha_min>0`，则

```text
max_y Pr[Y=y | f_A(Y)=h] <= min(1,(M+delta_wrap)/alpha_min),
H_infinity(Y | f_A(Y)=h) >= -log2(that upper bound).
```

API `conditional_atom_upper(...)` 用精确 Fraction 输出上界和整数位数下界；三个输入都只是调用方提交的前提，不会被该函数认证。对无穷 Gaussian µ，若确有格 normalizer 下界 `Z_Σ>=(1-epsilon_Z)*sqrt(detΣ)`，可代入 `M=1/Z_Σ` 的相应上界。不能以连续 normal 密度峰值代替离散归一化常数。

回绕应针对 `V=U+JE`，不是仅针对 U。充分好事件为 `max_(i<=H)|U_i| < Q/2-(p-1)`；其右侧不正时这个充分界没有信息，需直接估计真实事件。对 U 的全局一维 tail 做 H 次并集可给 delta_wrap；它与 per-target norm reject 是不同量。若又条件于 G，最大条件点质量还需除以 b_h 的正下界。

这些界没有建立原文需要的熵数值，也没有建立 one-wayness。公开正向关系与良好熵并不构成 SIS/ISIS 归约。

## 7. 原文安全对应仍须单独完成

本项实现和证明的对象是一个候选 PSF 域参考：原全局 Gaussian 加有限均匀 head 平移、再规范化。不能因此直接继承原文 Gaussian-secret SIG 定理、preimage 条件熵、hardness、强不可伪造或固定服务的自适应多查询模拟。尤其：

- 若 SIG 定理固定 Gaussian secret law，混合域需要新的对应／归约，不能把 `D_mix` 直接改名为该 Gaussian。
- HNF 输出域和 norm 约束、对同一目标的多次服务、异常恢复和状态替换仍受现有固定服务契约约束。
- 原文 sEUF 与 fresh-message 实验的差异、已知同消息 Q 倍移动及小参数公开伪造负例不受本项影响；本文件不关闭这些问题。
- 不引入依赖具体 HIBE 的公共组合；Kyber/NIST 仅是长期比较目标，未给本方案授予安全等级。

## 8. 有限实现、检查及复现

新增 `experiments/research/candidates/srgg/mixed_domain.py` 是纯 Python、exact Fraction 的有限 law 参考，不是可替换后端的采样器。它限制 4096 个枚举状态、64 个坐标，拒绝浮点概率、非归一化 law、错误 identity-head、非规范目标和 `p>Q`。`None` 只在显式 norm gate 输出中表示 abort，不能重新输入成理想 raw law。

测试用公开合成 law；身份是 H=1 或 2 的有限剩余类，坐标维数 2 或 3，Q=3/4/5、p=2/3/4/5；没有真实消息、随机重复或 Gaussian 采样。它们穷举目标并核对 `µ(S_h)=p^H*alpha_h`、精确条件 law、aliases、同一 norm gate 的完整 law、多公钥同一域、p=Q 的均匀像，以及全局 norm 条件化反例。额外 envelope 检查包含 Q=2/3/4/5/11。以上是确定性代数／有限实现证据，不是安全实验。

```text
python -m pytest -q tests/test_srgg_mixed_domain.py
python -m experiments.research.candidates.srgg.mixed_domain --output build/outputs/srgg-bridge-2026-10-16/mixed-domain.json
```

该文件的 27 项测试通过；与 spectral、fiber-normalizer、convolution、PSF、issuance 六项文件联测共 121 项通过（2026-10-16，Python 3.14.7 / MSC v.1944 64-bit AMD64，Windows 11 10.0.26200，Intel64 Family 6 Model 198 Stepping 2）。实验不使用 ROM；后续论文哈希／ROM 条件未在这个纯分布模型内实例化。n512 真正采样、完整生命周期、正式参数、安全归约和安全准入均未由本项完成。
