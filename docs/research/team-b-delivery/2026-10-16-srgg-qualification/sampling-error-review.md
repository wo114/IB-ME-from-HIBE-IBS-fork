# 最终整数采样误差界：独立数学复核

本审查针对 `experiments/research/candidates/srgg/sampling_error.py` 与实际 `full_sampling.py`、`runtime.py`、`geometry.py`。复核包括默认遍历 `bad_bits` 选择最小公开上界的版本。下文是条件性数学推导，不以测试、矩样本或高精度重复运行替代证明，也不声称验证了外部 Sage/MPFR 实现。

理论引用限于本地冻结 Peikert 作者稿 `papers/2011_peikert_parallel_gaussian_author.pdf`，SHA-256 `39ae6ea450a98267ab7f3ac682e4daae4a91ec8aed9432dca666e05eefd46163`：PDF p.7 §2.4、p.9 Theorem 3.1 的连续分支、p.11 Lemma 4.1。本文使用 `ρ_S(x)=exp(-π xᵀS⁻¹x)` 的密度形状约定；连续物理协方差为 `S/(2π)`。

## 适用条件和比较目标

固定一个真实 SampleF 叶，维数 d、精确形状 `Σ`、精确中心 c、舍入宽度 r≥1，并满足 `C=Σ-r²I≻0`。形状先执行 exact rational LDL，随后产生 MPFR 因子。设公开界 `C_ii≤M`，`R=ceil(sqrt(M))`。精度 P、票据位数 b 满足 `P≥b+2`；定义 `u=2^(2-P)`，要求 `d*u<1/1024`。

需要显式保留的条件是：

- 输入字节独立均匀，票据及整数提取符合实际路径；测试固定熵不建立这一条件。
- MPFR 各基本和初等函数操作采用正确的 round-to-nearest，包含有理数转换、π、log、sqrt、sin、cos；各非零结果的单操作相对误差可由 u 上界。
- 没有指数溢出、下溢或未建模硬件/库异常。所有实际路径的有理中心、输出及熵预算通过现有 preflight。
- LDL、Schur 更新、中心平移、最终把已表示的 MPFR 数变成其精确有理值均与代码所述一致；尤其不把大中心先转换成浮点再相加。
- 标量整数采样器的有限 law 证书适用于每个实际精确中心，并包含其内部中止质量。

以下先比较实际有限票据/浮点流程的**最终整数输出**与“精确连续扰动后进行理想整数 Gaussian 舍入”的 law；再引用 Peikert 的连续分支比较目标离散 Gaussian。有限中间连续值与真正连续 Gaussian 的 TV 本来为 1，本推导不为该中间层声称小 TV。

## 1. 整数 Gaussian 中心核的统一 Lipschitz 常数 240

令

```text
p_c(k)=exp(-π(k-c)²/r²)/Z(c), k∈Z, r≥1.
```

最近整数距 c 至多 1/2，因此
`Z(c)≥exp(-π/(4r²))>exp(-1)>1/3`，只用 `π<4`、`e<3`。按壳 `j≤|k-c|<j+1` 分组，每壳至多两个整数，可得

```text
N=sum_k |k-c| exp(-π(k-c)²/r²)
 ≤2 sum_(j≥0) (j+1) exp(-πj²/r²).
```

对递减 Gaussian，矩形积分界给 `sum exp(-πj²/r²)≤1+r/2`。对非负单峰函数 `f(x)=x exp(-πx²/r²)`，按峰两侧的矩形积分界，`sum f(j)≤∫f+2sup f≤r²+2r`。因 r≥1，

```text
N≤2r²+5r+2≤9r²,
E_c|K-c|≤27r²,
E_c|K-E_cK|≤2E_c|K-c|≤54r².
```

Gaussian 尾部可在紧中心区间上一致支配，故可逐项微分正规化级数，得到
`∂_c p_c(k)=(2π/r²)(k-E_cK)p_c(k)`。于是

```text
(1/2) sum_k |∂_c p_c(k)|
 =π/r² * E_c|K-E_cK|≤54π<216<240.
```

沿中心线段积分，`TV(D_Z,r,c,D_Z,r,c')≤min(1,240|c-c'|)`，常数对 r≥1 和所有中心统一。d 个条件独立舍入坐标应用逐坐标耦合，给 `TV≤min(1,240*sum_i|c_i-c'_i|)`。这也适用于已固定前序历史的条件核。

## 2. Box–Muller 票据耦合

令真正均匀数 `U,V∈(0,1)` 按宽度 `2^-b` 的格子取 midpoint，分别为 `Û,V̂`。其 law 与 b-bit 均匀票据相同，且每个绝对差至多 `δ=2^(-b-1)`。取任意整数 `1≤t≤b`、`a=2^-t`，于是 `δ≤a/2`。

在好事件 `U≥a` 上，`Û≥a/2`。令 `h(U)=sqrt(-2log U)`，用 `|sqrt(x)-sqrt(y)|≤sqrt(|x-y|)` 及 log 的导数界，

```text
|h(U)-h(Û)|≤sqrt(4δ/a).
```

真、格点两个 radius 均小于 `Rt=2(b+1)`：格点全局最小值为 `2^(-b-1)`，并有 `sqrt(2(b+1)log 2)≤2(b+1)`；真值在好事件上的 radius 更小。角差至多 `2πδ<8δ`，故 sin/cos 的 1-Lipschitz 性给每个 normal 分量

```text
|z_true-z_grid|≤G=sqrt(4δ/a)+8δRt.
```

代码把第一项向上替换成 `2^ceil((1+t-b)/2)`，是严格保守的二幂上界。d 维需要 `m=ceil(d/2)` 对票据；所有 radius 均好的补事件由联合界至多 `m*a`。不需要为该联合界另加独立性假设。

对精确因子 F，`FFᵀ=C/(2π)`，故每项 `|F_ij|≤R`，票据引起的连续位移坐标差至多 `d*R*G`。

默认遍历 t 选择最小界是**证明参数优化**：每一个 t 已有合法界，有限取最小仍合法；优化项仅含公开 d、b、R，且 MPFR 项与 t 无关。它没有改变任何采样票据、拒绝条件或输出分布。

## 3. MPFR 常数如何合成为 1024

本节是在以上 MPFR 语义假设下的舍入误差推导，不是通过若干实测精度点认证正确舍入。

### exact LDL 因子的相对误差

对 `C=L diag(D_j)Lᵀ`，精确因子项为 `F_ij=L_ij sqrt(D_j/(2π))`。实际路径先转换 exact `L_ij,D_j`，舍入 π，除法、sqrt、乘法。若 `L_ij=0`，对应项精确为零；其它项由逐操作相对误差可写出比率，其绝对值上下界为

```text
(1-u)^4/sqrt(1+u) ≤ |Fhat_ij/F_ij| ≤ (1+u)^4/sqrt(1-u).
```

`u<1/1024` 时，用 `log(1+u)≤u`、`-log(1-u)≤u/(1-u)` 即得到上下偏差均小于 `8u`。因此 `|Fhat_ij-F_ij|≤8u|F_ij|≤8uR`，且 `|Fhat_ij|≤(1+8u)R≤(129/128)R`。LDL 在有理数上先精确完成，所以这里没有引入数值 LDL 的条件数误差。

### 格点 normal 的绝对误差

midpoint 的分子至多 b+1 bit，`P≥b+2` 保证其转换精确。设 exact grid radius 为 r0、角为 θ。

- log/sqrt 的逐操作相对误差给 `|rhat-r0|≤3u*r0`；负号与乘 2 是无溢出时的精确二进制缩放。
- π 转换和角乘法给 `|θhat-θ|≤3u|θ|<24u`，因为 `0≤θ<2π<8`。
- sin/cos 在实数上 1-Lipschitz，且其正确舍入绝对误差至多 u，故求得的三角值与真格点三角值相差至多 `25u`。
- 最后一乘的舍入再合并 radius、三角值误差，有每个 normal 分量误差 `<30Rt*u`，从而代码采用的 `128Rt*u` 保守成立。

因此 `|zhat_j|≤(1+128u)Rt≤(9/8)Rt`。

### 点积乘加误差

先把已算得的浮点因子和 normal 当作精确实数，比较其点积与真格点位移：每项输入扰动至多

```text
|Fhat_ij zhat_j - F_ij z_j|
 ≤8uR*Rt + (129/128)R*(128Rt*u)
 =137R*Rt*u.
```

故输入扰动和至多 `137dR*Rt*u`。乘法加顺序求和保守计 2d 次操作，标准展开的累计因子 `γ_(2d)=2du/(1-2du)≤4du`；又有
`sum_j|Fhat_ij zhat_j|≤d*(129/128)*(9/8)R*Rt<2dR*Rt`，所以点积自身舍入绝对误差至多 `8d²R*Rt*u`。

两项合计

```text
137dR*Rt*u + 8d²R*Rt*u
 ≤145d²R*Rt*u
 <1024d²R*Rt*u.
```

代码的大常数 1024 因而覆盖这条实际操作链。把最终 MPFR 表示值转换为其 exact rational，再加 exact mean，不新增浮点中心误差。r 的正确舍入标量核中心随后正是这个有理值。

## 4. SampleF 的最终离散误差

合并票据和 MPFR，任一位移坐标在好事件上的绝对误差被
`E=dRG+1024d²R*Rt*u` 上界。由第 1 节与坏事件概率，实际浮点位移后若接理想整数舍入，其最终整数 law 与精确连续位移后舍入的 TV 至多

```text
min(1, ceil(d/2)*2^-t + 240dE).
```

再对 d 个实际标量有限舍入 law 各加其逐中心 `scalar.tv_upper`，该证书本来包含内部中止，不应先删去这些质量重新归一化。

令 `q=exp(-πr²)`。因 `k²≥1+3(k-1)` 对 k≥1，标准格子单维非零对偶质量满足 `2 sum_(k≥1)q^(k²)≤2q/(1-q³)`；d 维对偶质量相应至多
`ε_d=(1+2q/(1-q³))^d-1`。使用包围区间与向上取 dyadic 值保留该上界。若 `ε_d≤1/2`，r 达到 `η_ε(Z^d)` 的条件，Peikert Theorem 3.1 连续分支可应用，最终理想舍入与 `D_Z^d,sqrt(Σ),c` 的 TV 至多 `8ε_d`。`C≻0` 与 r≥1 不能单独替代这一 smoothing 条件。若不满足，代码只使用 TV≤1 的平凡界。

该连续分支不需要离散 x2 分支的额外 `Σ3` smoothing 条件。它的中心/陪集记法通过整体平移对应当前 arbitrary exact center c。

## 5. SampleP 的联合 law 不能直接写成精确 Gaussian

实际 SampleP 按逆序 Schur 叶采样。令每叶块维数 s、块数 k，所有叶形状 `S_i≻r²I`。理想条件离散叶核的乘积分子由 Schur 平方配方等于完整 Gaussian 的指数分子，但分母 `Z_i(c_i(history))` 随已抽样整数历史而变。

Poisson 求和给任意中心下的正规化量
`Z_i(c_i)/sqrt(det S_i)∈[1-ε_s,1+ε_s]`，其中用 r 的对偶质量上界控制所有 `S_i≽r²I`。因此理想叶链 law 与 joint target law 的 likelihood-ratio 在全空间的最大/最小比至多

```text
Rchain=((1+ε_s)/(1-ε_s))^k.
```

其归一化后的平均 likelihood-ratio 为 1，于是 TV 保守地至多 `(Rchain-1)/2`，再截于 1。实际叶与理想叶的逐历史 TV 分别统一有界，所以另加 `k*leaf_error` 是合法逐步耦合界，不需要将各叶误差事件假设独立。若 ε≥1，不使用无效分母，而退回平凡界 1。

这正对应 `sample_p_class` 的 partition bias，不能省略该项而声称 sequential discrete Schur 本来就是精确 joint Gaussian。

## 6. geometry 的 lower 边缘偏差

设 perturbation 形状分块为 `[[A,B],[Bᵀ,d0 I]]`，上块 conditional 形状为 `S=A-BBᵀ/d0`，中心为 `Bz/d0`。完整 target Gaussian 的 lower 边缘 law 为

```text
Q_lower(z) ∝ exp(-π||z||²/d0) * Z_S(Bz/d0).
```

runtime 先从独立 lower Gaussian `exp(-π||z||²/d0)` 抽样，再从 upper 条件 law 抽样。由于 `Z_S(mean)/sqrt(det S)∈[1-ε_upper,1+ε_upper]`，目标边缘与这个 lower law 的 likelihood-ratio 最大/最小比至多 `(1+ε_upper)/(1-ε_upper)`，故边缘 TV 至多 `ε_upper/(1-ε_upper)`。这里必须使用整个 upper 维数的 smoothing 量，代码确实如此。

因此，有限 lower 标量总误差、upper SampleP 总误差与该边缘 bias 的和，才是当前 geometry sampler 到 joint perturbation Gaussian 的保守界。

## 7. 公开 diagonal envelope 为何有效

`geometry._geometry` 以 exact rational 检查实际
`Σp=Σtarget-noise*T*Tᵀ` 及 `Σp-r²I≻0`。减去的项半正定，所以 `Σp≼Σtarget`，真实对角不超过公开 target 最大对角。lower 是标量块，取条件 Schur 再减一个半正定项，因此 upper conditional 对角也不增。

若当前形状 `C≻r²I`，其 lower 块记为 D、cross 为 B，则检查 shifted Schur 得
`A-r²I-B(D-r²I)^-1 Bᵀ≻0`。因为 `(D-r²I)^-1≽D^-1`，其通常 Schur `A-BD^-1Bᵀ≻r²I`。故逐次 Schur 既保留 r² floor，又不增加主块对角。每叶的 residual 再减 `r²I`，其对角仍不超过相同公开 envelope。

所以 `build_report` 使用 master/signature 两组公开 target squared widths 的最大值作为所有叶的 `residual_diagonal_upper` 是保守的，并不需要导出秘密矩阵的真实对角。signing lower shape 的 `signature_second_squared-2*r_squared` 与当前明确 factor2 的代码对应；这里并没有证明 factor2 版本符合原文安全定理。

## 审查结论和边界

在本文件列明的 MPFR、熵和 all-path preflight 条件下，没有发现上述 240、1024、Schur partition bias、lower 边缘 bias 或公开 diagonal envelope 的数学阻断项。实际证书的大小还取决于 r、票据位数和查询预算，非平凡上界也不等于密码安全等级。

该比较参考是**同一顺序算法内用理想 perturbation Gaussian、理想 gadget fiber、理想 u 替换各子采样器**，保留相同哈希、HNF、norm 门及尝试预算。即使所有有限实现逼近误差有界，以下仍不随之闭合：raw extraction 的理想卷积分布、HNF 后 PSF 条件密钥 law、最终 signature Gaussian、范数成功概率、强不可伪造归约或正式参数准入。这些必须分别处理，见 [hnf-service.md](hnf-service.md)。
