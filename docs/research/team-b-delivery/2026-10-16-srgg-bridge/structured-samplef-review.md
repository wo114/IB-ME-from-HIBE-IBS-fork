# SRGG 结构化 SampleF：数学与实现独立审查

日期：2026-10-16。范围是 isotropic target 下，通过精确环 matvec、矩阵函数多项式和有限整数 Gaussian 舍入实现 SampleF。本文先给出独立推导，再记录实现核验；它不证明完整 IBS、源 PSF 或正式安全等级。

## 1. 对象与必要准入

系数空间维度 D，目标扰动形状为

```text
Sigma_p = s I - nu T T^*,
rounding shape = r_squared I,
a = s-r_squared > 0,
H = (nu/a) T T^*,
0 <= H <= rho I, rho<1.
```

这里的星号是 coefficient Euclidean adjoint，环表示中必须包含负循环共轭与转置。若 `||T||_2^2<=beta` 经公开支持类或实际见证范数证书核验，可取 `rho=nu*beta/a`。`rho<1` 等价于这个充分形状证书严格保证 `Sigma_p-r_squared I` 正定。仅有 s、nu 正数或 `lower_squared>nu+r_squared` 的下块门并不够。

SampleF 的精确连续 displacement 是

```text
Y = sqrt(a/(2pi)) sqrt(I-H) Z, Z~N(0,I_D).
```

于是其物理 covariance 为 `(Sigma_p-r_squared I)/(2pi)`，不是 `Sigma_p`。再做宽度平方为 `r_squared` 的离散 Gaussian 舍入。此约定与既有密度 `exp(-pi*x^T Sigma_p^-1*x)` 一致。实现若只支持 isotropic s，必须拒绝 anisotropic target；不能悄悄用最大或最小对角值代替实际目标。

## 2. 正系数展开及截断

在 `0<=x<1` 上

```text
sqrt(1-x) = 1-sum_(j>=1)c_j x^j,
c_1=1/2,
c_j=c_(j-1)(2j-3)/(2j), j>=2,
c_j>0, sum_(j>=1)c_j=1.
```

取 `P_J(H)=I-sum_(j=1)^J c_j H^j`。谱定理给 `sqrt(I-H)<=P_J(H)<=I`，所以 `||P_J(H)||_2<=1`；这保证输入 normal 的耦合误差不会随 J 线性放大。

截断算子误差满足

```text
tau_J = ||P_J(H)-sqrt(I-H)||_2
 <= sum_(j>J)c_j rho^j
 <= rho^(J+1).
```

提议中的更松 `rho^(J+1)/(1-rho)` 也合法。它是算子误差，不能直接当作中心误差；必须乘输入向量范数，再乘连续 scale。旧 knife-edge master shape 会导致 rho 极接近 1，在有界 J 下可能没有可用误差／资源证书。应明确拒绝或报告不足，不能把截断次数上限当作已逼近到目标精度。

## 3. 逐 matvec 量化误差

令每个坐标量化误差至多 `2^-B`，`eta=sqrt(D)*2^-B`。对已经量化的初始向量 q0，递推

```text
q_j = Quantize_B(H q_(j-1)).
```

精确环乘法和有理缩放本身没有舍入误差。令 `e_j=q_j-H^j q0`，则

```text
||e_j|| <= rho ||e_(j-1)||+eta,
||e_j|| <= eta*(1-rho^j)/(1-rho) <= eta/(1-rho).
```

如果加权和使用精确有理系数而无额外量化，则

```text
V_hat = q0-sum_(j=1)^J c_j q_j,
||V_hat-P_J(H)q0|| <= eta/(1-rho),
||V_hat|| <= ||q0||+eta/(1-rho).
```

`sum c_j<=1` 是误差没有额外 J 因子的关键。如果代码把每项加权和、最终 V 或最终中心再次量化，必须分别增加对应量化项，不能只计算 matvec 后的一次量化。

q0 自身的量化也不能漏算：可以把它计入 q0 与理想 normal Z 的初始耦合误差；此后上述幂递推从精确储存的 q0 出发。不得在证明中假设 q0 未量化、实现中却把它截成 B 位。

## 4. normal、截断与 scale 的统一中心误差

设 finite Box–Muller 与 ideal normal 的耦合有 good 事件，坏事件概率不超过 delta_bad，并在 good 上有

```text
||q0-Z|| <= epsilon_Z,
||q0|| <= R_q.
```

其中 `epsilon_Z` 必须包括票据格点误差、有限初等函数误差以及 q0 量化；如果已审的逐坐标 normal 界是 `G+128 R t u`，转为 2-norm 时须乘 `sqrt(D)`。`R_q` 应给有限路径的明确范数界，不能用“高斯典型范数”或观测最大值替代。把 sqrt(I-H) 作用于 `q0-Z`，再比较截断多项式，可得

```text
E_vector = epsilon_Z + tau_J R_q + eta/(1-rho),
||V_hat-sqrt(I-H)Z|| <= E_vector.
```

设真正 scale 为 `s0=sqrt(a/(2pi))`，directed interval 给 `[s_lo,s_hi]`，取精确有理中点 `s_hat=(s_lo+s_hi)/2`、误差 `delta_s=(s_hi-s_lo)/2`，并取已证实上界 `s_upper>=s0`。则

```text
||s_hat V_hat-s0 sqrt(I-H)Z||
 <= s_upper E_vector + delta_s*(R_q+eta/(1-rho)).
```

最后一个 scale 误差也必须乘向量范数。中点必须从精确区间端点构造为 rational，不能经普通 float 绕回；正确 directed interval 的转换、pi、除法与 sqrt 是该证书的数值假设。

任一坐标绝对中心误差至多上述 2-norm 上界 E；采用已审的 Gaussian 舍入核全中心 Lipschitz 常数 240，逐坐标 hybrid 给 `240*D*E`。E 已包含 sqrt(D) 时不能再次解释为每坐标 normal 输入误差而少乘维度。

## 5. 最终整数 law 与全局 abort

有限 support 的连续中间向量与真正连续正态的 TV 为 1；这里通过 good coupling 上相近的最终舍入中心比较最终整数输出，不宣称两个连续 law 在 TV 上接近。

当 rounding width `r>=1`、`Sigma_p-r_squared I` 严格正定、相应 `Z^D` smoothing 前提满足时，依既有 SampleF 分析，最后整数输出到目标离散 Gaussian 的保守完整 law 界可写为

```text
TV <= delta_bad + 240 D E + D*epsilon_scalar
      + delta_batch_abort + 8*epsilon_smoothing,
```

最终截到 1。标为 `epsilon_scalar` 的量是否已包含单 scalar abort 必须明确，避免把它误当成功条件 law；另外的 batch-abort 对应不同的全局熵／尝试门。添加它可保守，但不得遗漏全局截断造成的质量。

有限全局 tape 或 candidate 总数门需要一个证明出的全局中止界。不能用单次观测熵均值、实际运行未失败或每 scalar 的典型代价代替。若用统一条件接受率给几何／负二项尾界，要说明自适应中心下的逐历史下界、uniform-integer rejection 的 byte 上界、scalar 自身 trial cap，以及 batch gate 的具体触发条件。

全部矩阵函数误差来自显式截断、量化、normal 近似与 scale 包络；精确环乘法不引入浮点 FFT 误差。这个说法不免除 all-path 整数／有理位数、D、J、熵和输出界的资源准入。

## 6. 实现核验记录

2026-10-16 已逐段只读核对 `structured_samplef.py` 及其独立测试源码。展开系数递推、精确 QQ 环伴随、H matvec、截断、逐步量化和加权和与本文一致。目标各宽度不等时明确拒绝；CBD1 见证检查全部系数支持，另一入口核验实际能量不超过公开 cap，再用实负循环共轭频率对给 `beta=1+(n/2)*cap`。后者来自每个奇异值至少出现两次以及 Frobenius 平方 `n*cap`，不是观测谱范数或概率筛选。

q0 在有限 Box–Muller 后显式量化到 B 位，初始误差加入 `D*2^-B`。实现用 D 放松 sqrt(D)，保守但合法。取 `R_t=2(b+1), R_q=2D R_t`：midpoint 票据满足 `U>=2^(-b-1)`，精确 BM 径向幅度至多 `sqrt(2(b+1)ln2)`，远小于 R_t；在列明的正确 MPFR 运算及 `P>=b+32,B>=64` 前提下，有限计算与量化的增量仍在这个余量内。因此量化后每坐标绝对值小于 `2R_t`，范数小于 `2D R_t`。此处不能只引用量化前的 `abs(normal)<=2R_t` guard 来推出量化后界；余量来自更强的 BM 幅度推导。两个 runtime guard 在这些显式数值假设下是不触发的算术断言，不应作为未计概率的采样重试。

scale 从 directed interval 精确端点取 QQ 中点；未经过 float。中心 E 采用不截到 1 的向上 dyadic，只有概率／TV 项才截到 1。全路径有理位数 reserve 使用实际 mean 分母位数、实际 scale 分母位数、B、实际 J 和公开幅度位数：q_j 分母整除 `2^B`，c_j 分母整除 `2^(2j)`，所以精确加权和分母整除 `2^(B+2J)`；加上 scale、mean 后的分母用乘积界，再用幅度界控制分子。constructor 在读熵前拒绝不足 reserve。

batch 使用独立的成功次数尾界，为所有标量的合计 uniform candidates 和 Gaussian proposals 设置熵 cap；midpoint BM 票据数另外精确加入。该 cap 与 scalar 自身有限 trial abort 分别计入同一完整整数 law，未对成功条件化。对应测试包含独立 dense H、广义 binomial 多项式、零见证解析平方根、真实确定／系统熵样本、平移等变性及错误资源输入。本文的实现核验指源码与数学对应审查，测试执行结果由执行记录单独提供。

即使该 sampler 通过，也只证明特定参数／数值假设下的 SampleF law 对应，不等于 n512 完整 IBS、HNF PSF 对应或安全等级准入。它是 joint perturbation 采样入口，不宣称与旧顺序 Schur 有限 law 完全相同。

保持 `security_claim=none,backend_admitted=false,parameters_are_formal=false`。
