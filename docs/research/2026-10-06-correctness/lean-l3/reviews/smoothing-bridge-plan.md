# L3：C2 到陪集高斯尾界的只读桥接审查

状态：**桥接仍未完成。本文是源文核对与形式化路线，不是 Lean 证明或编译通过声明。**

本轮只读审查源码与 MP12 原文，仅新增本说明；未修改任何 Lean 代码，未运行构建，未改缓存。

## 1. 结论与当前声明边界

`IntegerGaussian.lean` 的 `CosetMassComparison q A u s e` 是当前尾界推导的真实、充分的额外解析前提：

\[
Z_u(2s)\le 2^m\frac{1+e}{1-e}Z_u(s),\qquad
Z_u(r)=\sum_{x\in\Lambda_q^u(A)}e^{-\pi\|x\|_2^2/r^2}.
\]

结合文件里明确列出的 `s > 0`、`0 ≤ e < 1`、陪集非空与已证明的可和性，
足以推出当前归一化尾质量上界。**但它既不是 C2 的别名，也未由 L2 推出。**
因此，现阶段可以声明“从真实陪集质量比较证书推出尾界”，不能声明
“已从账本全部原始前提机器证明 MP12 Lemma 2.6 / 完整 L3”。

C2 到 `CosetMassComparison` 是尚缺的关键定理，而不是可以略去的类型适配。
单有陪集非空、可和性或归一化，不能保证这个质量倍增界。

## 2. 原文、符号和源码对应

已核对本地原文 `papers/2011_lattice_trapdoors_micciancio.pdf`：

- PDF/印刷页 12，Definition 2.2：平滑关系直接以对偶高斯总质量 `≤ 1 + ε` 表述。
- 页 12，Lemma 2.4 证明首段：对秩 m 格，中心质量满足
  `ρ_t(Λ) ≤ ρ_r(Λ) ≤ (r/t)^m ρ_t(Λ)`，其中 `r ≥ t > 0`；原文说明来自 Poisson 求和。
- 页 13，Lemma 2.5：陪集质量不超过中心质量；在平滑条件下，陪集质量至少为
  `(1−ε)/(1+ε)` 倍中心质量。
- 页 13，Lemma 2.6：`r ≥ η_ε(Λ)`、`0 < ε < 1`、`c ∈ span(Λ)` 时，
  `Pr[‖D_{Λ+c,r}‖ ≥ r sqrt(m)] ≤ 2^(−m)(1+ε)/(1−ε)`；原文是 **≥**。
  账本拒绝事件使用 **>**，属于该事件的子集，没有阈值方向冲突。

账本位置：`FooLi-条件式正确性定理与参数账本.md` 的 C2、C3 和 L3。

必须保持两种参数约定：

| 对象 | 源码权重 | 参数解释 |
|---|---|---|
| L2 `dualTheta q C s` | `exp(−π s² ‖y‖²)`，y 在对偶格 | 对偶高斯宽度为 `1/s`；这里实参是 s |
| L3 `rho s (vectorSq x)` | `exp(−π ‖x‖²/s²)`，x 在原格陪集 | 原格高斯宽度为 s |

L3 的输入应是 `dualTheta q (liftMatrix q A) s ≤ ε₀`，不是在 `1/s` 处的 theta 界。
L3 使用主矩阵 A 和 `ε₀`；L4 才使用扩展矩阵 F 和 `ε_F`。

## 3. 当前额外前提是否还漏了条件

对**当前条件式尾界定理本身**，没有发现必须补上的解析前提：

- `coset_rho_summable` 已从整数向量高斯可和性证明 s 和 2s 两处收敛。
- `hx` 陪集非空与 `s > 0` 经 `coset_gaussianZ_pos` 给出正归一化常数，避免空陪集或除零。
- `0 ≤ e < 1` 使误差比非负且分母正；原文的 `0 < ε₀ ≤ 1/4` 更强。
- `rho_tail_le` 在 `m s² ≤ ‖x‖²` 上使用宽度倍增；`tail_constant` 将
  `exp(−3πm/4) 2^m` 放宽为 `2^(−m)`。它不需要额外 Banaszczyk 定理来完成这一步。
- 泛型 `sqLength` 的非负性不是该条件式解析推导遗漏的前提；实际实例 `vectorSq` 本来就是平方和。

对**从账本 C2 调用该定理**，还必须落实以下桥接条件和证明：

1. `q ≠ 0`，与源码 `[NeZero q]` 一致。原方案的素数 q 足够，但下述 q-元路线只需正模数及模映射满射。
2. 模矩阵 A 的满射性，提供每个 syndrome u 的非空陪集。
   `coset_nonempty_of_surjective` 已有此接口；从有效主陷门关系、gadget 满射性到该接口的链不能凭一句话替代。
3. L2 整数 lift 与 L3 模矩阵的匹配：用 `mod_liftMatrix`，并证明/展开 `InKernel` 与 `InCoset ... 0` 的一致性。
4. 原格陪集的质量与 L2 真实对偶格质量之间的 Poisson/相位恒等式，以及其质量上下界。
5. 对所有 u 统一建立 `CosetMassComparison`，才能覆盖 C3 的每列 syndrome，不能只证 u=0。

将归一化尾质量转换为概率时，仍需调用 `GaussianLaw` 的事件等式并提供其显式可测性参数；
这是概率层的接线，不是本文重点，也不能拿“质量比”直接充当所有实现输出上的概率声明。

## 4. 为什么 L2 尚未填上这个缺口

L2 已有、可复用：

- `Cosets.dualEquiv`：真实 integral-pairing 对偶格与有限 residue × 整数向量的双射。
- `dualMass_eq_coset_sum`、`dualTheta_eq_nonzero_tsum`：真实对偶质量及删去唯一零向量的对应。
- `smoothAt_iff_theta`：直接点态平滑证书；不涉及下确界反向推理。
- `gaussianMass_le_zero`：一维**移位整数格**质量不超过零中心质量。
- `gridMass_antitone` 及绝对收敛、有限维产品、`tsum` 重排工具。

尚未有：任意 q-元原格陪集 `Λ_q^u(A)` 的质量与其真实对偶格之间的带相位 Poisson 等式。
该陪集一般不是坐标独立的整数网格，不能直接把 `gaussianMass_le_zero` 逐坐标相乘当成其质量定理。
L2 的 `Gaussian.lean` 中 `poisson_gaussianMass` 是 private 的一维引理，
并且保留复幂系数；不能未经新封装就当成已公开的一般格 Poisson API。

`smoothingInf_le_of_mass_le` 仅证明“点态质量证书 ⇒ infimum 上界”。
**禁止倒用成 `smoothingInf ≤ s ⇒ dualTheta s ≤ ε`**，因为当前没有证明所需的反向性质或端点取到性。
C2 已直接给出点态 theta 界，完全没有绕经这个下确界的必要。

## 5. 最短目标：先证明真实陪集的质量上下界

固定 `q > 0`、满射 A、任意 u、`s > 0`，令 `Λ=Λ_q^⊥(A)`。
若选择一个整数代表 c 使 `A c=u`，待证的标准 Poisson 形式为

\[
Z_u(r)=\frac{r^m}{q^n}
\sum_{y\in\Lambda^*}e^{-\pi r^2\|y\|^2}e^{2\pi i\langle y,c\rangle},\quad r>0.
\tag{P}
\]

左侧嵌入复数。相位的正负取决于 Fourier 约定；需要一致证明，而最终绝对值界不依赖该选择。
`q^n` 的归一化来自满射模映射的指数，不能随意省去。
相位在零向量为 1，在所有向量上模长为 1。因此待证

\[
\left|\frac{q^n}{r^m} Z_u(r)-1\right|\le\Theta_A(r).
\tag{M}
\]

在 `Θ_A(s) ≤ ε₀` 下，由已有逆宽度单调性另外封装出
`Θ_A(2s) ≤ Θ_A(s)`。再从 (M) 得到

\[
Z_u(s)\ge(1-\varepsilon_0)\frac{s^m}{q^n},\qquad
Z_u(2s)\le(1+\varepsilon_0)\frac{(2s)^m}{q^n}.
\]

由于 `1−ε₀>0`，两式正好推出当前 `CosetMassComparison`。
这一路线**数学上充分，当前未写成机器证明**。

另一条等价路线是证明 MP12 Lemma 2.5 的陪集上下比较，再配合无误差的中心倍增界
`Z_0(2s) ≤ 2^m Z_0(s)`。不要把两个粗糙的含误差比上下界重复相乘，
否则会错误地产生 `((1+ε)/(1−ε))²`，改变账本常数。

## 6. 推荐的 q-元专用形式化路线

为复用现有 L2，建议优先处理有限模群字符展开，而非先建设任意实格基、协体积及通用格 Poisson 库。
以下每一步仍是待证明任务：

1. 用有限字符正交性将 `A x=u` 的指示函数展开成 `(ZMod q)^n` 上的字符平均。
2. 由模长为 1 及现有整数高斯可和性，正当化有限字符和、整数向量无限和及有限坐标积的交换。
3. 使用 `Complex.tsum_exp_neg_quadratic` 对每一坐标的带线性相位整数高斯做变换；
   将正宽度下的复幂系数精确化为实数 s，再组合出 `s^m/q^n`。
   L2 的非负实数产品引理不能不加证明地直接套到复值带相位函数；需要绝对收敛的复值产品版本或等效重排论证。
4. 得到 `Z_u(s)` 的有限 residue 求和表达，内层为 L2 的 `gridMass m s (residueShift ...)`，
   每项乘一个模长为 1 的 syndrome 字符。借 `dualEquiv`/`dualMass_eq_coset_sum` 对齐真实对偶格。
5. 单独分离 `a=0,z=0` 的唯一零点，界住其余项得到 (M)。
   **不能删掉整个 a=0 分支**，因为它还包含所有非零整数对偶向量。
6. 封装点态单调性、质量上下界和最终
   `dualTheta ... s ≤ ε₀ → ∀ u, CosetMassComparison ... u s ε₀`。

这条专用路线可由字符平均直接处理 `q^n` 因子，不必先在 Lean 中证明一般协体积理论；
若改用 (P) 的一般格版本，则要另证 `qℤ^m ⊆ Λ ⊆ ℤ^m`、满维离散性、
`span(Λ)=ℝ^m`、陪集等同及指数/协体积 `q^n` 等结构条件。

只读检索到的基础候选 API（未在本轮构建或验证调用语法）：

- `Mathlib.Analysis.SpecialFunctions.Gaussian.PoissonSummation` 的 `Complex.tsum_exp_neg_quadratic`。
- `Mathlib.Analysis.SpecialFunctions.Complex.CircleAddChar` 的 `ZMod.stdAddChar` 与 `isPrimitive_stdAddChar`。
- `Mathlib.Analysis.Fourier.FiniteAbelian.Orthogonality` 的字符平均正交性。

存在这些基础 API 不等于上述 q-元桥接已经存在，更不等于已经完成。

## 7. 推荐完成门槛和本轮快照

下一轮完成门槛应是：从 `q > 0`、A 满射、s 正、`0 < ε₀ ≤ 1/4` 和真实
`dualTheta ... s ≤ ε₀` 出发，证明每个 u 的 `CosetMassComparison`，
没有把 (P)、(M)、目标质量比较或原论文 Lemma 2.6 新增成未经证明的参数/公理。
在那以前，L3 应保留“解析桥接未完成”的总体状态。

审阅源码快照 SHA-256：

- `GaussianTail.lean`：`04BB33703321D094DE190527A7113EC3033D1F6D5FCEC2AE99D7D31C6FEAEA15`
- `IntegerGaussian.lean`：`2ECD66196E65847B0C7BA08C0EE74099396EC505BE0D5F967FCEB96DAD4F7813`
- L2 `DualMass.lean`：`975721DE02B708CD1483E94B0D83ABDFE8C08B72150E756257D5A358AC038FAA`
- MP12 本地 PDF：`BF1160F088825ED28C343B299F5BC2ACDCA41CC50293310A03A4506D2FDBDB84`

本报告以这些源码快照及上述原文页码为依据。构建结果由主智能体单独取证，
本文未运行新构建，也未证明概率代理负责的联合分布/TV 部分。
交接前检测到主智能体更新了 `IntegerGaussian.lean`，已重新完整读取该文件；
变更是证明中的类型标注与展开，`CosetMassComparison` 的陈述及本文缺口判断未变。
