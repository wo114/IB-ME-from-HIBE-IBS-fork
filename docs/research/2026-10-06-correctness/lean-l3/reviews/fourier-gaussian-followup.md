# L3 C2 一维 Fourier–Gaussian 与有限维乘积工具复核

日期：2026-10-06。状态：本工具范围内全部证明和单文件检查通过；不代表整个 C2→陪集质量比较或 L3 已完成。

## 1. 写入范围

- `FooLiL3/FourierGaussian.lean`：1 个公开定义、19 个公开定理。
- `FourierGaussianAudit.lean`：逐声明公理审计、主接口检查、两个边界例子。
- 本 review。

没有修改 L2 源码、其他 L3 模块、主审计脚本、声明清单、README 或 Git 仓库。没有运行 `lake build`、`lake update` 或安装命令。主控仍需纳入总构建、声明清单和总审计。

## 2. 精确约定

`phaseTerm s b z` 定义为

```text
exp (ofReal (-π * z² / s²) - 2 * π * I * b * z).
```

一维与乘积求和定理只有 `s > 0` 这一宽度前提；`b`、各 `c i` 可为任意实数，`m` 为任意自然数，包括零。

这里使用负号 Fourier 相位。因此右侧直接是正移位 `FooLiL2.gaussianMass s b`，无需额外使用 `b ↦ -b` 的偶性转换。

`FooLiL2.gaussianMass s b = ∑' z : ℤ, exp (-π * s² * (z+b)²)`。

`FooLiL2.gridMass m s c = ∏ i : Fin m, gaussianMass s (c i)`。

所有无限和均遍历完整整数格，不是截断近似、数值实验或归一化概率假设。

## 3. 主控可直接引用的接口

导入 `FooLiL3.FourierGaussian`，命名空间为 `FooLiL3`。

### 精确一维变换

```lean
theorem tsum_phaseTerm_eq_gaussianMass {s : ℝ} (hs : 0 < s) (b : ℝ) :
    (∑' z : ℤ, phaseTerm s b z) =
      (s : ℂ) * (FooLiL2.gaussianMass s b : ℂ)
```

另有 `hasSum_phaseTerm hs b`、`tsum_gaussian_mul_phase hs b`（左侧显式写成实高斯乘复相位）。

### 精确有限维变换

```lean
theorem tsum_prod_phaseTerm_eq_gridMass (m : ℕ) {s : ℝ} (hs : 0 < s)
    (c : Fin m → ℝ) :
    (∑' z : Fin m → ℤ, ∏ i, phaseTerm s (c i) (z i)) =
      (s : ℂ) ^ m * (FooLiL2.gridMass m s c : ℂ)
```

另有 `hasSum_prod_phaseTerm m hs c`。

### 逐项连接向量 `rho` 与总相位

```lean
theorem prod_phaseTerm_eq_rho_mul_exp (m : ℕ) (s : ℝ)
    (c : Fin m → ℝ) (z : Fin m → ℤ) :
    (∏ i, phaseTerm s (c i) (z i)) =
      (rho s (∑ i, (z i : ℝ) ^ 2) : ℂ) *
        Complex.exp (-2 * Real.pi * Complex.I *
          ∑ i, (c i : ℂ) * (z i : ℂ))
```

这里不涉及模约简，也不假设字符恒等式。可以接主控的 `χ(-a·Ax)` 转换。

### 收敛和模长工具

- `norm_phaseTerm s b z`：模长为 `exp (-π*z²/s²)`。
- `norm_phaseTerm_eq_rho s b z`：模长为 `rho s z²`。
- `phaseTerm_eq_mul_exp s b z`、`phaseTerm_eq_rho_mul_exp s b z`。
- `summable_norm_phaseTerm hs b`、`summable_phaseTerm hs b`。
- `summable_norm_dualGaussian hs b`：右侧复高斯也绝对可和。
- `norm_prod_phaseTerm_eq_rho m s c z`：乘积模长为向量 `rho`。
- `summable_norm_prod_phaseTerm m hs c`、`summable_prod_phaseTerm m hs c`。
- `summable_norm_fin_complex_product d f hf`：一般有限维复级数的绝对可和性。
- `tsum_fin_complex_product d f hf`：一般有限维复级数的乘积求和分解；`hf` 逐坐标要求范数可和，不偷偷假设非负性。

## 4. 证明依赖与审查结论

1. 绝对收敛先由 L2 `summable_gaussian_coefficient` 和单位模相位得到，再推出复级数可和。
2. `gaussian_poisson_prefactor hs` 严格证明
   `1 / (ofReal ((s²)⁻¹))^(1/2 : ℂ) = ofReal s`。
   使用 `Complex.ofReal_cpow`、`Real.sqrt_eq_rpow`、`Real.sqrt_inv` 和 `Real.sqrt_sq hs.le`，因此没有遗漏复幂主值分支或 `|s|`。
3. 一维恒等式使用 Mathlib `Complex.tsum_exp_neg_quadratic`，代入正实 `a = (s²)⁻¹` 及复线性参数 `-I*b`。代入和所有实复转换均在 Lean 内完成。
4. 有限维分解用 `Fin.consEquiv` 归纳及 `tsum_mul_tsum_of_summable_norm`；范数乘积可和性由 L2 非负实乘积引理获得。求和交换未省略绝对收敛前提。
5. 一维前因子在 m 维逐项相乘为 `s^m`；没有漏掉维数或前因子。
6. 本文件不声明矩阵满秩、模字符正交、Poisson 陪集公式、平滑界或质量比较。这些是主控下一段的接线，不应把本工具通过解释为完整 C2 已通过。

`proof-writer` 仅用于明确前提、符号和接口检查；数学依据为固定版本 Mathlib 与既有 L2 定理。

## 5. 实际检查

环境：Lean 4.34.1，commit `5045d0056413266e57c625dcd7c365b10e377c52`；Mathlib `d13f23b723b8a846827a245b89c10fc7d3f11612`。

最终从 `D:\Lean\projects\fooli-l3` 执行：

```powershell
. D:\Lean\Enter-Lean.ps1
lake env lean -o .lake/build/lib/lean/FooLiL3/FourierGaussian.olean FooLiL3/FourierGaussian.lean
lake env lean FourierGaussianAudit.lean
```

- 源文件：退出码 0，没有报错或警告；已生成供主控 import 的 `.olean`。
- 审计 scratch：退出码 0，没有报错或警告。
- 20 个公开声明逐一 `#print axioms`：均只依赖 `[propext, Classical.choice, Quot.sound]`。
- 源码占位/绕过标记扫描没有命中。
- 零维空乘积为 1 的边界例子通过。
- `b = 0` 的中心恒等式保留 `s` 前因子的例子通过。

初次检查因主控的 L2 本地构建尚未生成对象文件而无法加载。中间单文件迭代临时使用原 L2 项目的既有同版本对象；最终检查已在 L3 的 vendored L2 构建完成后重新执行。没有另开并行项目构建。

已核对被引用 L2 文件与 vendored 版本 SHA-256 相同：

- `Gaussian.lean`：`606BDFF24E306CEAFA32A5C113088DBE21969CAE1BF046F420389409519978E8`。
- `VectorGaussian.lean`：`7796B7EEBF4690CC8BA115157342DD9EA8357B01A787F7E14544C1211658F791`。

最终源码 SHA-256：

- `FooLiL3/FourierGaussian.lean`：`135DE376491AFDDC8EAE05F5A74FCBE7AE7E090FAB7155185840BA0EEBB4E39D`。
- `FourierGaussianAudit.lean`：`3763B7499D8AD5F5F7F684CCC947ED1B270F6B82BDBAC909E6F86A6F7A74AB0A`。

## 6. 主控四模块的独立只读语义复核

时间：2026-10-06，约 13:26—13:29。复查 `FiniteCharacters`、`PhaseFactors`、`CosetPoisson`、`SmoothingBounds` 当时的源码，并回查 L2 的 `shift_pairing`、`cosetParam_injective`、`dualEquiv`、`dualMass_eq_coset_sum` 和 Mathlib 的 `stdAddChar_coe`。没有修改主控源码，没有运行其构建。

**结论：在所读公式和假设中未发现需要立即修正的数学错误。以下是源码语义复核，不是对正在变化的文件作最终编译认证，也不是宣告 C2 接线已经完成。**

### 三项重点

1. **`q^n` 因子正确。** 字符索引域为 `(ZMod q)^n`，大小 `q^n`；正交关系给出 `q^n * 1[u-Ax=0]`，因此 indicator 必须乘 `q^(-n)`。m 个一维变换各贡献 `s`，最终 `coset_poisson` 的前因子 `s^m/q^n` 正确，不是 `s^n/q^m`，也没有多余或遗漏的 `q`。`[NeZero q]` 足够让该分母非零；字符恒等式不要求 q 素数。
2. **正负号一致。** `stdAddChar(k)=exp(2π i k/q)`；`u-Ax` 分成外部正相位 `χ(⟨u,a⟩)` 和内部负相位 `χ(-⟨Ax,a⟩)`。`shift=Cᵀ lift(a)/q` 满足 `⟨shift,x⟩=⟨lift(a),Cx⟩/q`，内部相位正好变成 `exp(-2π i ⟨shift,x⟩)`。这和本工具的负相位一致，Poisson 后的网格高斯移位为 `+shift`。整数 lift 不需要是居中代表，负的 C 元素也不破坏等式。
3. **保留了零剩余类的非零整数。** `weighted_mass_deviation` 在指定的零标签仅减 `1`，不是减去整个 `v(0)`。代入 `v(a)=gridMass m s (residueShift a)` 后，右侧为
   `gridMass m s 0 - 1 + ∑_{a≠0} gridMass m s (residueShift a)`。
   第一项完整保留 `a=0` 下的所有 `z≠0`；只有 `(a,z)=(0,0)` 的质量被扣除。`one_le_gridMass_residue_zero` 提供了对这项取模时需要的非负性。

### 满射假设的准确边界

`coset_poisson` 本身不要求 `FullRowRank` 是正确的：即使 C 不满射，有限字符展开仍给出正确的 indicator。但把 `∑a gridMass(...)` 识别成真实 `dualMass` 时，**必须保留 `FullRowRank q C`（模线性映射满射）**，因为此时才由 L2 的 `dualEquiv` 保证不同标签没有重复计数。

这不是抽象风险：取 `q=2,n=m=1,C=0`，两个标签的 shift 都是零，剩余类质量和等于 `2*gridMass 1 s 0`，而真实对偶格 `ℤ` 的质量只有 `gridMass 1 s 0`。Poisson 公式仍正确，但若删掉满射前提来接 `dualMass`，质量解释就错误。当前 `dualTheta_antitone` 已正确携带 `hC`。

### 后续接线应保持的公式

对任意 syndrome u，在满射及正宽度下，先得到

```text
| (q^n/s^m) Z_u(s) - 1 | ≤ dualTheta(C,s).
```

再用 C2 的实际对偶质量界 `dualTheta(C,s) ≤ e`（不反向使用 smoothing-inf 的端点不等式）。由对偶权重 `exp(-π*s²*||y||²)` 随 s 增大而下降，已有 `dualTheta_antitone` 正确给出 `Theta(2s) ≤ Theta(s)`。上下界应分别是

```text
(1-e) * s^m/q^n ≤ Z_u(s),
Z_u(2s) ≤ (1+e) * (2s)^m/q^n.
```

随后 `doubling_comparison_of_normalized_bounds` 得到
`Z_u(2s) ≤ 2^m * (1+e)/(1-e) * Z_u(s)`；该比率只出现一次，不应平方。必须保持 `e<1`、同一 C、同一 syndrome 和同一分母 `q^n`，且在除法/范数转为实数绝对值时保留 `s^m/q^n>0`。

### 边界与收敛复核

- `q=1` 时只有零标签，剩余质量仍为 `gridMass-1`，不能因此把 `Theta` 误设为零。
- `n=0` 时字符和只有一项，前因子退化为 `s^m`；`m=0` 的空乘积也与字符 indicator 相容。
- `CosetPoisson` 从完整整数子类型求和转到 indicator，没有截断；有限字符和与整数无限和的交换调用了 `summable_modularGaussian`，后者由本文件的绝对可和性导出。
- 尚未独立检查后续新增的 normalized-bound/C2 总接线代码；应由主控最终集成后再复核。

复查快照 SHA-256（`CosetPoisson` 的证明体在检查过程中更新过，已重读更新版本；定理公式不变）：

- `FiniteCharacters.lean`：`8850D7DDE3804541F960EA600490287CC02F5490D82B0643C46CFDB82D8EA882`。
- `PhaseFactors.lean`：`615DD3E7E1DBC50EA699AE34250E9010906E67BDE65F40264D5EB9D387144DFC`。
- `CosetPoisson.lean`：`F0C754DED800F94DAEF5C92B54D4B46A082995F50865552F147ADAD70D5D44AC`。
- `SmoothingBounds.lean`：`AB75B877BF6423C8A05D008AB4B4163D8A02BC2AE3FD4DB2BEF6CDF9B6AF6D8E`。

## 7. SmoothingBridge / ClosedL3 的独立输入与尺寸复核

时间：2026-10-06，约 13:29—13:32。只读检查两文件，并追踪 `IdealDelegation`、`SetupRank`、`L3`、`EventBounds` 的相关定义，回查原参数账本 §2.1、C2/C3 和 L3。本轮没有编译主文件，也没有修改主文件。

**结论：当前最终定理没有遗留 `CosetMassComparison`、列尾概率、`CosetColumnLaw/hMarginal` 或理想支持假设。未发现新的数学接线错误。有一项 gadget 参数命名的对照需要明确，见下文。**

### 最终输入是否真的闭合

| 旧的额外接口 | 现在的内部来源 |
|---|---|
| 每个 syndrome 的 `CosetMassComparison` | `SmoothingBridge.cosetMassComparison_of_smoothing` 从同一 A 的实际 `dualTheta ≤ e` 推出 |
| 列的 Gaussian tail | 既有尾概率定理由内部生成的质量比较证书推出 |
| `hMarginal/CosetColumnLaw` | `independentFinPMF_marginal` → `idealDelegationMeasure_columnLaw` |
| 理想支持/非中止 | subtype 的列方程及 `some` 映射 → `idealDelegationMeasure_invalidOutput` |
| A 的模满射性 | 最终 `l3_from_c2_c3` 中由主关系 `A[R₀;I]=G` 和 gadget 单位列推出 |
| 坏事件可测性 | 有限维整数矩阵的可数性及 `MeasurableSingletonClass`，没有把任意坏事件可测另当输入 |

`IdealDelegation.l3_from_mass_certificates_and_product_ideal` 作为中间引理仍有 `hMass`，这是预期的模块接口，不是最终遗漏：`ClosedL3.l3_from_smoothing_and_product_ideal` 逐列调用 smoothing bridge 消掉它。最终 `l3_from_c2_c3` 进一步消掉中间接口的 `hA`。

最终数学输入为：主关系 `hmaster`、`s>0`、`0≤e<1`、真实对偶质量界 `hTheta`、质量阈值 `Q≥mws²`、原始实际分布对**具体构造的独立产品理想分布**的 TV 契约 `hTV`；另有维度、`q≠0`、概率测度和可测空间类型条件。没有自由理想测度 ν、自由边缘分布或假设式质量比较藏在最终签名里。

### SmoothingBridge 复核

- `normalized_coset_mass_deviation` 的正因子 `f=s^m/q^n` 显式证明为正，复数域消去 f 后再把实数嵌入的范数转成绝对值；没有把复和的实部直接替代模长。
- 从 `|Z/f-1|≤e` 推出 `(1-e)f≤Z≤(1+e)f` 的两条除法不等式方向正确。
- `hC` 从 `liftMatrix A` 的 round trip 和 A 的满射性构造，随后用于真实对偶质量重索引；没有丢掉上一轮强调的满射前提。
- 宽度 `2s` 使用同一 C、同一 syndrome u，并从 `Theta(2s)≤Theta(s)≤e` 取得上界；最终只出现一次 `(1+e)/(1-e)`。
- `CosetMassComparison` 在最后是结论。源码中的 `change CosetMassComparison ... at h` 只是展开同一命题的类型转换，不是引入假设。

### gadget 尺寸正确，但 k 与账本不是同一个记号

`SetupRank.powersGadget n k 2` 的块索引是 `Fin (k+1)`，故指数范围为 `0,…,k`，向量为 `[1,2,…,2^k]`，**块长确实为 k+1**。因此 `ClosedL3` 中

```text
w = n*(k+1),  m = r+n*(k+1),
R₀ : r × w,  B,G : n × w,  delegated R : m × w,
Q ≥ m*w*s²,  budget = min(1, εDel + w*tailBudget(m,e))
```

彼此一致。主关系使用 `[R₀; I_w]` 的正号和正确的行重索引；输出方程仍为 `AR=B-G`。

**文档对照提醒：** 原账本 §2.1 的 `k_ledger=ceil(log₂ q)` 是**块长**，其 gadget 为 `[1,2,…,2^(k_ledger-1)]`。Lean 当前的 k 是**最高指数**。实际套用账本应设置

```text
k_Lean = k_ledger - 1,  r = mbar,
k_Lean + 1 = k_ledger,  w = n*k_ledger,  m = mbar+w.
```

这里 `k_ledger≥1` 由账本的素数 q≥2 保证。不能直接令 `k_Lean=ceil(log₂q)`，否则每块多出一列，w、m 和尾预算都会错位。建议在最终 README 或该定理说明中明确这张映射；当前定理本身及现有“k+1 是块长”注释没有代数错误，但尚未写出与账本同名 k 的差一对应。

该形式定理不限制 gadget 长度必须取 `ceil(log₂q)`，是因为本段只利用每块 `2^0=1` 的单位列和外给的 C3 契约；它没有另行证明任意长度下的 bit-decomposition 采样实现。

### 仍然明确保留的证明边界

- μ 是包含 `none` 的原始输出概率测度，坏事件包含中止、关系无效、质量超限；理想法没有按质量预过滤。TV 在统一原始空间上使用，没有重复添加中止预算。
- 最终结论是**固定好初始化后的条件式 L3**，不是 Setup 的无条件总失败率。C2 的实际发生概率、C3 的实际有限采样器 TV 证书仍需单独证明。
- 不出现 Q₀/主陷门范数并非漏洞：本引理只需从好初始化条件中取主关系和平滑界；C2 的其他更强条件不在这一步被使用。账本 `0<e≤1/4` 同样蕴含此处较弱的 `0≤e<1`。
- 本轮是独立语义复核，最终 kernel 检查及全声明公理审计仍由主控集成执行。

所读快照 SHA-256：

- `SmoothingBridge.lean`：`3096998534B7D8548D4D8083E607E951360918581F6DBDEE17D7803431BFE615`。
- `ClosedL3.lean`：`035070CD073465A447A8BAF4D0C334E0B87EDF60DCA81A1D02A6115556FD5F8C`。
- `IdealDelegation.lean`：`922BD615EC7790D961726674C5FAACC1470C2488307BAC6C96409A27DE44F10B`。
- `SetupRank.lean`：`20ABA6AC4ACF8C936EC72D38BEF6F73820436CC382DB651C273B715E5387DB40`。
