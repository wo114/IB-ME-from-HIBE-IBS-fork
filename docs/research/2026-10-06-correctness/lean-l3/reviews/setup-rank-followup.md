# L3 Setup 秩条件与 integer lift 接线复核

日期：2026-10-06。范围：只补 Setup 有效陷门关系推出模 q 满射，以及 L2/L3 整数核、陪集兼容。此审查不宣布整个 L3、采样器分布契约或安全性证明完成。

## 已完成

`FooLiL3/SetupRank.lean` 新增 28 个定理、3 个定义。主证明路线是构造右逆，不把 A 满射作为额外前提。`proof-writer` 仅用于核对前提、符号和证明链；证明依据为 Lean 内核通过的项和所复用 L1/L2 的精确接口。

### 1. 优先使用账本 C2 的 H=I 版本

账本 C2（`FooLi-条件式正确性定理与参数账本.md` 第 112 行起）采用 `A[R₀;I]=G`，不是一般标签版本。优先接口：

- `standard_master_relation_surjective`：A 为扁平索引 `Fin (m + n*(ℓ+1))` 的实际矩阵；R₀ 为整数矩阵；前提恰为 A 乘 entrywise-reduced、扁平化的 `[R₀;I]` 等于标准 gadget。结论为 `Function.Surjective A.mulVec`。没有 H、K、A 满射或 G 满射假设。
- `master_relation_surjective_of_identity_columns`：适用于任意具体 gadget G，只需给定选择函数 `sel` 并证明 `G i (sel j) = if i=j then 1 else 0`。A 用块索引 `Fin m ⊕ Fin w`。
- `master_relation_flat_surjective_of_identity_columns`：上述接口的 L3 `Fin (m+w)` 扁平版本。

正号 `[R₀;I]` 与 L1 `master_trapdoor_equation` 一致，不误用签名阶段的 `[-R;I]`。本文件只读取 L1，没有修改或依赖其未冻结版本。

### 2. Gadget 的满射不是新假设

`blockGadget n g` 定义块对角 `I_n ⊗ g`；只要 g 的某个坐标等于 1，各块对应坐标即构成单位矩阵列。

- `columnSelector sel` 是明确的选列矩阵；`mul_columnSelector` 证明乘法确实抽取这些列。
- `rightInverse_of_identity_columns` 证明 `G * columnSelector sel = I`。
- `blockGadget_rightInverse` / `blockGadget_surjective` 将上述结论用于每块含 1 的 gadget。
- `powersGadget n ℓ b` 为 `[1,b,...,b^ℓ]`，第零项等于 1；`powersGadget_rightInverse` / `powersGadget_surjective` 不限制 b 是否为单位。
- `powersGadget_flat_identity_columns` 给出标准扁平索引下的精确选列位置 `finProdFinEquiv (j,0)`，即行块优先顺序的 `j*(ℓ+1)`。
- `powersGadget_flat_surjective` 通过双射重编号搬运满射。

标准 gadget 宽度使用 `ℓ+1`，显式保证至少一项。若上层账本将宽度记为 k，应以 k=ℓ+1 实例化，或使用任意 G 的 identity-columns 接口并提供合法列下标，不能默默把 k=0 当作含有首列。

### 3. 通用标签版本保留作辅助

`mulVec_surjective_of_trapdoor`：从 `A*T = H*G`、`H*K=I` 和已证明的 G 满射，构造每个 u 的原像 `T*z`，其中 `G*z=K*u`。

`rightInverse_of_trapdoor`：若另有 `G*J=I`，则明确证明 `A*(T*J*K)=I`。

`mulVec_surjective_of_trapdoor_unit_tag`：若标签输入形式为 `IsUnit H`，则由该单位本身取逆，不要求上层再手写 K。非零标签不等于可逆标签，尤其合数 q 下不能混淆。

`master_setup_trapdoor_equation` 与 `master_setup_surjective` 覆盖具体 Setup 形状 `[Abar | H*G-Abar*R]`；`standard_master_setup_surjective` 使用标准 gadget 自动消去 G 的满射前提。

### 4. L2 integer lift 与 L3 陪集完全接线

原样复用 `FooLiL2.Cosets.mod_liftMatrix` 和 `mod_liftVector`，没有重写或修改 L2。它们已经证明：

```text
modMatrix q (liftMatrix q A) = A
modVector q (liftVector q u) = u
```

新增接口：

- `fullRowRank_liftMatrix_iff A`：`FullRowRank q (liftMatrix q A) ↔ Function.Surjective A.mulVec`。
- `fullRowRank_liftMatrix_of_trapdoor`：通用陷门证书直接输出 L2 的 `FullRowRank` 前提。
- `inCoset_liftMatrix_iff A u x`：L3 `InCoset q A u x` 当且仅当 `modVector q ((liftMatrix q A)*ᵥx)=u`。
- `inKernel_liftMatrix_iff A x`：L2 的整数核恰为 L3 零 syndrome 陪集。
- `inCoset_iff_sub_inKernel A u x x₀ hx₀`：已知整数解 x₀ 后，`x∈Λ_q^u(A)` 当且仅当 `x-x₀∈Λ_q^⊥(liftMatrix A)`。
- `coset_nonempty_of_trapdoor`：从陷门证书推出每个 L3 实际整数陪集非空，调用现有 `coset_nonempty_of_surjective`，不重写高斯归一化论证。

建议主控接线：

```lean
have hA := FooLiL3.standard_master_relation_surjective A R₀ (2 : ZMod q) hmaster
have hLift := (FooLiL3.fullRowRank_liftMatrix_iff A).mpr hA
have hCoset := FooLiL3.coset_nonempty_of_surjective q A hA u
```

其中最后一步沿用 L3 原接口的 `[NeZero q]`。代数满射及 lift 兼容引理本身无需 q 为素数；需要真格/对偶分解的其他 q 条件仍由相应 L2 定理单独要求。

## 核验结果

只运行单文件 Lean，没有运行全项目 `lake build`，没有安装、更新依赖或修改工具链。

1. `. D:\Lean\Enter-Lean.ps1` 后，在 `D:\Lean\projects\fooli-l3` 执行：

   `lake env lean -o .lake/build/lib/lean/FooLiL3/SetupRank.olean FooLiL3/SetupRank.lean`

   最终 exit 0，无警告。

2. 独有 scratch `SetupRankChecks.lean`：`lake env lean SetupRankChecks.lean` 最终 exit 0，无警告。覆盖：

   - 合数 q=6 的标准幂 gadget 满射；
   - 每块仅 `[1]`，且底数为 0；
   - n=0 的空行边界；
   - q=6、H=I、任意 Abar/R 的完整具体 Setup 形状；
   - 无效零 gadget/零 A 不能推出满射的反例：机器证明零 `1×1` 矩阵在 `ZMod 7` 上不满射。

3. 对全部 31 个公开声明逐一 `#print axioms`：仅出现 `propext`、`Classical.choice`、`Quot.sound`；三个定义无公理，部分简单定理仅用 `propext`。未使用 `sorry`、`admit`、自定义公理或 `native_decide`。

4. `SetupRank.lean` 当前 SHA-256：`20ABA6AC4ACF8C936EC72D38BEF6F73820436CC382DB651C273B715E5387DB40`。独立复查轮仅将开头的 `/-!+#` 改为正常换行的 `/-!` 与 `#`；修复前 SHA-256 为 `07CE9AF4A880925354E3C35C31D02C96920B99E48054C98C79E1B1A408378FB7`。将当前文本的该处注释替换反向恢复后，重算哈希精确等于旧值，确认数学声明与证明正文逐字节未变。新哈希源码再次单文件 Lean 检查 exit 0、无警告。

开发过程中修复了泛型矩阵的隐式类型参数、doc-comment/omit 顺序及 product equivalence 被 simp 过早展开的问题；最终检查针对上述哈希的源码，不以早期失败运行代替最终证据。

注释格式修复后同轮重新执行 `SetupRankChecks.lean`：exit 0、无警告，31 个声明的公理依赖仍仅为上述标准三项。

## 边界和交接

本子任务的 Setup→模 q 满射与整数 lift 兼容缺口已补齐；无新增数学占位前提。仍需主控将模块纳入 root imports、声明清单、全局 Audit/Verify，并重新冻结全项目证据；本子任务未修改这些共享文件。L2 vendor 字节及 provenance 由主控统一审计。

未触碰生产代码、L1/L2 文件、Git 状态或提交。新增/改动的人工源仅为本模块、此审查和独有 `SetupRankChecks.lean` scratch；Lean 单文件核验另生成了本模块的构建产物。无新缓存需求。

这里不证明实际 Setup 采样成功概率、C2 对偶质量界、C3 TV 契约、独立高斯联合分布或整套 IB-ME 的安全性。这些不能从代数满射结论推断。

## 只读独立复查 IdealDelegation.lean

复查对象 SHA-256：`922BD615EC7790D961726674C5FAACC1470C2488307BAC6C96409A27DE44F10B`；读取前后及单文件核验后哈希一致。未修改该文件。复核了全文、L3/IntegerGaussian/GaussianLaw/EventBounds 对应接口，以及 Mathlib PMF 的 bind、map、外测度和单点可测条件。另独立运行 `lake env lean FooLiL3/IdealDelegation.lean`，exit 0、无警告；没有写其 olean，也没有运行全项目构建。

结论：在本次检查范围内，未发现 product law、support、边际或可测性的假设偷换，没有阻断接入的问题。

- **真实乘积分布**：`independentFinPMF` 逐列 bind 时，余下列的 PMF 不依赖首列取值，只在最后 `Fin.cons` 拼接结果；`independentFinPMF_rectangle` 证明任意矩形事件概率等于各坐标概率乘积，`independentFinPMF_apply` 还证明逐点质量相乘。这不是仅凭“各边际正确”推断独立性。w=0 有 pure 空函数的明确基例。
- **理想高斯与支撑**：`idealColumnsPMF` 的每列是现有实际整数陪集上完整归一化高斯，syndrome 为 `B_j-G_j`，宽度为同一个 s。`idealDelegationPMF` 只将列转置装配成 `some R`，没有截断、质量过滤或成功条件化。invalidOutput 的原像被证明为空，所以理想中止和模方程无效输出的真实概率为零；并非利用 `ENNReal.toReal ∞=0` 伪造零概率。质量差的理想输出仍保留，后续才计入坏事件。
- **边际**：`independentFinPMF_marginal` 给出 PMF 等式，再经外测度原像公式接入 `CosetColumnLaw`。量化的是任意整数列集合 E，不只一个尾事件；矩阵组装的行列顺序与 L3 定义一致。`idealDelegationMeasure_rectangle` 同时保留了组装后列间的矩形事件乘积分解。
- **可测性**：PMF bind/map 在离散质量层定义，不需要偷偷假定某个连续映射可测。使用 measure=outer-measure 的版本明确要求 `MeasurableSingletonClass`；Mathlib 对应定理由 PMF 的可数支撑保证任意事件等式。最终 L3 定理又明确给出有限维整数矩阵的 Countable 实例，由单点可测推出所需坏事件可测。实际与理想测度共享同一个 Option 输出空间及 MeasurableSpace，不能靠粗化可测集合隐藏 TV 差异。
- **剩余显式前提**：`hA` 是陪集非空的代数入口，可用本模块的 master-relation 定理解除；`hTV` 仍须由真实有限原始委派分布证明，包含 abort；`hMass` 仍须由 C2 真对偶质量界推出。该文件已消去原先单独输入的 hSupport/hMarginal，但尚不能仅凭自身声明“整个 C2+C3→L3 已闭合”。主控最终装配时应明确连接这三项，不把构造理想分布当成实现采样器已满足 C3 的证据。

以上是 `proof-writer` 前提检查流程下的独立语义审查与单文件核验；新模块的全声明公理审计、全项目冻结和 vendor provenance 仍由主控执行。
