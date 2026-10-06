# Foo–Li L2：对偶格高斯质量与平滑传递的 Lean 核验

日期：2026-10-06。对应原账本的 **L2**，不替代 L1、L3、L4 或安全性证明。

## 1. 证明了什么

令 q 为素数，A∈Zq^(n×m)、B∈Zq^(n×w)，F=[A|B]。设 A **在模 q 上满行秩**、0<s≤t、w≤m、0<ε₀≤1/4，且

\[
\Theta_A(s)\le\varepsilon_0,\qquad
\Theta_C(r)=\sum_{y\in\Lambda_q^\perp(C)^*\setminus\{0\}}
             e^{-\pi r^2\|y\|_2^2}.
\]

本包的目标定理给出

\[
\Theta_F(t)\le\varepsilon_F:=2\varepsilon_0+\varepsilon_0^2,
\quad 0<\varepsilon_F\le9/16<1,
\quad\eta_{\varepsilon_F}(\Lambda_q^\perp(F))\le t.
\]

同时直接给出 `SmoothAt`：t>0 且完整对偶格质量不超过 1+εF。后续可以使用这个质量证书，不必从 η 的数值不等式反推平滑性。

这里 Gaussian 的参数是 **1/r**，指数才是 −πr²‖y‖₂²。B 任意，不假设均匀或与 A 独立。原型参数、接口及 `security_claim: none` 均未改变。

最终验收依据是 `verification/run-*/verification.json` 中的 `status: pass`，及同一目录的源码检查、公理审计和负控制日志。中间调试编译不算最终验收。

公开声明清单共 **113 项，其中 87 个定理（含 7 个精确控制定理）**。这些数量反映证明拆分，不代表完成了 87 项密码学安全性质。

## 2. 不是把关键结论当作假设

最终 `l2_prime_rank` / `l2_modular_matrices` 只接受上面列出的原始条件。以下桥梁均由源码证明，而非另加公理或主定理前提：

| 文件 | 已形式化的责任 |
|---|---|
| `FooLiL2/Cosets.lean` | 模秩与满射；整系数核格及真正的积分配对对偶；对偶格的双向陪集分解、标签唯一性、显式双射；拼接满射与位移拼接 |
| `FooLiL2/Gaussian.lean` | 全体整数上的高斯可和性；Poisson 求和导出的平移质量最大值；正性及逆宽度单调性 |
| `FooLiL2/ProductSum.lean` | 任意有限维整数向量上的可和性和无限和乘积分解，不使用截断数值和 |
| `FooLiL2/VectorGaussian.lean` | 多维高斯、分块乘积、平移上界和单调性 |
| `FooLiL2/MassBounds.lean` | 非负质量的代数组装；εF 的严格范围；可行点到 sInf 上界 |
| `FooLiL2/Assembly.lean` | 有限陪集族上的完整高斯质量扩展界（中间层，不独自冒充对偶格定理） |
| `FooLiL2/DualMass.lean` | 用真实对偶格双射重索引；对偶格可和性；只扣原点；整数提升无关性；Euclidean 范数和 `SmoothAt` 桥接 |
| `FooLiL2/L2.lean` | 主定理、素数模秩版本、直接平滑证书及 ZMod 矩阵输入版本 |
| `FooLiL2/Controls.lean` | 精确边界与错误变体的反例；不是密码实现测试 |

主要入口：`FooLiL2.l2_modular_matrices`（ZMod 矩阵）、`FooLiL2.l2_prime_rank`（整数提升+模秩）、`FooLiL2.l2_smoothAt`（直接平滑关系）。通用 `l2_qary_mass_extension` 甚至允许任意非零模数，但要求模线性映射满射；项目仍按原素数模数表述。

## 3. 推理链及容易出错之处

1. 从积分配对定义证明
   \(\Lambda_q^\perp(C)^*=\bigsqcup_a(\mathbb Z^d+\widetilde C^T\widetilde a/q)\)。反向包含、无重复及整数提升均被处理。
2. 证明每个无穷级数可和，并通过双射把真实对偶质量改写为陪集质量和。
3. 对每个 a，扩展块的移位质量不超过零位移质量。证明来自固定 Mathlib 的 Poisson/Jacobi theta 理论，不把 MP12 Lemma 2.5 作为新公理。
4. 完整保留 a=0 陪集。零点之外的整数点仍有正质量；从总量只减去原点的 **1**。
5. 用 t≥s、w≤m 及一维零位移质量≥1，得 `1+ΘF(t) ≤ (1+ε₀)^2`，再减 1。

`gaussianWeight_eq_euclidean` 明确连接 `WithLp.toLp 2` 的 Euclidean 范数；没有误用 `Fin d → ℝ` 默认的最大值范数。

`smoothingInf` 定义为正宽度可行集合的下确界。这里只证明“已获得质量界 ⇒ η≤t”，并显式证明可行点和下界。**没有声称下确界达到，也没有证明仅凭 η≤t 就能反推端点平滑性。** MP12 Definition 2.2 的球形平滑关系由 `SmoothAt` 直接表达，足以保留本次需要的方向。

## 4. 复验

固定环境：Lean **4.34.1**（commit `5045d0056413266e57c625dcd7c365b10e377c52`），Mathlib **`d13f23b723b8a846827a245b89c10fc7d3f11612`**；另外八个依赖由 `lake-manifest.json` 锁定。不要运行 `lake update` 改写锁文件。

本机在 `D:\Lean\projects\fooli-l2`：

```powershell
. D:\Lean\Enter-Lean.ps1
Set-Location D:\Lean\projects\fooli-l2
.\Verify.ps1
```

`Verify.ps1 -LeanHome D:\Lean` 也可使用。脚本只改变本次进程环境，不安装编辑器插件、不改系统 PATH。该工程的 `.lake/packages` 在本机复用固定依赖目录；交付包不包含这个连接、Mathlib 源码、工具链或编译缓存。

另一台机器须自行准备锁定的 Lean 和依赖；普通 `lake build` 可获取锁定依赖并构建。可选使用 `lake exe cache get Mathlib.NumberTheory.ModularForms.JacobiTheta.TwoVariable Mathlib.LinearAlgebra.BilinearForm.DualLattice Mathlib.LinearAlgebra.Matrix.Rank Mathlib.Analysis.InnerProductSpace.PiL2 Mathlib.Algebra.Field.ZMod Mathlib.Tactic.Linarith` 获取对应缓存。这一步需要网络，不能把旧日志当作另一台机器已经复验。

验收脚本会：

- 核对 Lean 版本及全部依赖 HEAD/已跟踪源码状态；
- 对照 `declarations.json` 检查全部公开定理和定义的清单；
- 构建主库与正控制，并逐个重新检查本地 Lean 源文件；
- 审计所有公开声明的传递公理依赖，仅允许 `propext`、`Classical.choice`、`Quot.sound`；
- 排查证明占位、额外公理和不可信计算替代路径；
- 确认 `Checks/WrongErrorBound.lean` 中故意错误的 `εF≤2ε₀` 断言因假命题被拒绝，而不是因缺文件或缺环境失败；
- 核对检验前后文件哈希不变，记录命令、退出码、耗时、源码与日志 SHA-256。

故意失败的检查文件不在默认构建目标中。复制包后，如改动源码或文档，应生成新的日志目录；不要覆盖本次证据。

## 5. 多智能体与独立复核

- Socrates：原论文数学条件、反例及最终语义/假设审计；见 `reviews/math-review.md`、`reviews/final-review.md`。
- Gauss：一维 Gaussian/Poisson 证明；见 `reviews/gaussian-progress.md`。
- Bacon：矩阵、真正对偶格和陪集双射；见 `reviews/cosets-progress.md`。
- 主代理：有限维无限和、质量组装、实际对偶质量到 L2 的整合、控制测试、统一核验与交付。

智能体交叉审查不是人类专家审稿。`proof-writer` 只用于组织前提、桥梁和范围，不作为数学证据。最终定理前提及编译日志应由主代理和后续人工共同查阅。

## 6. 仍未覆盖的内容

- `ΘA(s)≤ε₀` 是本次 L2 的条件，不是已经证明实际 Setup、所有参数和每次生成的 A 自动满足它。满秩与实际陷门生成器的连接仍须在整体正确性定理中履行。
- 未证明实际采样器实现满足论文的分布契约；未完成 L3 的用户陷门界、L4 的签名范数界及整体失败概率组装。
- 未证明 Foo–Li 的正式安全归约，也未完成 HIBE 或完整 IB-ME 的正确性、安全性、参数估计或性能验收。
- 未建立 Mathlib 的通用 `IsZLattice` 类型类封装；本次使用明确定义的 q-ary 整数核格、其真正双线性对偶子模及点集。主定理不依赖遗漏的该类型类。
- 可信边界仍包括 Lean 内核、标准逻辑公理、锁定依赖和数学模型与论文/实现的对应。不能据此承诺整个项目“万无一失”。

## 7. 固定来源

- 上级 `FooLi-条件式正确性定理与参数账本.md`，L2（SHA-256 `F1B769CA2F71C2784877CCF4B34F62BE7155BA468DA8030C12F2CFA7D2724159`）。本次不改动该已提交基线或 L1。
- Micciancio–Peikert，[ePrint 2011/501](https://eprint.iacr.org/2011/501)，本地 `papers/2011_lattice_trapdoors_micciancio.pdf`；对偶格关系、Definition 2.2、Lemma 2.5。PDF SHA-256 `BF1160F088825ED28C343B299F5BC2ACDCA41CC50293310A03A4506D2FDBDB84`。
- 固定 Mathlib 的 `Analysis/SpecialFunctions/Gaussian/PoissonSummation.lean`、`NumberTheory/ModularForms/JacobiTheta/TwoVariable.lean`、`LinearAlgebra/BilinearForm/DualLattice.lean` 等；以实际导入的锁定版本为准。

本包是官方验收 A01–A15 中相关理论证据的补充，不能独自表示任一整项或全部赛题要求已经达标。没有新增“必须 128 位安全”、Ring-SIS 或固定速度门槛。
