# Task C — matrix and dual-coset progress

Owner/scope: `FooLiL2/Cosets.lean` and this file only. Actual repository remains read-only.
Source: `docs/research/2026-10-06-correctness/FooLi-条件式正确性定理与参数账本.md`, §§2–4, L2.

## Initial API report

- `Mathlib.Data.ZMod.Basic`: `ZMod.intCast_zmod_cast`, `ZMod.intCast_surjective`, `ZMod.intCast_zmod_eq_zero_iff_dvd`.
- `Mathlib.Data.Matrix.Mul`: transpose, multiplication and dot-product identities; available cache.
- `Mathlib.LinearAlgebra.Matrix.ToLin`: `Matrix.vecMul_injective_iff` links row independence and transpose injectivity; initially missing cache.
- `Mathlib.LinearAlgebra.Matrix.Rank`: `rank_transpose`, `rank_eq_finrank_span_row`; initially missing cache.
- `Mathlib.LinearAlgebra.BilinearForm.DualLattice`: `LinearMap.BilinForm.dualSubmodule`, `mem_dualSubmodule`, duality of basis spans; initially missing cache. No dedicated q-ary lattice decomposition was found.
- `Mathlib.Data.Real.Basic`: initially missing cache. Coordinate algebra can first be proved over any characteristic-zero field (in particular the reals).

## 已完成的结果与冻结状态（2026-10-06）

Task C 于 12:16 对当时的 `FooLiL2/Cosets.lean` 整文件执行 `lake env lean FooLiL2/Cosets.lean`，退出码 0，标准输出为空，无警告。Lean 版本实测为 4.34.1；两个 Mathlib 源码目录的 HEAD 均核验为 `d13f23b723b8a846827a245b89c10fc7d3f11612`。

12:16 已编译快照 SHA-256：`28EDF56D94920D2D0F09FF7C64670127DBDA02994B17B9F0DCD73C78652EE882`。

恢复 `fullRowRank_iff_rank` 兼容包装后，main 已通知：通过 `lake build` 成功本地构建 `Mathlib.Algebra.Field.ZMod` 与 `Cosets`，耗时 27 秒。此前缺失 `.olean` 的阻碍已解决，无需下载。此最终构建结果来自 main 的明确通知，Task C 本次没有重跑构建；主进程将统一执行直接源码检查与公理清单审计。

最终冻结源码 SHA-256（Task C 本次只读复核）：`64385A442C8010E4250ABE53556B2A5800DA850E50F0021FC3D1A27A435E0372`。代码与接口均已冻结，本次仅更新本进度文件。

所有以下声明位于 `FooLiL2.Cosets` namespace。

| 接口 | 机器检查的具体内容 |
|---|---|
| `modVector`, `modMatrix`, `liftVector`, `liftMatrix` | 整数向量/矩阵与 `ZMod q` 的显式映射；`mod_liftVector`, `mod_liftMatrix` 证明提升后约简回原对象 |
| `matrix_surjective_iff_rank` | 任意域上，`Function.Surjective C.mulVec ↔ C.rank = n` |
| `fullRowRank_iff_rank q C` | 保留的素数模兼容包装：`[Fact q.Prime]` 下，`FullRowRank q C ↔ (modMatrix q C).rank = n`；最终构建成功由 main 确认 |
| `transpose_injective_of_surjective` | 任意交换环上，矩阵满射推出转置作用单射；通过坐标点积直接证明 |
| `inKernel_iff_dvd` | `C x = 0 mod q` 与每个整数坐标被 q 整除等价 |
| `integerCoset_subset_dual` | 每个 `Z^d + Cᵀ a/q` 都包含于真实整数配对对偶集合 |
| `exists_integer_right_inverse` | 从模矩阵满射构造整数提升 D，满足 `C D = I mod q`；D 不是新增假设 |
| `right_inverse_residual_inKernel` | `x - D(Cx)` 确属整数模核 |
| `dual_denominator`, `denominator_pairing` | 对偶点 y 的 qy 为整数，并对任意整数向量建立配对恒等式 |
| `dual_subset_integerCosets` | 从对偶成员构造整数 a,z，完成反向包含；未假设格分解或消去子等式 |
| `integerCoset_eq_of_mod_eq` | a 的整数提升改变但模 q 不变时，陪集不变 |
| `dual_eq_residueCosets` | 完整双向等式，标签空间恰为 `Fin n → ZMod q` |
| `residueCoset_label_unique`, `residueCosets_pairwiseDisjoint` | 满行秩下不同模标签的陪集不交 |
| `integerCoset_zero`, `residueCoset_zero` | 零标签对应完整整数子格，未误删其中非零点 |
| `qaryLattice`, `dualSet_eq_dualSubmodule` | q-ary 整数格的实际嵌入与 Mathlib `LinearMap.BilinForm.dualSubmodule` 的双向桥梁 |
| `real_dual_eq_residueCosets` | 在 `Fin d → ℝ` 中、以标准点积计算的 Mathlib 对偶子模，等于模标签陪集之并 |
| `cosetParam_injective`, `dualEquiv`, `dualEquiv_apply` | `(a,z) ↦ z + Cᵀlift(a)/q` 是到 DualSet 的 Equiv，明确给出实际坐标公式 |
| `appendMatrix`, `fullRowRank_append`, `shift_append` | 使用逐行 `Fin.append` 的矩阵扩展；A 满射则 `[A\|B]` 满射，shift 按两块分解 |

## 给主进程的稳定集成接口

```lean
open FooLiL2.Cosets

-- C : Matrix (Fin n) (Fin d) ℤ
-- hq : q ≠ 0
-- hC : FullRowRank q C
dualEquiv (K := ℝ) q hq C hC
  : ((Fin n → ZMod q) × (Fin d → ℤ)) ≃
      {y : Fin d → ℝ // y ∈ DualSet q C}

-- 对任意 az，dualEquiv_apply 给出 subtype 值：
-- intVector az.2 + shift q C (liftVector q az.1)

-- A : Matrix (Fin n) (Fin m) ℤ
-- B : Matrix (Fin n) (Fin w) ℤ
appendMatrix A B
  -- 定义展开为 fun i => Fin.append (A i) (B i)
fullRowRank_append q A B hA
shift_append (K := ℝ) q A B a
```

`shift` 的参数 a 为整数向量；模标签须显式传 `liftVector q a`。`DualSet` 与 `dualEquiv` 可在任意特征零域中使用，因此直接取 `K := ℝ`，无需先以有理数为中介。`qaryLattice` 的 carrier 恰为满足模核条件的整数向量在 K 中的像，且已经证明为 Z-submodule。

`Fin d → ℝ` 在本文件中仅作坐标向量空间；点积是 `dotProduct`。其默认函数空间范数不是 L2 的欧氏范数。Gaussian 集成应使用 `∑ j, (y j)^2`，或另证与 `EuclideanSpace` 的标准转换；不要将默认函数空间范数直接带入原命题。

## 前提账本与边界

1. 原文 q 为素数。本文件的格分解实际上仅需 `q ≠ 0` 和模矩阵满射，也适用于满足该条件的合数模数。这是已证明的推广，不是对模数的额外限制。
2. `FullRowRank q C` 定义为 `(modMatrix q C).mulVec` 满射。`matrix_surjective_iff_rank` 已证明域上的等价关系，未以转置单射或格分解替代满行秩前提。
3. `fullRowRank_iff_rank q C` 是 `[Fact q.Prime]` 下的兼容包装，并通过 `Mathlib.Algebra.Field.ZMod` 使用库提供的域实例。该模块一度缺失 `.olean`，现已由 main 本地构建成功，且 main 已确认 `Cosets` 构建成功；不再存在待下载或待构建的依赖阻碍。没有复制库的域实例，也没有以新假设代替素数性。
4. 对偶格双向集合等式、Mathlib dualSubmodule 桥梁和陪集唯一性均已完成；此处没有保留单向包含作为完整分解。
5. 本文件未建立 `IsZLattice` 的离散/余紧类型类实例，也未建立平滑参数的 infimum 定义。现有真实对偶子模集合与点集 Equiv 不依赖这些实例。
6. 未接管高斯可和性、Poisson/移位质量界、无限和重索引后的乘积质量估计、L2 最终不等式或平滑参数推论。那些结论由主进程另行组合与审计；不能以本文件编译替代整个 L2 的完成。

## 检查记录与协作边界

- 按科研路由采用的 `proof-writer` 工作流用于拆分主张、假设和双向证明；本轮 primary skill 由 main 选择，研究策略不作为数学证据。
- Task C 的 12:16 检查命令（工作目录 `D:\Lean\projects\fooli-l2`）：`. D:\Lean\Enter-Lean.ps1; lake env lean FooLiL2/Cosets.lean`。
- 2026-10-06 12:16 整文件结果：exit 0，无输出；包含新增的两个 append 引理。
- 后续最终包装与依赖构建：main 明确通知 `lake build` 成功，耗时 27 秒。本次仅记录该来源，不将其表述为 Task C 重新执行的检查。
- 删除模块内 `#print` 之前，`real_dual_eq_residueCosets`、`residueCosets_pairwiseDisjoint`、`dualEquiv` 的传递依赖输出均为 `[propext, Classical.choice, Quot.sound]`。按主进程要求已移除全部 `#print`；最终统一 Audit 由主进程负责。
- 最终源码对 `sorry/admit/axiom/native_decide` 及行首 `#print` 的文本检查无匹配。
- 只编辑两个独占文件；未新建聊天、未派发子智能体、未运行 `lake update` 或 cache 下载；实际 IB-ME 仓库只读，既有交接文档未改，无 Git 提交。
- 收到 main 构建完成通知后的本次修改仅涉及 `reviews/cosets-progress.md`。`Cosets.lean` 不再改动；后续直接源码检查与公理清单审计由主进程统一负责，本文不提前宣布审计通过。
