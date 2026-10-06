# L3 确定性矩阵范数片段交接

状态：本片段完成并冻结；不据此宣称完整 L3 概率定理已经完成。

## 范围与接口

唯一 Lean 源文件：`FooLiL3/MatrixBounds.lean`。

源文件 SHA-256：`DB0580FCCFE4FE536D775EEF2B82E208E796315A3446EBDAC8F906ED1172A41A`。

本文件有 20 个公开定理、6 个公开定义，全部位于 `FooLiL3` 命名空间。

对于任意整数矩阵 `R : Matrix (Fin m) (Fin w) ℤ`：

- `colSq R j` 是第 j 列整数条目嵌入实数后的平方和。
- `frobSq R` 是所有列的 `colSq` 之和。
- `frobSq_eq_int_sum` 将它与整数域中精确计算的全矩阵平方和相连。
- `colSq_eq_norm_sq` 将每列平方和与真正的实数欧氏范数平方相连。
- `colSq_le_iff_column_norm_le` 与 `column_norm_gt_iff_colSq_gt` 在 `s ≥ 0` 下，将论文的 `s sqrt(m)` 范数阈值与 `m s²` 平方和阈值双向对应。
- `frobeniusVec R` 是矩阵全部条目展开后的真实欧氏向量；`frobeniusNorm R` 是其欧氏范数。已证其平方为 `frobSq R`，且其值等于 `sqrt(frobSq R)`。
- `euclideanLin R` 是 `Matrix.toEuclideanLin` 作用于整数条目的实数嵌入所得线性映射；`euclideanOp R` 是该映射的连续线性实现。定义域、值域都是 `EuclideanSpace ℝ (Fin _)`，不是默认 sup-norm 的函数空间。
- `euclideanOp_apply` 给出实际坐标运算 `sum j, (R i j : ℝ) * x j`，因此算子没有被替换为另一个抽象对象。

主接口：

```lean
frobSq_le_of_columns R hcols hQ
euclideanOp_norm_le_frobeniusNorm R
frobeniusNorm_le_sqrt_of_columns R hcols hQ
euclideanOp_norm_le_sqrt_of_columns R hcols hQ
euclideanOp_norm_sq_le_of_columns R hcols hQ
```

其中 `hcols : ∀ j, colSq R j ≤ (m : ℝ) * s ^ 2`，
`hQ : (m : ℝ) * (w : ℝ) * s ^ 2 ≤ Q`。
这给出账本 L3 的确定性链：逐列合格推出 `frobSq R ≤ Q`、
`‖euclideanOp R‖ ≤ frobeniusNorm R ≤ sqrt Q`、`‖euclideanOp R‖² ≤ Q`。

## 证明方式与前提检查

先用有限和单调性累加逐列界，再逐行使用有限 Cauchy–Schwarz 得到
`‖R x‖² ≤ frobSq(R) ‖x‖²`。平方根及非负性将其转成范数界，
最后由 `LinearMap.mkContinuous_norm_le` 得到实际连续算子范数上界。
构造连续映射之前已经完成点态范数界，未循环假设所需的算子界。

定理允许 m 或 w 为零；不存在遗漏的非空类型假设。平方和链不要求 s 为正，
但与论文非平方阈值的双向转换明确要求 `s ≥ 0`。论文的 `s > 0` 足以满足该条件。

本片段没有任何随机变量、产品分布或独立性假设，也没有以概率假设偷渡矩阵范数结论。
Skill `proof-writer` 用于检查前提、类型、已知不等式与最终结论之间的桥接；它不作为数学证据。

## 实际运行的核验

在 `D:\Lean\projects\fooli-l3` 中，每个 shell 先执行：

```powershell
. D:\Lean\Enter-Lean.ps1
lake env lean FooLiL3/MatrixBounds.lean
```

最终命令退出码 0，无警告、无错误。

另外将冻结的源文件读取到内存，追加对所有 26 个声明的 `#print axioms FooLiL3.<name>`，
通过 `lake env lean --stdin` 重新核验。退出码 0；所有 26 项的传递公理依赖均且仅为
`[propext, Classical.choice, Quot.sound]`。未向文件或共享缓存写入这份临时审计输入。

源码关键字检查未发现 `sorry`、`admit`、`axiom`、`native_decide`。
无需额外模块下载；只使用已存在的 PiL2、Linarith 与 Ring 依赖。
曾有一次新增平方根桥接时的定义展开重写失败，已修正并再次完整编译及逐项审计；
不是被保留或忽略的失败。

## 未覆盖范围

本片段不证明离散格高斯尾概率，不证明 C2 到该尾界的解析桥接，
不证明理想分布与实际委派输出的 TV 契约，也不证明概率并合界或初始化好事件概率。
这些由其他 L3 模块及主智能体分别核验。它也不声称具体采样实现、最终参数或完整算法安全性已经通过。

未修改仓库、L1/L2、环境持久设置、生产代码或共享缓存。交由主智能体统一构建、
汇总审计、归档和提交；本片段不单独提交或推送。
