# L3 事件与 TV 转移模块交付

## 范围与冻结状态

- 专属源文件：`FooLiL3/EventBounds.lean`。
- 本模块使用真实的 `MeasureTheory.Measure`、`IsProbabilityMeasure` 和 `Measure.real`，没有自行定义抽象概率函数来代替测度。
- 已完成本模块的 15 个定理及 4 个定义；未改动其他模块、L1/L2、生产代码、参数、仓库、工具链或缓存。
- 源文件 SHA-256：`02B9A99B808974284797B9C0E744CC061CDC3D1DABE2AA205748798B2E409676`。
- 本交付后冻结源文件，后续集成修改由主智能体负责。

## 可集成接口

1. `TVWithin μ ν ε`：对每个可测事件 `E`，`|μ.real E - ν.real E| ≤ ε`。这是同一原始输出空间上的事件式 TV 契约，包含 abort；没有对成功输出条件化。
2. `tv_transfer_min`：由理想事件界 `ν.real E ≤ b` 得到 `μ.real E ≤ min 1 (ε+b)`。
3. `finite_union_probability_le` / `fin_union_probability_le`：有限事件并集的非均匀/均匀上界。无需独立性，覆盖零列情形。
4. `ideal_bad_probability_le`：由 `E ⊆ V ∪ ⋃j,Cj`、理想无效事件零质量、每列尾界得到 `ν.real E ≤ w*τ`。
5. `actual_bad_probability_le`：把上一项与 TV 契约组合，证明 `μ.real E ≤ min 1 (ε+w*τ)`。
6. `badOutput`：`none`，或 `some x` 的无效关系/质量失败；`invalidOutput` 包含 abort 与无效关系；`someEvent` 不包含 abort。
7. `badOutput_eq_invalid_union`：质量条件为“没有任何坏列”时的精确集合分解。
8. `badOutput_subset_invalid_union`：只需证明“所有列都好 ⇒ 整体质量好”即可得到所需集合包含。
9. `actual_badOutput_probability_le`：上述 Option 输出事件的直接组装定理，便于以整数矩阵为 `X` 实例化。

## 前提与边界检查

- TV 应用于原始真实分布与理想分布，不能把质量筛选后的条件分布直接代入。
- actual/ideal 在同一个测度空间。最终坏事件须显式可测；有限并集上界本身不要求可测性或独立性。
- 理想无效/abort 质量 `ν.real V = 0` 是需要由理想采样器支撑集证明的接口前提，不能替换成真实零 abort 假设。
- abort 已在坏事件中，最终只添加一次 `ε`，没有额外再加实际 abort 概率。
- 这里证明的是条件于固定好初始化之后的测度论组装部分；初始化失败概率由外层定理处理。
- 本模块不证明离散高斯尾界、不证明 Frobenius/算子范数桥接、不证明采样器满足 C3 的 TV 契约，也不证明完整算法的安全性。这些不是本模块已完成结论。
- `TVWithin` 明确采用事件式总变差约定；没有声称已经形式化其与某个数值 TV 距离 API 的等价性。

## 测试与公理审计

环境：每个命令进程先执行 `. D:\Lean\Enter-Lean.ps1`，工作目录为 `D:\Lean\projects\fooli-l3`；使用既定 Lean 4.34.1 / mathlib 固定版本。

1. `lake env lean FooLiL3/EventBounds.lean`：首次及最终版本均 exit 0，无诊断。
2. 最终源代码经 stdin 原样送入 `lake env lean --stdin`，末尾追加全部 19 个公开声明的 `#print axioms`：exit 0，无警告/错误。
3. 全部公开声明的传递公理依赖只包含 `propext`、`Classical.choice`、`Quot.sound`，部分声明无公理依赖；没有占位证明或自定义公理。

主智能体仍应运行最终项目构建、源文件冻结检查、统一公理审计和负对照。这里的模块级核验不能代替最终集成核验。

## 方法说明

按 `proof-writer` 的前提—中间引理—结论流程，将集合包含、零质量事件、有限并集、TV 单侧转移和概率上界 1 分开证明。Skill 只用于组织核验，不作为数学证据。
