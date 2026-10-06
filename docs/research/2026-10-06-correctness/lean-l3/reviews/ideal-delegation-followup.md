# C3 独立理想分布接口补齐 review

日期：2026-10-06。范围：仅补齐理想联合分布、支持集与边缘分布接线；不声称实际采样器的 TV 保证或 C2 已在本文件证明。

## 已完成

主文件：`FooLiL3/IdealDelegation.lean`，新增 4 个定义、7 个定理、1 个具名实例，均在 `FooLiL3` 命名空间。

- `independentFinPMF`：用独立的 `PMF.bind/map` 递归构造有限依赖类型乘积，涵盖零列；后续列的分布不依赖先前采样值。
- `independentFinPMF_marginal`、`independentFinPMF_rectangle`、`independentFinPMF_apply`：分别证明完整坐标边缘、任意矩形事件概率乘积、点质量乘积；独立性不是输入假设。
- `idealColumnsPMF`、`idealDelegationPMF`、`idealDelegationMeasure`：每列使用既有未截断 `cosetGaussian`，陪集为 `A x = B_j - G_j`，拼装为 `some R`；不做质量筛选、成功条件化或重采样。
- `idealDelegationMeasure_isProbabilityMeasure`：由 PMF 的归一化性质推出概率测度实例。
- `idealDelegationMeasure_rectangle`：矩阵拼装后仍满足列矩形事件的概率乘积公式。
- `idealDelegationMeasure_invalidOutput`：中止与非法模关系事件的理想概率严格等于 0。
- `idealDelegationMeasure_columnLaw`：证明每列的全部事件满足现有 `CosetColumnLaw`，不只证明尾事件。
- `l3_from_mass_certificates_and_product_ideal`：接入现有 L3；不再输入 `hSupport`、`hMarginal` 或坏事件可测性证明。

## 保留的前提和边界

- `q ≠ 0`、`A.mulVec` 满射、`s > 0`、`0 ≤ e < 1`、`m*w*s^2 ≤ Q`。
- 实际原始输出测度 `μ` 是概率测度，且与构造出的理想测度满足给定 `TVWithin ... εDel`；**本文件没有证明实际有限采样器的 TV 界**。
- 每列仍输入 `CosetMassComparison`；**C2 到质量比较由主控另外补齐**。
- 输出可测空间要求 `MeasurableSingletonClass`。这是使用离散整数矩阵原始输出空间的可测性条件；配合已证明的可数性，全部事件可测。检查文件确认取 `MeasurableSpace := ⊤` 可直接实例化。
- 结论保持 `μ.real badOutput ≤ min 1 (εDel + w * tailBudget m e)`。中止已包含在原始坏事件中，TV 损失只添加一次。
- `security_claim: none`。这不是整套密码方案的安全归约，也不是实际代码采样分布的认证。

## 单文件核验

环境：Lean `v4.34.1`；Mathlib `d13f23b723b8a846827a245b89c10fc7d3f11612`。所有命令在 `D:\Lean\projects\fooli-l3`，先执行 `. D:\Lean\Enter-Lean.ps1`。

| 命令 | 结果 |
| --- | --- |
| `lake env lean FooLiL3\IdealDelegation.lean` | exit 0，无输出/警告 |
| `lake env lean -o .lake\build\lib\lean\FooLiL3\IdealDelegation.olean FooLiL3\IdealDelegation.lean` | exit 0，供独立检查导入 |
| `lake env lean Checks\IdealAgent_Audit.lean` | exit 0；检查全部 12 个公共声明及 4 项正向控制 |
| `lake env lean Checks\IdealAgent_WrongPointMass.lean` | 预期 exit 1：`unsolved goals`、`False`；错误点质量被拒绝 |

12 个公共声明与 4 个控制定理的传递公理均仅为 `[propext, Classical.choice, Quot.sound]`。主文件不存在 `sorry`、`admit`、`axiom`、`native_decide`。

主文件 SHA-256（当前 Windows 文件字节）：`922BD615EC7790D961726674C5FAACC1470C2488307BAC6C96409A27DE44F10B`。主控如统一换行应重新计算交付哈希。

## 主控集成事项

1. 将模块加入根导入、声明清单及统一审计。声明扫描须包含具名 `instance idealDelegationMeasure_isProbabilityMeasure`，不能只扫描 `def/theorem`。
2. 单文件独立检查位于 `Checks/IdealAgent_Audit.lean`；故意失败的 `Checks/IdealAgent_WrongPointMass.lean` 必须排除默认构建。
3. 与 C2 新证明接线时调用 `l3_from_mass_certificates_and_product_ideal`，用 C2 推导结果提供 `hMass`；不要把本 review 当作 C2 已完成的证据。

本次没有修改其他现存源码/审计清单，没有运行全项目 `lake build`、`lake update`、安装或缓存下载，没有提交 Git。按 `proof-writer` 流程明确了理想分布构造与实际采样保证之间的边界。

## 后续只读复查：原始事件与单次 TV 转移

复查日期：2026-10-06。重新完整读取 `EventBounds.lean`、`L3.lean`、`IdealDelegation.lean`，逐步重建事件推导，而非仅沿用编译通过的结论；并回查高斯归一化定义。本轮只修改本 review，未重跑 Lean、未修改任何证明或检查文件，也未审查仍在主控编写的 `SmoothingBridge` / `ClosedL3`。

**结论：在当前三个接口声明的前提下，未发现原始中止遗漏、无效关系遗漏、质量筛选条件化或 TV 重复计入。**

### 事件逐项核对

| 项目 | 当前定义/推导 | 复查结果 |
| --- | --- | --- |
| 原始空间 | `Option (Matrix (Fin m) (Fin w) ℤ)` | `none` 是显式输出，不从实际样本空间删除 |
| 总坏事件 E | `badOutput valid good`：`none` 或 `some R` 且 `¬valid R ∨ ¬good R` | 三类失败完整保留；是并集，不要求彼此互斥 |
| 理想零事件 V | `invalidOutput valid`：`none` 或非法模关系 | 理想 PMF 只输出满足各列陪集关系的 `some R`，其逆像为空，故质量严格为零；并非先筛掉实际非法结果 |
| 质量失败 | `QualityGood Q` 同时要求 Frobenius 平方与真实 Euclidean 算子范数平方不超过 Q | 在 `m*w*s^2 ≤ Q` 下，“所有列不大”推出质量合格；使用逆否命题得到坏事件覆盖 |
| 列事件 Cj | `someEvent (columnLarge s j)` | 明确排除 `none`，但 `none` 已由 V 覆盖，不会漏算 |
| 阈值边界 | 大列定义为 `m*s^2 < colSq`；高斯尾界使用 `m*s^2 ≤ vectorSq` | 前者包含于后者，方向正确；等于阈值的列仍可通过质量检查，尾界仅适度放宽 |
| 独立性 | 联合 PMF 从独立列构造，另有矩形事件乘积定理 | 非假设式封装；之后并集界本身并不需要列独立，更不要求实际输出列独立 |

代码定位：`EventBounds.lean:103`、`:109`、`:115` 为三类事件，`:136` 证明覆盖；`L3.lean:33` 为确定性质量推出关系，`:106` 至尾界接线使用严格事件到非严格事件的包含；`IdealDelegation.lean:148` 证明 V 的理想质量为零。

### TV 只计一次的完整链条

记 `τ = tailBudget m e`，实际原始分布为 μ，构造出的理想分布为 ν：

```text
E ⊆ V ∪ ⋃j Cj
ν(E) ≤ ν(V ∪ ⋃j Cj) = ν(⋃j Cj) ≤ Σj ν(Cj) ≤ w*τ
μ(E) ≤ ν(E) + εDel ≤ εDel + w*τ
μ(E) ≤ 1  ⇒  μ(E) ≤ min 1 (εDel + w*τ)
```

- `EventBounds.lean:78` 只处理理想测度：零事件加法和有限并集界，不涉及 TV。
- `EventBounds.lean:89` 对**完整 E** 调用一次 `tv_transfer_min`，后者在 `:47` 调用一次 `tv_event_le`。没有逐列添加 TV，没有另外添加实际 abort/非法概率，也没有把 `εDel` 乘以列数。
- `L3.lean:43`、`:84` 以及 `IdealDelegation.lean:197` 逐层传递同一个 `hTV`，未另做转移。
- `TVWithin` 是同一空间上的事件概率差界 `|μ(E)-ν(E)| ≤ εDel`；当前转移没有额外的因子 2。外部 C3 证书须与这一统计距离口径对齐。
- 实际和理想测度的概率归一化保证 `Measure.real` 不会因无穷质量的 `toReal` 而伪装成零；最后截断到 1 使用实际测度的概率性质。

### 与新 C3 定理的前提一致性

1. 最终新定理使用同一个 A、B、G、q、s、hA 构造理想律，列目标始终为 `B_j-G_j`，没有换成不同陪集或不同宽度。
2. `hSupport` 和全部事件的 `hMarginal` 由构造定理给出，不由调用者假设；`hMass` 仍是 C2 待接入的准确接口。
3. `hA` 满射与 `q ≠ 0` 确保每个目标陪集非空；`s > 0` 保证未截断高斯的归一化有效。定义中的 `rho/Z` 是完整陪集高斯自身的归一化，**不是**对实际成功、短列或质量合格事件作条件化。
4. 两个测度在同一原始可测空间上；`MeasurableSingletonClass` 加整数矩阵可数性保证坏事件可测。没有把可测性、概率测度性质当作未说明的自动假设。
5. `0 ≤ e < 1`、`m*w*s^2 ≤ Q` 仍显式保留；无需额外假设 `εDel ≥ 0`，因为 `TVWithin` 对空事件即推出该性质。
6. 原始分布定义和证明链中没有 `PMF.filter`、限制到成功集再归一化、成功概率作分母、拒绝后重采样或独立重试假设。

**调用边界（不是当前证明中的错误）**：μ 是抽象测度输入。Lean 类型本身不能证明它确实来自某段实际采样代码；主控及后续实现接线必须提供含所有失败质量的原始 μ（若原实现是子概率语义，须把缺失质量纳入 `none`），不能传入“给定成功”的重新归一化分布后声称得到了原始失败率。本层参数 A/B/G 等为固定值；固定合格初始化状态下的 C3 保证与“给定本次委托成功”的条件化是不同的，也不能未经证明把无条件 TV 界移成任意初始化条件下的 TV 界。

只读复查对应源码 SHA-256：

- `EventBounds.lean`：`02B9A99B808974284797B9C0E744CC061CDC3D1DABE2AA205748798B2E409676`
- `L3.lean`：`4783223688F55A07C3971A32E0DF4456917D3C876AB2AC61739E49D81D1E97A5`
- `IdealDelegation.lean`：`922BD615EC7790D961726674C5FAACC1470C2488307BAC6C96409A27DE44F10B`

既有负向检查 `Checks/IdealAgent_WrongPointMass.lean` 未改动，可由主控纳入总 Verify；其预期仍为退出码 1 且出现未解决的 `False`。
