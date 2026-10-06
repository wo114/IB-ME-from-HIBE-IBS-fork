# L3 主控汇总与接线检查

状态：**阶段交付；完整 L3 为 WIP。** 本说明在统一冻结核验之前写定；
最终运行、源码及日志哈希以同目录上层 `verification/run-*/verification.json` 为准。

## 分工与接收

- Galileo：`MatrixBounds.lean`、矩阵审查，以及 C2/Poisson 桥接计划。
- Kuhn：`EventBounds.lean`、事件审查，以及解析边界和最终集成语义复核。
- 主控：`GaussianTail.lean`、`GaussianLaw.lean`、`IntegerGaussian.lean`、`L3.lean`、
  `Controls.lean`、负对照、统一审计、复跑脚本和中文说明。

两个模块交付均已由主控完整读取并接入；未修改它们冻结的源码。
主控初次集成构建 `lake build FooLiL3 FooLiL3.Controls` 已 exit 0，无诊断。
刻意漏掉列数因子的错误命题已被 Lean 以 `unsolved goals / False` 拒绝（exit 1）。
开发阶段的类型推断错误和一次心跳超限已经修复，未通过提升安全声明绕过。
最后再执行统一 `Verify.ps1`；本说明不替代最终日志。

## 逐项语义检查

| 问题 | 检查结果 |
|---|---|
| 是否真正使用整数矩阵 | `R : Matrix (Fin m) (Fin w) ℤ`，不是余数代表的无符号范数 |
| 列、Frobenius、算子范数是否混淆 | `colSq` 对应列欧氏范数平方；`frobeniusNorm` 为全条目欧氏范数；`euclideanOp` 为 EuclideanSpace 上的实际连续线性算子 |
| 模关系是否与 Foo–Li 一致 | `ValidDelegation` 逐列检查 `A R_j=B_j−G_j`；未改成 MP12 负号输出 |
| 是否偷偷使用列独立性 | 并合界和主定理只使用各列边际；C3 的产品律比这里需要的条件更强 |
| abort 是否被重复计数 | `badOutput`、`invalidOutput` 均把 `none` 纳入；TV 在共同原始空间中使用一次 |
| 是否误用成功条件分布 | 没有对质量合格或采样成功条件化；`hTV` 比较原始实际与理想输出 |
| 无限和是否被截断 | `rho` 的全整数向量和由 Jacobi-theta 收敛得到，陪集继承可和性；PMF 精确归一化 |
| 空陪集是否除零 | 主定理以模映射满射构造所有目标陪集的非空证据；正质量单独证明 |
| 范数等号边界是否漏掉 | 非严格高斯尾事件覆盖严格拒绝事件；`Q` 上界包含等号 |
| 是否将尾界隐藏成名义不同的假设 | 低层定理明示 `hColumnTail`；高层定理不输入尾界，但明示尚未从 C2 推导的 `hMass` |
| `CosetColumnLaw` 是否仅假设坏事件的概率 | 不是；量化所有整数向量集合 E，将完整边际事件概率与真实陪集 PMF 对应 |
| 概率是否超出 1 | 最终用实际概率测度归一性证明 `min 1 (...)`，不是数值截断测试 |

## 两类未闭合衔接及其他实例化义务

1. **解析衔接未闭合**：`Theta_A(s)≤epsilon_0` 尚未在 Lean 中推出所有 syndrome 的
   `CosetMassComparison`。两份独立审查都确认该缺口真实，L2 不可直接代替它。
   已给出字符正交性→带相位 Poisson→真实对偶质量→上下界的后续路线。
2. **理想联合律接线未闭合**：高层定理中的 `hSupport` 与 `hMarginal` 尚未通过
   在 Lean 中显式构造 C3 独立列产品分布来消除。当前给出的都是可精确核验的接口，不声称已经实例化。

此外，若要求完整覆盖原账本初始化接口，还须把有效主陷门/gadget 满射性连接到这里
显式要求的 `hA : Function.Surjective A.mulVec`，并对齐 C2 的整数 lift；
这属于同一 C2/C3 端到端接线工作，当前不能因原文一句说明就视为机器证明。
真实有限采样器满足 C3 的 TV 契约仍是算法实现与分布证明的独立任务，不能通过这个
条件式 L3 反向推出。

因此完成口径只能是“已经核验条件式组成部分”，不能是“完整原前提 L3 已核验”。
下一步优先补上述衔接，不能把推进到 L4 当作这些缺口已关闭。

## 审查快照说明

`analytic-boundary-review.md` 审阅的是两份解析文件的早期冻结快照。
其后 `GaussianLaw.lean` 修复 Lean 重写语法并添加 `gaussianPMF_outer_event`；
尾界公式、宽度、质量比较假设不变。主控完整复核新增事件接口，最终集成审查另外覆盖它。
`smoothing-bridge-plan.md` 的 `IntegerGaussian.lean` 哈希与接收时版本一致。
旧审查哈希只标识历史审阅对象；所有最终交付文件的现行哈希由统一核验脚本重新计算。

## 安全性与参数

`security_claim: none`。全部主定理为符号参数，没有选择正式密码参数。
测试中的 1×2 全一矩阵、`e=1/4` 等仅用于数学边界对照，不作为安全实例。
本次没有运行生产实现/批量身份测试或性能基准；没有证明完整 IB-ME 安全性。
人工语义审查来自本轮 AI 协作，不冒充导师或外部专家签字。
