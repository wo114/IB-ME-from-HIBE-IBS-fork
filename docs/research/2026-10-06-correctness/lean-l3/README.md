# Foo–Li L3：条件式委派质量定理已闭合

日期：2026-10-06。本次补齐 C2→陪集质量比较、C3→独立理想联合分布接口，以及有效主陷门→满秩→L2 整数 lift 的连接。

**“L3 已闭合”仅指从明确的 C2/C3 前提推出 L3 结论的机器证明，不是这些前提已在实际代码中兑现，也不是整个算法安全性已证明。**

## 1. 结论与入口

主入口：[ClosedL3.lean](FooLiL3/ClosedL3.lean) 的 **l3_from_c2_c3**。

对固定的满足 C2 的好初始化状态，在 C3 原始输出空间上证明：

\[
\Pr[\text{委派中止、模关系无效或质量不合格}]
\le\min\left\{1,\varepsilon_{\rm Del}+w\,2^{-m}
   \frac{1+\varepsilon_0}{1-\varepsilon_0}\right\}.
\]

质量条件同时要求 Frobenius 平方和与真实欧氏算子范数平方不超过 Q₁；已证明等价于只检查 Frobenius 平方。要求 Q₁≥mws²。中止、非法关系、质量失败包含于同一坏事件；TV 只加一次，不作成功条件化。

| 最终前提 | 精确含义和后续边界 |
| --- | --- |
| 合法维度、q>0、s>0 | 标准二进制 gadget，每块至少一项；参数及实现仍须接线 |
| 有效主关系 | A[R₀;I]=G；整数先模约简，索引显式扁平化；不能用签名阶段的负号代替 |
| C2 对偶质量界 | L2 真正积分配对对偶格的 dualTheta(q,liftMatrix(A),s)≤e；实际 Setup 好事件概率预算仍未证明 |
| 0≤e<1 | 原账本 0<epsilon₀≤1/4 更强；正式数值参数尚未定 |
| C3 TV 契约 | 实际原始概率测度 μ 与独立、未截断、未质量过滤的列高斯产品律相距≤εDel；**实际有限采样器的统一证书仍未证明** |
| 可测性与质量阈值 | 可数整数矩阵 Option 空间，单点可测；Q≥mws² |

最终入口**不再输入**陪集质量比较、列尾界、理想无效事件零质量、列边际律或 A 的满射性。满射性从有效主关系及标准 gadget 的单位列推得。辅助入口 l3_from_smoothing_and_product_ideal 支持任意满射 A 及任意 B/G；更底层条件式接口仍保留，不能混写其前提。

维度：Lean 主入口 r 为未扩展块宽，k+1 为 gadget 完整长度，因此账本 w=n(k+1)、m=r+w。k 不是完整 gadget 长度，不能少算一项。R₀ 是主陷门，结论中的 R 是委派用户陷门。

与原账本同名符号换算：账本 k_ledger=ceil(log₂q) 是块长；应取 k_Lean=k_ledger−1，
r=mbar，且确认 k_ledger≥1。不能直接令 k_Lean=ceil(log₂q)，否则每块多一列。
这里证明代数与条件式分布结论，不证明任意 gadget 长度下的实现采样契约。

## 2. 本轮证明链

1. **FiniteCharacters**：模 q 字符正交和陪集指示函数的 q⁻ⁿ 因子，不要求 q 为素数。
2. **FourierGaussian**：复幂主值前因子恰为正实 s；一维负相位 Poisson 恒等式、绝对可和及有限维乘积分解。
3. **PhaseFactors / CosetPoisson**：整数 lift、模字符和正移位对齐，对完整实际陪集证明
   \[
   Z_u(s)=\frac{s^m}{q^n}\sum_a\chi(a\cdot u)
       \operatorname{gridMass}(m,s,A^Ta/q).
   \]
4. **SmoothingBounds / SmoothingBridge**：单位模相位和 L2 对偶格陪集分解给出
   \[
   \left|\frac{Z_u(s)}{s^m/q^n}-1\right|\le\Theta_A(s).
   \]
   减去的仅是真正原点的质量 1；**零剩余类中的非零整数格点仍保留**。再由 Theta_A(2s)≤Theta_A(s) 导出任意 u 的
   \[
   Z_u(2s)\le 2^m\frac{1+e}{1-e}Z_u(s).
   \]
5. **IdealDelegation**：实际构造独立 PMF 产品；证明矩形事件乘积、归一化、理想非法/中止零质量、完整列边际。
6. **SetupRank / ClosedL3**：主关系推出满射并接通 lift；合并解析尾界、矩阵范数、并合和一次 TV 转移。

使用精确实数/复数、整数和完整无限和，不用随机实验、数值截断或估计器替代证明。未反用 L2 的 smoothingInf 上界，而是直接使用 C2 点态质量界。非严格尾事件 ≥ms² 覆盖严格大列事件 >ms²，未误称两者相等。

## 3. 核验与复现

固定 Lean **4.34.1**，commit 5045d0056413266e57c625dcd7c365b10e377c52；Mathlib **d13f23b723b8a846827a245b89c10fc7d3f11612**。其余 8 个依赖由 lockfile 固定。

~~~powershell
Set-Location D:\Lean\projects\fooli-l3
. D:\Lean\Enter-Lean.ps1
lake build FooLiL3 FooLiL3.Controls FooLiL3.BridgeControls FooLiL2 FooLiL2.Controls
.\Verify.ps1 -LeanHome D:\Lean
~~~

其他机器按 lockfile 准备相同工具链，运行相同 lake 命令；Verify 可省略 LeanHome。D 盘缓存联接不属于交付物，不执行 lake update。

Verify 检查工具链与 9 个依赖提交、依赖工作树干净；L2 vendor 哈希；全量构建、每库文件直接检查、正向边界检查；全部公开定义/定理/具名实例的传递公理；三个错误结论必须拒绝；人工源核验前后哈希不变。所有退出码和日志哈希保存在 verification/run-*。

允许公理只有 propext、Classical.choice、Quot.sound。负对照分别为漏列数、错误产品点质量、抹去整个零剩余类余量。检查公理不能替代前提语义审查，两者都做。

以成功核验 JSON 为准。新记录 full_l3_complete:true 的范围仅为**条件式 L3**，同时保留 actual_sampler_contracts_verified:false 和 security_claim:none。旧 run-20261006-130731 及旧 review 保留原样，描述此前 WIP，不改写历史证据；本轮结论另见 closure-review.md。

L2 源码 FooLiL2/ 与根文件逐字节复用自仓库提交 edf82ab55939eea399863c2091b5e8890298d21c，哈希见 vendor-l2.json。它们重新编译与审计，但不计成此次新写成果。两库分项计数见核验 JSON。RefreshAudit.ps1 仅机械生成清单，清单差异仍需审阅。

## 4. 文献、审阅与验收边界

依据原账本 C2/C3、L3，文件 SHA-256：
F1B769CA2F71C2784877CCF4B34F62BE7155BA468DA8030C12F2CFA7D2724159。

数学路线对照 [Micciancio–Peikert 原文](https://eprint.iacr.org/2011/501) Definition 2.2、Lemmas 2.4–2.6，本地 PDF SHA-256：
BF1160F088825ED28C343B299F5BC2ACDCA41CC50293310A03A4506D2FDBDB84。
本轮证明所需 q-元高斯特殊情形，没有声称机器化了 MP12 全文或一般格的全部定理。

三个子智能体补产品律、Fourier 高斯、Setup/lift；主控补有限字符、完整陪集 Poisson、平滑桥接、总定理，组织交叉审阅和全量复跑。proof-writer 只用于前提和证据检查，不是数学依据；多 AI 复核不是外部专家审稿。

此成果仅是 A02/A04/A09 的部分正确性证据。仍未完成实际 Setup 好事件预算、实际 C3/C4 采样契约、L4、完整 Foo–Li/HIBE/IB-ME 正确性接线、正式安全归约、参数选择、性能及实现一致性验证。L3 不保证失败概率为零。本轮不修改生产代码/参数/安全声明。仅本地提交；远程提交按 fork→PR 另行操作。
