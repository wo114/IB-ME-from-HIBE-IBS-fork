# Foo–Li L3：Lean 阶段交付（WIP）

日期：2026-10-06。**完整 L3 尚未闭合，不能标记“L3 已全部机器证明”。**
本目录保存已形式化的条件式子定理、汇总核验脚本与尚待补齐的解析桥接。
不改变 L1/L2 的已交付版本，不修改生产算法、参数或安全声明。

## 一、现在证明到哪里

| 层次 | 本目录内容 | 完成边界 |
|---|---|---|
| 确定性矩阵界 | 列平方和 → Frobenius 平方和 → 真实欧氏算子范数 | 已写成完整 Lean 定理；不是默认函数空间的 sup 范数 |
| 概率组合 | 有限并合、理想无效事件零质量、原始输出 TV 转移、上界截断到 1 | 已写成测度论定理；不需要列独立；中止只计一次 |
| 真正的高斯分布 | 有符号整数向量、实际模陪集、全无限和可和性、正归一化、归一化 PMF | 已形式化；不是均匀分布或有限截断近似 |
| 条件式尾界 | 在显式 `CosetMassComparison` 下，推出每列尾界并连接最终失败概率 | 已形式化；**质量比较仍是前提** |
| C2 → 质量比较 | 从真实对偶格 `Theta_A(s) ≤ epsilon_0` 推出任意目标陪集的比较界 | **尚未形式化，是主要缺口** |
| C3 → 理想支撑/边际接口 | 将 C3 指定的独立列产品分布实例化为这里的 `hSupport`、`CosetColumnLaw` | **尚未在本目录构造该产品分布并证明接口** |

机器核验以 `verification/run-*/verification.json` 为证，只有该记录中的
`verification_status: pass` 才表示该冻结版本的构建、逐文件检查、公理审计和负对照通过。
记录同时保留 `full_l3_complete: false`，不把“文件可编译”混同于“原目标已完整证明”。

## 二、原目标和当前主定理

原账本 L3（固定一个满足 C2 的好初始化输出）要求：

\[
\tau_m=2^{-m}\frac{1+\varepsilon_0}{1-\varepsilon_0},\qquad
Q_1\ge mws^2,
\]

\[
\Pr[\text{原始委派中止、无效关系或质量不合格}]
\le\min\{1,\varepsilon_{\rm Del}+w\tau_m\}.
\]

`L3.lean` 提供两个层次：

- `l3_from_column_tail_bounds`：每列尾界作为显式输入，完成矩阵与概率组合。
- `l3_from_mass_certificates_and_marginals`：使用真实模陪集高斯的完整事件边际律，
  由质量比较证书推导尾界，再完成组合；不再将尾界本身作为输入。

第二个定理的前提包括正模数、模矩阵满射、`s>0`、`0≤e<1`、`Q≥mws²`、
实际/理想概率测度、原始输出 TV 契约、坏事件可测、理想支撑及各列完整边际律、
各目标陪集的 `CosetMassComparison`。原账本 `0<epsilon_0≤1/4` 强于此处的误差范围。
当前并未把这些前提全部从 C2/C3 的原始算法描述推导出来。

质量好条件同时写入 `frobSq R≤Q` 和 `‖euclideanOp R‖²≤Q`；已证它等价于只检查
Frobenius 平方和。整数平方和与实数中的这一检查也有精确等式。
`ValidDelegation` 逐列使用 `A R_j=B_j−G_j (mod q)`，保持 Foo–Li 加号约定。

## 三、没有隐藏的解析前提

对真实陪集定义

\[
Z_u(r)=\sum_{x\in\Lambda_q^u(A)}\exp(-\pi\|x\|_2^2/r^2).
\]

`CosetMassComparison` 的确切含义是

\[
Z_u(2s)\le 2^m\frac{1+e}{1-e}Z_u(s).
\tag{MC}
\]

在 (MC) 下已证明：当 `‖x‖²≥ms²` 时，
`rho_s(x)≤exp(-3*pi*m/4)*rho_(2s)(x)`；对完整尾集合求和、归一化，
再用 `2^m exp(-3*pi*m/4)≤2^(-m)` 得到 `tau_m`。
`s` 是高斯参数，不是标准差。这里是原格宽度；L2 的 `dualTheta ... s` 使用
对偶权重 `exp(-pi*s²*‖y‖²)`，不可直接把两个质量函数当成同一函数。

原文 MP12 Lemma 2.6 的尾事件用 `≥`，质量拒绝用 `>`；主定理已用集合包含和
测度单调性连接二者，不误称两个事件相等。

**(MC) 是尚需证明的解析命题，不是新增密码学困难假设，也不是已经由 L2 自动给出的事实。**
下一步应从 q-元陪集的带相位 Poisson 求和式证明

\[
\left|q^n r^{-m}Z_u(r)-1\right|\le\Theta_A(r),
\]

结合 `Theta_A(2s)≤Theta_A(s)≤epsilon_0`，导出 (MC)。
路线见 [桥接计划](reviews/smoothing-bridge-plan.md)。该路线目前是数学计划，不是机器证明。
不得反用 L2 仅有单向证明的 `smoothingInf` 上界；C2 本身已提供直接点态质量界。

## 四、文件索引与复跑

- [MatrixBounds.lean](FooLiL3/MatrixBounds.lean)：列范数、整数/Frobenius、欧氏连续算子。
- [EventBounds.lean](FooLiL3/EventBounds.lean)：真实概率测度、TV、并合、Option 中止语义。
- [GaussianTail.lean](FooLiL3/GaussianTail.lean)：点态指数界和条件式无限和尾界。
- [GaussianLaw.lean](FooLiL3/GaussianLaw.lean)：归一化 PMF 与事件概率等式。
- [IntegerGaussian.lean](FooLiL3/IntegerGaussian.lean)：模陪集、高斯可和性、正质量及证书。
- [L3.lean](FooLiL3/L3.lean)：两层组合定理与完整列边际律接口。
- [Controls.lean](FooLiL3/Controls.lean)：精确阈值、列数因子、零列、错误误差范围和原始中止对照。
- `Checks/MissingColumnFactor.lean`：刻意错误的上界，必须编译失败；不属于默认构建目标。
- `Audit.lean`、`declarations.json`、`Verify.ps1`：公开声明清单、定理/传递公理检查和日志留存。
- `reviews/`：两个子智能体的模块审查、解析边界及后续桥接方案，主控汇总另见集成记录。

环境固定：Lean **4.34.1**（提交 `5045d0056413266e57c625dcd7c365b10e377c52`），
Mathlib **`d13f23b723b8a846827a245b89c10fc7d3f11612`**；全部依赖在 lockfile 中。
不运行 `lake update`，不升级工具链。构建缓存与本机环境仅在 D 盘，不提交到仓库。

本机 PowerShell：

```powershell
Set-Location D:\Lean\projects\fooli-l3
. D:\Lean\Enter-Lean.ps1
lake build FooLiL3 FooLiL3.Controls
.\Verify.ps1 -LeanHome D:\Lean
```

其他机器安装同版本工具链并按 lockfile 获取依赖后，在目录中运行相同的 `lake` 命令；
`Verify.ps1` 可不传 `LeanHome`，使用当前进程的工具链。首次缓存获取可用
`lake exe cache get`；这会下载构建缓存，应先确认磁盘与网络条件。
本机 `.lake/packages` 是复用既有缓存的目录联接，不属于可移植交付物。

审计允许的基础公理仅 `propext`、`Classical.choice`、`Quot.sound`；检查公开定义及
定理的传递依赖，并扫描全部证明源码。此检查能排除占位证明，但**不能替代前提语义审查**：
即使零自定义公理，定理参数中仍可能有未实现的前提；本目录对此明确列账。

## 五、文献、协作和验收边界

依据原账本 `FooLi-条件式正确性定理与参数账本.md` 的 C2、C3、L3，
SHA-256 `F1B769CA2F71C2784877CCF4B34F62BE7155BA468DA8030C12F2CFA7D2724159`。
回查 [Micciancio–Peikert 原文](https://eprint.iacr.org/2011/501)，
固定本地 PDF 第 12–13 页，Definition 2.2、Lemmas 2.4–2.6；没有声称本轮通读全篇。
PDF SHA-256 `BF1160F088825ED28C343B299F5BC2ACDCA41CC50293310A03A4506D2FDBDB84`。

协作：矩阵与事件模块各由一个子智能体编写并测试；主控负责解析模块、集成、
全量复跑、声明审计和交付。两个子智能体另外审查解析假设与文献桥接；
这不是外部密码专家评审。`proof-writer` 仅用于组织前提和证据边界，不是数学依据。

对应官方 A02/A04/A09 的部分正确性论证资料，**不表示这些验收项已整体通过**。
未实施算法安全归约、正式参数选择、采样器实现精化、HIBE 正确性、完整 IB-ME 批量测试、
性能测试或侧信道分析。没有实际安全参数集；对照中的小整数不是候选密码参数。
`security_claim: none`。本目录不宣称 L4、完整正确性或整体安全性已完成。

本轮只本地提交本目录；未经另行要求不推送远程、不创建 PR。后续远程提交沿用 fork → PR。
