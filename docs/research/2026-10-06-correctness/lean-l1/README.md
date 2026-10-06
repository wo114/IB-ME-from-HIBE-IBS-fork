# Foo–Li L1：陷门与签名模方程的 Lean 形式化

日期：2026-10-06。范围：原《FooLi-条件式正确性定理与参数账本》§4 的 **L1 主陈述及代数适配说明**。

结果：L1 主陈述及本包的辅助结论已通过 Lean 4.34.1 检查；18 个本地定理的传递依赖均限定在 `propext`、`Classical.choice`、`Quot.sound` 三个标准基础公理内，无 `sorryAx` 或自定义未证公理。故意改错负号的断言按预期被拒绝。

本目录不修改密码算法、参数、接口或已有正确性文档。它提供可复验的 Lean 证明，不是完整 Foo–Li/IB-ME 正确性或安全性证明。详细结果以本目录 `verification/` 下实际运行的 `verification.json`、命令退出码及原始日志为准。

## 1. 证明了什么

以横杠表示整数逐项取模。给定

\[
A\in\mathbb Z_q^{n\times m},\quad B,G\in\mathbb Z_q^{n\times w},\quad
R\in\mathbb Z^{m\times w},\quad p\in\mathbb Z^{m+w},\quad z\in\mathbb Z^w,
\]

定义 $F=[A\mid B]$、$J=[-R;I_w]$、**整数**向量 $x=p+Jz$。
`FooLiL1.l1` 的两个前提恰为

\[
B=A\overline R+G,\qquad G\overline z=u-F\overline p.
\]

结论为

\[
F\overline J=G\quad\land\quad F\overline x=u.
\]

证明对所有满足前提的矩阵和向量成立，不是枚举测试。特别地，源码分别证明了整数加法、矩阵乘向量与取模交换，**没有把整数短向量偷换成模剩余类向量**。

这些是纯代数恒等式，故源码允许任意自然数 `q,n,m,w`、任意同型 `G`；实际密码方案仍需原文规定的正维度、素数模数、gadget、采样及安全参数。`ZMod 0` 在 Lean 中为整数环，`q=1` 也包含在更一般的代数陈述中，均不表示它们是可用密码参数。L1 不需要素性、满秩或高斯前提，并不等于整个方案不需要。

## 2. 命题与源码对应

| 原文/审查事项 | Lean 声明 | 本次范围 |
|---|---|---|
| $J=[-R;I]$、$x=p+Jz$ | `trapdoorLift`、`signature` | 定义在整数域 |
| 整数运算与取模相容 | `reduceVec_add`、`reduceVec_mulVec`、`reduceMat_trapdoorLift`、`reduceVec_signature` | 完整证明 |
| $FJ=G\bmod q$ | `trapdoor_equation` | 完整证明 |
| $Fx=u\bmod q$ | `signature_equation` | 完整证明，显式依赖两个前提 |
| L1 两个结论合取 | `l1` | 主交付定理 |
| $D=m+w$ 的坐标对应 | `flatten_mulVec`、`flattened_signature_equation` | 用 `finSumFinEquiv` 保持运算 |
| 主阶段 $A=[\bar A\mid G-\bar A R_0]$，$A[R_0;I]=G$ | `master_trapdoor_equation` | 主矩阵另一符号约定 |
| MP12 $AT=G-B$ 与 Foo–Li $R=-T$ 的关系 | `reduceMat_neg`、`mp12_sign_iff` | 两向代数等价；未证明分布结论 |
| 一般 tag 的 $FJ=HG$ 与修改后的 syndrome | `tagged_signature_equation` | 显式给定 $HK=I$，实际 IBS 取 $H=I$ |
| 正例和三个错误前提/符号反例 | `Controls` 中五个定理 | 小实例 sanity check，不替代一般证明 |

`Fin m ⊕ Fin w` 用于保留矩阵分块结构：左块是前 `m` 个坐标，右块是后 `w` 个坐标。`flattened_signature_equation` 给出 `Fin (m+w)` 上相同的结论，不是口头假定两种索引“差不多”。主阶段定理中的 `m` 表示 $\bar m$，是该独立定理的局部维度参数。

`Audit.lean` 打印主定理、平铺版本、主陷门、符号等价和 tag 版本的完整类型，并审计全部 18 个本地定理的传递公理依赖。复核时重点检查前提 `hB`、`hz`，而不只是查看“编译成功”。

## 3. 没有证明什么

- **没有构造或证明采样器必然产生**满足 `hB`、`hz` 的短矩阵/向量，也未证明其终止、随机性或概率分布。L1 是“这些关系成立，则签名模方程成立”。
- 没有证明离散高斯、平滑参数、协方差正定、范数界、统计距离、失败概率、重试策略；原 L1 末尾关于取负保持高斯权重、Frobenius/算子范数和 TV 的补充文字未在本包形式化。
- 没有证明 `Verify=1`，因为验证还涉及范数、身份/消息/比特、解析及可能的其他检查。更没有证明不可伪造、隐私、抗量子性或某一安全等级。`security_claim: none`。
- 没有将 Lean 模型与 Python/Sage 实现做程序精化证明；实际算法是否保持这些前提仍须逐函数检查。
- `G` 在 L1 中是任意矩阵，未证明二进制 gadget 的满秩、可解性或采样算法。
- 未执行独立的第二证明内核，也未从零重编译/重验全部 Mathlib。使用固定版本 Lean 和固定提交 Mathlib 的缓存依赖。

这些边界意味着：此包补强 A02/A04 的底层正确性证据，但不能将 A01—A15 标成已全部验收。L2—L4、总失败概率以及完整 IB-ME 组合正确性仍应分别推进。

## 4. 检查与信任边界

1. `lake env lean FooLiL1.lean` 直接检查当前主源码；`lake build FooLiL1 FooLiL1.Controls` 构建一般证明和小实例。
2. `lake env lean Audit.lean` 输出命题类型及全部定理的 `#print axioms`。
3. 检查脚本只允许标准基础公理 `propext`、`Classical.choice`、`Quot.sound`；实际各定理依赖以日志为准。不允许 `sorryAx`、自定义未证公理或原生计算信任捷径；源文件也检查占位/绕过标记。
4. `Checks/WrongSign.lean` **预期编译失败（退出码 1）**：在同一正例中错误断言 $[A\mid B][R;I]=G$，Lean 应报告 `decide` 判为 false。失败文件刻意排除在默认库目标之外；这不是遗留未完成证明。
5. `Controls.valid_premises` 证明两个前提在一个具体例子中同时成立。`wrong_sign_fails`、`wrong_syndrome_fails`、`wrong_key_fails` 分别检查改符号、改 syndrome、破坏密钥关系的错误。小例子使用 `q=7,n=m=w=1`，不作为密码参数或性能样本；`decide` 生成由内核检查的证明，不使用 `native_decide`。

机器检查大幅减少已形式化推导的逻辑错误，但仍依赖 Lean 内核、依赖文件和运行环境。还需人工/导师检查“形式化命题是否忠实对应论文和最终实现”，不能称为整套算法万无一失。`Verify.ps1` 是复验辅助脚本，不是 Lean 内核的替代品。

## 5. 环境与复现

- Lean 4.34.1，提交 `5045d0056413266e57c625dcd7c365b10e377c52`。
- Mathlib4 提交 `d13f23b723b8a846827a245b89c10fc7d3f11612`；其他依赖锁定在 `lake-manifest.json`。
- 本机工作项目：`D:\Lean\projects\fooli-l1`。工具链、缓存和临时文件在 D 盘，未改持久 PATH。
- 本机 `.lake/packages` 是指向既有 `D:\Lean\projects\lean-check\.lake\packages` 的 Junction，仅复用依赖；不修改安装验收示例，不把 Junction、工具链或缓存交入 Git。

本机复验（产生新的时间戳日志目录，不覆盖旧记录）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File D:\Lean\projects\fooli-l1\Verify.ps1 -LeanHome D:\Lean
```

队友只需此小型源码项目、固定版本 Lean/elan、Git，以及获取 Mathlib 的网络条件；不需要付费账号、专用密码学插件或 VS Code 扩展。进入此目录后，按锁文件取得依赖并准备所需模块缓存：

```text
lake exe cache get Mathlib.Data.Matrix.ColumnRowPartitioned Mathlib.Data.ZMod.Basic Mathlib.Logic.Equiv.Fin.Basic
lake build FooLiL1 FooLiL1.Controls
lake env lean Audit.lean
```

不应随意运行 `lake update` 或升级依赖改变复验版本。`Verify.ps1` 可在 PowerShell 中运行；非 Windows 环境可执行上述 Lean 命令并人工检查同样的公理清单和负例。全新机器仍需下载依赖，**本次没有在第二台机器上验证安装流程**。

## 6. 来源、版本与交付文件

本次只回查下列相关片段，不声称重新阅读全文：

- 原正确性账本：仓库提交 `d683b05`，`docs/research/2026-10-06-correctness/FooLi-条件式正确性定理与参数账本.md` §4 L1；SHA-256 `F1B769CA2F71C2784877CCF4B34F62BE7155BA468DA8030C12F2CFA7D2724159`。
- Foo–Li：`papers/2023_tightly_secure_ibs_foo.pdf`，PDF 第 13 页/印刷第 12 页，Fig. 2 和 Correctness；SHA-256 `845855B9B39FDCBBE61831D9D1C431DC8D898B5A6244863FF87B23171B1E45B8`。
- MP12：`papers/2011_lattice_trapdoors_micciancio.pdf`，PDF 第 28 页 Algorithm 3，输出 $x=p+[R;I]z$；代入 $R_{\rm MP}=-R$ 对应此包。SHA-256 `BF1160F088825ED28C343B299F5BC2ACDCA41CC50293310A03A4506D2FDBDB84`。
- Mathlib 的矩阵拼接、乘法、取模同态、有限索引定理均直接依据上述锁定提交的源码，并由实际 Lean 检查确认调用。

文件清单：`FooLiL1.lean`（主体）、`FooLiL1/Controls.lean`（正反例）、`Audit.lean`（类型/公理清单）、`Checks/WrongSign.lean`（预期拒绝）、`Verify.ps1`（复验入口）、`lean-toolchain`/`lakefile.lean`/`lake-manifest.json`（环境锁）、`.gitignore`、本 README，以及 `verification/` 下生成的日志/JSON。

按 `proof-writer` 的“提取前提—逐步推导—核对命题”流程组织材料；其工作流不是定理证据。依用户要求，交付的是 `.lean` 源码而非 LaTeX 排版。
