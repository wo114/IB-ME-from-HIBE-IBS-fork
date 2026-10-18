# Zhang 2020 理想格 HIBE：原文可实施性判定（2026-10-18）

**结论：Section 3 的 IBE 自洽、可以实施；Section 4 的 HIBE 从深度 1 起就自相矛盾，按原文无法实施。**
本轮因此不投入 `zhang2020` 的后端编码，该候选继续保持"无 HIBE 后端"。

## 0. 口径与来源

- 判定对象：Yuan Zhang, Yuan Liu, Yurong Guo, Shihui Zheng, Licheng Wang，*Adaptively Secure Efficient (H)IBE over Ideal Lattice with Short Parameters*，Entropy 2020, 22, 1247，19 页。
- 文件：`papers/2020_ideal_lattice_hibe_zhang.pdf`，1225215 B，SHA-256 `6b31a181e1461b491c69cd41ce637a63db14f0404c3105f2827e64347e191c60`（本次 `Get-FileHash` 复核，与 2026-10-15 [资格表](../2026-10-15-zhang-qualification/README.md) 记录一致）。
- 方法：`pdftotext -layout` 抽全文，再 `pdftoppm -r 150` 渲染 p.7／10／11／12 逐页目视核对。本节引用的公式、维度、实参个数一律取自**渲染页**；纯文本抽取会丢上标（实测把 `2^β` 压成 `2β`），不能作为判据。
- 基线提交 `d4721bd`（分支 `codex/independent-primitive-assembly-2026-10-11`）。只读原文，未运行任何采样、委派或加解密实验。

复现命令（TeX Live 自带 poppler 工具，路径随环境）：

```text
pdftotext -layout papers/2020_ideal_lattice_hibe_zhang.pdf zhang.txt
pdftoppm -f 10 -l 11 -r 150 -png papers/2020_ideal_lattice_hibe_zhang.pdf zhang-page
```

## 1. 记法与原文定义

- 私钥采样算法见 Algorithm 1（p.6）`SampleLeft(a, m1, Ta, u, σ)`：输入 `a ∈ R_q^m`、`m1 ∈ R_q^{m1}`、**`Λ⊥_q(a)` 的陷门 `Ta`**、`u ∈ R_q`、`σ`，输出 `R_q^{m+m1}` 的短向量 `s` 满足 `f1^T s = u`（`f1 = (a; m1)`）。
- 预像采样 `SamplePre(a, Ta, u, σ)`（p.6）：输入 `a ∈ R_q^m` 与**它的陷门**，输出 `a^T x = u` 的短原像 `x`。
- 层级公开向量 `f_{id|id_l} = (f_{id|id_{l−1}} ; Σ_{i=1}^{l''} a_{l,i} b_{l,i} + b) ∈ R_q^{(l+1)m}`（p.10 Derive 第 1 步）。

**关键点：`SampleLeft`／`SamplePre` 的陷门实参必须是"格 Λ⊥(·) 的陷门"，短原像向量不能顶替。**

## 2. 判定表

| # | 位置 | 原文怎么写 | 问题 | 后果 |
|---|---|---|---|---|
| 1 | p.10 Derive 2–3；p.11 Decrypt 2 | Derive 输出 `SK = s ∈ R_q^{2m}`；Decrypt 第 2 步 `s_id ← SamplePre(f_{id|id_l}, SK_{id|id_l}, u, τ_l)` | 同一个 SK 对象在一处是短原像、在另一处被当成 `Λ⊥(f_{id|id_l})` 的陷门 | 两种身份不能同时成立，**深度 1 即断** |
| 2 | p.10 Derive 1–3 | `f_{id|id_l} ∈ R_q^{(l+1)m}`，同一步却写 `s ∈ R_q^{2m}` | 按 Algorithm 1，`SampleLeft(a, m1, …)` 输出 `R_q^{m+m1}`；此处 `a = f_{id|id_{l−1}}` 维度为 `lm`，应输出 `(l+1)m` | `2m` 只在 `l = 1` 成立；`l ≥ 2` 时少 `lm` |
| 3 | p.10 Derive 2 | `SampleLeft(f_{id|id_{l−1}}, Σ a_{l,i}b_{l,i}+b, SK_{id|id_{l−1}}, σ_l)` —— 只有 4 个实参 | 缺 `u`；且第 3 实参位要求"`Λ⊥(f_{id|id_{l−1}})` 的陷门"，而上一级 SK 若为短向量（见 #1）不合规 | `u` 可由 PP 的全局 `u` 补齐（**不阻塞**）；陷门位无法通过补记号解决 |
| 4 | p.13 Game 3 | 对任意深度查询一律 `s ← SampleRight(a0, h_id·b, R_id, Tb, u, σ) ∈ R_q^{2m}` | Encrypt 使用的 `f_{id|id_l}` 是 `(l+1)m` 维 | 归约只对 `l = 1` 自洽 |
| 5 | p.7 Theorem 2、p.12 参数条；p.11 Theorem 4 | 定理假设 `q ≤ 4[l'(2^β−1)√(mn)+1]δcσ√(mn/2π)`；同页式 (5)／(14) 给出 `T = q/(4[…]δ‖x‖) ≥ q/(4[…]δcσ√(mn/2π))`，错误率 `2exp(−πT²)` | 要 `T` 大必须 `q ≫ 分母`；定理假设方向相反。按假设取值则 `T ≤ 1`，错误率约为常数 | **方向性错误**，非记号问题；实现必须改成 `q ≥ …` |
| 6 | §5 p.14–16 | 只给 PP／SK／CT 的渐近尺寸与百分比（`l = 160`、`β = 10／20`），以及符号条件 `m = O(n log q)`、`σ > ‖T̃_B‖·2βl''√(lm)ω(√log m)`、`Q ≤ q^l/2` | 全文没有任何 `n`、`q`、`m`、`σ`、`δ`、`β` 的具体数值 | 若实施须自选参数并逐条重核 |
| 7 | 全文 | Theorem 5 只声称 IND-ID-CPA | 无匿名／接收者隐藏的定义、定理或论证 | 只能按项目 2026-10-18「默认所选论文算法具备所需安全性与匿名性」的工作假设使用，**不能引本文作匿名依据** |
| 8 | p.6–7 §3.1 | Extract 输出 `s ∈ R_q^{2m}`；Encrypt `c_1 ∈ R_q^{2m}`；Decrypt `w = c_0 − s^⊤c_1`，直接用 `s` | 无类型冲突 | Section 3 的 **IBE 可实施**（仍受 #5、#6 影响） |

## 3. 为什么不能靠"挑一种读法"落地

- **短向量读法**（沿 §3 IBE）：委派无法进行。短原像不是陷门，无法再喂给 `SampleLeft` 生成下一层。
- **陷门派读法**（沿 Decrypt）：Extract／Derive 打印的 `SampleLeft` 输出的是短原像而非陷门。要真正产出陷门，必须换成 `ExtendBasis` + 随机化（MP12／CHKP 路线），这已经**不是原文算法**。
- 原文在 §2.2／§2.4 确实说过"IN HIBE 我们还需要 ExtendBasis"，暗示原意是陷门派；但打印的 Extract／Derive 没有写这一步，且与 #1、#2、#4 一起构成三处独立矛盾。

因此不存在"只补记号、不动算法"就能通过类型检查的实现；任何可运行版本都要替换原文的委派步骤。

## 4. 若要做的替代路线（需 owner 批准，且必须改名）

| 路线 | 内容 | 代价 |
|---|---|---|
| A 仅 IBE 研究核 | 按 §3 实现，修正 #5 方向、自选参数 | 按项目规则 IBE 不计 HIBE，而 `zhang2020` 的用途是两层匿名 HIBE，收益有限 |
| B 重写委派 | 保留 PP 阻断技巧（`a_id = b + Σ b_i a_i`，`l₀` 个向量替代 `l` 个矩阵），私有对象改为每层 `((l+1)m−k)×k` 环 g-trapdoor，委派用 `ExtendBasis` + 随机化，Decrypt 保留 `SamplePre`；须改名如 `zhang2020-repaired` | 需要新建环 g-trapdoor 的 TrapGen／SamplePre／ExtendBasis；SK 尺寸从"`2mn log q`"变成随层增长，原表结论不再成立；噪声／参数须整体重估 |
| C 不实现 | `zhang2020` 记为"原文不足以实施 HIBE"，储备保留 | 无新增后端；候选盘点 HIBE 3/8 不变 |

## 5. 与已有材料的关系

- 本次不改变安全标记：`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。
- 与 2026-10-15 [资格表](../2026-10-15-zhang-qualification/README.md) 的差异：资格表把问题记为"实施阻塞、需澄清"，本次逐页渲染核对后升级为**原文 HIBE 定义不自洽**，并给出确切位置（p.10／p.11／p.13 与 Theorem 2／4）。资格表本身保留为原版本证据，不覆盖。
- 未取得作者勘误，未与作者通信；判定基于仓库内固定 PDF。

## 6. 未做的事情

- 未运行任何采样、委派、加解密或攻击实验。
- 未逐 game 复核 §3.3／§4.3 的其余论证（除 #4 的维度问题外）。
- 未评估路线 B 的实际工作量与参数可行性。
