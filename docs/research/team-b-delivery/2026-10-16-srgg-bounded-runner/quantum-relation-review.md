# SRGG 商识别的量子提取关系：可闭合的短核子结论

2026-10-16。本页只审查一个问题：能否把诚实密钥的短原像关系，正确扩大成“短原像或短核”，再使用 DFMS 的量子知识提取路线。**关系类型可以修复，商验证器的 2-soundness 和关系求解的等价变换可以证明；实际 QCUR / collapsing 假设及其匹配公钥分布没有因此得到证明。** 本页不宣称完整 QROM 或 native strong 安全性。

```text
security_claim=none
backend_admitted=false
parameters_are_formal=false
nist_security_category=null
```

本页没有修改冻结算法、参数、接口或证据清单；没有生成新的密钥、签名或 n512 抽样实验。H2 partial-byte/offset 的相干包装由统筹本轮的 [raw-h2-relabel.md](raw-h2-relabel.md) 独立处理，不在这里重复把它列为关系提取的未完成子引理。

## 1. 一手来源与核读范围

主来源是 Don–Fehr–Majenz–Schaffner，*Security of the Fiat–Shamir Transformation in the Quantum Random-Oracle Model*，[arXiv 1902.07556](https://arxiv.org/abs/1902.07556)。本轮通过只读 HTTP 在内存取得 PDF，并用已有 `pdftotext -layout - -` 定向核读；没有安装依赖或保存 PDF。所得 391144 B 的 SHA-256 为：

```text
36e305e50d5f074cfb745d5a470a2757cc252019eae8d7d50a9f0fc8efee3dd1
```

它与上一交付包记录的版本相同。本轮实际核对 PDF p.8–9 的 Definition 4 / Remarks 6–7 / FS 定义，p.10–12 的 Remark 11 / Definition 14 / Corollary 16，p.13–18 的 Definitions 18–20 / Theorems 21–22 / Definitions 23–24 / Theorem 25 / Assumption 27，以及 p.20–21 的静态至自适应论证和 Lemma 29。未声称读完全文、重证 DFMS，或核准论文中的所有应用。

本地代数来源是冻结的 [native-sig.md](../2026-10-16-srgg-reduction/native-sig.md) §1、[quotient-challenge.md](../2026-10-16-srgg-classical-rom/quotient-challenge.md) §1–7，以及 `structured_execution.py` 的 `ExactRing.signing_matrix/response/recover`。下面的关系、等价变换和反例是本项目推导，不归到 DFMS 或 SRGG 原论文名下。

## 2. 固定实例和有类型的见证

令 `R_Z=Z[X]/(X^n+1)`，n 为至少 4 的二次幂，`m=n/2`，Q 为奇数。A 有 d 行、ℓ 列，目标 `h in R_Q^d`。身份和底层公钥在本节固定；不在多个身份间更换 h。B 是**签名系数欧氏范数的平方上界**，U 是用户密钥系数范数的平方上界。令

```text
zeta=1+X^m, zeta*=1-X^m,
j=(zeta*,0,...,0)^T,
M_h=[2A, Qj-2h] mod 2Q,
c0(chi)=(chi,0), chi in {0,1}^m.
```

商识别的承诺是 W，挑战是 chi，响应是 `z in R_Z^(ℓ+1)`。其验证谓词为

```text
V_x(W,chi,z)=1 iff
  ||z||^2 <= B and M_h*z-Q*j*c0(chi)=W mod 2Q.
```

这里的 x 包括公共环参数、A、h、B、U。令 `C=4B`，并明确要求

```text
U+1 <= C;                         (R1)
Q^2 > C.                         (R2)
```

定义带标签的关系 `R_or`，标签必须在对象层面区分：

```text
R_pre(x,y):  Ay=h mod Q, ||y||^2<=U.

R_ker(x,Delta):
  [A,-h]*Delta=0 mod Q,
  0<||Delta||^2<=C,
  Delta mod Q != 0.

R_or(x,(0,y))       iff R_pre(x,y).
R_or(x,(1,Delta))   iff R_ker(x,Delta).
```

标签 0 是诚实密钥原像，标签 1 是增广矩阵短核。它们的维度、方程和用途都不同；提取出标签 1 不等于恢复诚实密钥，也不保证能从该核向量重新发钥或签名。

**命题 1（同一实例分布下的求解等价）。** 在 (R1) 下，求解 `R_or` 与求解 `R_ker` 有逐输出、成功概率不变的多项式时间变换。

证明：`R_ker` 求解器的输出直接加标签 1。反向时，标签 1 直接去标签；标签 0 的 y 变为 `Delta=(y,1)`。此时 `[A,-h](y,1)=0 modQ`，`||Delta||^2<=U+1<=C`，最后一个系数为 1，故整数非零、模 Q 也非零。两个变换不重抽实例、不条件化成功、不丢弃任一见证分支。证毕。

因此，在某个明确的实例分布 G 上，宣称 `R_or` 是 DFMS Definition 18 意义下的 hard relation，实质上仍须证明同一 G 上的增广矩阵短核困难性。**关系加 OR 没有免费提供一个新的困难性结论。** 反过来，若该短核困难性已成立，则不必另证短原像分支的困难性；命题 1 已包含它。这里的 G、量子辅助信息和求解时间必须一致，不能把实公钥分布换成独立均匀矩阵而不支付所需分布归约。

诚实实例生成器可以仍输出标签 0 的已发密钥，诚实签名算法原样使用它。用于提取的关系可以接纳标签 1；不应要求提取器最后一定输出 G 当初选中的那把密钥。DFMS Definition 14 要求的是**某个满足关系的见证**，不是同一 witness 的恢复。

## 3. 已闭合：商验证器的 2-soundness

**命题 2。** 固定任意 x、W，并取两条接受 transcript `(W,chi,z)`、`(W,chi',z')`，其中 `chi!=chi'`。在 (R2) 下，确定性算法输出 `(1,z-z')`，它满足 `R_or`。

证明：令 `Delta=z-z'`。相减验证式得

```text
M_h*Delta=Q*j*(c0(chi)-c0(chi')) mod2Q.       (1)
```

若 `Delta=0`，则 `zeta* (c0(chi)-c0(chi'))=0 mod2`。对规范 lift 的两半 `(a,0)`，乘 `zeta*` 后为 `(a,-a)`；它模 2 为零当且仅当 `a=0 mod2`。binary chi 和 chi' 因而相同，与前提矛盾，所以 Delta 整数非零。

式 (1) 模 Q 后给 `2[A,-h]Delta=0 modQ`；Q 为奇数，可以消去 2。三角不等式给

```text
||Delta||^2 <= (||z||+||z'||)^2 <= 4B=C.
```

若 Delta 的每个整数系数均为 Q 的倍数，其非零性给 `||Delta||^2>=Q^2>C`，再次矛盾。因此它也模 Q 非零，满足全部 `R_ker` 条件。证毕。

DFMS p.15 的 t-soundness 允许对 t 个独立均匀挑战存在一个可忽略的坏挑战集合。这里取常数 `t=2`：两挑战独立均匀时，唯一需要舍弃的挑战事件是重复，其概率恰为

```text
Pr[chi=chi']=1/|C_challenge|=2^(-n/2).       (2)
```

对其余所有挑战对，命题 2 对**任意**接受响应成立，包含响应在看到挑战后由对手自适应产生的情况。不要求响应来自诚实 Gaussian，不要求知道 y，也不要求挑战差是模 Q 的 unit。n 随安全参数增长、`n/2=omega(log eta)` 时，(2) 才是其渐近定义要求的 negligible 项；固定 n512 的 `2^-256` 只是该事件的数值，不代表整个方案有 256-bit 安全性。

**原 full-c 验证器也有这一 t-soundness 子结论。** DFMS 这里用的是允许可忽略坏挑战集合的 t-soundness，而不是“任意两个不同 full c 都可提取”的无例外 special soundness。对独立均匀的原 full c、c'，坏事件取 `eta(c)=eta(c')`，概率仍为 `2^(-n/2)`；其余挑战对的响应差按命题 2 的同一证明给非零短核。因而现有 same-coset 零差分反例继续否定无例外 full-challenge special soundness，却不否定 DFMS 所需的这一较弱 2-soundness。这个子结论不需要改变真实哈希或签名格式；商视角只是把坏事件和可提取类型写得更清楚。

**严格反例：不能把这个结论改写成短原像提取。** 取 `n=4,Q=45,U=1,B=81`，一行四列的 `A=[1,0,5,15]`，`h=10`。`Q^2=2025>4B=324`。对 `W=0`：

```text
chi=(0,0), c0=0, z=(0,0,0,0,0);
chi'=(1,0), c0'=1, z'=(0,0,0,0,9).
```

两者均通过验证：第二条的恢复式为

```text
9*(45*zeta*-20)-45*zeta*
 =360*zeta*-180=0 mod90.
```

且 `||z'||^2=81`。但是范数平方不超过 1 的整数 y 只能是零或某个系数位置的 `+/-1`，Ay 只能为零或 `+/-X^k,+/-5X^k,+/-15X^k`，没有一个为常量 10 模45。因此这个实例根本不存在 `R_pre` 见证，而 `(0,0,0,0,9)` 是有效的增广短核。

这是同一验证方程的代数夹具，反驳“两个不同商挑战必能提取 U 界短原像”的无条件陈述。它不是当前冻结参数、诚实 G 支持或实际 IBS 的安全攻击；不据此否定在更窄实例集上可能成立的其它原像定理。它足以说明本路线的**已证明输出类型必须是短核或正确标记的 OR 见证**。

## 4. DFMS 真正还要求哪一种提取性质

下表只核本关系路线的定理链，不重复旧量子 oracle 待办表。

| DFMS 原文位置 | 实际要求 | 本页能否提供 |
|---|---|---|
| Definition 14，p.11–12 | 一个统一量子多项式时间黑盒 extractor；成功概率对任何合法攻击者/实例和自适应谓词满足其多项式关系；knowledge error negligible | 关系已明确，完整实际 extractor 的这些保证尚未由工程测试给出 |
| Theorem 25，p.16 | 常数 t 的 t-soundness **及** Definition 24 的 quantum computationally unique responses | t=2 已由命题 2 和 (2) 证明；QCUR 未被已有短核碰撞归约证明 |
| Definitions 23–24，p.15 | 接受关系从响应寄存器到 `(W,chi)` 寄存器 collapsing；须比较测量响应和不测量响应的量子实验 | 是比普通 CUR 更强的前提；见下一节的精确映射与辅助信息边界 |
| Definition 18 / Theorem 21，p.13–14 | 与诚实 G 一致的 hard relation、superpolynomial 挑战空间、Definition 14 的 PoK；结论是单公钥 EUF-NMA | 命题 1 修复关系类型，但没有建立真实 G 的量子短核困难性或 QCUR |
| Theorem 22，p.14 | 在上行基础上，还需 KLS 意义的 naHVZK、承诺 min-entropy、普通 CUR | 不能因 OR 关系、t-soundness 或 H2 重标记成立而自动获得 native strong CMA |

DFMS §5 明确指出普通 computationally unique responses 不足以替换 perfect unique responses；Definition 24 是 collapsing 的量子版本。其 §6.2 的 Assumption 27 又**单独假设**短域上、由均匀有限域矩阵 keyed 的线性映射 collapsing，并没有把普通 SIS 困难性直接当成该假设的证明。当前对象是 composite Q 的 negacyclic 模块、带固定 identity 块和目标列的 `M_h`，不能仅因也叫“格签名”就继承那个有限域假设。该文 p.16 还明确把实际优化签名的适配和 concrete bounds 留给后续工作。

Definition 4 / Remark 6 允许诚实协议中止，并不让中止费用或诚实分布自动消失。这里保持诚实 G 只输出短原像分支，未主张任意 kernel-only 见证都可用于真实签名；本页的 2-soundness 只由验证器决定。若将 `R_or` 包装为完整 `Sig[Sigma]`，仍须写出关系、生成器、诚实 P 和 FS verifier 的完整接口，并核其正确性/中止约定，而不是仅改一个关系名称。

### 4.1 可证明的条件量子子结论

假定上述商验证器**在实际需要的实例族、量子初态和辅助信息模型中**满足 Definition 24，并拥有 DFMS 所要求的黑盒 unitary / inverse 访问，而不只是 Python 的经典回放。命题 2 给 t=2，故可使用 Theorem 25 的提取论证，输出 `R_or` 见证，并可再用命题 1 输出短核。

更具体地，DFMS Appendix B 的 Lemma 29 在只测量接受性的理想投影实验中给两次接受概率 `F>=v^3`，其中 v 是交互攻击者的接受概率。两挑战重复事件最多为 (2)。将响应测量替换成接受性测量的那些 QCUR hybrids 的**总**差额记为 `epsilon_meas`，得到该条件论证的形式

```text
Pr[K outputs a valid R_ker witness]
 >= v^3 - 2^(-n/2) - epsilon_meas.             (3)
```

对承诺 W 取平均时使用 x^3 的凸性，正是原文所述 Jensen 步骤。这里 `epsilon_meas` 不是已经为当前实例估出的数字；只有完整匹配的 QCUR 前提才使其 negligible。DFMS Theorem 25 在所核版本只给 proof sketch，本页不伪造其没有展开的 concrete 时间/优势常数。式 (3) 是明确前提下的提取子结论，不是实际 IBS 的已证优势界，也不能通过“经典两次 fork 实跑成功”来验证该前提。

若进一步建立同一 G 的 hard relation，Theorem 21 / Corollary 16 才给相应**单固定底层公钥**的 NMA 路线。它的 statement/message/commitment 哈希对象须和目标实例保持一致；本页不把这一结果扩展成同时更换 h 的 chosen-identity IBS 定理。native strong 还须使用 Theorem 22 的额外前提，不把 NMA 当作 strong CMA。

## 5. QCUR 的精确对象与一个有限范围反例

令有限响应域 `D_B={z:||z||^2<=B}`，定义受限公开映射

```text
f_x:D_B -> R_(2Q)^d,   f_x(z)=M_h*z mod2Q.
```

商验证关系是 `f_x(z)=W+Qj*c0(chi)`。在接受子空间上，测量 `(W,chi)` 与测量 `(f_x(z),chi)` 仅差一个可逆的输出平移。故若 f_x 在相同 x 分布、相同允许辅助信息和任意相干输入下 collapsing，则固定 chi 后的平移及已测量 chi 的侧信息给出 Definition 24 的 QCUR。反向固定 `chi=0` 即嵌入 f_x 的 collapsing 游戏。因此，**在一致的量词和侧信息约定下**，本协议 QCUR 可以精确定位成这个受限映射的 collapsing 性质；不能替换成“找不到两个短核”的经典碰撞命题。

Q 为奇数时 CRT 还给出其输出的等价信息：

```text
M_h*z modQ = 2[A,-h]*z modQ,
M_h*z mod2 = j*z_last mod2.
```

所以 f_x 同时包含增广模 Q 线性像和最后一项的 parity 信息。忽略后一项把它直接叫作“原有限域 A 的 collapsing”会改变接受关系；本页没有据此建立任何现成 collapsing 假设到当前实例的归约。

**命题 3（给定诚实密钥的 auxiliary 模型不满足 QCUR）。** 给区分器一个满足 `Ay=h modQ,||y||^2<=U` 的 y，并假定

```text
2(U+1)<=B.                                      (AUX)
```

令 `T=(y,1)` 为按多项式列堆叠的映射，取 `z0=0`、`z1=T*zeta`。冻结密钥关系给

```text
M_h*T=Qj mod2Q,
M_h*T*zeta=Qj*zeta=0 mod2Q,
||z1||^2=2(||y||^2+1)<=B.
```

`z1!=z0`，且对同一 `W=0,chi=0`，两个响应都接受。知道 y 的多项式时间区分器可准备

```text
|psi>=(|z0>+|z1>)/sqrt(2),   |W,chi>=|0,0>.
```

关系判定恒接受，输出寄存器测量也不改变它。不测响应时，对 `|psi>` 的投影成功概率为 1；测量响应后，态变为两个正交响应的等权混合，该投影成功概率为 1/2。准备电路的逆实现这个投影，区分概率差为 **1/2**。这是精确的量子测量反例，不是统计模拟。

**量词边界不能省略。** DFMS Remark 11 明确说明其算法初态量化包含任意 quantum advice；Definition 24 本身写固定 `V(x,...)` 的关系，没有另外列一个“随机公钥、辅助态如何依赖生成器 coins”的实验。若把需要验证的 QCUR 强读成“给定该 x 的任何辅助态，包括它自己的 y，仍 collapsing”，命题 3 正好否定这项强读法。它不说明所有 Sigma PoK 都失败：有 perfect unique responses 的协议不存在这样的响应对。

但**命题 3 不否定**以下不同的候选假设：先按 G 抽随机公钥，隐藏生成器秘密，只允许独立于该秘密抽样的原始 advice，区分器只获得公钥。把 y 交给区分器改变了这个实验，也不是当前未 Extract 目标身份的签名攻击游戏。DFMS §6 使用随机 keyed family 的应用方式也不能被这项有密钥反例一概否定。若走这种分布式 QCUR 路线，需要明确给出该实验，并证明 DFMS 所用每个测量 hybrid 的区分器都保留其允许的 auxiliary 来源；本页没有把这种修改后的平均实例提取证明冒充原定理的无条件实例化。

这个反例的用途很窄且确定：**禁止为了得到一个统一的 Theorem 25 结论而偷偷假设 witness-robust collapsing。** 关系 `R_or` 的类型修复仍成立；是否能在目标安全游戏产生的、无私钥辅助态类别上完成提取，是另一项需要实际证明的条件。

## 6. 冻结点核算与有限验证

从冻结 [structured-execution-n512-d2w8.json](../2026-10-16-srgg-bridge/structured-execution-n512-d2w8.json) 的公开参数读取：

```text
n=512, d=2, w=8, base=31, p=16383, r^2=64, L=16,
Q=13972913866395903,
U=338122385570209792,
B=238255596480161099521436160.

U+1=338122385570209793,
2(U+1)=676244771140419586,
4B=953022385920644398085744640,
Q^2=195242321917718902992738735185409.
```

因此 (R1)、(R2)、(AUX) 在此冻结研究点均成立。它们分别支持上述类型变换、非零模 Q 核，以及**在额外给定 y 的实验中**的反例；没有一个不等式提供实际量子困难性估计或正式准入。

Windows Python 3.14.7 本轮运行一次独立整数 negacyclic schoolbook 核算，验证 §3 的 Q45 两 transcript 恢复式、穷尽 U=1 的全部可能原像支持；另以同一 A、h=5、`y=(0,0,1,0)` 验证 §5 的两个同挑战响应，其范数平方为 0 和 4。全部显式检查通过；量子概率用 exact `Fraction(1)` / `Fraction(1,2)` 记账。未调用 Gaussian、未取熵、未测性能、未运行量子设备或仿真器。

这不是新的一组 pytest 或安全攻击收据，不与先前 1096 项回归相加。数学反例和有限代数核算不能替代当前随机公钥分布的安全归约。本次交付的正结论是命题 1–2；式 (3) 为显式 QCUR 条件下的子结论；命题 3 仅排除所写明的有诚实密钥 auxiliary 强模型。
