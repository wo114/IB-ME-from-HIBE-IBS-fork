# Foo–Li 条件式正确性定理、参数条件与失败概率账本

版本：v1.0；日期：2026-10-06。证据基线：`800e4dd49790d0723b2a02be7698c713b93169f6`。

## 0. 结论与阅读方法

本文把已有分散论证整理成可审查的正确性证明，**不是**宣布当前 Foo–Li 后端、正式参数或完整 IB-ME 已验收。

- 第 4 节：代数、平滑传递、委派质量、签名范数四个子引理。
- 第 5 节：一次诚实流程及预先确定批次的条件式正确性定理。
- 第 6 节：逐项参数条件；“待定”不等于零或自动满足。
- 第 7 节：总失败概率表及可选的初始化估计路线。
- 第 8—10 节：实现映射、已有证据、完成门槛和赛题对应。

本次只整理和核验研究材料，不修改生产接口、参数和采样代码。理论沿用 Foo–Li 的算法骨架，以及项目第七轮的固定用户状态、经典 ROM 有限实现适配。这里的正确性不依赖 SIS 困难性，也不提供 UF-CMA、强不可伪造、QROM 紧性或密文完整性证明。

数学结论采用“前提 ⇒ 结论”的形式；具体方案要获得正确性声明，还必须证明实际算法满足前提，并给出具体失败预算。多智能体审查是内部复核，不是机器形式验证或外部同行评审。

## 1. 固定来源与声明边界

| 编号 | 来源与定位 | 用途 |
|---|---|---|
| P1 | Foo–Li，*Tightly Secure Lattice Identity-Based Signature in the Quantum Random Oracle Model*，ACISP 2023，接受稿；PDF 11—13 页、印刷 10—12 页，§2.5、§3、Figure 2；[出版标识](https://doi.org/10.1007/978-3-031-35486-1_17) | IBS 正确性定义、固定种子、签名与验签算法 |
| P2 | Micciancio–Peikert，*Trapdoors for Lattices: Simpler, Tighter, Faster, Smaller*，[ePrint 2011/501](https://eprint.iacr.org/2011/501)；固定 PDF 12—14、27—29 页 | Lemmas 2.3、2.5、2.6；Algorithm 3、Theorem 5.5；Algorithm 4 |
| R7 | `docs/research/2026-10-04-round7/FooLi经典ROM证明补全与修复路线.md`，§2、§5.2、§7.1—7.2 | 本项目的模块契约、真实委派尾界、扩展矩阵平滑与有限误差 |
| R8 | `docs/research/2026-10-05-round8/MP12完整SampleD有限误差与随机带核验.md`，§2—5 | 非球形扰动、MP12 组合、固定带与中止 |
| R10 | `docs/research/2026-10-05-round10/任意中心在线采样与MP12扩展核验.md`，§2—4 | 在线有限采样、整类资源证书、调试参数与负面对照 |
| I | `IMPLEMENTATION_SPEC.md`，§1—5；`docs/PROJECT_RESTART.md` | 当前生产接口与未完成边界 |
| O | 工作区 `outputs/IBME-赛题验收基准/2026-09-27/赛题验收基准.md`，R1、R4、A02、A04、A09、A14 | 官方验收范围；不是数学引理来源 |

P1 本地文件：`papers/2023_tightly_secure_ibs_foo.pdf`；SHA-256：
`845855b9b39fdcbbe61831d9d1c431dc8d898b5a6244863ff87b23171b1e45b8`。

P2 本地文件：`papers/2011_lattice_trapdoors_micciancio.pdf`；SHA-256：
`bf1160f088825ed28c343b299f5bc2acdca41cc50293310a03a4506d2fdbdb84`。

本文仅声称读取和核对与本次正确性有关的章节，不声称本次重新审完这些论文的全部安全证明。R7—R10 是待审查的项目推导，不能代替 P1/P2 原始依据。各仓库路径均相对于上述证据基线；两个本地交付副本使用相同正文。

## 2. 统一符号与算法对象

### 2.1 维度及分布

取质数模数 $q$，正整数 $n,\bar m$，并定义

$$
k=\lceil\log_2q\rceil,\quad w=nk,\quad m=\bar m+w,\quad D=m+w.
$$

$m$ 只表示主矩阵列数，消息记为 $M$。令
$G=I_n\otimes(1,2,\ldots,2^{k-1})\in\mathbb Z_q^{n\times w}$。
它包含每个块的首列单位向量，因此模 $q$ 行满秩。

| 对象 | 维度/空间 | 含义 |
|---|---|---|
| $\bar A$ | $\mathbb Z_q^{n\times\bar m}$ | 主公开基块 |
| $R_0$ | $\mathbb Z^{\bar m\times w}$ | MP12 减号约定的主陷门 |
| $A=[\bar A\mid G-\bar A R_0]$ | $\mathbb Z_q^{n\times m}$ | 主公开矩阵 |
| $B=H_1(id,b)$ | $\mathbb Z_q^{n\times w}$ | 身份扩展块 |
| $R$ | $\mathbb Z^{m\times w}$ | Foo–Li 加号约定用户陷门：$AR=B-G$ |
| $F=[A\mid B]$ | $\mathbb Z_q^{n\times D}$ | 签名矩阵 |
| $u=H_2(id,M)$ | $\mathbb Z_q^n$ | 消息 syndrome |
| $\sigma=(x,b)$ | $\mathbb Z^D\times\{0,1\}$ | 签名对象；范数在有符号整数上检查 |
| $r_{\rm gen}$ | 正实数 | 主陷门生成的高斯参数 |
| $s,t$ | 正实数，$t\ge s$ | 主委派输出、签名输出的球形高斯参数 |
| $r_0,r_1$ | 正实数 | 两阶段 MP12 内部平滑因子；不是 $r_{\rm gen}$ |
| $Q_0,Q_1$ | 非负实数；当前代码用整数 | 主/用户陷门 Frobenius 范数平方准入上限 |

对 $C\in\mathbb Z_q^{n\times d}$，定义
$\Lambda_q^\perp(C)=\{z\in\mathbb Z^d:Cz=0\bmod q\}$、
$\Lambda_q^u(C)=\{z\in\mathbb Z^d:Cz=u\bmod q\}$。
定义 $\rho_a(x)=\exp(-\pi\|x\|_2^2/a^2)$，集合的 $\rho_a$ 为逐点求和。
$D_{\Lambda+c,a}$ 表示权重正比于 $\rho_a(x)$ 的陪集离散高斯。

$a$ 是高斯参数，不是通常正态分布的标准差。矩阵参数 $C_p$ 对应权重
$\exp(-\pi x^\mathsf TC_p^{-1}x)$，不能把 $C_p$ 直接当成概率协方差。
所有范数默认为欧氏范数；Frobenius 范数和算子范数分别明确标注。

### 2.2 真实状态、输入和失败语义

固定一个公钥上下文和密钥世代。每个身份持久保存同一份
$(R,b,k_{id})$。主种子 $k_1,k_2$ 与用户种子 $k_{id}$ 独立生成。
本文签名尾概率写作 $\tau_{\rm sig}$；R7 的 $\tau_D,\tau_S$ 是委派/签名随机带长度，不与本概率符号混用。
按 P1，五个哈希/预言机域分开：

- $b=\mathcal H_1(k_1,id)$；
- 委派带 $\psi=\mathcal H_2(k_2,id)$；
- $B=H_1(id,b)$；
- $u=H_2(id,M)$；
- 签名带 $\varphi=\mathcal H_3(k_{id},id,M)$。

使用公开固定输出长度的独立随机预言机，首次访问不同地址给出独立均匀输出，重复地址返回原值。定理针对事先固定的合法输入和诚实调用，不针对攻击者预先挑选随机带或消息的任意转录。实际 SHAKE/PRG 替换不是自动满足信息论 TV 契约；它需要单独的实现与模型说明。

为衔接代码，身份和消息来自公开规定的有界字节域，采用无歧义的域分隔和长度编码。P1 的固定长度位串域与当前变长字节域并不自动相同。本文件要求同一合法对象在签名、验签和序列化往返中保持同一解释；若另做压缩哈希，安全碰撞问题另行处理，不能不加说明地继承原文模型。

定义失败值 $\bot$。以下任一情况使本次诚实流程失败：Setup/Ext/Sig 返回 $\bot$、用户质量不合格，或验签拒绝。固定随机带的中止结果须保持可重算；不能在失败后悄悄换带或换用户种子。

本文采用 P1 Figure 2 的数学验签谓词：

$$
b\in\{0,1\},\quad x\in\mathbb Z^D,\quad Fx=u\bmod q,\quad \|x\|_2^2\le t^2D.
\tag{V}
$$

P1 未额外规定 $x\ne0$。当前旧后端的拒零及重试政策不在这个谓词中；本文件不擅自修改现有接口。如果后续保留拒零、修改上界或引入重试，须版本化定义并重算正确性预算。

## 3. 定理前提：哪些是需要实现证明的契约

所有下列条件均是前提，不是因写入本文就自动成立。

**C1（公共配置与语义）。** 第 2 节的维度、合法输入、精确整数运算、哈希一致性及验签谓词成立。主/用户公共采样类满足资源证书；资源条件不满足时是配置不准入，不能删掉失败样本后继续声称覆盖整类陷门。排除硬件故障、进程被杀等环境故障；这不免除软件异常记录。

**C2（实际初始化好事件）。** 对实际 Setup 的联合输出，定义 $\mathsf{InitGood}$ 为：Setup 成功；主陷门关系有效；$\|R_0\|_F^2\le Q_0$；且

$$
\Theta_A(s):=\rho_{1/s}\bigl(\Lambda_q^\perp(A)^*\setminus\{0\}\bigr)\le\varepsilon_0,
\quad 0<\varepsilon_0\le\tfrac14 .
$$

存在经证明的实际概率上界
$\Pr[\neg\mathsf{InitGood}]\le\delta_{\rm init}$。
有效关系 $A[R_0;I_w]=G$ 已蕴含 $A$ 满秩；不把满秩当成未经检查的幸运事件。
近均匀公钥不是本正确性定理的必要条件；第 7 节仅把它作为估计 $\delta_{\rm init}$ 的一种可选路径。

**C3（未过滤委派的统一 TV 契约）。** 对每个好初始化输出和每个 $B$，原始有限委派输出（含 $\bot$），与 $w$ 列独立的
$D_{\Lambda_q^{B_j-G_j}(A),s}$ 的联合分布相距至多
$\varepsilon_{\rm Del}$。这里使用 Foo–Li 加号约定；实际 MP12 负号输出经取负后对应这一分布。
在原始输出后执行质量检查 $\|R\|_F^2\le Q_1$，并要求

$$
Q_1\ge mws^2.
\tag{Q}
$$

TV 比较发生在质量过滤之前；不能把过滤后的成功条件分布直接称为上述未过滤高斯。

**C4（未过滤签名采样的统一 TV 契约）。** 对每个可达的合格固定用户陷门、每个 $u$，原始有限 SampleD 输出（含 $\bot$）与
$D_{\Lambda_q^u(F),t}$ 相距至多 $\varepsilon_{\rm SP}$。这要求签名带尚未通过自身输出被条件化，并独立于此前的委派带。最终范数检查在这一原始输出上做确定性后处理。

**C5（诚实接口保持）。** 合法密钥、签名和消息的序列化/加载、上下文以及身份顺序保持；合法返回的整数向量满足完整维度；非中止采样确实保持对应模方程。当前研究采样器的这些代数条件可单独检查，但完整 Foo–Li 字节后端尚未实现，C5 的端到端部分待落实。

C3/C4 的距离在包含 $\bot$ 的共同输出空间上定义，理想高斯在 $\bot$ 上质量为零。因此中止已包含在 TV 中。反过来，“采样成功条件下距离小”不能替代 C3/C4。

## 4. 四个正确性子引理

### 引理 L1：陷门与签名模方程

**陈述。** 若 $B=AR+G\bmod q$，令 $J=[-R;I_w]\in\mathbb Z^{D\times w}$，则 $FJ=G\bmod q$。对任意整数扰动 $p\in\mathbb Z^D$ 和满足 $Gz=u-Fp\bmod q$ 的 $z\in\mathbb Z^w$，向量 $x=p+Jz$ 满足 $Fx=u\bmod q$。

**证明。**

$$
FJ=[A\mid B]\begin{bmatrix}-R\\I_w\end{bmatrix}
=-AR+B=G\pmod q,
$$

$$
Fx=Fp+FJz=Fp+Gz=Fp+(u-Fp)=u\pmod q.
$$

维度逐项相容，等式在所有成功路径上成立，不依赖高斯尾界或 SIS 困难性。主阶段同理使用 $J_0=[R_0;I_w]$ 和 $AJ_0=G$。
MP12 委派原始输出 $T$ 满足 $AT=G-B$；取 $R=-T$ 是两个陪集间的双射，且 $\rho_s(-r)=\rho_s(r)$，保留 Frobenius/算子范数及 TV 距离，不产生新误差项。$\square$

**适配说明。** MP12 的输入约定是 $[\bar A\mid HG-\bar A R_{\rm MP}]$。用户阶段取 $\bar A=A,H=I_n,R_{\rm MP}=-R$；若忘记负号，不能再用本引理。一般可逆 tag $H$ 下，前提须同步改成 $B=AR+HG$，于是 $FJ=HG$，再令 $Gz=H^{-1}(u-Fp)\bmod q$；不能只改 syndrome 而保留 $FJ=G$。本 IBS 使用 $H=I_n$。[P1 Figure 2；P2 Algorithm 3；R8 §1]

### 引理 L2：从主矩阵向签名矩阵传递平滑条件

**陈述。** 设 $A$ 满行秩、$B$ 任意、$t\ge s$、$w\le m$，且 $\Theta_A(s)\le\varepsilon_0$。则

$$
\Theta_F(t)\le\varepsilon_F:=2\varepsilon_0+\varepsilon_0^2<1,
\qquad t\ge\eta_{\varepsilon_F}(\Lambda_q^\perp(F)).
\tag{S}
$$

**证明。** 对满行秩 $C\in\mathbb Z_q^{n\times d}$，

$$
\Lambda_q^\perp(C)^*
=\bigsqcup_{a\in\mathbb Z_q^n}\left(\mathbb Z^d+\frac{C^\mathsf Ta}{q}\right).
$$

求和必须包含 $a=0$ 对应的所有整数点；$\Theta_C$ 只删去完整对偶格中的零向量，不能删去整个整数子格。
这些陪集互不相交：若两个代表的差是整数向量，则
$C^\mathsf T(a-a')=0\bmod q$，由满行秩推出 $a=a'$。
代表取模 $q$ 的任意整数提升不改变陪集。故

$$
\begin{aligned}
1+\Theta_F(t)
&=\sum_{a\in\mathbb Z_q^n}
 \rho_{1/t}(\mathbb Z^m+A^\mathsf Ta/q)\,
 \rho_{1/t}(\mathbb Z^w+B^\mathsf Ta/q)\\
&\le \rho_{1/t}(\mathbb Z^w)
 \sum_{a\in\mathbb Z_q^n}\rho_{1/t}(\mathbb Z^m+A^\mathsf Ta/q)\\
&=\rho_{1/t}(\mathbb Z^w)(1+\Theta_A(t)).
\end{aligned}
$$

第一个不等式使用移位整数格高斯质量不超过零中心质量，见 P2 Lemma 2.5。
$t\ge s$ 使每个非零对偶点的 $\rho_{1/t}$ 权重不增，故
$\Theta_A(t)\le\varepsilon_0$。
又 $\mathbb Z^m\subseteq\Lambda_q^\perp(A)^*$，且
$\rho_{1/t}(\mathbb Z)\ge1$、$w\le m$，于是

$$
\rho_{1/t}(\mathbb Z^w)
\le\rho_{1/t}(\mathbb Z^m)
\le1+\Theta_A(t)\le1+\varepsilon_0.
$$

因此 $1+\Theta_F(t)\le(1+\varepsilon_0)^2$。
$\varepsilon_0\le1/4$ 给出 $\varepsilon_F\le9/16<1$，由平滑参数定义得到结论。$\square$

这个证明对每个 $B$ 成立，不需要 $B$ 均匀；也没有把真实陪集签名换成零中心整数高斯。[对 R7 §7.1 的展开；P2 Definition 2.2、Lemma 2.5]

### 引理 L3：委派陷门质量，明确衔接 Frobenius 检查

令

$$
\tau_m=2^{-m}\frac{1+\varepsilon_0}{1-\varepsilon_0}.
$$

在 C2 的好矩阵上，P2 Lemma 2.6 对每一理想委派列 $R_j$ 给出
$\Pr[\|R_j\|_2>s\sqrt m]\le\tau_m$，对所有 syndrome 统一成立。
如果所有列均满足此界，则

$$
\|R\|_F^2=\sum_{j=1}^w\|R_j\|_2^2\le mws^2\le Q_1,\qquad
\|R\|_{\rm op}\le\|R\|_F\le\sqrt{Q_1}.
$$

对 $w$ 列取并合界，理想质量拒绝概率至多
$\min\{1,w\tau_m\}$。并合界本身不要求列独立；C3 的理想产品分布由委派契约提供。
把实际原始委派通过 C3 转回，并把 $\bot$、无效关系和超质量定义为同一个坏输出集合，有

$$
\Pr[\text{委派中止或用户密钥不合格}\mid\text{固定好初始化}]
\le \min\{1,\varepsilon_{\rm Del}+w\tau_m\}.
\tag{K}
$$

这里不把“真实分布在质量合格条件下的 TV”误认为仍为 $\varepsilon_{\rm Del}$。$\square$

### 引理 L4：诚实签名的验签范数

令

$$
\tau_{\rm sig}=2^{-D}\frac{1+\varepsilon_F}{1-\varepsilon_F}.
$$

由 L2 与 P2 Lemma 2.6，对每个 $u$ 和理想签名
$X^\star\leftarrow D_{\Lambda_q^u(F),t}$，

$$
\Pr[\|X^\star\|_2>t\sqrt D]\le\tau_{\rm sig}.
$$

取坏集合为 $\{\bot\}\cup\{x:\|x\|_2^2>t^2D\}$；若希望只使用 TV 而不使用 L1，还可把不满足模方程的输出加入该集合，理想分布在这部分的质量为零。由 C4，真实中止或验签失败概率至多

$$
\min\{1,\varepsilon_{\rm SP}+\tau_{\rm sig}\}.
\tag{N}
$$

成功采样时的模方程由 L1 精确保证；范数通过仅是高概率结论。不要在 C4 外再重复加“有限拒绝中止”项。$\square$

## 5. 条件式正确性定理

### 定理 T1：一次诚实初始化—发钥—签名—验签

**陈述。** 固定公共配置、一个合法身份 $id$ 和一条合法消息 $M$。它们不依赖本次待抽取的随机带。若 C1—C5 成立，以实际 Setup 随机性、种子和首次预言机值为概率空间，并把任何阶段的 $\bot$ 或验签拒绝都计为失败，则

$$
\Pr[\mathsf{Fail}_{id,M}]
\le \epsilon_{\rm corr}:=
\min\left\{1,\,
\delta_{\rm init}+\varepsilon_{\rm Del}+w\tau_m
+\varepsilon_{\rm SP}+\tau_{\rm sig}
\right\}.
\tag{T1}
$$

**证明。** 先按 $\mathsf{InitGood}$ 分解事件。其补事件贡献至多
$\delta_{\rm init}$。对任一好初始化输出，L3 使 Ext 中止或用户不合格的贡献至多
$\varepsilon_{\rm Del}+w\tau_m$。如果用户合格，则在其固定陷门上、尚未披露的独立签名带下，L4 给出本次 Sig/Ver 失败上界
$\varepsilon_{\rm SP}+\tau_{\rm sig}$。对所有合格密钥取平均不会增加这个统一上界；C5 保证从数学对象到诚实接口不会额外失败。合并三项，概率截断到 1，得证。$\square$

**量词与原文措辞。** P1 §2.5 使用“对所有生成密钥”的正确性表述。本定理显式给出两个层次：

1. 对每份固定、满足上述条件的可达好用户状态，在新消息地址的签名带尚未被自身输出条件化时，成立 L4 的局部界；
2. 对完整随机生成流程，成立 T1 的平均失败界，坏初始化和坏用户密钥明确计入。

这不宣称每份可能生成的坏密钥、每条固定随机带都成功。若报告要采用“每份返回密钥都合格”的更强接口，需要真正实现相应质量/参数准入并独立记录被拒绝概率；不能靠把失败密钥从统计中删掉来加强结论。

### 推论 T2：固定批次及重复签名

在同一个 Setup 下，事先确定 $U$ 个不同身份和 $N$ 个不同的“身份、消息”对。
同一身份只生成一套持久状态；同一地址重算时复用原带，不实施额外重试。
C3/C4 对所涉及的各首次调用统一成立，则并合界给出

$$
\Pr[\text{批次至少一项失败}]
\le
\min\left\{1,\delta_{\rm init}
+U(\varepsilon_{\rm Del}+w\tau_m)
+N(\varepsilon_{\rm SP}+\tau_{\rm sig})\right\}.
\tag{T2}
$$

证明可对每个身份/消息对的坏事件取边际并合界；这些事件不必独立。
共享 Setup 的坏事件只计一次，重复相同输入只重现同一成功或失败事件。
不能把连续重试 $h$ 次写成失败概率 $\epsilon_{\rm corr}^h$。
本文不把 T2 自动推广为攻击者自适应选择所有消息、泄露随机带后的任意条件分布定理。

有限参数的 $\epsilon_{\rm corr}$ 是数值界；要写成“随安全参数可忽略”，必须给出参数族 $\lambda\mapsto(n,q,m,s,t,\ldots)$，证明 T1 各项之和可忽略，批次数量至多多项式且运行时间/数值位长受控。一次 $10^{-10}$ 量级的局部证书不等于渐近可忽略性。

## 6. 逐项参数条件：待填账本

### 6.1 MP12 两阶段参数必须分别代入

对阶段 $j=0$（主委派）与 $j=1$（用户签名），分别设
$d_0=m,d_1=D$、$\gamma_j\ge2$、球形平方尺度 $\kappa_j>0$。
使用

$$
J_0=[R_0;I_w],\quad J_1=[-R;I_w],\qquad
s^2=r_0^2\kappa_0,\quad t^2=r_1^2\kappa_1.
$$

统一 Frobenius 准入的一个充分选择是

$$
\kappa_j\ge(\gamma_j+2)(Q_j+1).
\tag{P-cov}
$$

记阶段陷门 $T_0=R_0,T_1=-R$，于是 $J_j=[T_j;I_w]$。
因为 $\|J_j\|_{\rm op}^2=1+\|T_j\|_{\rm op}^2\le Q_j+1$，
它推出 MP12 所需的
$\kappa_j I_{d_j}\succeq(\gamma_j+2)J_jJ_j^\mathsf T$。
扰动平方参数矩阵与 gadget 平方参数分别为

$$
C_{p,j}=r_j^2(\kappa_j I_{d_j}-\gamma_jJ_jJ_j^\mathsf T)>0,\qquad
a_{G,j}^2=r_j^2\gamma_j.
$$

固定 $\Lambda_q^\perp(G)\subset\mathbb R^w$ 的完整格基，其最大 Gram–Schmidt 长度平方为 $L_G^2$。
由 P2 Lemma 2.3，以下条件足以覆盖两个内部平滑要求：

$$
r_j^2\ge
\frac{\ln(2w(1+1/\varepsilon_{\mathrm{MP},j}))}{\pi}
\max\{1,L_G^2/\gamma_j\},\qquad 0<\varepsilon_{\mathrm{MP},j}\le\tfrac12 .
\tag{P-smooth}
$$

这里 $\varepsilon_{\mathrm{MP},j}$ 是阶段 $j$ 的 MP12 卷积平滑误差，与好主矩阵的 $\varepsilon_0$ 是不同参数。
P-smooth 的两项分别保证
$r_j\sqrt{\gamma_j}\ge\eta_{\varepsilon_{\mathrm{MP},j}}(\Lambda_q^\perp(G))$
和 $r_j\ge\eta_{\varepsilon_{\mathrm{MP},j}}(\mathbb Z^w)$。
第二项经 $J_j$ 映射，在相应非球形度量下保证 $J_j\mathbb Z^w$ 的平滑；
结合 P-cov，覆盖 MP12 乘积高斯中的子空间质量比较。
两个格的秩均为 $w$，所以对数中是 $2w$ 而不是 $2d_j$。
有限扰动本身的近似误差仍由 $\mu_{p,j}$ 承担。

若有限扰动与有限 gadget 的统一 TV（含中止）为 $\mu_{p,j},\mu_{G,j}$，
还要求 $\mu_{G,j}$ 对每个扰动输出所决定的 syndrome 的条件采样核统一成立。
gadget 使用与已经消耗的扰动字节独立的新随机字节；它们可以来自同一足长均匀带的未读后缀，但须对所有有限读取历史维持该条件。
主委派各列使用独立的完整随机带，或提供同等强度的逐历史条件核保证。
只有边际 TV 小、却任意相关的子采样器，不足以推出下面的误差相加。
在这些前提下，沿 R7 §7.2、R8 §4 的保守有限归一化界，可以选择契约上界为

$$
e_j=\min\left\{1,
\frac{4\varepsilon_{\mathrm{MP},j}}
{(1-\varepsilon_{\mathrm{MP},j})^2}
+\mu_{p,j}+\mu_{G,j}\right\},
\quad
\varepsilon_{\rm Del}:=\min\{1,we_0\},\quad
\varepsilon_{\rm SP}:=e_1.
\tag{P-TV}
$$

固定阶段 $j$，令 $\varepsilon:=\varepsilon_{\mathrm{MP},j}$。MP12 原文给 $O(\varepsilon)$；这里的显式常数是项目推导：
设 $a=(1-\varepsilon)/(1+\varepsilon)$，两次平滑质量比较后未归一化权重比在
$[a,a^{-1}]$，归一化后在 $[a^2,a^{-2}]$。其 TV 可保守上界为
$a^{-2}-1=4\varepsilon/(1-\varepsilon)^2$，再用采样核的数据处理和逐步耦合加入两项有限误差。没有把此常数冒充原文逐字定理。

### 6.2 参数填写表

| 编号 | 条件/需要填写的数据 | 判据或证据 | 当前正式实例 |
|---|---|---|---|
| P01 | $q,n,\bar m,k,w,m,D$ | $q$ 质数；$k=\lceil\log_2q\rceil,w=nk,m=\bar m+w,D=m+w$ | 待定 |
| P02 | 合法身份/消息长度、上下文、编码 | 有界合法域；签验一致；序列化往返无损 | Foo–Li 字节后端未接入 |
| P03 | $r_{\rm gen},Q_0$、实际主质量预算 | $A[R_0;I]=G$；好主状态满足 $\|R_0\|_F^2\le Q_0$；失败计入 $\delta_{\rm init}$ | 待定 |
| P04 | 好主矩阵 $\varepsilon_0$ 与失败预算 | $\Theta_A(s)\le\varepsilon_0\le1/4$；或有效格基平滑证书 | 待证明/代入 |
| P05 | $r_0,\gamma_0,\kappa_0,s$ | P-cov、P-smooth；$s^2=r_0^2\kappa_0$ | 待定 |
| P06 | $Q_1$ 与用户质量失败 | $Q_1\ge mws^2$；L3 同时覆盖 Frobenius 与算子范数 | 待定 |
| P07 | $r_1,\gamma_1,\kappa_1,t$ | P-cov、P-smooth；$t^2=r_1^2\kappa_1,t\ge s$ | 待定 |
| P08 | 两阶段 $\mu_{p,j},\mu_{G,j},e_j$ | 未过滤输出空间含 $\bot$，对所有准入陷门及 syndrome 统一 | 研究参数有证书；正式参数待定 |
| P09 | 公共精度、整数位数、尝试上限、带长 | 整个准入质量类的有限路径证书，不只验证一个样本陷门 | 128 维等研究上限内有实现 |
| P10 | 秘密种子长度、五域、带扩展、状态持久化 | 首访模型、重复输入行为、无系统熵回退、密钥加载一致 | 协议级待接入 |
| P11 | 目标 $\epsilon_{\rm corr}^{\rm target}$、批次 $U,N$ | T1/T2 数值不超过团队明确目标；不是自行补出的官方门槛 | 由团队确定 |
| P12 | 实际逐项预算及总值 | 所有待定项必须有来源；未知项不能填 0 | 尚不能给完整数值 |
| P13 | 安全参数要求（另表） | SIS 估计、归约范数、主公开分布、安全模型等 | 不由正确性放行 |

另一种检查 P04 的充分方法是：给出实际 $\Lambda_q^\perp(A)$ 的有效格基，
最大正交化长度为 $L_A$，证明
$s^2\ge L_A^2\ln(2m(1+1/\varepsilon_0))/\pi$。
这是 P2 Lemma 2.3 的直接代入，不要求主公钥近均匀；本次未提供正式参数下这种证书。

P1 的渐近维度/宽度配方与 R7 的保守渐近族不能直接填成有限精度的实际参数。
签名向量的范数应比较精确的 $\sum_i x_i^2$ 与 $t^2D$；可用有理数交叉相乘，避免先算平方根再取浮点近似。

## 7. 总失败概率表

| 项 | 发生位置和定义 | 上界来源 | 计数/不可重复项 | 正式数值 |
|---|---|---|---|---|
| $\delta_{\rm init}$ | 实际 Setup 中止或未满足 C2 | 实际联合分布证明/下述充分路线 | 同一个 Setup 只计一次 | 待定 |
| $\varepsilon_{\rm Del}$ | 原始有限委派与理想 $w$ 列高斯的 TV | P-TV；每列新带的逐步耦合 | 已含委派采样中止；不再逐列重复加中止 | 待定 |
| $w\tau_m$ | 理想委派用户质量坏事件 | L3；$Q_1\ge mws^2$ | 不代表经验拒绝率 | 待定 |
| $\varepsilon_{\rm SP}$ | 原始有限签名采样与理想陪集高斯的 TV | P-TV | 已含签名采样中止；不再加一次拒绝循环耗尽 | 待定 |
| $\tau_{\rm sig}$ | 理想诚实签名超验签范数 | L2、L4 | 不是 SIS 提取范数，也不是采样 TV | 待定 |
| 编码/状态一致性 | 本定理作为确定性契约 C1/C5 | 实现规范、往返及生命周期测试 | 若实际会失败，须另加有证明的 $\delta_{\rm impl}$，或判定不满足前提 | 待接入，不能填 0 |
| 环境故障 | 进程/OS/硬件故障等 | 本定理外的运行可靠性记录 | 不伪装成可忽略密码学概率 | 不适用 |
| 错误身份/伪造/篡改被接受 | 不是本表的诚实正确性失败事件 | 认证/安全性与负向测试 | 不混入 T1 充当正确性证明 | 另行审查 |

### 7.1 初始化的一种可选估计路线

设实际**未按质量筛选、未重试**的公开输出为 $\widetilde A$，生成中止映射为
$\bot$。在扩展输出空间上，若已证明

$$
\Delta(\mathcal L(\widetilde A),U(\mathbb Z_q^{n\times m}))
\le\varepsilon_{\rm TG},
$$

并对均匀 $A$ 证明
$\Pr[\operatorname{rank}(A)<n\ \text{或}\ \Theta_A(s)>\varepsilon_0]\le\delta_A$，
再令

$$
\delta_0\ge
\Pr[\widetilde A\ne\bot\ \text{且实际主陷门不满足质量/有效性契约}],
$$

在公共资源类已准入、其他诚实接口无额外失败的前提下，可取

$$
\delta_{\rm init}\le\min\{1,\varepsilon_{\rm TG}+\delta_A+\delta_0\}.
\tag{I}
$$

证明是 TV 对事件概率的控制加并合界。$\varepsilon_{\rm TG}$ 已覆盖生成
$\bot$；不能在式 I 后再加同一次生成中止。若手上证书仅比较“生成成功条件下”的分布，
则不符合这个定义，必须先加入成功概率重新推导。

式 I 可能很松。公开分布远离均匀只说明这条充分路线可能无用，**不能据此判定代数正确性失败**。也可直接证明实际联合 $\mathsf{InitGood}$ 概率，避免经均匀分布转接。有限高斯生成误差、主质量尾界若在某个总证书中已经计入，不应再当作新的独立事件相加。

### 7.2 为什么本表没有 SIS 攻击优势和猜种子损失

T1 证明的是固定合法输入上的诚实运行成功，不需要假设攻击者不能解 SIS。
R7 安全归约中的猜目标槽位、非零提取、公开种子猜测、归约查询次数和
$\beta_{\rm red}$ 不能不加区分地搬入本表。真实采样随机源模型的替换仍须论证，但那与安全游戏中攻击者猜中种子的事件不是同一个问题。

## 8. 与当前代码的对应及不能混同之处

| 证明对象 | 当前研究入口 | 当前能支持的结论 | 尚缺 |
|---|---|---|---|
| 原始有限标量高斯 | `experiments/research/online_gaussian_reference.py`：`OnlineScalarGaussian` | 截断、量化、有限中止与固定带的局部证书 | 正式公共配置 |
| 完整 MP12 两阶段 | `experiments/research/online_mp12_reference.py`：`OnlineMP12SampleD` | 扰动、gadget、$p+Jz$ 和分布证书 | 完整 Foo–Li 签名接口 |
| 公共质量类 | 同文件：`quality_stage`、`sampler_for_quality` | Frobenius 门槛、统一宽度类、位数和带长准入 | 正式维度/参数可执行性 |
| 主生成 | 同文件：`OnlineGaussianGenTrap` | 陷门关系及有限生成 | 正式 $\delta_{\rm init}$ 与安全公钥条件 |
| 委派 | 同文件：`delegate_stream` | 独立整段列带、符号适配 | 身份分支/种子与持久状态 |
| 数学验签 | P1 Figure 2；研究输出可验算方程和范数 | 局部向量诊断 | $\sigma=(x,b)$ 的真实对象和 Verify |
| 旧生产后端 | `src/ibme/ibs/sis_ibs.py` | 教学实现，不能视为 Foo–Li | 算法、拒零、重试及格式均需版本化适配 |

代码中的 `r_squared` 对应 $r_j^2$，
`sigma_squared`/`Sigma_scalar` 对应 $\kappa_j$，
`spherical_target_width_squared` 对应 $r_j^2\kappa_j$。
不要因为字段名带 `squared` 再额外平方一次。
原文使用 $s'$ 的地方本文写 $t$；原文签名向量 $d$ 本文写 $x$，避免与维度 $D$ 混淆。

`sample_from_tape` 要求恰好公开长度的带，带不足与有限拒绝中止是不同事件。
独立列带的未用后缀也不得作为另一列的随机带重新利用。
R10 的资源界是参考实现准入条件，不是所有数学上可行参数都被当前代码支持的声明。
当前 `quality_stage` 要求整数 $Q_j,\gamma_j$，并固定取 $\kappa_j=(\gamma_j+2)(Q_j+1)$。
第 6.1 节允许更大的 $\kappa_j$ 在数学上成立，但不能直接复用这个工厂针对原宽度类出具的资源证书，必须重新验证。

## 9. 已有数值证据与本次复核范围

R10 固定调试样例：

| 量 | 值 |
|---|---:|
| $q,n,\bar m,w,m,D$ | $2147483659,1,1,32,33,65$ |
| $Q_0,Q_1$ | $64,4324320$ |
| $s^2,t^2$ | $4095,272432223$ |
| $mws^2$ | $4324320$ |
| $t^2D$ | $17708094495$ |
| 主/用户完整采样局部 TV 上界 | 各约 $1.6817553\times10^{-10}$ |
| 委派样例数/建立用户采样器数 | $3/1$ |
| 保存的用户采样尝试 | $64$；原记录方程错误和中止均为 $0$ |

这些数值仅能填入部分局部账项；$\varepsilon_0$ 的好矩阵证书、
$\delta_{\rm init}$ 及正式编码状态条件并未随这个表完成，不能把未填项当成零后输出“总正确率”。

该样例的 $n=\bar m=1$ 主陷门可以从公开矩阵恢复，公开分布距均匀有很大的已证明下界。[R10 §4.2]
这是安全负面对照，不是 Foo–Li 正式安全参数，也不是本正确性定理的反例。
维持 `security_claim: none`。

本次主代理通过交付脚本再次重放相同固定测试流的 64 次用户采样：
中止、模方程错误、超范数、零向量计数均为 0；
最大范数平方 $4158936628<17708094495$，与上一轮原始工具输出一致。
同时复算存档的 5 个向量，并检查两个 syndrome 各前 2 个重放输出与存档逐项一致。
这里复用存档的主/委派陷门，没有重新生成主密钥或消费完整委派随机带；
这是同一固定流的诊断，不是新增 64 个独立随机样本，也不是完整 IBS 签名。

重新计算的局部采样预算和为 $we_0+e_1\approx5.5497923463491755\times10^{-9}$。
它仅是 T1 中两项采样误差的上界和，不含 $\delta_{\rm init}$ 和两项理想尾界，
因此不是总失败概率。精确有理数与未填的总预算保存于核验记录。

本次新执行的测试、归档向量复算、环境与文件哈希见
[核验记录](核验记录.json)；
多智能体意见的处理及最终交付状态见
[汇总与复核](汇总与复核.md)。
既有测试通过不能替代 L1—L4/T1 的证明；这些证明也不能代替真实后端测试。

## 10. IB-ME 衔接、验收与下一步

### 10.1 只给组合的正确性接口，不提前宣布完成

匹配身份时，IBS 签的是 $\operatorname{encode}(rcv,M)$；
HIBE 载荷含 $\sigma,M$，身份层级为 $(rcv,\phi)$。
当 $\rho=rcv$ 且 $snd=\phi$，若 HIBE 正确解出同一载荷，
且解析无损，那么验签重算的身份、接收者和消息与签名端相同。

在上述载荷域内、若 HIBE 给出统一的正确性失败界
$\delta_{\rm HIBE}$，且接口/编码额外失败有界为 $\delta_{\rm codec}$，
则可由事件包含与并合界整理

$$
\delta_{\rm IBME}\le
\min\{1,\epsilon_{\rm corr}+\delta_{\rm HIBE}+\delta_{\rm codec}\}.
$$

此式要求实际 HIBE 覆盖签名载荷容量及 Extract/Derive/Encrypt/Decrypt
整个所需流程；不能仅引用某个单步或不同消息空间的解密界。
本次没有计算这两个新增项，也没有证明错误身份或篡改密文必然被拒绝。

### 10.2 本文对应的验收边界

| 项目 | 本文贡献 | 尚不能据此通过的部分 |
|---|---|---|
| A02 双向匹配 | 匹配时签名端与验签端相同输入的条件说明 | HIBE 实例与全部错误身份情形 |
| A04 完整实例 | Foo–Li 条件式正确性及参数接口 | 正式参数、真实 Foo–Li 后端与完整 LWE/SIS 系统 |
| A09 批量正确性 | T2、失败统计规范与研究测试 | 多组真实身份/消息的完整系统批次 |
| A14 优化保持 | 在线采样需保持的方程、分布、质量和失败条件 | 完整系统性能收益及安全保持证明 |

官方要求合法测试批次全部成功，不代表数学上每条随机带失败概率为零。
不得删失败重跑后把保留样本称为完整批次。官方没有规定必须 $128$ 位安全、
固定错误率、固定测试组数或必须 Ring-SIS；团队可另定更高目标，但须标明来源。

### 10.3 可执行的完成清单

1. 用本表冻结符号、诚实算法和失败接口；确认与 P1 及生产规范之间的拒零/重试差异如何处理。
2. 队长给出有限候选参数；逐行检查 P01—P12，无法证明的项保留“待定/不满足”，不以程序跑通代替。
3. 给实际主生成的好事件预算；完成 C3/C4 在该配置上的统一有限证书，计算 T1/T2。
4. 接入真实 Foo–Li 状态、编码和验签，记录完整失败类型；加上精确范数检查的持久回归。
5. 再接 HIBE 正确性与载荷范围，完成真实身份/消息批次；认证与篡改拒绝继续单列论证。

建议对外表述：
“已形成具有显式前提、参数条件和失败概率账本的 Foo–Li 条件式正确性证明；
正式有限参数和协议级实现尚未完成代入，不宣称完整 IB-ME 已通过验收。”
