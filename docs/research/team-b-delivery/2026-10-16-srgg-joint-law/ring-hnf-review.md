# Uniform ring-HNF 的短域 collapsing：随机相位条件归约

2026-10-16，代码基线 `f3831ac`。本页给出一个新的、完整列明假设的数学归约：
uniform composite-Q ring-HNF 的短域 collapsing，可以归约到**指定形状、指定
Gaussian 秘密和误差的 normal-form Module-LWE**。归约使用系数 Fourier 相位，
不把 negacyclic block 矩阵当成独立标量矩阵，也不调用未经核验的环版 LMZ 定理。
这关闭的是 uniform-HNF 条件定理，不是实际 SRGG 服务的完整 QROM 证明；新增
Module-LWE 实例的困难性、实际辅助信息与 H1 模拟仍须分别对应。

```text
security_claim=none
backend_admitted=false
parameters_are_formal=false
nist_security_category=null
```

## 1. 一手来源与本页新增部分

一手参照为 Jiahui Liu、Hart Montgomery、Mark Zhandry，*Another Round of
Breaking and Making Quantum Money: How to Not Build It from Lattices, and
More*，[arXiv 2211.11994v2](https://arxiv.org/pdf/2211.11994v2)，2022-12-30。
本轮取得的 PDF 为 710070 B，SHA-256：

```text
c73f31e96ef46c095f60a11f697f11b6e3773b5d76b53daf1ba70e41f96a33e1
```

实际定向核读 §7.3 的 Problem 4、Theorem 5、Lemmas 6–7 及完整相关证明，
以及 Appendix B.1–B.4；没有声称全文核读。正文 Theorem 5 在该 PDF 第 22 页，
Appendix B 在第 43–47 页。LMZ22 给普通 SIS 在适当 plain-LWE 假设及
`q/(W*Sigma)=omega(sqrt(log lambda))` 下的 collapsing 结果。

原证明的粗粒测量分析使用随机内积的分布，例如 Lemma 6 的 `r·u` 和 Lemma 7
的两个内积。不能把这些逐项概率说明不加条件地搬到复合环上：零 syndrome、
相关的两个输入及非单位元素都需要检查。这里不据局部表述断言原定理错误；本页
完全绕开上述粗粒测量分析。Appendix B 的 scalar normal-form、modulus/dimension
switching 也不自动把独立标量矩阵变成 negacyclic block 分布。本页没有引用它们
来证明所需 Module-LWE 的困难性。

下文的 HNF 嵌入、相位通道界和 signed-polynomial 归约均为本次显式推导。
它们是条件数学结果，不是 LMZ22 已发表的环版定理，也不是新安全等级声明。

## 2. 实验、系数配对与明确的假设

令 `R_Z=Z[X]/(X^n+1)`，`R_Q=R_Z/QR_Z`，Q 为奇数，n 为本项目使用的二次幂。
本页的相位论证本身不要求 Q 为素数。设 d、r 为正整数，抽取

```text
U <- uniform R_Q^(d x r),        C_U=[I_d | U],
N=n(d+r),                       D={z in R_Z^(d+r): ||z||_2<=W},
g_U(z)=C_U*z modQ,              Q>2W.                         (1)
```

范数是 N 个整数系数的欧氏范数。输入使用规范整数系数编码。Q>2W 保证 D 中
不同输入仍是不同的模 Q 系数向量；本页不把可能相差 Q 的编码无偿合并。

对两个环向量，`<a,b>_coef` 表示对应系数的普通点积，取值再约简模 Q。定义
`a*=a(X^-1)`；在当前环中 `X^-1=-X^(n-1)`。矩阵的 `T^dagger` 是转置并逐项
应用 *。由乘法矩阵的系数转置关系，逐项展开可得

```text
<r,C_U*z>_coef = <C_U^dagger*r,z>_coef modQ,
C_U^dagger*r=(r,U^dagger*r),       U^dagger in R_Q^(r x d).     (2)
```

* 是系数的有符号置换和环上的双射，因此 uniform U 对应 uniform U^dagger。
这里没有任意子矩阵求逆或 determinant 非零即为单位的步骤。

固定标量离散 Gaussian `chi=D_(Z,Sigma)`，约定
`Pr[x=t] proportional to exp(-pi*t^2/Sigma^2)`。令 ν 是其**实际系数标准差**：

```text
nu^2 = sum_(t in Z) t^2 exp(-pi*t^2/Sigma^2)
       / sum_(t in Z) exp(-pi*t^2/Sigma^2).                    (3)
```

χ 关于 0 对称，均值为 0。ν 不能不经换算就写成 Gaussian width Sigma；特别
不能混用 `exp(-x^2/(2 sigma^2))` 的参数。下文先处理精确数学分布，实际 bounded
sampler 的误差在 §6 单独计费。

**NF-MLWE 假设实例。** 定义两个分布：

```text
M <- uniform R_Q^(r x d),
NF:   (M, v=M*s+e1 modQ),    s<-chi^(dn), e1<-chi^(rn),
RAND: (M, v<-uniform R_Q^r),
```

s、e1、M 相互独立；Gaussian 在整数系数上抽样，随后才模 Q。优势
`Adv_NF(D)=|Pr[D(NF)=1]-Pr[D(RAND)=1]|`。困难性须对所需量子时间及公开 oracle
访问预算成立。此处的 secret module rank 为 d，ring samples 为 r，系数维数
分别为 dn、rn。它不是已有 square-Ahat、CBD1、逐公钥列 hybrid 的同一个实例。

collapsing 游戏先给对手 C_U 及允许的公共辅助信息。第一阶段生成 Z 与任意
纠缠保留态；challenger 测量 D 成员标志，在接受分支计算并测量 g_U(Z)，保留
经典值 u；两世界分别保持 Z 或再在规范基测量 Z。拒绝分支在两世界采用同一
显式 bottom/拒绝流程，均不额外测量 Z。第二阶段输出一个 bit。

允许的 Aux 必须能仅从 C_U、公开随机性和与 NF challenge 独立的公共 oracle
模拟。setup 前 advice 独立于 M、s、e1、v；之后对手当然可以依赖 C_U。Aux 可
与攻击者保留态纠缠，但不能免费包含 challenge 秘密/误差、master trapdoor 或
目标用户密钥。若要扩展到 Extract/Sign 服务视图，须另给联合模拟与费用。
以下不对接受或某个 syndrome 条件化后重新归一化；全部失败质量均保留。

## 3. 两个精确通道引理

**引理 1（HNF normal-form 嵌入）。** 给定上述 `(M,v)`，令 `U=M^dagger`，
独立抽 `r0<-uniform R_Q^d`，并取

```text
b=(r0, M*r0+v) in R_Q^(d+r).                                 (4)
```

NF 世界中，令 `rbar=r0+s modQ`，则

```text
b=C_U^dagger*rbar+e modQ,       e=(-s,e1).                    (5)
```

rbar 是 uniform 且独立于完整 e：固定 s、e1、M 后，加上独立 uniform r0
仍得同一 uniform 分布。χ 的对称性使 -s 与 s 同 law，故 e 的 N 个系数恰好
独立服从 χ。RAND 世界中，给定 M，映射
`(r0,v)->(r0,M*r0+v)` 是双射，故 b 是整个系数模块上的 uniform，且独立于
M。两结论都是精确等式，没有 CRT 因子独立性或环单位条件。证毕。

对任意 b 定义公开可计算的对角相位

```text
P_b|z> = exp(2*pi*i*<b,z>_coef/Q)|z>.
```

相位仅在已经通过 D 检查的分支施加。由于 g_U(Z)=u 已测量并保留为经典值，
(2)、(5) 中 `C_U^dagger*rbar` 的相位在每个 u block 内是全局相位。因此 NF
世界在 Z 及全部辅助系统上的平均作用是

```text
L(rho)=E_(e<-chi^N) P_e*rho*P_e^dagger.                      (6)
```

不能在未测量 g_U(Z) 的任意叠加态上直接丢掉该相位。u 的任意分布、u=0、
aux 与 Z 的任意纠缠均不影响这个逐 block 结论。

**引理 2（uniform 相位就是规范基测量）。** RAND 世界的 uniform b 使

```text
E_b P_b |z><z'| P_b^dagger
 = |z><z'| * product_(j=1)^N E_(b_j<-Z_Q)
                         exp(2*pi*i*b_j*(z_j-z'_j)/Q)
 = indicator[z=z'] * |z><z'|,     z,z' in D.                 (7)
```

最后一步用有限循环群完整字符正交性和 Q>2W。只要某个系数差非零模 Q，其
字符平均即为 0；不要求该差是单位，也不要求两个环乘积内积独立。令此规范基
去相干通道为 P；在接受域上，uniform challenge 恰实现 P。在拒绝分支 L、P
均定义成恒等通道。已测量成员标志后无跨分支相干，故整体结论成立。证毕。

特别地，在完整游戏状态空间上

```text
P*L^j=L^j*P=P,                 j>=0.                       (8)
```

## 4. 对纠缠输入成立的相位扰动界

**引理 3。** 在 D 上，L 与恒等通道 I 的 diamond norm 距离满足

```text
||L-I||_diamond <= delta := 4*pi*nu*W/Q.                     (9)
```

证明：令 p_e 为 χ^N 的概率质量。在同一环境空间使用 Stinespring 等距嵌入

```text
V_L|z> = |z> sum_e sqrt(p_e) exp(2*pi*i*<e,z>/Q)|e>,
V_I|z> = |z> sum_e sqrt(p_e)|e>.
```

因不同 z 的第一寄存器正交，二者之差的算子范数平方是各 z 对应环境向量
距离平方的最大值。用 `|exp(it)-1|<=|t|`、独立零均值系数及实际方差 ν²：

```text
||V_L-V_I||_op^2
 <= max_(z in D) (2*pi/Q)^2 E_e <e,z>_coef^2
  = max_(z in D) (2*pi*nu/Q)^2 ||z||_2^2
 <= (2*pi*nu*W/Q)^2.
```

对附加任意辅助系统的纯态，两个等距输出态的 trace-norm 差不超过等距输出
向量距离的两倍；环境偏迹不增 trace norm。取输入上确界即得 (9)，混态由
凸性处理。拒绝分支两个嵌入取相同值，不增界。这里**没有额外 sqrt(N) 因子**：
方差直接是 `nu²*||z||²`，而不是先用各系数最大值再求和。证毕。

该引理只使用协方差 `nu² I`；本页仍把困难性假设固定为 §2 的 Gaussian
实例，未据方差相同就替换困难性假设。

## 5. Signed-polynomial 的可操作归约

**定理 4（条件 concrete reduction）。** 对 §2 实验中的任意 collapsing
区分器 A，任意整数 K>=1，存在一个执行 A 一次、只用一个 NF challenge 的
区分器 D_K，使

```text
Adv_col(A) <= (2^K-1)*Adv_NF(D_K) + delta^K.                 (10)
```

此处先允许精确的 nonzero-binomial 取样；下方给 j 选择严格有界的版本。D_K 还需
至多 K-1 个本地 χ^N 向量、K 次公开系数相位操作和原游戏的公开计算/模拟。
没有 K 份独立攻击者态，没有 cloning。

证明：固定 key、oracle、经典 hash 输出及全部保留寄存器，用 ρ 表示对手第一
阶段和 hash 测量后的状态，T 表示其最终 bit=1 的测量效应。后续对手计算和
公共 oracle 均可并入 T。令

```text
epsilon_signed = E Tr[T*(rho-P(rho))],
a_j = E Tr[T*(L^j(rho)-P(rho))],          1<=j<=K,
c_j = (-1)^(j+1)*binom(K,j),             S=2^K-1.
```

期望包含相同合法 key/Aux 和全部共同随机性，signed epsilon 的绝对值就是
Adv_col(A)。通道多项式和 `sum_j c_j=1` 给出

```text
sum_(j=1)^K c_j*a_j
 = epsilon_signed - E Tr[T*(I-L)^K(rho)].                   (11)
```

由 diamond norm 次乘性、(9)、`||T||_op<=1`、`||rho||_1=1`，余项绝对值至多
delta^K。这是对整个未后选实验的界。

D_K 以 `binom(K,j)/S` 的概率取 j，运行原对手至上述 ρ，用独立本地噪声
实施 j-1 次 L，再用 (4) 的 challenge 相位一次。NF 世界得到 L^j(ρ)；RAND
世界由 (8) 得到 P(ρ)。随后运行原第二阶段，若 c_j<0 则翻转输出 bit。
因此该 D_K 两世界的 signed 概率差恰为 `(sum_j c_j*a_j)/S`；由 (11) 及
三角不等式得到 (10)。取 j 的符号由 j 奇偶确定，不需知道 a_j 或 epsilon
的未知符号。证毕。

**j 选择严格有界的版本（其余仍为理想数学操作）。** 抽 K 个均匀 bit，令 j
为 Hamming weight。j=0 时不运行 A，输出固定 bit；其余 j 按上面构造并按奇偶
翻转。j=0 在两世界概率相同
且输出相同，故归一化分母改成 2^K，得到

```text
Adv_col(A) <= 2^K*Adv_NF(D_K^bin) + delta^K.                 (12)
```

此处只有 j 的分布精确且耗时有界；Gaussian、模 Q 均匀抽样及相位仍先采用
上述理想数学操作，完整 D_K^bin 尚未据此成为硬 PPT。若要 (10) 的分母，可
对全零 bitstring 重抽，期望尝试次数至多 2；但不能把该未截断拒绝抽样称作
硬 PPT。式 (12) 不需要 j 的拒绝重抽。

**渐近推论。** 另要求 χ 与模 Q 均匀源可在给定精度 κ 下以多项式
`poly(lambda,kappa)` 时间逼近、相位与全部公开模拟可在同一时间模型中逼近，
且能选择多项式精度使 §6 乘过 2^K 后的误差仍可忽略。若 NF-MLWE 对该
**实际有界实现**的预算量子 PPT 困难、其余模拟误差可忽略，
且对整个渐近 family 有 `delta<=delta0<1` 的固定常数界，则此 family 在本页
Aux 量词下 collapsing。证明用反设：若某 A 在无限多个 λ 有逆多项式优势，
根据该多项式选足够大的常数 c，取 `K=ceil(c log lambda)`，使余项小于该
优势的一半；2^K 仍为多项式，(12)、(14) 给 NF-MLWE 的非可忽略优势。若 delta=o(1)，
例如在明确方差对应下满足 LMZ 风格的渐近 gate，则 K=ceil(log lambda) 已使
delta^K 可忽略。不能在 delta 为固定常数时，把任意固定 c 对应的 delta^K
一律写成可忽略；也不能让 K 为多项式后忽略 2^K 的指数损失。

## 6. 数值 gate、运行量与近似实现的费用

有限目标余项 τ 及可信 `0<deltabar<1` 时，可取

```text
K=ceil(log(1/tau)/log(1/deltabar)).                           (13)
```

然后 separately 评估 (12) 中实际时间/查询预算下 NF 优势，再乘 2^K。若
deltabar>=1，增加 K 不能由本页界压低余项；不能人为填小余项。

冻结 n512 点为 `Q=13972913866395903`、
`Bsig=238255596480161099521436160`、`W=sqrt(Bsig)`，有整数证书
`905²*Bsig<=Q²<906²*Bsig`。其 C_U 是 `[I2|U]`，U 为 2x19 环矩阵；NF
challenge M 是 **19x2 环矩阵**，秘密有 1024 个系数，误差有 9728 个系数，
本地相位噪声向量有 10752 个系数。

纯条件算术例：**若**实际 ν<=8，则由 `pi<22/7`，

```text
delta <= 4*(22/7)*8/905 = 704/6335 < 1/8.
```

K=43 时余项小于 2^-129；若同一预算的 NF 优势再不超过 2^-172，则理想
式 (12) 的两项和小于 2^-128。这里的 ν<=8 与 NF 优势均是待满足前提，不是
本页选定/估计完成的正式参数，更不是 NIST category。K=43 的归约至多抽 42
个本地完整噪声向量；不能只估计一次 NF 核心操作而省略这些时间与 Aux/oracle
模拟时间。

旧 n2048/d3/b3/w22 点的 `Q/W≈2.0000078540`。若实际 ν>=1，则
`delta=4*pi*nu/(Q/W)>1`，故本页余项界不能认证它；这不是单独的攻击证明。
ν 更小的理论分布也不能仅凭此 gate 自动满足 NF-MLWE 困难性。

实际归约还要保留以下误差账本。令 ξ 为 actual target game 与本页理想
collapsing advantage 的联合模拟差；若在 NF/RAND 两世界，所实现的 D_K 输出
概率分别与上述精确 D_K 相差至多 η_NF、η_RAND，则

```text
Adv_col_actual <= xi
                  + 2^K*(Adv_NF(D_K_implemented)+eta_NF+eta_RAND)
                  + deltabar^K.                            (14)
```

这是直接三角不等式；不会把归约内误差忘记乘 2^K。每世界的 η 可由其实际
联合 sampler-TV、相位电路误差、公开辅助模拟和时间截断失败作顺序 hybrid
求和。例如每个本地完整噪声向量的 TV<=eta_vec、每次相位的 event-distance
误差<=eta_phase，则保守取
`eta_world<=(K-1)*eta_vec+K*eta_phase+eta_aux_world+eta_other_world`。
若只有标量 sampler 误差，完整向量还须按至多 N 个调用合成。

固定长度的整数范数、环运算、系数点积和精度给定的相位可用多项式可逆计算
与相位近似实现；本页没有交付这些量子电路。Gaussian 无限尾的精确数学分布
也不等于硬 PPT 采样器；需要选择尾界、采样精度、相位精度和硬运行上限，
并使乘过 2^K 后的误差满足目标。挑战实例本身的精确/近似分布应按所引用假设
固定，不能在假设中换分布而不计费。

## 7. 与真实 SRGG 矩阵及既有桥的关系

[collapsing-route.md](../2026-10-16-srgg-crt-review/collapsing-route.md)
已给出相同 Aux 量词下的 deterministic refinement、CRT 输出双射，以及真实
CBD1 公钥列到 uniform HNF 的双端 hybrid。若每端第 i 列优势分别界为 eps_i，
且本页新增 Gaussian NF-MLWE 的对应优势为 eps_NF，则**仅在那页和本页的
相同显式代数 key/Aux 模型中**可以代入

```text
Adv_col(f_real)
 <= 2*sum_i eps_i + 2^K*eps_NF + deltabar^K
    + separately charged joint simulation/implementation errors. (15)
```

两类 Module-LWE 不合并：前者是 shared square Ahat、CBD1 秘密/误差，负责
替换真实 Bpub；后者是 U^dagger 的非方形矩阵、Gaussian normal-form 秘密/
误差，负责 uniform HNF 的相位转换。不能只估计其中之一就给两项填同一个数。

此外依然需要：实际 seeded public 与显式 algebraic key 的联合 oracle 桥；
chosen identity 的 H1 值/目标相关性；提取各测量 hybrid 中其它身份密钥和
Sign transcript 的合法公共 Aux 模拟；setup/采样 abort 的未条件化质量；
新增 Gaussian NF 实例的具体困难性及总时间/查询预算。独立 seed 切片的
[预查询引理](seed-prehistory.md)只支付其明确的先验相关性，不能替代这些项。
本页也不把 ROM 的理想 oracle 模型误写成实际 SHAKE 的信息论结论。

因此，本轮取得的是一个无 HIBE 依赖、可审查的 uniform-ring-HNF **条件数学
归约**，以及可接入先前显式代数 hybrid 的准确位置。实际 SRGG 的 collapsing/
QCUR 数值、完整 QROM/native-strong 声明和正式参数准入仍未据此完成。

验证范围为上述逐步数学推导、由另一 agent 独立复核的 HNF 嵌入/diamond
界/signed 混合、已冻结整数点的精确 gate 证书、引用定位与本地链接/格式检查。
没有新运行量子硬件、量子模拟器、Gaussian 样本实验或生产后端测试。
