# SRGG 原生 SIG：混合密钥下的交互 HVZK、挑战商与条件归约

日期：2026-10-16。本文保留 native strong 目标，证明**固定真实密钥下、独立均匀交互挑战的完整 transcript 分布界**，并给现有 n512 点的精确算术证书。它没有把该分布自动认作 Fiat–Shamir 签名分布，没有闭合 UF-NMA、CUR 的实际困难假设或 QROM 归约。冻结的算法、公开参数、采样器、密钥选择和 n512 收据均未改变；`security_claim=none, backend_admitted=false, parameters_are_formal=false`。

来源：SRGG 原文 [DOI 10.1049/ise2/6684889](https://doi.org/10.1049/ise2/6684889)，本地 `papers/2025_efficient_ibs_jia.pdf`，SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。本阶段定向核对 p.4 Theorem 1、p.8 Algorithms 7/8；Theorem 1 只声明 EUF-CMA，不是完整 native strong 定理。以下完成平方、Poisson 与概率界是本项目给出的条件推导，不假称原文已证明任意混合密钥版本。KLS2018 定向原文范围与精确游戏见 [strong-games.md](strong-games.md) §1/8；本项不声称重证 KLS 或其 full version。

## 1. 真实密钥、系数空间和 ζ 的像格

令 `n=2h` 为二的幂，`R=Z[X]/(X^n+1)`，`m=(2+w)d`，用户密钥 `y in R^m`，满足 `Ay=H1(id) mod Q`。令 `N=mn,D=(m+1)n,H=dn`。所有范数均为整数系数空间欧氏范数；Gaussian 的密度形状约定为 `rho_C(x)=exp(-pi*x^T*C^-1*x)`，C 是 squared shape，不是直接写入连续 normal 库的协方差。

`M(y)` 为按列叠放的多项式乘法算子，`T=[M(y);I_n]` 为 `D by n` 整数矩阵。记 `Z=M(zeta)`，`zeta=1+X^h`；`Z^T=M(zeta*)`，`zeta*=1-X^h`。有

```text
Z^T Z = Z Z^T = 2I_n.
Z(a,b) = (a-b,a+b),  a,b in Z^h.
L_zeta = Z Z^n = {v: v_i = v_(i+h) mod 2 for all i<h}.
det(L_zeta) = [Z^n:L_zeta] = 2^(n/2).
```

最后一个格是 `sqrt(2)` 乘一个正交变换后的 `Z^n`。因此其对偶的最短长度平方为 `1/2`；后面 C-normalizer 的有效 smoothing 形状是 **`lambda_min(C)/2`**，不能漏掉这个 ζ 因子。

记 `j=(zeta*,0,...,0)`，`M=Abar_h=[2A,Qj-2H1(id)] mod 2Q`；在系数空间把 `Z^T` 嵌入首个输出环的算子记作 J。密钥关系给

```text
M T = Q J mod 2Q,
J Z = 2 * (first-output-ring embedding).
```

因此 `MTZu=0 mod 2Q`，正是诚实响应恢复承诺所用的恒等式。这些结论对每个满足密钥关系的 y 成立，不要求 y 是零中心 Gaussian。混合密钥 law 必须单独满足所声明的发钥分布与坏密钥界，不能因逐密钥代数成立而略去。

## 2. 一个理想交互签名的精确联合 law

固定公开参数、A、目标、y，令 `nu=2r^2`，公开目标形状为 `Sigma`，且

```text
S = Sigma - nu*T*T^T > 0.
```

理想交互算法为：

```text
P <- D_(Z^D),S;
W = MP mod 2Q;
c uniform in {0,1}^n, independently of P;
u <- D_(Z^n),r^2,-Z^T*c/2;
v = Zu+c;                 z = P+Tv.
```

真实 FS 执行器在第二步之后取 `c=H2(W,message)`，并不使用这里独立的 c；这个区别在 §5 保留。

映射 `u -> v` 是 `Z^n -> c+L_zeta` 的双射，而且

```text
||u+Z^T*c/2||^2 / r^2 = ||v||^2 / nu.
```

所以条件于 c，v 的**归一化离散** law 恰为

```text
Pr[v|c] = rho_(nu I)(v) / Z_c, v in c+L_zeta,
Z_c = rho_(nu I)(c+L_zeta).
```

这一步没有连续 Jacobian；`det(L_zeta)` 进入后面的 Poisson 常数。不能将 `Z_c` 偷换成不依赖 c 的常数。

对任意 `z in Z^D`，逐个 v 唯一确定 `P=z-Tv`。定义

```text
C = (nu^-1 I + T^T*S^-1*T)^-1
  = nu I - nu^2*T^T*Sigma^-1*T > 0,
a_z = C*T^T*S^-1*z = nu*T^T*Sigma^-1*z,
Theta_C(c-a_z) = sum_(v in c+L_zeta) rho_C(v-a_z).
```

Woodbury 与展开二次式给出精确等式：

```text
(z-Tv)^T*S^-1*(z-Tv)+||v||^2/nu
 = z^T*Sigma^-1*z+(v-a_z)^T*C^-1*(v-a_z).
```

因而未施范数门的响应 law 为

```text
Pr[z|c] = rho_Sigma(z)*Theta_C(c-a_z)
          / (rho_S(Z^D)*Z_c).                       (1)
```

不能只读式 (1) 的指数而认定 z 是 Gaussian：`Theta_C` 依赖 z。对 z 求和并使用概率归一化，得到

```text
rho_S(Z^D)*Z_c
 = rho_Sigma(Z^D)*E_(Z0~D_(Z^D),Sigma)[Theta_C(c-a_Z0)].
```

于是**所有** `rho_S`、`Z_c`、目标 Gaussian 常数恰好消去为

```text
Pr[z|c] = D_(Z^D),Sigma(z)
          * Theta_C(c-a_z)/E_(Z0~D_Sigma)[Theta_C(c-a_Z0)].    (2)
```

这不是假定不同 challenge coset 的 normalizer 相等。它是针对每个固定 c 的条件归一化恒等式，对非整数中心与所有 coset 都有效。

## 3. 从 Poisson 得到完整 HVZK 联合分布界

令 `K_C=sqrt(det(C))/det(L_zeta)`。Poisson 求和给

```text
|Theta_C(t)/K_C - 1|
 <= sum_(xi in L_zeta^*, xi!=0) exp(-pi*xi^T*C*xi)
 <= (1+2*sum_(k>=1) exp(-pi*(c_min/2)*k^2))^n-1
 =: epsilon_C,
```

其中 `C>=c_min I`，界对所有实中心 t 同时成立。若 `epsilon_C<1`，式 (2) 中的分子/期望比落入

```text
[(1-epsilon_C)/(1+epsilon_C), (1+epsilon_C)/(1-epsilon_C)].
```

因此每个固定 c 都有保守的充分界

```text
TV(law(z|c),D_(Z^D),Sigma) <= epsilon_C/(1-epsilon_C) =: delta_zk.
```

构造公开 simulator：独立取 `c uniform {0,1}^n` 和 `z~D_(Z^D),Sigma`，再令 `W=Mz-QJc mod2Q`。诚实算法也满足此恢复式，因此对同一个确定映射应用数据处理得到

```text
TV(law(W,c,z)_interactive_real, law(W,c,z)_Sim) <= delta_zk.   (3)
```

式 (3) 比响应 marginal 更强：它包含 c、W 及二者与 z 的相关性。对每个准入 y 均成立时，可以对任意同一真实密钥分布取平均；若仅在 GoodKey 上成立，则须另付坏密钥事件。这里 simulator 只使用公开 Sigma、M，不读取 y 或陷门。

**带范数门的完整 transcript。** 定义共同映射：`||z||^2<=Bsig` 时保留 `(W,c,z)`，否则将整个三元组替换为 `(bottom,bottom,bottom)`。式 (3) 的 TV 不增，不能只将失败的 z 置空而保留另两个字段。Sim 中 c 与 z 独立，且门只读 z，因此它的 c 在成功条件下仍严格均匀。这对应 KLS Definition 2.5 要求比较的联合 Trans 和 `c|c!=bottom` 条件；不是以 normtail 代替 HVZK。

也可保留无门 Sim：真实 gate 与无门真实 law 的距离恰为该 gate 的拒绝率 eta，三角不等式给距离至多 `delta_zk+eta`；Sim 极少量超范数输出必须算进该误差，不能声称它始终产生有效签名。若选成功条件化的 Sim，则须另核采样成本及条件化损失。本文没有据此直接宣称 KLS 的全部 no-abort/算法接口前提已满足。

## 4. 当前 n512 点：全类阻塞与高概率 GoodKey 界

读取冻结 `srgg-bridge/integrated-bridge.json` 的 `query-bounded-deep`，不是重新采样或换参数：

```text
n=512,d=2,w=8,p=16383,b=31,r^2=64,nu=128,L=16,
s = signature_squared = 22159188660729268928705,
U = user_norm_cap = 338122385570209792,
master_squared = 1031865954433,
raw_norm_cap = 169060917974302720.
```

目标 `Sigma=s I`。实系数 negacyclic Parseval 给 `||T||^2<=1+(n/2)||y||^2`；该公共范数界已用于冻结签名采样计划。故在 `||y||^2<=u` 时

```text
beta(u)=1+(n/2)*u,
c_min(u)=nu*(s-nu*beta(u))/s.
```

下列数字用 `native_sig.py` 的有理数 π 下界、定向 `exp(-x)` 上界和 outward dyadic rounding 计算。没有浮点 FFT、私钥实际范数统计或数值拟合；2^-256 的 transport floor 显式保留。

| 分析类别 | `c_min/2` | `epsilon_C` 充分上界 | `delta_zk` 充分上界 | `2^40 * L * delta_zk` |
|---|---|---|---|---|
| 全允许密钥 `u=U` | `32-2016/s` | `2593797304823843752149562878744176946 / 2^256` | `2593797304823843752149562878744176947 / 2^256`，约 `2^-135.0355` | 约 `2^-91.0355` |
| 分析事件 `u=U/4` | `1240914565000839060000832/s`，略小于 56 | `4666/2^256` | `4667/2^256`，约 `2^-243.8117` | 约 `2^-199.8117` |

全类上界在这里未通过 `2^-128` 的长期统计目标。这是**该充分界不足**，不是证明真实 HVZK 距离一定大，也不是安全攻击。不能拿旧 finite-sampling TV 取代新项来报告通过。

为消除此最坏界的松弛，可以分析

```text
GoodKey(y) = {y != bottom and ||y||^2 <= U/4}.
```

这只是证明事件，运行时既不检查它，也不据它挑根、重发钥或改变失败策略。由已证 mixed-domain/HNF 恒等式，理想单目标 raw vector V 服从公开 Gaussian 限制在相应近似逆像 union 的 law，且修复输出 Y 满足

```text
||Y||^2 <= 2||V||^2+2H(p-1)^2.
```

因此 `||Y||^2>U/4` 蕴含

```text
||V||^2 > (U/4-2H(p-1)^2)/2 = 42265023385474048.
```

`psf_bridge.norm_tail_upper` 在已经核实的 uniform union/coset smoothing 前提下，给这个 raw threshold 的每目标理想 tail `delta_bad<=2^-256`，选择 `t=1/16`。输出范数门只会删掉更多坏 key，故同界适用于保留 bottom 的理想发钥 law 中的坏成功输出。

冻结 deep 包给出整次发钥到同一 public-output-norm-gated 参考的

```text
delta_key = 345730044353416620273573 / 2^256,
```

其中保留 sampler、raw gate、HNF 和 abort。因坏成功输出是完整 law 上的一个事件，实际每次发钥满足

```text
Pr[issued nonabort key and not GoodKey] <= delta_key+delta_bad
 = 345730044353416620273574 / 2^256, 约 2^-177.8060.
```

若只报告返回成功条件下的概率，须再除真实成功下界；工具另给此字段，主账本不先删除 bottom。同一密钥反复签名不应再次支付发钥坏事件；自适应发钥由 uniform-per-history 界按**实际计入的不同发钥执行数**并集。若服务窗口开始前已经发过相关密钥，其最初生成也必须计入归约的总 key count，不能记成零成本。

一条避免双计的**条件统计**拼接是：先按每次发钥付 `delta_key` 换成理想参考，再按每个理想发钥付 `delta_bad` 标记 GoodKey，最后对各签名尝试使用 GoodKey 内的逐调用界。若发钥/签名 histories 已在单独的正确 simulator 中配对，则其算术上界为

```text
q_E*(delta_key+delta_bad)
 + q_S*L*(delta_finite_sign+delta_zk_good+eta_sign),            (4)
delta_finite_sign = 211293825113957804024819 / 2^256,
eta_sign <= 2 / 2^256.
```

`q_E=q_S=2^40,L=16` 时式 (4) 的上界为

```text
3726431246176741484745382 / 2^216, 约 2^-134.3759 < 2^-128.
```

这只闭合所列互动分布/采样/范数项的**条件算术**。它未计算 KLS 的 `kappa_m` 等安全归约放大、oracle 编程/预查询损失、UF-NMA/CUR 优势、实际 MLWE/MSIS 困难性或基础设施/全服务运行 cap 的概率，故不是 128-bit 安全证书、已证 FS transcript 距离或 `2^40` 次服务实测容量。

## 5. 交互挑战与 Fiat–Shamir 挑战不能直接混同

在 §2 的交互 law 中，`P -> W` 后仍取 fresh independent uniform c。在冻结 FS 实现中，c 为某个已固定或已查询的 `H2(W,message)`。不能将 §3 当成对任意自适应挑战函数都 uniform 的证明，再以数据处理直接替换真实签名。交互 law 条件到一个预定 challenge 函数的图上，通用条件化代价可能达到 `2^n`。

从 Sim transcript 产生 FS 签名需要在 `H2(W,message)` 编程 c、处理已查询承诺和重复点、范数重试及保留的失败；QROM 还需其相干 oracle 与测量/改编定理。KLS2018 Theorem 3.3 是潜在的已发表桥，其输入还包括 commitment min-entropy、UF-NMA、CUR 等；本文没有将式 (3) 单独当作该定理所有条件的结论。

对诚实执行，冻结有限 sampler 的 uniform-center TV 与自适应 normtail 仍可分别使用：它们比较每个真实调用的条件采样 law，不要求 challenge 预先独立。**这和用独立交互挑战证明 FS signing simulation 是两件事。** 每次最多 L 次 norm-retry 的组合须先给正确逐历史 hybrid；其余数值/熵异常立即中止的策略不能改成悄悄重抽。式 (4) 只规定正确 hybrid 一旦建立后这些项如何累计。

## 6. 承诺 min-entropy 的条件充分界

KLS 的 alpha 指 `P1` 输出 W 的 min-entropy，不是 key entropy 或响应 entropy。这里给一个不使用实际密钥范数的充分界；它尚不自动完成 seeded-public-matrix 或 FS 编程前提。

设全允许密钥类均有 `ell I<=S<=s I`。将 P 分为 A 的首个 identity-head 的 H 个系数 `P0` 和其余 `Ptail`。分块写 S 后，条件于任意固定整数 `Ptail=t`，完成头部平方得到 `P0~D_(Z^H),S0,a(t)`，其中

```text
S0 = S00-S01*S11^-1*S10,
S0^-1 = (S^-1)00.
```

由 `s^-1 I<=S^-1<=ell^-1 I`，取主子块保持 Loewner 次序，再取逆，严格得 `ell I<=S0<=s I`；所以结论不要求头尾坐标独立，也不要求条件中心 a(t) 是整数。M 的这 H 列是 `2I mod2Q`：给定 tail 和 W，若 `2P0=W-Mtail*t mod2Q` 一致，其解恰是一个 `QZ^H` coset；不一致则概率为零。

若 `S0` 的 Z^H all-center Poisson relative error 至多 `eps_head<1`，其分母至少 `(1-eps_head)*sqrt(det S0)`。逐点比较 `rho_S0<=rho_(s I)`，再用一维 Gaussian 的 `peak+integral/Q` 求和界，得

```text
max_W Pr[W | Ptail]
 <= (1+sqrt(s)/Q)^H / ((1-eps_head)*ell^(H/2)).
```

对 tail 平均保持此界，故

```text
alpha >= (H/2)*log2(ell)-H*log2(1+sqrt(s)/Q)+log2(1-eps_head).
```

这里的格点和界可直接证明：对任意实 t，一维 `exp(-pi*x^2/s)` 在峰的两侧单调，除了跨峰的一项至多 1，其余矩形分别由间距 Q 的积分包住，故 `sum_k exp(-pi*(Qk+t)^2/s)<=1+sqrt(s)/Q`。H 维 isotropic majorant 是它们的乘积。分母仍是实际相关 `S0` 的 Poisson 下界，不能替换成连续密度峰值。

现有 full-cap 给

```text
ell = s-nu*beta(U) = 11079594330364634464321,
H=1024, floor(log2 ell)=73,
ceil(sqrt(s))=148859627370<Q,
eps_head <= 2^-256 < 1/2.
```

这里 head 的格是 Z^H，Poisson majorant 用 ell 本身，不能再次引入 ζ 的 `/2`。保守用 `1+sqrt(s)/Q<=2`、`1/(1-eps_head)<=2` 得

```text
max_W Pr[W] <= 2^(H+1-73*H/2) = 2^-36351,
alpha_ideal >= 36351.
```

该界对每个满足 full-cap 形状条件的 key 成立，在这个已声明 class 内 keygen exception 为零；不靠 GoodKey 的例外概率来冒充 `2^-alpha`。它没有核准原文的完整 keygen/IGen 对应。有限 sampler 会带来 additive TV；先在**整场**实验中支付已证逐调用/完整法则的 TV，再对理想 P1 使用 alpha，不能原封不动地给有限实现同一个巨大 alpha，也不能把有限采样 TV 在 `q_H` 个 commitment 点上另行重复放大。key entropy 的现有 aliases 证书不承担这一项。是否有正确整场 hybrid，仍受 §5 的 FS/QROM 模拟义务限制。

## 7. ζ 商挑战、CUR 与 UF-NMA 的最小正确关系

[strong-games.md](strong-games.md) 给出完整 ordinary/strong 游戏和独立反例，这里只列对 SIG 归约必要的关系。写 `c=a+X^h b`，定义 `eta(c)=a XOR b`。`Qjc mod2Q` 只依赖 eta，因此挑战有效商空间大小为 `2^(n/2)`，每个 fiber 有 `2^(n/2)` 个完整 binary c。

明确反例：`c=0,c'=1+X^h,z=z'=0,W=0` 均满足识别关系，因为 `zeta_adjoint*c'=2`。所以**不同完整 c 不保证 fork 的响应差非零**。这不表示固定同一 FS hash 点同时返回了两个挑战，也不能据此直接改写成同消息伪造。

对固定零响应和零承诺，每次独立理想经典 RO 消息查询恰以 `2^(-n/2)` 落入 `eta(c)=0`，从而产生有效签名。这个公开 NMA 搜索负控必须保留；本项没有执行 n512 搜索，也没有据它宣称某个量子搜索安全等级。

同一承诺的两有效识别 transcript 给 `Delta=z-z'`，有

```text
[A,-hID] Delta = 0 mod Q,
||Delta||_2 <= 2*sqrt(Bsig).
```

同 c 的 CUR pair 由 `z!=z'` 自带 Delta 非零；不同 c 的 fork 则须保证 `eta(c)!=eta(c')` 才能从关系推出 Delta 非零。`Q>2sqrt(Bsig)` 只排除非零 Delta 全为 Q 倍数的平凡类，既不是 CUR 也不是 UF-NMA 的困难性证明。

**一个最小经典 fork 引理。** 固定重放 prefix 和指定的 fresh-hash 位置，令成功且挑战商为 b 的概率质量是 `alpha_b`，总成功质量 `a=sum_b alpha_b`。因为商挑战均匀且每类质量至多 `2^(-n/2)`，两个独立 suffix 的成功且商不同概率为

```text
a^2-sum_b alpha_b^2 >= a^2-2^(-n/2)*a.
```

这只证明指定位置、正确独立重放条件下的局部计数式；攻击者 query-position 猜测、其它 oracle 的一致性、经典全程 forking 及 QROM extraction 损失仍须另证。不能将右式直接贴成任意实际对手的 UF-NMA 优势。

**从真实矩阵到 HNF-MSIS 的硬前提。** CUR 或非零 fork 首先给的是实际 `[I,Ahat,Bpub,-hID]` 的短核。KLS §4.5 的 HNF-MSIS 明确定义了 `[I|U]`，可直接用这一形式作目标，无须擅自引入首块求逆成功率；实际欧氏短向量同时满足相同门限的 coefficient-infinity 约束。但它不自动是均匀 U：

- `Bpub=pG-R0-Ahat*R1 modQ`，各列的 CBD1 secret/error 使用同一 Ahat。替换 Bpub 为独立均匀列需要明确的同 Ahat、多样本 decisional Module-LWE hybrid，最多 `wd` 列的代价；真实 Q 为复合奇数、噪声 CBD1，须按该分布假设和估计，不能借 Kyber 的参数声明。
- hID 必须由真正适用的 mixed-domain image/keygen 证明换为独立均匀目标，包含目标范数门与失败；逐像近均匀不自动给完整 oracle 实验。
- 冻结实现的 Ahat 是**公开 seed + SHAKE/XOF 展开**，公开对象可重算一致性。普通 MLWE/MSIS 挑战直接给显式均匀矩阵，reduction 不能凭空找到使该矩阵展开的 seed。必须显式采用 seeded distribution 的困难假设，或证明 matrix oracle 可编程嵌入且给出预查询/seed 猜测损失；QROM 下还要核其量子接口。单纯“输出看似均匀”不提供这个嵌入。

这些前提满足之后才有条件的 hardness reduction；本项没有把它们列为已经成立的新困难性假设或安全定理。与最终 IBS 的目标 Sign 转发和跨身份新鲜性还须对接 [target-signing.md](target-signing.md)，不能只证明底层识别差分后跳过这一层。

## 8. 工具、复现和交付边界

新增 `experiments/research/candidates/srgg/native_sig.py` 只做 exact rational 数学证书，输入为冻结 integrated bridge 收据（SHA-256 `23534aec4f2a5d208d083e5830001318c072c6c4af157d6d3c27cc73b934033e`）。它将旧证书的 uniform hypotheses 作为明确前提读取，不重跑采样、不重新认证其 theorem correspondence。若输入变化，报告记录新哈希，不能继续沿用本文旧数值。输出另记录本工具、`fiber_normalizers.py` 和 `psf_bridge.py` 的源码 SHA-256；本轮工具哈希 `a0791f0a3c483902f38baf0897e6a77620ea22429ca15e708807edb3f97d55ae`。relative normalizer error 不是概率：充分几何级数失效时该字段为 null；可用但大于 1 时保留原界，不能封顶为 1 再宣称它是上界。

```text
python -m experiments.research.candidates.srgg.native_sig --output build/outputs/srgg-reduction-2026-10-16/native-sig.json
python -m pytest -q tests/test_srgg_native_sig.py --junitxml=build/outputs/srgg-reduction-2026-10-16/native-sig.junit.xml
```

本轮定向测试 **28 passed**，Python 3.14.7 / Windows 11 10.0.26200，无新依赖、无随机字节、无新身份/消息或密码学实例。测试覆盖 ζ 的 dual scale、有限 theta-majorant 包络、错误/奇异形状拒绝、有限归一化 tilt 的 joint-TV/完整 bottom 映射、发钥和签名计数边界、full-cap 不足与 GoodKey 算术、相关 head 的 Schur 界/整数承诺熵，以及失去正 HNF threshold 或非平凡 normalizer 时返回 vacuous 界。测试检查数学工具和有限模型，不能代替上述一般推导、安全归约或困难性估计。

本项完成：精确交互 joint law、全部归一化常数处理、ζ coset smoothing、高概率 GoodKey 与其条件统计账本。尚未完成：实际 seeded 矩阵困难性桥、完整 UF-NMA/CUR 安全结论、FS/QROM 的编程/查询损失、KLS 全部适用性及完整 IBS strong 归约、正式安全参数或 NIST 等级。未引入 HIBE 选择或任何依赖 HIBE 的接口变更。
