# SRGG 参考分布桥梁的独立数学与代码审查

日期：2026-10-16。审查对象：[psf_bridge.py](../../../../experiments/research/candidates/srgg/psf_bridge.py)、[对应测试](../../../../tests/test_srgg_psf_bridge.py)。采用固定公开参数、系数空间欧氏范数与 `rho_Sigma(x)=exp(-pi x^T Sigma^-1 x)`。本项检查参考分布、正规化和完整输出 law 的条件性数学界；没有运行新密码学实例、没有宣称 source PSF 或强不可伪造归约已经适用。

结论：完整核格基的构造成立；原 raw 列长上界合法但过松，已改用基顺序带来的更紧 GSO 上界。GSO 到 smoothing、Hellinger 移位、head wrap、norm-Markov 与包含 abort 的 triangle 传播在下述假设下成立。另明确区分共同 HNF／范数门的公开直接参考与不 abort 的 exact-fiber 高斯参考；二者不可混用。

## 1. 构造的是完整 q-ary kernel

令 `k=dn,m=wdn,N=2k+m`，系数矩阵满足

```text
A=[I_k,Ahat,B], T=[R;I_m], AT=F mod Q,
F=p[I,bI,...,b^(w-1)I], Q=p*b^w.
```

使用整系数酉模变换 `U=[[I_(2k),R],[0,I_m]]`，则 `AU=[I,Ahat,F] mod Q`。对变换前坐标 `(x_head,x_middle,z)`，构造三组列：

1. gadget：每个系数 fiber 的 `b e_i-e_(i+1)`，以及末列 `b e_last`；它们组成 `B_g`，`det B_g=b^m`。
2. head：`x_head=p e_j,z=-e_firstdigit(j)`，其 `[I,Ahat,F]` 像为零。
3. middle：`x_middle=e_j`，各 head 坐标取 `-Ahat e_j mod p` 的居中代表，再用平衡 b 进制给剩余的 p 倍数作 gadget lift。每个 digit 的绝对值至多 `(b-1)/2`，最后只须模 `b^w` 等式，不要求最终 carry 为零。

代码对变换后的每一列重新核验 `A v=0 mod Q`。重排块后的基矩阵对角块为 `I_k,p I_k,B_g`，所以绝对行列式

```text
p^k b^m = (p*b^w)^k = Q^k.
```

A 的首块是 I，故映射到 `(Z/QZ)^k` 满射，完整 kernel 的指数也恰为 `Q^k`。这就证明所得子格等于完整核格，而非 gadget kernel 的秩亏嵌入。这里不需要 p 与 b 互素。

`exact_kernel_basis` 仅用于小尺寸公开测试 fixture；返回的列可能暴露输入陷门，不得从真实服务密钥导出。正式大维度报告只使用符号基构造及公开支持类界。

## 2. 基顺序显著收紧 GSO

`exact_kernel_basis` 的实际顺序是：全部 gadget、全部 head、全部 middle。gadget 列为 `T B_g`；`B_g` 可逆，所以前 m 列张成 `im(T)`。若 `||T||_2^2<=beta`，其原始列长平方不超过 `beta*(b^2+1)`。

head 列变换后是 `p e_head - T e_digit`。投影掉之前全部 gadget 的张成空间后，T 项消失，余向量长度至多 p；再投影已有 head 只会缩短。因此所有 head 的 GSO 长度平方至多 `p^2`。

加入全部 head 后，前序空间包含 `im(T)+span(e_head)`。middle 列是 `e_middle+head+Tz`，后两项已在该空间中，所以其 GSO 长度至多 1。由此

```text
max_i ||b_i^*||^2 <= max(beta*(b^2+1), p^2, 1).
```

旧代码取最大 raw 列长是有效上界，但 middle 的大 lift 抹掉了这个重要顺序结构。代码现在分别报告 raw 列界和 ordered GSO 界，并拒绝 `beta<1`：由于 T 的底块为 I，这种输入不可能是真实 T 的上界。

新增测试对 rank1、rank2 以及不同 n/w 的 fixture，精确核验分阶段 GSO 界及 GSO 范数乘积 `Q^(2k)`。原有极小基还直接核验行列式和所有 kernel 方程。

## 3. GSO 到全中心 smoothing 的合法性

令 `Lambda=ker(A mod Q)`，`s_min=min(first_squared,second_squared)`，g 为上节 GSO 平方上界。对线性变换 `L=Sigma^-1/2`，每一步 GSO 是到前序子空间的距离，故

```text
dist(L b_i, L span(b_1,...,b_(i-1)))
 <= ||L|| dist(b_i,span(b_1,...,b_(i-1)))
 <= sqrt(g/s_min).
```

这一步不要求原基正交，也不把 raw 列长误当作必须的 GSO 长度。对变换后的完整格 `L Lambda`，沿 GSO 坐标由外向内求整数高斯和：每个一维 coset normalizer 的宽度至少 `sqrt(s_min/g)`，其相对误差至多相同标量 theta 尾界 t。于是

```text
rho_I(L Lambda) <= det(L Lambda)^-1 * (1+t)^N.
```

零中心 Poisson 等式给

```text
rho_I((L Lambda)^*)-1 <= (1+t)^N-1.
```

再对任意平移使用 Poisson 及三角不等式，得到所有实中心下共同常数 `K=sqrt(det Sigma)/det Lambda` 的界

```text
(1-epsilon) K <= rho_Sigma(Lambda+c) <= (1+epsilon) K.
```

`smoothing_certificate(N,floor(s_min/g),80)` 使用 `pi>2 log2` 和几何级数给 `(1+t)^N-1` 的精确有理充分上界，参数向下取整且封顶 512；这只会放松证书。证书对象是完整 coefficient kernel，不能仅拿 gadget 的正规化证书替代。

既有 n512 d2/3/4 的公开 CBD1 bound 在精化后分别有 GSO 平方上界 `16139682754,36314284994,64558728130`，归一化整数形状均为 63。全 coset 相对误差上界约 `2.4074e-34,3.6111e-34,4.8148e-34`。这与 [convolution.md](convolution.md) 中旧 master 余量导致的 C 下界失败是两项独立条件，不能互相替代。

## 4. exact-fiber 高斯旁路：正规化、移位与 wrap

明确参考为

```text
Q_h = D_(Z^N,Sigma) conditioned on AY=h mod Q.
```

它是给定公开 A、Sigma、h 后定义的 law；代码尚未证明它就是 SRGG 原文安全定理所采用的 PSF conditional law。近似并集高斯按 `e=h-AU mod Q in {0,...,p-1}^k` 分解；每个分量归一化后是 `Lambda+h-e` 上的高斯。修复 `Y=U+J e` 后，它在同一个 exact fiber 上的密度是中心为 `J e` 的高斯，各分量权重保留。不能把这些平移直接删掉。

设 `delta=J e`，`d2=delta^T Sigma^-1 delta<=k(p-1)^2/first_squared`。与 Q_h 的 Hellinger affinity 精确为

```text
affinity = exp(-pi*d2/4) * Z_(delta/2)/sqrt(Z_delta Z_0),
```

其中三个 Z 是同一个完整核格不同实中心的正规化量。因此共同 smoothing 界给

```text
affinity >= exp(-pi*d2/4)*(1-epsilon)/(1+epsilon),
TV^2 <= 1-affinity^2 <= (pi/2)*d2 + 4epsilon/(1+epsilon)^2
                         <= 2*d2+4epsilon.
```

最后取概率范围内的平方根向上有理包络。对所有 e 都有同一界，所以按实际分量权重作混合仍满足它；没有假定 e 均匀，也没有漏掉三个正规化量。

HNF 对 raw U 的 tail 解码，等同于对修复后 Y 的同一 tail 解码。把同一 decoder 应用于两边是收缩映射，因此先得到 decoded-reference 比较。若再比较不做 head recenter 的完整 Q_h，则须加入 Q_h 自身的 head-wrap 概率。

对头部任一坐标，完整 coset 高斯的 Chernoff 界为

```text
Pr[|Y_i|>=a] <= 2*(1+epsilon)/(1-epsilon) * exp(-pi*a^2/first_squared).
```

其 mgf 的完成平方同样保留全中心 normalizer 比例。取 `a=Q/2` 并对 k 个坐标联合界，代码用更松但有效的 `2^-floor(Q^2/(2*first_squared))` 包络指数项。Q 为奇数时实际非居中整数点绝对值至少 `(Q+1)/2`，所以使用 Q/2 保守。加入 wrap 后才能与完整 Q_h 比较。

现有 n512 d2/3/4 的移位 TV 上界仍约 `0.7298,0.5959,0.5161`。这说明当前保守 exact-reference 旁路界很松，并不证明实际分布差异有这么大，也不能宣称该差异已可忽略。

## 5. 范数拒绝与 abort 不能悄悄条件化

对 exact coset 或有限多个近似 coset 的并集，形状放大为 `Sigma/(1-t)` 不会破坏原 smoothing 充分条件。每个 coset 的原始／放大正规化量之比至多

```text
(1+epsilon)/(1-epsilon) * (1-t)^(-N/2).
```

同一界可对并集逐项相加，不能因为已经条件于某个 coset 就直接使用连续高斯尾。由 `||Y||^2/s_max<=Y^T Sigma^-1Y`，Markov 给

```text
Pr[||Y||^2>C] <= (1+epsilon)/(1-epsilon) * (1-t)^(-N/2)
                    * exp(-pi*t*C/s_max).
```

代码对 `t=j/16,j=1,...,15` 取最小上界，以 `pi>4log2` 包络指数；全部 N 均为偶数，故幂次精确有理。极小正概率向上包络不会静默下溢为零。

HNF 的一般范数界给 `||HNF(U)||^2<=2||U||^2+2k(p-1)^2`，因此 raw cap `C_user/2-k(p-1)^2` 为正时，raw 并集高斯的相应 norm tail 上界可作为 HNF norm 拒绝的上界。

`complete_key_comparison` 的 exact-reference 旁路以 **decoded full witness 加 abort 符号**为共同样本空间。若有限实现到理想 raw sampler 的完整 law TV 已含 sampler abort，raw 到并集参考的 TV 也已给出，则先加 raw、shift、wrap 三步，得到过滤前上界 epsilon_pre。令同一个 norm gate 把不合格输出映射为 abort：

```text
TV(G#P, Q_h) <= TV(G#P,G#Q_h) + TV(G#Q_h,Q_h)
             <= epsilon_pre + Pr_Qh[norm reject].
```

这不是成功发钥后的条件 law。新增三点精确反例测试取 `Q=(0.9,0.1,0)`、`P=(0.85,0.1,0.05_abort)`，拒绝第二点后恰有 TV 到不 abort 的 Q 为 `0.15=0.05+0.10`；到共同过滤的 GQ 则只有 0.05。该例核对了参考范数拒绝与已有 sampler abort 的不同作用。

## 6. 公开直接参考与 source PSF 之间仍有边界

可另外定义

```text
Q_union,h = D_(Z^N,Sigma) conditioned on h-AX mod Q in {0,...,p-1}^k,
R_h = NormGate # HNF # Q_union,h.
```

只要固定公开 A、Sigma、p、h、decoder 和 norm cap，R_h 的定义不使用陷门。若实际 raw 完整 law 与 Q_union,h 的距离至多 `epsilon_finite+epsilon_raw`，则把 HNF、范数门以及已有 abort 全部作为同一确定性映射，有

```text
TV(actual complete issuance law, R_h) <= epsilon_finite+epsilon_raw.
```

**这里不另加 R_h 的 norm-abort 概率**，因为两边应用共同范数门并保留 abort。其自身 abort 率仍可用上一节的 raw cap 尾界单独报告；不能把完整 law 界直接当作成功条件 law 界。

该直接参考避免了不必要的 approximate-to-exact 移位、head-wrap 与不 abort 参考范数拒绝损失，但并未自动建立 `R_h=SampleDom | f=h`。其数学 forward map、image regularity、PSF domain law 与原文强安全前提仍需独立识别。它是明确的 trapdoor-independent 公开分析参考，不能仅凭这个定义就称 source PSF 或强不可伪造已获准入。

## 7. 签名 norm 与服务 ledger 的追加只读审查

另检查 [oracle_ledger.py](../../../../experiments/research/candidates/srgg/oracle_ledger.py) 的 `signature_norm_bound`、`hnf_reference_comparison` 和 `service_ledger`。签名部分不需要把最终响应证明成高斯：令 `T_sig=[M(y);I_n]`，`Zeta` 为乘以 `1+X^(n/2)` 的系数算子，则 `Zeta^T Zeta=2I`。给定扰动 `P_sig` 及其 commitment 派生的任意 challenge c，理想 scalar u 的中心是 `-Zeta^T c/2`，所以

```text
v = u+Zeta^T c/2 is a centered Gaussian on a shifted Z^n,
z = P_sig + T_sig Zeta v,
||T_sig Zeta v|| <= sqrt(2 beta_sig) ||v||.
```

对任意 `alpha in (0,1)`，只要

```text
||P_sig||^2 <= alpha^2 B,
||v||^2 <= (1-alpha)^2 B/(2 beta_sig),
```

就有响应范数不超过 `sqrt(B)`。扰动 marginal 使用自己的高斯尾；v 的全中心 coset 尾界对每个已给定的 `P_sig,c` 一致成立，积分后可直接联合界。没有假定 challenge 与扰动独立，也没有对 commitment 事件条件化之后错误沿用扰动 marginal。

`Sigma_p<=Sigma` 给扰动最大形状界，已经核验的 `Sigma_p>=r_squared I` 给其 `Z^D` smoothing 证书。`beta_sig=n*U_user+1` 由实际已准入的完整 user 向量 norm cap 推出。若只是假设一个 beta，工具不能把它自动当成已认证的密钥条件。

设每个尝试、每个可达历史上的实际 sampling-abort 概率至多 delta_S，实际 norm-reject 事件概率至多 rho，最多 L 次尝试。因 sampling-abort 不重试，norm-reject 才重试，仍可用保守界

```text
Pr[signature operation abort] <= L delta_S + rho^L.
```

其中 `rho^L` 来自逐历史条件概率连乘，不来自消息、challenge 或密钥之间的独立性。若 rho 从理想 norm tail 推得，必须先加实际每尝试完整输出 TV 修正；代码这样处理。`L delta_S` 另加该 sampling-abort 联合界是保守的，不会漏算。

同理，若首次发钥完整 law 到共同 HNF/norm reference 的逐历史距离为 epsilon_E，签名每尝试完整 law 到同 key 的理想 sequential reference 的逐历史距离为 epsilon_S，则在一致缓存、同一 generation、同一状态机和 fresh attempts 条件下，耦合给

```text
transcript TV <= q_new epsilon_E + q_sign L epsilon_S.
```

失败后被记为 failed 的首次身份也计入 q_new；后续相同身份的确定性缓存／阻断不增加 sampler 调用。基础设施异常另需模型，不应从 fsync 或测试成功推一个概率。共同门 reference 的 TV 不另加 norm-reject；actual issuance 的 abort 率可另由该 TV 加 reference 的 norm-abort 率控制。所有这些仍是条件 oracle 分布／可靠性预算，不能自行升级为原文安全游戏模拟器。

有限 sampler 证书用于这里时，需要它在 common HNF/norm gate **之前**就控制 raw hybrid law；仅有后处理后的 TV 不能反推 raw-TV。现有 sampling 分析由逐阶段 sampler 误差相加建立这个 hybrid 上界，后处理只收缩；交付报告应明确这一复用范围。

## 8. 验证范围

```powershell
python -m pytest -q tests/test_srgg_psf_bridge.py
python -m experiments.research.candidates.srgg.psf_bridge --output build/outputs/srgg-bridge-2026-10-16/psf-reference.json
```

测试使用公开的小尺寸整数 fixture、精确 `Fraction` GSO／行列式／概率；无 Sage、无生产随机性、无新身份或消息样本及生命周期实验。所述一般推导是显式条件下的分布分析，不是安全归约或正式安全估计。代码与报告保持 `security_claim=none,backend_admitted=false,parameters_are_formal=false`。未更改协议、原语实现或原始候选参数。
