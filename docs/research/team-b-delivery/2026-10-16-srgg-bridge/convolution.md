# SRGG 理想发钥卷积：C 正规化与 raw-TV 条件桥梁

日期：2026-10-16。代码：[convolution_bridge.py](../../../../experiments/research/candidates/srgg/convolution_bridge.py)，测试：[test_srgg_convolution_bridge.py](../../../../tests/test_srgg_convolution_bridge.py)。本项承接 [hnf-service.md 的实际理想卷积表达](../2026-10-16-srgg-qualification/hnf-service.md)，并复用 [fiber-normalizers.md](fiber-normalizers.md) 的全部可达 fiber 共同正规化界。

**新增结论是条件于明确形状与见证界的理想 sampler 分布界。** 两个 n8 研究配置有非平凡 raw-TV 数值；既有 n512 d2–4 条件候选只凭其现有公开最坏情况界还不能得到 C smoothing 证书。本项没有把近似原像并集上的高斯识别为 exact-fiber PSF law，也没有完成 HNF、成功条件化、有限采样、中止或安全参数准入。

## 1. 固定对象与精确代数

采用实现明确使用的密度形状约定

```text
rho_M(z) = exp(-pi z^T M^-1 z),
continuous physical covariance = M/(2pi).
```

系数空间维度为 `N=(2+w)dn`、`m=wdn`。令 `T=[M(R);I_m]`，`AT=F mod Q`，`sigma_squared=b^2 r_squared`，`Sigma_p=Sigma-sigma_squared*T*T^T`。以下要求 `Sigma_p` 正定。`P` 为 `Z^N` 上形状 `Sigma_p` 的理想高斯；给定 P，X 是 Algorithm 6 参考的对应完整 fiber 上、形状 `sigma_squared I_m` 的理想球形高斯。此处没有用有限递推 sampler 替代该参考，也不包含实现的范数失败或采样异常。

在前述文档已推得的支持

```text
S_h = {u: Au=h-e mod Q, e in {0,...,p-1}^(dn)}
```

上，理想 `U=P+TX` 的精确未简化边缘是

```text
Pr[U=u] = (1/Z_P) sum_(x in Z^m)
           rho_Sigma_p(u-Tx) rho_(sigma_squared I)(x) / Z_F(Fx mod Q).
```

其它 u 的概率为零。取

```text
C = (sigma_squared^-1 I + T^T Sigma_p^-1 T)^-1,
mu(u) = C T^T Sigma_p^-1 u.
```

直接配平方给出

```text
rho_Sigma_p(u-Tx) rho_(sigma_squared I)(x)
    = rho_Sigma(u) rho_C(x-mu(u)).
```

测试对非对角目标形状、矩形 T 与非零中心精确核对这一恒等式；全部矩阵运算使用 `Fraction`，没有浮点特征值判断。

## 2. C 的公开／显式见证条件下界

由 Woodbury 恒等式，精确有

```text
C = sigma_squared I - sigma_squared^2 T^T Sigma^-1 T.
```

注意 `sigma_squared^2` 表示 `sigma^4`。给定已验证或显式假设的两个输入

```text
Sigma >= s_min I,
||T||_2^2 <= beta,
s_min > sigma_squared * beta,
```

逆矩阵序与谱范数界推出

```text
lambda_min(C) >= c_lower
    = sigma_squared * (s_min-sigma_squared*beta)/s_min > 0.
```

第三个条件同时保证 `Sigma_p` 的公开充分正定条件。它比单独给出 `Sigma_p>0` 强，是可计算的充分证书条件；本工具失败不表示实际 C 不平滑。

对全部 CBD1 根见证，系数均在 `{-1,0,1}`，R 的 `2d*wd` 个环元素各有 n 个系数，故

```text
||M(R)||_F^2 = n ||R||_coeff^2 <= 2 d^2 w n^2,
||[M(R);I]||_2^2 = ||M(R)||_2^2+1 <= 2 d^2 w n^2+1.
```

因此默认 `beta=2d^2wn^2+1`，`s_min` 取两个公开 master squared widths 的较小值。这是整个 CBD1 支持类的确定性界，不需要导出根陷门。

`bridge_certificate` 也允许显式 `t_squared_upper`，但必须传入 `witness_bound_origin`。调用方可以使用经另一个工具验证的实际见证谱／范数界，或明确标为假设的 norm cap；本工具只做条件传播，始终输出 `actual_witness_cap_verified=false`，不会因为给了数值就把它认证为真。

**不对秩亏形状套用 Peikert 的正定双形状定理。** 在这里 `sigma_squared TT^T` 通常秩为 m<N。上述路线使用辅助变量、配平方及正定 C 的 Poisson 正规化；不能把它写成直接调用冻结 Peikert 作者稿 Theorem 3.1。密度约定也不自动解决 SRGG 原文标准差术语对应。

## 3. 全中心 C 正规化证书

定义 `Theta_C(mu)=sum_x rho_C(x-mu)`。对任意中心，Poisson 恒等式给

```text
Theta_C(mu)/sqrt(det C)
 = sum_(k in Z^m) exp(-pi k^T C k) exp(2pi i <k,mu>),

|Theta_C(mu)/sqrt(det C)-1|
 <= sum_(k != 0) exp(-pi k^T C k)
 <= sum_(k != 0) exp(-pi c_lower ||k||^2).
```

这给出同一个共同常数 `K_C=sqrt(det C)`，并且界同时适用于所有中心。C 可以依赖陷门；这一步不宣称 trapdoor independence。

代码先取 `j=floor(c_lower)`，再保守地取 `j_used=min(j,1024)`。非整数下界绝不向上取整；`j=0` 时本证书明确不给非平凡数值。实现上限仅控制有理数运算与序列化大小，不代表数学形状不能更大。

使用初等严格界 `pi>4 log 2`：`pi>3`，而 `exp(3/4)>1+3/4+(3/4)^2/2+(3/4)^3/6>2`，故 `log 2<3/4`。令 `a=2^(-4*j_used)`，则

```text
sum_(k in Z\{0}) exp(-pi j_used k^2)
 <= t = 2a/(1-a^3),
x = m*t,
rho_dual_nonzero <= x/(1-x), if x<1.
```

第一式使用 `k^2>=1+3(k-1)`；第二式使用 `(1+t)^m-1<=sum_(l>=1)(mt)^l`。最终把精确有理数上界再向上包络为一个 2 的整数幂，便于检查并避免巨大十进制输出。所有准入比较仍用精确有理数；文档科学计数法只供展示。

## 4. fiber 与 C 两项误差传播，包含最后正规化

假定 `fiber-normalizers.py` 或调用方已给出全可达 fiber 的共同正数界

```text
L_F <= Z_F(s)/K_F <= H_F,
1-epsilon_C <= Theta_C(mu)/K_C <= 1+epsilon_C,
L_F>0, 0<=epsilon_C<1.
```

由配平方，实际 raw 权重相对于 `rho_Sigma(u)` 的乘子是

```text
a(u) = (K_F/K_C) sum_x rho_C(x-mu(u))/Z_F(Fx mod Q),
L = (1-epsilon_C)/H_F <= a(u) <= U = (1+epsilon_C)/L_F.
```

令 `Q_raw(u)=rho_Sigma(u)/sum_(v in S_h)rho_Sigma(v)`，则真实理想边缘必须写成

```text
P_raw(u) = Q_raw(u) a(u)/E_Qraw[a],
TV(P_raw,Q_raw) = E_Qraw[|a-E_Qraw a|]/(2 E_Qraw a)
               <= min(1,(U-L)/(2L)).
```

最后一步使用 `E[a]>=L` 与 `|a-E[a]|<=U-L`。该界保守，并非最优范围界；优点是没有平方根，能直接做精确有理传播。对称 fiber 偏差 `1-epsilon_F<=Z_F/K_F<=1+epsilon_F` 时有

```text
TV <= min(1,(epsilon_F+epsilon_C)/((1-epsilon_F)(1-epsilon_C))).
```

两项都必须计入；不能只把两个相对偏差相加，也不能省去 `E[a]`。测试枚举三点有理 reference 上所有端点 reweights，逐一计算最终正规化后的精确 TV 交叉核验。fiber 工具的 `L_F=1-x_F,H_F=1/(1-x_F)` 直接以非对称比例输入，不强行改成较松的对称误差。

## 5. 既有五组形状的数值

这些都来自现有研究配置／条件候选，**不是新增正式参数**。n8 两 profile 采用 [qualification_audit.py](../../../../experiments/research/candidates/srgg/qualification_audit.py) 中相同的 n/d/b/w/r 与 master shape 字段；本项不运行发钥、签名或高斯 sampler。n512 三组来自 [formal_candidates.py](../../../../experiments/research/candidates/srgg/formal_candidates.py) 的原有 builder。

| 配置 | beta | c_lower（精确） | floor(c_lower) | C 全中心相对误差上界 | 理想 raw 到 S_h 高斯的 TV 上界 |
|---|---:|---:|---:|---:|---:|
| baseline-n8 | 385 | 1659807487/524288 | 3165 | 2^-4090 | 1.674344758995e-4 |
| density-width3-n8 | 513 | 34178002479/8388608 | 4074 | 2^-4089 | 3.363510825845e-11 |
| conditional n512 d2 | 16777217 | 3997760/1031865954433 | 0 | 本证书不足 | 未给出 |
| conditional n512 d3 | 37748737 | 307520/178592178501 | 0 | 本证书不足 | 未给出 |
| conditional n512 d4 | 67108865 | 799552/825492726605 | 0 | 本证书不足 | 未给出 |

n512 的原 builder 取 `s_min=sigma_squared*beta+r_squared+1`，余量只有 65，所以

```text
c_lower = sigma_squared*65/(sigma_squared*beta+65) < 1.
```

其旧有充分正定／算术门通过，并不保证本项的卷积正规化条件。不能用 fiber 已有约 10^-83 的优秀界覆盖这个独立缺口。可能的后续条件输入是扩大 master shape 余量，例如 `s_min=2*sigma_squared*beta` 则 `c_lower=sigma_squared/2`；测试验证工具接受并正确传播这种**显式新条件**，没有改写原候选或宣称安全与效率已获验证。

## 6. 范围、复现与尚未闭合事项

复现无需 Sage，无网络或生产随机性；Python 精确矩阵测试与有理证书是开发／数学交叉证据，不能替代形式安全归约。身份与消息不参与本项无中止理想发钥正规化界，故未选身份／消息字节串；没有真实生命周期重复次数或性能测量，也没有新 ROM 假设。原 SRGG 的 ROM、安全前提、参数／源公式对应仍须按其专属核验材料判断。

```powershell
python -m pytest -q tests/test_srgg_convolution_bridge.py tests/test_srgg_fiber_normalizers.py
python -m experiments.research.candidates.srgg.convolution_bridge --output build/outputs/srgg-bridge-2026-10-16/convolution.json
```

本项实际补上：公开或显式条件见证界到 C 最小形状下界；全中心正规化证书；两项共同正规化比例到理想 approximate-union 高斯的 TV；五个既有 study point 的如实数值和失败条件。

仍须接续：有限 sampler 与无中止理想 law 的严格误差及中止传播；HNF 后 tail／恢复 witness 到一个明确 exact-fiber PSF reference 的对应；image regularity、trapdoor independence、norm gate 成功率、head wrap 及服务 query 损失；源分布约定与强不可伪造前提；实际攻击估计与参数准入。保持 `security_claim=none, backend_admitted=false, parameters_are_formal=false`。
