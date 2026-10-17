# SRGG：所有 gadget fiber 的共同正规化界

日期：2026-10-16。范围为 SRGG 独立原语的理想 gadget／raw 分布桥，不依赖 HIBE 选择。
`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。

本项闭合两个具体问题：**不同可达目标的 gadget Gaussian 总质量相对同一个常数的统一界**，以及**在 raw 卷积中删去该变化分母、再正确归一化所引入的 TV**。这两个结论不要求假定各 fiber 的质量相同，也不使用单个已归一化 fiber 内的采样 TV 来替代跨 fiber 质量比较。

## 1. 符号和实施对应

在普通系数 Euclidean 空间中，令 `H=dn`、`m=wH`、`b>=2`、`p>=1`、`Q=p b^w`，

```text
F = p[I,bI,...,b^(w-1)I],
σ² = b²r²,  r²>=1,
ρ_σ(x) = exp(-π||x||²/σ²),
Z_F(s) = sum_{x∈Z^m: Fx=s mod Q} ρ_σ(x).
```

目标可达当且仅当其每个规范系数是 p 的倍数。给定可达 s 后，每个系数的目标可唯一写成 `p t`，其中 `t∈Z/(b^w)`。本项不要求 p 与 b 互素；实际研究配置另有互素检查。

主论文固定版本为 `papers/2025_efficient_ibs_jia.pdf`，SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`，DOI `10.1049/ise2/6684889`。原文 p.7 Algorithm 2 的 gadget 接入及 p.7 附近的 digit 递推由当前 `sampling.GadgetSampler` 实现。本文严格采用实际配置中的 `digit_width_squared=b²r²` 密度约定；不解决原文 Algorithm 6 字面宽度和 Table 3／其它算法之间的解释差异。

`sampling.GadgetSampler.sample_scalar` 从 `state=t` 开始，逐位抽取 `x_i∈bZ+(state mod b)`，再令 `state=(state−x_i)/b`。其 `certificate` 已提供有限采样和单 fiber 内偏差证书；本项新推导比较不同完整 fiber 的**未归一化质量**。

## 2. 单 digit 的统一 Poisson 界

对 `a∈{0,...,b−1}`，定义无限 coset 质量

```text
z_a = sum_{k∈Z} exp(-π(bk+a)²/(b²r²)).
```

一维 Gaussian Poisson 求和给出

```text
z_a/r = sum_{ell∈Z} exp(-πr² ell²) exp(2πi ell a/b).
```

因此对所有 a 同时成立

```text
|z_a/r−1| <= 2 sum_{ell>=1} exp(-πr² ell²)
          <= 2q/(1−q³) = t_0,       q=exp(-πr²).
```

第二个不等式使用整数 `ell>=1` 时 `ell²>=1+3(ell−1)`。令计算证书给出的有理数 `t>=t_0`，则

```text
r(1−t) <= z_a <= r(1+t)        对全部 a.
```

Poisson 公式是这里使用的分析恒等式；后续证书只需要有理数上界，不要求浮点数正确舍入或区间软件作为可信条件。

## 3. 从 digit 递推得到所有完整 fiber 的共同常数

先看一个系数，固定 `tgt∈Z/(b^w)`。完整 fiber 是

```text
L_tgt = {x∈Z^w: sum_i b^i x_i = tgt mod b^w}.
```

理想 digit 递推对它给出概率质量

```text
q_tgt(x) = ρ_σ(x) / product_{i=0}^{w−1} z_{a_i(x)}.
```

每一步是完整 coset 上已经归一化的 Gaussian，步数有限，故 `sum_x q_tgt(x)=1`。其支持恰为 `L_tgt`：逐步的整除条件等价于最终模 `b^w` 的等式，末状态只要求为整数，没有另加末状态为零的条件。由非负项求和可得精确恒等式

```text
Z_tgt = E_{X~q_tgt}[product_i z_{a_i(X)}].
```

于是每个 tgt 都满足同一组界

```text
r^w(1−t)^w <= Z_tgt <= r^w(1+t)^w.
```

F 的 `dn` 个系数 fiber 是独立笛卡尔积，Gaussian 权重也逐系数相乘。令 `m=wdn`，共同常数为 **`C_F=r^m`**，则

```text
(1−t)^m <= Z_F(s)/C_F <= (1+t)^m
```

对**所有可达 s**同时成立。特别地，该常数不依赖目标、公开矩阵 A、陷门 R、扰动中心或实际抽到的随机数。

另一个对共同常数的核对：单系数 kernel 的整基可取列 `b e_i−e_(i+1)`（`i<w−1`）和 `b e_(w−1)`。这些列均在 kernel 中，行列式绝对值是 `b^w`，而 gadget 映射因首项为 1 而满射，故其确实生成整个 kernel。Gaussian Poisson 的零频常数为 `σ^w/b^w=r^w`，与递推推导一致。本项数值证书不依赖额外的高维 smoothing 假设。

为控制有理数大小，实现取 `x=mt`。若 `x<1`，Bernoulli 不等式和 `binomial(m,k)<=m^k` 给出

```text
L_F = 1−x <= Z_F(s)/C_F <= 1/(1−x) = H_F,
max_s Z_F(s)/min_s Z_F(s) <= H_F/L_F = 1/(1−x)².
```

若 `x>=1`，当前简单充分证书明确返回 vacuous，不返回虚假的正下界。它不表示真实 normalizer 一定不均匀。

## 4. 在 raw 卷积中消去分母的 TV

允许任意正的、可求和扰动权重 `a(P)`，令 `A_P=sum_P a(P)`。给定 P 后的目标为某个可达 `s(P)`，并记 `z(P)=Z_F(s(P))/C_F`。原始理想 joint law 为

```text
J(P,X) = a(P) ρ_σ(X) 1[FX=s(P)] / (A_P Z_F(s(P))).
```

删去分母之后必须重新归一化。比较对象明确是

```text
K(P,X) = a(P) ρ_σ(X) 1[FX=s(P)]
         / sum_{P',X'} a(P')ρ_σ(X')1[FX'=s(P')].
```

两边 `X|P` 的条件 law 完全相同。J 的 P 边缘是 `μ(P)=a(P)/A_P`，K 的边缘是 `μ(P) z(P)/E_μ z`，因此

```text
TV(J,K) = E_μ |z−E_μ z| / (2 E_μ z).
```

一般地，若 `z∈[L,H]`、`0<L<=H`，令 `v=E z`。绝对值凸性、区间端点的线性插值得

```text
E|z−v| <= 2(H−v)(v−L)/(H−L),
TV <= (H−v)(v−L)/(v(H−L))
   <= (sqrt(H)−sqrt(L))/(sqrt(H)+sqrt(L)).
```

最后一步使用 `v+LH/v>=2sqrt(LH)`；若 `L=H`，TV 直接为零。本项 `L_F H_F=1`，所以无需计算无理平方根即可得到

```text
δ_F = x/(2−x),
TV(J,K) <= δ_F.
```

这是给定区间后的最坏情况 sharp 界：在 `z=L_F,H_F` 上取均值为 1 的二点 μ 可达等号。实际 SRGG 不必达到它。

`U=P+TX` 是确定映射，故其 raw 边缘满足同一个 TV 上界。旧文档给出的 `u∈S_h` 的边缘求和因此可把 `1/Z_F(Fx)` 替换为同一个常数因子后**整体重新归一化**，代价至多 `δ_F`。这一步没有声称替换后的 law 已是球形 Gaussian，也没有控制配平方后的 `rho_C(Z^m−μ(u))`。

与已有有限采样证书的组合仅能按三角不等式进行：若既有完整有限 law（含中止）到上述 J 的 TV 是 ε，则它到 K 的 raw 输出 TV 至多 `min(1,ε+δ_F)`。随后相同确定性 HNF 和“失败映射到 ⊥”的范数门均收缩完整 law 的 TV。若只看成功条件 law，仍需独立的成功率下界。

## 5. 精确有理证书的计算方法

新增工具 `experiments/research/candidates/srgg/fiber_normalizers.py` 不依赖 Sage。其流程为：

1. 用 Machin 恒等式 `π=16atan(1/5)−4atan(1/239)`，第一项取 32 项交错级数下界，第二项取 33 项交错级数上界，得到严格有理下界 `π_low`。该恒等式可由 `tan(4atan(1/5)−atan(1/239))=1` 和角度范围核对。
2. 对 `a=π_low r²`、`N=2^32`，使用 `exp(−πr²)<=exp(−a)<=(1+a/N)^(−N)`。从精确倒数开始，每次平方后向上舍入为分母 `2^512` 的 dyadic，共 32 次。每一步均为整数／有理运算。
3. 计算并向上舍入 `t>=2q_upper/(1−q_upper³)`，然后精确计算 `x=mt`、`L_F`、`H_F`、`δ_F`。JSON 保存这些完整有理数；decimal 字段仅供阅读，不能用作不等式判定。

宽度很大时 `2^-512` 的向上舍入底限使界变松，但不会使其失效。本批 r²<=64，底限远低于所列数值。共同常数用幂表达式保存，避免 n512 的大整数十进制输出。

API：`normalizer_certificate(degree=...,rank=...,base=...,digits=...,r_squared=...)` 返回 `uniform_relative_lower_exact`、`uniform_relative_upper_exact`、`all_fiber_max_min_ratio_upper_exact` 和 `raw_denominator_removal_tv_upper_exact`，均为 `Fraction` 可直接解析的精确字符串。后续卷积组合可直接用前两个比例，无需显式计算 `C_F`。

## 6. 现有 profiles 的结果

所有行均为 `b=31`。下表的 x 是显示近似；TV 列采用向上放宽后的短数。精确判定使用生成 JSON 中的有理数。

| 配置 | n / d / w | r² | m=wdn | x 的显示近似 | raw 分母变化 TV 严格小于 |
|---|---:|---:|---:|---:|---:|
| baseline-n8 | 8 / 1 / 3 | 4 | 24 | 1.673924361753e-4 | 8.371e-5 |
| density-width3-n8 | 8 / 1 / 4 | 9 | 32 | 3.363510825675e-11 | 1.682e-11 |
| conditional-n512-d2-w8 | 512 / 2 / 8 | 64 | 8192 | 7.840347958085e-84 | 3.921e-84 |
| conditional-n512-d3-w8 | 512 / 3 / 8 | 64 | 12288 | 1.176052193713e-83 | 5.881e-84 |
| conditional-n512-d4-w8 | 512 / 4 / 8 | 64 | 16384 | 1.568069591617e-83 | 7.841e-84 |

这里的 n512 行只核验该 gadget 项；原先 residual-positive 的候选不因此获得配平方 C 的 smoothing 资格。两组 n8 仍有 8 位公开可枚举 challenge，不是安全实例。所有行都不是正式参数或任何 NIST 安全等级证书。

复核命令（仓库根目录，Python 可见 `src`；不需要 WSL/Sage）：

```text
python -m pytest -q tests/test_srgg_fiber_normalizers.py
python -m experiments.research.candidates.srgg.fiber_normalizers --output build/outputs/srgg-bridge-2026-10-16/fiber-normalizers.json
```

本项测试：16 passed。包含全部 9 个小 gadget 目标的直接密度求和独立检查、可达范围的精确二点 TV 取等例、五组实际参数输入、有理计算边界与明确 vacuous 返回。直接小维求和和 Decimal 指数检查是补充的实现证据；上述一般结论依赖这里写明的数学推导，不能由有限数值检查代替。

## 7. 本项没有闭合的内容

配平方后的 C 与所有中心的 lattice-sum 界、扰动 Gaussian 到 raw Gaussian 的剩余步骤、近似 fiber 并集到 exact PSF fiber 的平移和混合、image 正则性、HNF head-wrap、范数准入成功率、服务安全游戏，以及论文 strong-security 条件仍需分别核验。有限采样、中止和浮点误差沿用各自已有证书，不被本项的理想 normalizer 界取代。

本项没有运行 n512 密钥生成、发钥或签名，没有修改采样器，没有声称修复原文证明或实现正式安全准入。
