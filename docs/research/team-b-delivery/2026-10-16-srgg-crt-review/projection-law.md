# SRGG 实际 CBD1 的 mod 3 投影与公开多列分布界

2026-10-16。本文件是对当前代码分布的新推导及精确算术核验，不把它归为论文已经证明的结论。它只覆盖 `R_3=F_3[X]/(X^n+1)`；即使原模数含 `3^w`，也不把 mod 3 的结果提升到 `3^w`、其它素因子联合、整个 `Q` 的 Module-LWE，或 IBS 安全。所有安全标志保持 `security_claim=none, backend_admitted=false, parameters_are_formal=false, nist_security_category=null`。

## 1. 代码分布、来源与前提

当前 `experiments/research/candidates/srgg/structured_execution.py` 的 `ExactRing.build_public` 把 witness 分成上下各 `d` 行，按

```text
F = pG,
R0,R1 <- CBD1^(d by ell), independently,
B = F-R0-Ahat R1 mod Q, ell=wd
```

构造公开 `B`。`structured_backend.py` 复用该实现，没有另换一套矩阵分布。经典条件路线的对应接口见 `../2026-10-16-srgg-classical-rom/direct-ibs.md` 第 8 节的 shared-Ahat hybrid：各列 `V_j=Ahat S_j+E_j` 的 secret/error 系数均独立服从

```text
Pr[-1]=1/4, Pr[0]=1/2, Pr[1]=1/4.
```

以下严格区分两个前提：

1. 代数和 CBD1 投影，只需 `n>=4` 为 2 的幂、`3|Q`，与 gadget 底数是否为 3 无关；系数约化至 mod 3 没有歧义。
2. 公开 noisy-hash 的统计界，还需 `Ahat` 均匀于完整 `R_3^(d by d)`，并独立于全部 secret/error；不同列在给定同一个 `Ahat` 后使用相互独立的 secret/error。均匀 `R_Q` 矩阵在 `3|Q` 时满足这一投影前提。实际 32 B seed/SHAKE 的模型嵌入须由独立 seeded-XOF 论证承担，本文件不宣称有限 seed 的输出恰均匀，也不量化实际 SHAKE 与理想 XOF 的距离。

`F_j-V_j` 对每个固定 `Ahat` 是输出集合上的双射，因而公开 `B` 与 `V` 相对均匀的 TV 相同。它不要求 `F` 可逆、不要求 `p` 在 mod 3 非零；`3|p` 时仍成立。

论文来源识别沿用项目冻结版本：DOI `10.1049/ise2/6684889`，PDF SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。本文未重新完成该论文 theorem 的分布覆盖审查，因此不能拿这个来源标识替代实际 CBD1/复合模数下的困难性定理。

## 2. 两个不可约因子

令 `k=n/4`。在 `F_3[X]` 中，

```text
X^n+1 = (X^(2k)+X^k-1)(X^(2k)-X^k-1).
```

乘积中的中项为 `-3X^(2k)`，在 mod 3 消失。两个因子互素：差为 `2X^k`，而它们的常数项非零。

设 `n=2^m, m>=2`，`ord_(2n)(3)=2^(m-1)=n/2`。可由 `v_2(3^(2^r)-1)=r+2`（`r>=1`）及 `3` 对 mod `4` 的阶为 2 得到。`X^n+1=Phi_(2n)` 的不可约因子次数均为该阶；上述两因子各有次数 `n/2`，因此均不可约。于是

```text
R_3 ~= F x F, F=F_(3^(n/2)).
```

均匀 `R_3` 在两个因子上的投影独立均匀。**CBD1 的两个投影通常相关**，下文的联合计算保留该相关性，不能把两个边缘 TV 直接拼成完整结果。

## 3. 实际 CBD1 的单因子 pair law

固定 `epsilon in {-1,+1}`，在 `f_epsilon=X^(2k)+epsilon X^k-1` 下，有

```text
X^(2k) = 1-epsilon X^k,
X^(3k) = -epsilon-X^k.
```

原多项式在 `j,j+k,j+2k,j+3k` 的四个独立 CBD1 系数 `(a,b,c,d)`，对输出两坐标贡献为

```text
(a+c-epsilon d, b-epsilon c-d) mod 3.
```

穷举 `3^4=81` 个取值并使用 CBD1 的整数权重 `2^(zero count)/256`，对两个符号均得：

```text
P[(0,0)] = 1/8,
P[x] = 7/64 for each of the other 8 points,
CP(pair) = (1/8)^2+8(7/64)^2 = 57/512.
```

各个 `j` 使用互不相交的原始系数，所以 pair 相互独立。一个 `d` 元 secret/error 向量投影到一个因子后的碰撞概率是

```text
c = (57/512)^(dn/4).
```

对完整 `R_3^d`，每个系数 mod 3 的碰撞概率为 `3/8`，CRT 是双射，故完整向量碰撞概率是

```text
C = (3/8)^(dn).
```

此处 `c`、`C` 都是概率的精确值，不是高斯近似、均匀近似或抽样估计。

## 4. 一个因子的公开 noisy-column 界

记 `t=|F|^d=3^(dn/2)`，取 `Ahat` 在 `F^(d by d)` 均匀，`S,E` 独立服从上一节的真实投影 law。令 `V=Ahat S+E`。

独立取两份 `(S,E),(S',E')`。若 `S=S'`，概率为 `c`，碰撞需要 `E=E'`，条件概率也为 `c`。若 `S-S'` 非零，均匀矩阵乘它得到均匀 `F^d`，碰撞概率为 `1/t`。因此

```text
E_A CP(V|A) = c^2+(1-c)/t,
chi2((A,V)||(A,U)) = E_A chi2(V|A || U) = c(tc-1).
```

这里 `U` 独立均匀于 `F^d`，比较中包含公开 `Ahat`。利用 Cauchy-Schwarz，

```text
TV((A,V),(A,U))^2 <= c(tc-1)/4.
```

这是包含公开矩阵的平均分布结论，**不是对每一个固定矩阵成立的同一上界**。例如 `Ahat=0` 时 `V=E`，不会因其它矩阵的混合而自行接近均匀；小域测试显式保留这一反例。

## 5. 完整 mod 3 的双因子联合界

现把 `S-S'` 按两个因子上的零/非零情况分四类。两个边缘的零概率均为 `c`，同时为零的概率为完整碰撞概率 `C`。`E-E'` 的对应概率相同，并与 `S-S'` 独立。

| secret 差的两个投影 | 事件概率 | 对均匀 Ahat 的输出碰撞概率 |
|---|---:|---:|
| 都为零 | `C` | `C` |
| 只有第一个为零 | `c-C` | `c/t` |
| 只有第二个为零 | `c-C` | `c/t` |
| 都非零 | `1-2c+C` | `1/t^2` |

理由是均匀 `Ahat` 的两份 CRT 矩阵独立；在非零差的因子上，矩阵乘差给出均匀向量。在差为零的因子上，只有误差差为零才碰撞。这里没有假设 secret 的两份投影独立。

因此输出完整 `R_3^d`（基数 `t^2`）满足

```text
E_A CP(V|A) = C^2+2(c-C)c/t+(1-2c+C)/t^2,
chi2_full = t^2 C^2+2t c(c-C)-2c+C,
TV((A,V),(A,U_full))^2 <= chi2_full/4.
```

对于 `n=4,d=1`，独立的原始负循环 ring 枚举 `81 A x 81 S x 81 E` 个组合、按 CBD1 精确整数权重累计完整 `(A,V)`，得到

```text
chi2_full = 205665/16777216.
```

它与公式完全相等。此枚举不调用新模块的 CRT 投影函数、不使用 pair law、也不依赖 Sage 的商环计算。

## 6. 共享 Ahat 的 ell 列

给定同一个 `Ahat=a`，各列噪声输出相互独立。令 `P_a` 为单列 law、`U` 为均匀 law；逐列替换的乘积分布 hybrid 给出

```text
TV(P_a^ell,U^ell) <= ell TV(P_a,U).
```

对公开 `Ahat` 平均后，设单列的包含 Ahat 的上界为 `delta`，得到

```text
TV((A,V_1,...,V_ell),(A,U_1,...,U_ell)) <= min(1,ell delta).
```

因此代码对每个单因子及完整 mod 3 分别取精确 squared upper `min(1,ell^2 chi2/4)`。它没有把同一个 Ahat 误算为每列重新独立抽取的矩阵，也没有把 CBD1 在两因子上的相关性丢掉。

最后报告整数 dyadic 上界 `2^-b`：用整数移位寻找最大的 `b>=0` 满足 `square<=2^(-2b)`，全程不使用浮点数或可能下溢的数值近似。两点核验为：

| 公开算术点 | 列数 ell | 单因子单列 TV 上界 | 完整 mod 3 单列 TV 上界 | 完整 mod 3 共享列 TV 上界 |
|---|---:|---:|---:|---:|
| `n512,d2`，旧 `b31,w8` 点 | 16 | `2^-406` | `2^-406` | `2^-402` |
| `n2048,d3`，`b3,w22` 候选 | 66 | `2^-2431` | `2^-2430` | `2^-2424` |

这些指数是统计距离上界，**不是攻击成本或安全 bits**。第二点也只是候选算术点，没有据此成为正式参数。旧点同样含因子 3，故不因 `b=31` 而排除；反过来，`b=3` 也不能让本结论自动覆盖高次 `3^w`。

## 7. 可执行证据与界限

实现：`experiments/research/candidates/srgg/crt_projection.py`。测试：`tests/test_srgg_crt_projection.py`。输出使用排他创建，不覆盖已有收据；精确分子分母采用十六进制，避免极小概率经浮点下溢或超长十进制转换丢失。

定向测试包含：两个符号的 81 项独立带权长除；单因子 `F9` 的完整公开 `(A,V)` 分布；完整 `n4,d1` 的负循环枚举；同一个 Ahat 的两列精确分布及固定 shift/sign 的 TV 不变性；真 Sage `n4/n8` 商环与不可约性；碰撞张量、四类差支持概率、多列 hybrid 上界、dyadic 的最紧整数指数、非法参数与零熵/安全标志。

Windows 定向首测：`35 passed, 2 skipped`，两项 skip 均为真实 Sage 商环测试；指定 WSL Sage 定向首测：`37 passed`，无跳过，同目录独立 JUnit 收据记录结果。本工具不取熵、不抽根/密钥、不改 sampler，也不改变旧冻结实验源码与收据。

```text
python -m pytest -q tests/test_srgg_crt_projection.py --junitxml=build/outputs/srgg-crt-review-2026-10-16/projection-windows-first.junit.xml

PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_crt_projection.py --junitxml=build/outputs/srgg-crt-review-2026-10-16/projection-sage-first.junit.xml

python -m experiments.research.candidates.srgg.crt_projection --output build/outputs/srgg-crt-review-2026-10-16/projection-final.json
```

这些精确计算闭合 mod 3 的分布问题。仍未闭合的是 `3^w (w>1)`、其它素因子间的完整联合分布与整体 Q 的困难性，实际 seeded 模型对应，以及整个 SRGG 的参数安全估计/安全归约。小模投影的统计接近均匀既不是对完整分布的区分攻击，也不是完整 Module-LWE 或 IBS 安全证明。论文 theorem 覆盖与具体困难性准入必须另核。
