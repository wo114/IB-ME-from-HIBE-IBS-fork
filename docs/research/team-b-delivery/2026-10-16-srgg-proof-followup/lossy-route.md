# WIP：SRGG 商识别的 lossy 路线与保守统计充分界

2026-10-16。本页分析一种**证明用**低秩公钥分布，不改变真实 Setup、签名、参数、接口或服务。完成的是条件代数、一个统计充分引理和六点零熵算术；当前研究点不满足此充分界。未完成实际 seeded 公钥的 LOSS 嵌入、完整 IBS/QROM 游戏或正式参数准入。

`security_claim=none, backend_admitted=false, parameters_are_formal=false, nist_security_category=null`。

## 1. 一手定理入口及读取范围

Kiltz、Lyubashevsky、Schaffner，*A Concrete Treatment of Fiat-Shamir Signatures in the Quantum Random-Oracle Model*，EUROCRYPT 2018，DOI [10.1007/978-3-319-78372-7_18](https://doi.org/10.1007/978-3-319-78372-7_18)。本轮实际在线定向读取 [UvA 官方开放 PDF](https://pure.uva.nl/ws/files/45974860/A_Concrete_Treatment_of_Fiat_Shamir_Signatures.pdf?download=1) 的 PDF p.13–16、21，对应印刷 p.563–566、571；响应 PDF SHA-256 为 `b51a7f1aeda17232969e38bb56a89cbeea6241043aa333035639b2334b54ab09`。只读 HTTP 响应进入内存后交给已有 `pdftotext`，没有安装或落盘归档论文。

- Definition 2.8（印刷 p.564 / PDF p.14）要求明确的 `LossyIGen`，返回公钥而不返回 secret key；LOSS 是真实/损失公钥分布对量子区分器的差。
- 同页 lossy soundness 是对**任意可能无界的量子交互对手**成立的统计性质。式 (3) 给出上界

  ```text
  E_(pk_ls)[ max_W Pr_(fresh uniform c)[exists Z: V(pk_ls,W,c,Z)=1] ].
  ```

  W 在 fresh 经典 challenge 前提交；量子对手、量子内部存储并不允许事后改变已经提交的经典 W。
- Theorem 3.4（印刷 p.571 / PDF p.21）在 ID 为 lossy 且 εls-lossy sound 的前提下给

  ```text
  Adv_UF-NMA(A) <= Adv_LOSS(B) + 8*(QH+1)^2*εls,
  Time(B)=Time(A)+QH.
  ```

  这里是对应底层 FS 签名、无签名查询的量子对手，不是直接的自适应 IBS/Extract/Sign 定理。
- 同页 Theorem 3.3 还要求 naHVZK、承诺熵；strong 版另有 CUR 项。LOSS 或本页统计引理不能替代这些条件。Definition 2.4 的 commitment recovery 与 §3.1 的签名变换也须按实际格式对齐。

本轮没有声称核读 KLS 全文或所有归约证明。Theorem 3.3 正文把证明指向 full version；Theorem 3.4 在 p.571 开始给证明，本页只核陈述与该页开头，不声称重证整个 KLS 定理。新推导如下，不能归到 KLS 原文或 SRGG 原文名下。

## 2. 候选 lossy 公钥与新困难性对象

令 `R=Z[X]/(X^n+1)`，`M=(w+2)d`、`k=M-d=(w+1)d`。以下先假设完整显式矩阵确实已经是

```text
A=[I_d | U],  U uniform in R_Q^(d×k),  h uniform in R_Q^d,
```

且 h 与 U 独立。真实 `Bpub=pG-R0-Ahat R1` 到均匀 B 的 shared-Ahat MLWE hybrids、以及公开 seed 与 raw-XOF 的合法嵌入，仍是这一步的前提。

证明用 `LossyIGen` 取 top rows `V uniform R_Q^((d−1)×k)`，独立取 `s in CBD1^(d−1)`、`e in CBD1^k`，再令

```text
U_ls = [ V ; s^T V + e^T ],
v^T  = (s^T,−1),
v^T A_ls = (s^T,−1,−e^T) mod Q.
```

负号不影响以下范数界。h 仍独立均匀，故 `H=v^T h` 在 R_Q 中均匀，条件于全部 `(V,s,e)` 也成立：h 的最后一行系数是 −1，提供逐点双射。

**这引入新的 MLWE 对象**：secret 有 d−1 个环元素，sample 有 k 个，误差为 k 个独立 CBD1 环元素。它不是旧的 rank d、d samples 单列比较，也不是把旧 wd 个 hybrid 项换一个名字。其系数对照尺寸将是 `n_lwe=(d−1)n, m_lwe=kn`，仍须保留实际负循环/复合模数结构；没有运行该对象的困难性估计，不能沿用旧估计成本。

## 3. 先排除一个不成立的 χ-unit 步骤

保持实际识别式。记 `z=(x,t)`，其中 x 有 M 个环元素，t 是最后一个环元素。`j=(ζ*,0,…,0)^T`，`ζ=1+X^(n/2)`。接受关系是

```text
W = 2 A x + (Qj−2h)t − Qj c0(χ) mod 2Q,
c0(χ)=(χ,0).
```

两个相同 W 的接受 transcript `(x,t,χ)`、`(x',t',χ')` 令 `f=t−t'`，则

```text
A(x−x') − h f = 0 mod Q,
j*( f−(c0(χ)−c0(χ')) ) = 0 mod 2.
```

第二式只给 `η(f)=χ XOR χ'`，其中 `η(a,b)=a+b mod2`。因此不同 χ 保证 f 是非零整数多项式；**它不把 f 替换成 χ−χ'**。真实 t 包含 `P_last+ζu+c`，可以有高次和大系数。

即使低次 binary 差 `χ−χ'` 在 `R_(3^w)` 是 unit，也不能推出 f 是 unit。简单反例是 `f=3^w`：η(f) 非零，f 在该模数下却为零。只有排除 `||f||∞>=3^w` 之后，才至少知道它不全为零；仍不能假定其乘法矩阵满秩。

一个完整小型关系夹具：取 n4、Q45、w2、d2、M8，`A=[I_2|0]`，`h=(1,2)`（均为常数多项式）。零响应/χ0 和

```text
x=(9,18,0,…,0), t=9, χ=(1,0), c0=1
```

均恢复 W0，第二个响应范数平方为 486。因为 `Ax=ht` 且 `t−c0=8`，恢复式中的剩余项为 `45j*8=0 mod90`。但 `f=9=0 mod9`、χ 差非零。该夹具反驳的是通用 unit 推断；它不是当前大维公钥下已执行的伪造攻击。

## 4. 短响应给出的整数范围

设验证范数门为 `||z||²<=B`。差分满足

```text
||Δx||²+||f||² <= 4B,
G = floor(sqrt(4B)),
J = (M−1)n+1,
T = floor(sqrt(4B*J)).
```

CBD1 的每个系数在 {−1,0,1}，而 v 的 −1 是单个常数系数。因此将 `v^T A_ls` 取上面的短整数代表，全部系数的平方和至多 J。每个 negacyclic 输出系数都是这些系数与 Δx 的一个带符号移位点积。Cauchy–Schwarz 给

```text
||f||∞<=G,
|| (v^T A_ls) Δx ||∞<=T.
```

左乘差分关系得到必要条件

```text
H*f = a mod Q,  ||a||∞<=T.                         (L)
```

这里的 a 是一个 n 系数整数多项式。以下把其可能值扩大为完整整数立方体，故只给保守充分界，不假装计算了真实短向量像的精确大小。

## 5. 不假设 f 可逆的 3-adic 计数引理

令 n>=4 为二次幂，m=n/2，`q0=3^w | Q`，并要求

```text
q0 > G >= 1.
```

有 `ord_(2n)(3)=m`：对 r>=1，`v2(3^(2^r)−1)=r+2`，逐次平方归纳即可；3 的奇数次幂还不等于 1 mod4。故 `X^n+1` 在 F3 上分解为两个互异、次数同为 m 的不可约因子。

对每个非零整数 f、`||f||∞<=G`，令 k 为全部系数共同的最大 3-adic valuation，即 `f=3^k f0`，f0 mod3 非零。前提 q0>G 保证 k<w。f0 mod3 不可能同时被那两个互异因子整除，否则 degree<n 的 f0 将为零；所以其乘法线性映射在 F3 上秩至少 m。

这已经足够，无须错误地把 f0 说成 unit：选择一个 m×m minor，其行列式不被 3 整除。该 minor 在 `Z/(3^(w−k))` 上可逆。条件于其余输入坐标，均匀 H 的这 m 个输出坐标均匀。因此

```text
max_a Pr_H[H*f=a modq0] <= 3^(-(w−k)m).
```

式 (L) 的整数 a 至多 `(2T+1)^n` 个。exact-content 为 k 的 f 数量至多 `(2 floor(G/3^k)+1)^n`，又因 `3^k<=G` 而至多 `(3G/3^k)^n`。对所有 f 和 a 并集，再把有限几何级数放大到无限级数，得

```text
p_bad <= min(1,
  [3G(2T+1)]^n * 3^(-wm) * sum_(k>=0) 3^(-km))
      = min(1,
  ( [3G(2T+1)]² / 3^w )^m / (1−3^(-m))).           (B)
```

`bad` 是“存在任意非零短 f、任意该范围 a 满足式 (L)”这个较大的公钥事件。它条件于 `(V,s,e)` 也成立，故对 lossy key 平均仍成立。没有把攻击者选择的 f 当成独立随机量：并集在整个短范围上先做完，允许 f/W/响应自适应依赖公钥。

好公钥上，相同 W 不可能对应两个不同 χ 的接受 transcript。于是对任意 W，接受 challenge 数至多 1；fresh uniform χ 有 m bits，按 KLS 式 (3) 可得此**证明用显式均匀目标商识别**的条件统计结论

```text
εls <= 2^(-m) + p_bad.                             (S)
```

它针对挑战前提交经典 W 的全部对手（包括无界量子对手）成立，不需要经典 rewind 或提取原 key。但它仍须与一个合法 `LossyIGen`/LOSS hybrid、KLS 格式、当前 IBS 的 H1/Sign 游戏相接；(S) 不是这些接口的自动安全结论。

量级上 (B) 要求 `3^w` 大于 `G²T²` 乘常数，即约 `J B²`。若另有正确证明说明全部相关 f 都是 unit，满秩计数才可能降到约 `G T ≈ sqrt(J) B`。本页没有该 unit 证明。即使 `Q>2sqrt(B)` 已成立，也远不足以推出任一 lossy 充分条件。

## 6. 当前点失败与有界算术对照

读取冻结 [finite-search.json](../2026-10-16-srgg-hardness/finite-search.json) 的 n2048/d3/b3/w22/r²128/p53615 候选。它仍未执行、未准入；其 B 来源是公开规划公式，不是一次观测范数：

```text
Q = 1682495510936535,
B = 707692227841418072592395159552,
G = 1682488903786789,
J = 145409,
T = 641575620354117759,
q0 = 31381059609.
```

q0<G，第一前提即失败；`f=q0` 的整数范数本身已落在允许差分范围，但这不保证对当前公钥存在配套短 Δx。本页没有由“充分界失败”反推真实攻击成立。

为限定探索，只固定 n2048/d3/r²128/p53615，按已有规划**公式**计算以下六个 w，未搜索其它 p、基数或维度。w>32 已越过冻结 `build_candidate`/执行资源 guard；这是公式外推的代数对照，不是调用或放宽实际执行器。

| w | q0 位数 | G 位数 | T 位数 | `[3G(2T+1)]²` 位数 | q0>G | 式 (B)<2^-211 |
|---:|---:|---:|---:|---:|:---:|:---:|
| 22 | 35 | 51 | 60 | 225 | 否 | 否 |
| 32 | 51 | 52 | 61 | 229 | 否 | 否 |
| 64 | 102 | 53 | 63 | 236 | 是 | 否 |
| 96 | 153 | 54 | 64 | 240 | 是 | 否 |
| 128 | 203 | 55 | 65 | 242 | 是 | 否 |
| 160 | 254 | 55 | 65 | 245 | 是 | 是 |

最后一行仅证明此统计充分界可在公式上非平凡，不提供新正式参数：Q 的 bit-length 已为 270，D=`(M+1)n=997376`，实际 finite sampler、谱、TV、整体失败和资源全部待重新实例化。更大的 Q/小 CBD1 会改变困难性，lossy MLWE 又有新的 rank/sample；不得沿用 w22 的估计或认为增加模数自动增加安全。

2^-211 是明确的局部演示阈值。表检验的是 p_bad，式 (S) 还须加 `2^-m`：在 w160 行，分子位数 245、q0 位数 254，故比值严格小于 2^-8，`p_bad<2^-8191`，进而 `εls<2^-1023`；这只是该极保守充分界在巨模数公式点上的算术。若 QH=2^40，则 `8(QH+1)^2<2^84`，仅要求 εls<2^-211 仍只给该乘积小于 2^-127；若希望此 NMA 项小于 2^-128，可采用 εls<2^-212。LOSS、IBS 身份损失、其余统计项和时间预算还须另付。本页不颁布 NIST category。

## 7. 核查、复现边界与未完成项

本页算术先在 Windows Python 3.14.7 使用 exact int、`isqrt`、整数幂和交叉乘法。完整核查脚本再在指定 WSL Sage 10.9/Python 3.13.15 运行：n4 穷举 80 个非零 ternary 多项式，n8/16/32/64 各 7 个确定多项式（含两个不可约因子），共检查 108 个乘法矩阵；各组最小秩恰为 n/2。同时核对 factor degrees、`ord_4096(3)=1024`、六点精确交叉乘法和小型关系夹具，所有断言通过。小型关系用冻结 `quotient_challenge.recover` 直接检查。没有生产随机源、Gaussian、新主密钥、身份/消息或签名服务。六点各一次确定性算术，身份/消息长度、随机重复次数不适用。这些检查只支持所列代数/算术，不能代替上面的一般论证或密码学困难性。

原始核查脚本/`checks.json`/stdout 位于 `build/outputs/srgg-lossy-route-2026-10-16/`，不覆盖既有收据。脚本 SHA-256 为 `3801adff7b7a37e0a63d920b15dfdf46323e2cdb93c77e4dddd9fbc4cd48b944`；输入 finite-search.json SHA-256 为 `2eaa9969e75513d0be2f6d3f29bd9c2b07845fa7e0a5412e3b646cadeb581799`。这些 ignored 原始材料不是默认随 Git 传输的文件；本页的公式、六点范围及反例均已完整列出，移交原始材料需另行打包或按这些公式重建。正文安全标志不因非平凡局部界而改变。

```text
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python build/outputs/srgg-lossy-route-2026-10-16/check-lossy-arithmetic.py
```

另外两位代理独立只读核查 §3–5，均未发现所列条件引理的实质跳步：核对 typed 差分、J/T 的卷积界、mod3 unit minor 提升、content 计数及几何和、all-W 唯一 χ 到 KLS 式 (3) 的关系。审查没有重新运行脚本或重读全部文献，不承担上述尚未闭合的游戏/困难性条件。

尚未完成：真实 seeded Ahat 到完整均匀矩阵的 coherent 嵌入；真实 h/发钥 law 到独立 uniform h 的量子 H1 游戏；新 rank(d−1)/k-sample CBD1 MLWE 困难性与真实复合模数/环结构攻击；全部 finite/ideal 和 bottom 费用；KLS 的实际 naHVZK、min-entropy、CUR/FS 包装及 strong 组合；足够大模数点的完整参数和资源验收。当前点的充分界失败不阻塞已经实现的服务，也不能被该服务的功能测试修补。
