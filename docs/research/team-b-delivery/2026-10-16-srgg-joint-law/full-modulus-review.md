# SRGG：完整 Q、3-adic 与联合 CRT 分布审查

2026-10-16；只读代码基线 `f3831ac`。本页不改冻结算法、参数、采样器或既有收据，不运行新重型估计，也不发布。主要结论是：**实际 CBD1 公钥不能通过完整 Q 的“小 TV 到均匀”来闭合；候选甚至在 mod 9 已统计远离均匀。该结论不是已找到高效区分或伪造攻击。** 必须保留实际分布的计算 Module-LWE 假设、结构攻击和时间/优势核验。

```text
security_claim=none
backend_admitted=false
parameters_are_formal=false
nist_security_category=null
```

## 1. 审查对象和本轮实际完成范围

承接 [hardness/README](../2026-10-16-srgg-hardness/README.md)、[mod 3 联合分布](../2026-10-16-srgg-crt-review/projection-law.md)、[collapsing 路线](../2026-10-16-srgg-crt-review/collapsing-route.md) 及 [lossy 路线](../2026-10-16-srgg-classical-rom/lossy-route.md)。这些文稿的条件项、有限估计和未完成游戏继续保留，本页不覆盖其历史证据。

`structured_execution.py` 的 `setup` 每份字节用 `(x&1)-((x>>1)&1)` 得到一个独立 CBD1 系数；`ExactRing.build_public` 计算

```text
R_Q = Z_Q[X]/(X^n+1), N=dn, ell=wd,
Ahat: d by d ring matrix,
S,E <- independent coefficient-CBD1^d,
V=Ahat S+E, B_j=F_j-V, F=pG.
```

各列的 S/E 不同，全部共享 Ahat。setup 没有根据某个 witness 的观测结果反复重抽根；固定公开采样类的准入发生在 secret entropy 之前。以下支持集下界对**任意固定 Ahat** 均成立，不需要将实际 seed/SHAKE 免费改为均匀矩阵。第 5 节的正向平均 χ² 结果另需其明确的均匀矩阵前提。

冻结参数源 [finite-search.json](../2026-10-16-srgg-hardness/finite-search.json) 的 SHA-256 是 `2eaa9969e75513d0be2f6d3f29bd9c2b07845fa7e0a5412e3b646cadeb581799`。本轮重算乘积确认：

| 研究点 | N=dn | ell | Q 的分解 |
|---|---:|---:|---|
| 旧 n512/d2/b31/w8/p16383 | 1024 | 16 | `3 * 31^8 * 43 * 127` |
| 未执行候选 n2048/d3/b3/w22/p53615 | 6144 | 66 | `3^22 * 5 * 10723` |

本轮完成的是下列一般推导及不足 1 秒的整数/有理数核对，没有取得或重读新论文。它们是本项目代码分布的推论，不能署为 SRGG、LMZ22 或 KLS 原文已经证明的结果。

## 2. 完整 Q 的近均匀路线为何不可能

CBD1 的支持为 `{−1,0,1}`。固定任意 Ahat=a，令

```text
T_a = {a s+e : s,e in {−1,0,1}^N} subset R_Q^d.
```

无论环乘法产生多少碰撞，`|T_a|<=3^(2N)=9^N`，而均匀输出空间有 `Q^N` 个元素。真实输出始终落在 T_a；均匀输出落入该集合的概率至多 `9^N/Q^N`。因此，按公开矩阵分布平均后仍有

```text
TV((Ahat,V),(Ahat,U_Q)) >= 1-(9/Q)^N.                 (1)
```

同理，ell 列全部公开时，固定同一个 Ahat 的输出支持至多 `9^(N ell)`：

```text
TV((Ahat,V_1,...,V_ell),(Ahat,U_1,...,U_ell))
    >= 1-(9/Q)^(N ell).                              (2)
```

固定 F 后 `B_j=F_j-V_j` 是双射，(1)–(2) 原样适用于实际 Bpub。公开 seed、更多矩阵 coins 或重复计算 Ahat 不能补足这些条件输出的秘密熵；比较中的 Ahat/seed 两端相同。结论也不依赖 Ahat 可逆。

两点 Q 都远大于 9。例如旧 Q 大于 `2^53`、候选 Q 大于 `2^50`，且 `9<16`，故单列的保守下界分别已为 `1-2^-50176`、`1-2^-282624`。这些指数衡量统计距离接近 1 的程度，**不是安全 bits 或攻击成本**。

这不会否定计算 LWE：高效判断一个公开输出是否属于 T_a 本身就是一个结构化短秘密问题。它明确排除了“将 mod 3 的小 TV 扩展为完整 Q 的小 TV，再删掉 MLWE 假设”这一思路。也不能用低维边缘均匀性给完整输出的 TV 上界。

一个独立碰撞校验同样说明普通 χ²→TV 上界在这里必然退化。相同 `(S,E)` 至少产生同一个 V，故

```text
CP(V|A=a) >= CP(S,E)=(3/8)^(2N),
chi2((A,V)||(A,U_Q)) >= (9Q/64)^N-1.                (3)
```

这里只用重复输入造成的碰撞；不假设不同输入输出互异。大 χ² 自身不推出大 TV，(1) 的支持集事件才是所需的直接 TV 下界。

## 3. 3 的高次幂：候选在 mod 9 已远非均匀

候选 Q 含 9。即使模数恰为 9，使粗略支持大小 `9^N` 与输出大小相等，CBD1 的权重仍给出更强的 typical-set 事件。

在 S/E 的 2N 个系数中，令 K 是非零系数数目。CBD1 每个系数非零的概率为 1/2，因此 `K~Bin(2N,1/2)`、均值 N。一个有 K 个非零系数的输入对的精确概率为 `2^-(2N+K)`。

对本候选 `N=6144`，取输入集合

```text
T = {(s,e): K<=9N/8}.
```

每个集合元素概率至少 `2^(-25N/8)`，所以 `|T|<=2^(25N/8)`。另一方面，可直接由矩母函数得到

```text
E exp(lambda(K-N)) = cosh(lambda/2)^(2N)
    <= exp(N lambda^2/4),
Pr[K-N>t] <= exp(-t^2/N).
```

第一步用 `log cosh x<=x^2/2`，其导数界来自 `tanh x<=x`；第二步取 `lambda=2t/N`。令 `t=N/8`，真实输入落在 T 的概率至少 `1-exp(-N/64)`。

固定 Ahat，把 T 映射到 mod 9 输出。真实分布落在该像的概率至少上述质量；均匀分布落在该像的概率至多 `2^(25N/8)/9^N`。由精确整数不等式 `9^32>2^101`、本点 N 是 64 的倍数，以及 `exp(-x)<2^-x`，得到

```text
TV((A,V mod9),(A,U_9))
    >= 1-2^(-N/64)-2^(-N/32)
     = 1-2^-96-2^-192.                              (4)
```

此结论保留公开 Ahat、适用于任意矩阵 law。它是对真实 IID CBD1 setup 的结论；若未来引入 secret-dependent root 条件化，必须重新核算 T 的质量，但第 2 节的纯支持集下界仍成立。

(4) 严格说明 mod 3 的近均匀结果不能向 `3^w` 提升；在 w=2 就已失败。它没有给出多项式时间的像集合成员测试，不构成当前候选的有效区分攻击。

## 4. 联合 CRT：两个好边缘也可能联合远离均匀

候选 Q 含 15，因此由 (1) 直接有

```text
TV((A,V mod15),(A,U_15)) >= 1-(3/5)^N
    > 1-2^(-N/2) = 1-2^-3072.                      (5)
```

最后一步只用 `(3/5)^2<1/2`。这里 mod 3 与 mod 5 的同一秘密/误差相关性被保留；不能分别把两端边缘替换为均匀后就无偿得到联合均匀。

这也解释旧点的风险口径。其 mod 31、mod 43、mod 127 的**完整环**输出各有 `1-(9/p)^1024` 的统计距离下界；这些下界不受某个单一不可约因子可能已经充分混合的影响。完整素数投影和它的一个小次数因子投影是不同的实验。

因此，“31 因子次数 32 / 127 因子次数 8”不能直接换算攻击成本；也不能把各因子独立重新抽一份 CBD1 去代替由同一原始多项式投影的相关 law。已冻结 mod 3 两因子推导正确保留了这种相关性，它并不覆盖更大模数上的这些事件。

## 5. 候选两个其它素因子的实际投影 law

### 5.1 mod 5：可闭合的完整边缘，不能与 mod 3 拼接

对 n2048，`ord_(2n)(5)=n/2`，有两个不可约因子

```text
X^n+1=(X^(n/2)-2)(X^(n/2)+2) mod5.
```

每个输出系数由两个独立 CBD1 输入 a,b 投为 `a+2b` 或 `a-2b`。9 个输入的精确带权穷举给

```text
Pr[0]=1/4, Pr[x]=3/16 for each other x in F5,
CP=13/64.
```

令 `c5=(13/64)^(N/2)`、`C=(3/8)^N`、`t5=5^(N/2)`。均匀 Ahat 在两个因子上的矩阵投影独立；secret 的两个投影相关。沿零差分的四种模式，完整 mod 5 的公开单列满足精确恒等式

```text
chi2_5 = t5^2 C^2+2 t5 c5(c5-C)-2c5+C,
TV_5^2 <= chi2_5/4.                                (6)
```

本轮以 Python `Fraction`、整数幂及移位重算，`N=6144` 的保守 dyadic 上界是单列 `2^-1562`、共享同一 Ahat 的 66 列 `2^-1555`。不使用浮点或抽样。这是显式均匀 Ahat 模型下的边缘统计结果；实际 seed 模型对应仍需单独处理。

(5) 与 (6) 并不矛盾：mod 3 与 mod 5 分别近均匀，而它们的联合远非均匀。同一组有限熵 S/E 跨模数的相关性不能由边缘界消除。

### 5.2 mod 10723：每个因子仍完整编码原始 ternary secret

`u=1318` 满足精确等式 `u^2+2=162*10723`。令 `k=n/4=512`，则

```text
X^n+1 = (X^(2k)+uX^k-1)(X^(2k)-uX^k-1) mod10723.
```

已冻结次数记录为 `ord_4096(10723)=1024`；本轮整数模幂再核该阶。因此两个次数 1024 的因子不可约。

固定符号，对位于 `j,j+k,j+2k,j+3k` 的四个 CBD1 系数，真实投影是

```text
(a+c-u d, b-u c-d) mod10723
```

或将 u 换为 −u。它不是两份独立 CBD1。各 j 使用独立原始四系数。

更强的是，在 ternary 输入上，每个因子上的这个四元组映射**单射**。若两份四元组给相同投影，各差系数属于 `[−2,2]`，两输出差的绝对值均至多 `2u+4=2640<10723`，故模零实际为整数零。第一式中 `|Delta a+Delta c|<=4<u`，强迫 `Delta d=0`；第二式进而强迫 `Delta c=Delta b=0`，最后 `Delta a=0`。u 的负号不影响此论证。

所以 projected secret 的单因子 law 是每块 81 个不同点，每点权重为其唯一四元组的 `2^(zero count)/256`；它保留原始 secret 的全部熵，可以用固定 81 项表逐块解码一个**已经给出的** secret 投影。该性质并不让攻击者从公开 V 中直接分离 S/E。

该投影单因子向量的碰撞概率恰为 `C=(3/8)^N`；两个 secret 投影之一的差为零就意味着原始 S=S'，因此“只有一个因子为零”的概率为 0。均匀 Ahat 模型下，令 `t=10723^(N/2)`，可得

```text
chi2_one_factor = C(t C-1),
chi2_full_10723 = C(t^2 C-1).                       (7)
```

它们都非常大，χ²→TV 上界退化；同时支持集给

```text
TV_one_factor >= 1-(81/10723)^(N/2).               (8)
```

(7)–(8) 是实际有限字母表 law 的结果，不能把这个因子另当系数 CBD1、独立高斯或一份均匀秘密送入旧估计器。它提供后续结构攻击的明确输入，没有提供可行的恢复算法。

## 6. 明确可实现但不可行的支持判定成本

对任意投影模数 m 或完整 Q，可以枚举 `s in {−1,0,1}^N`，计算 `e=V-Ahat s mod m`，检查是否每个系数都可取 `{−1,0,1}`。完整模数 Q>3 时这是一个完全明确的判定算法：真实输入一定通过；均匀输入通过的概率至多 `(9/Q)^N`。若需第 3 节的 mod 9 typical-set 事件，再检查 s/e 的总非零系数数目即可。

基础枚举使用 `3^N` 个秘密。Gray code 每次改一个 ternary 系数，可按 Ahat 一列的 negacyclic 移位更新残差，使用 `O(N)` 次模加法及检查；存储原始 Ahat 为 `O(d^2 n)` 个系数，另用 `O(N)` 残差，不需要把 N×N 展开矩阵放入内存。

| 实例 | N | 仅枚举数的精确整数位区间 |
|---|---:|---|
| 旧公钥单列 | 1024 | `2^1623 <= 3^N < 2^1624` |
| 候选公钥单列 | 6144 | `2^9738 <= 3^N < 2^9739` |
| lossy 候选 rank(d−1)=2 的 secret | 4096 | `2^6492 <= 3^N < 2^6493` |

这是一个明确资源上界，远超可运行预算；不是最优攻击估计。用 Grover 搜索只是平方根数量级的额外量子算法假设/开销分析，也不会把这些数变成此刻可行的攻击。本轮未执行大维枚举、格规约、BKW、GB 或伪造。

本轮**未找到**一个具有当前可行资源的低模数/CRT 公开区分器。有限阅读和轻量算术不能推出“所有结构攻击均不存在”。旧点仍有既有约 30–58 bits 的通用攻击成本对照，已经不足以支持正式参数；这里的更慢枚举不会修复它，也不覆盖那些实际成本模型。

## 7. 四种 LWE 对象与来源必须分开

| 用途 | 实际矩阵/secret/error | 本轮可复核结论 | 不能复用的证据 |
|---|---|---|---|
| 真实 Bpub 到均匀 Bpub 的公钥 hybrid | `d by d` 环 Ahat；单列 secret/error 各 d 个环元素，均为系数 CBD1；ell 列不同秘密共享 Ahat | 上述支持/typical-set/CRT law；是计算 MLWE 问题 | 不能把 ell 列当同一秘密的 ell 倍样本；不能用统计小 TV 删掉假设 |
| 证明用 lossy key 的 LOW/RAND hybrid | `V in R_Q^((d−1) by k)`，`k=(w+1)d`；一份 secret 有 d−1 个环元素，k 个 CBD1 errors，共享同一秘密 | n2048/d3/w22 时系数 secret 4096、samples 141312；不同于上一行 | 不能沿用公钥 rank d、m=dn 的旧成本；增大 w 又改变样本数与 Q |
| LMZ22 collapsing 的原始辅助 LWE | 按所引定理的 plain scalar 矩阵、相应 secret/noise Sigma、任意模数及定理量词 | 保留一手理论的参考入口；不直接实例化为本项目的环矩阵 | 不能用 CBD1 公钥 hybrid 代替 auxiliary LWE；不能把环展开矩阵误称独立均匀 scalar |
| 新 uniform ring-HNF 相位归约的 Gaussian NF-MLWE | `M=U^dagger in R_Q^(r by d)`，`r=(w+1)d+1`；secret/error 都按明确的系数 Gaussian 抽取 | [ring-hnf-review](ring-hnf-review.md) 给出条件归约；候选系数 secret 6144、samples 143360，实际方差/困难性待核 | 不能复用前三行的已估成本或把 Gaussian width 当系数标准差；`delta=4 pi nu sqrt(Bsig)/Q` 和 `2^K` 损失须分别计费 |

尤其 lossy 的第二行并不是 collapsing 的第四行，第三行也不能直接代替第四行。LOSS 与 uniform-family collapsing 各自有不同的困难性、参数、误差与优势收费。n2048/d3/w160 的公式对照把 Q 增至约 270 bits、lossy k 增至 483（NF 的 r 则为 484）；即便某个统计充分条件非平凡，也没有核完这些新的计算假设，更不能沿用 w22 的公钥成本。

新 ring-HNF 文稿的 HNF normal-form 变换、对纠缠态的 diamond 界和 signed-polynomial 条件归约已由本代理独立只读复核，未发现该明确实验中的实质跳步。它消除了先前“尚无 uniform-ring-HNF 条件归约”的一个理论缺口；新增 Gaussian NF 实例的实际困难性、相位/采样精度及真实 seed/H1/服务 Aux 对应仍未由该推导自动解决。旧候选 `Q/sqrt(Bsig)` 约为 2，若实际系数标准差 nu>=1，其 `delta` 上界大于 1，不能由该充分界认证；这也不是攻击证明。

## 8. 对 formal candidate 的实际决策

1. **停止完整 Q 的统计均匀化目标。** 对保持 CBD1 的 n2048/d3、Q 远大于 9 的 family，增大 n、d、w 或多抽公开矩阵 coins 不能修复 (1)–(4)。这条路线已由严格下界排除，不应再建设条件证书工具试图证明其相反命题。
2. **不据此强制换 Q 或根分布。** 计算 LWE 可以有统计稀疏输出；上述结果本身不证明必须改掉当前候选。要保留 CBD1，必须接受并独立评估实际复合模数/环/投影 law 的计算假设。高启发式成本、失败攻击或高 TV 各自都不能发放等级。
3. **若改为追求统计 uniform，则是协议参数/分布变更。** 同 rank 的每系数 S/E Shannon 熵合计只有 3 bits，典型输出空间的每系数模 9 熵需求已超过它；完整 Q 更严重。扩大根分布或换生成方法会改变 root 谱/范数、几何、SampleF/HNF、服务总误差及证明接口，不能当作不影响前项的局部补丁。公开 seed 不属于隐藏 S/E 熵。
4. **不把增大 w 当通用补救。** 它可能改善某条 lossy 统计充分条件，却改变 Q/噪声比例、样本数量、体积与全部资源。当前没有新困难性验证，w160 仍只是公式对照，不能成为 formal candidate。
5. **下一项有价值的验证应直接针对明确分布。** 公钥使用本页 mod 9/15 相关性和 mod10723 的 81 点 block law 作结构攻击输入；lossy 单独给出 rank(d−1)、k samples；collapsing 使用新条件归约的 Gaussian normal-form 实例，核实际方差/困难性与完整服务视图。固定时间、成功率和查询预算后，再判断哪些参数要变。本页不通过新接口、伪造安全位数或重跑同一通用点来替代这些工作。

本页所有结论与 HIBE 选择无关。它闭合的是“能否用完整 Q 的统计近均匀省掉计算假设”这个问题，并提供明确 CRT law；没有闭合完整 Q 的计算困难性、QROM、正式参数或真实大维资源准入。

## 9. 本轮轻量验证记录与复核片段

Windows Python 3.14.7，Intel Core Ultra 7 255HX；仅执行轻量确定性整数/有理数核对，各次计算不足 1 秒。未使用身份、消息、签名、生产随机数或 Gaussian；随机重复次数、身份/消息长度不适用；没有新 ROM 实验、下载或安装。以下计算验证公开算术，不替代一般推导或安全归约。

```python
from fractions import Fraction as F
from itertools import product

law = {x: 0 for x in range(5)}
for a, b in product((-1, 0, 1), repeat=2):
    law[(a+2*b) % 5] += (2 if a == 0 else 1)*(2 if b == 0 else 1)
assert law == {0: 4, 1: 3, 2: 3, 3: 3, 4: 3}
assert sum(F(v, 16)**2 for v in law.values()) == F(13, 64)
assert 9**32 > 2**101
assert 1318**2+2 == 162*10723

def order(a, modulus):
    x, count = a % modulus, 1
    while x != 1:
        x = x*a % modulus
        count += 1
    return count

assert order(5, 4096) == order(10723, 4096) == 1024

N, columns = 6144, 66
c, C, t = F(13, 64)**(N//2), F(3, 8)**N, 5**(N//2)
square = (t*t*C*C+2*t*c*(c-C)-2*c+C)/4

def bits(value):
    b = max(0, (value.denominator.bit_length()-value.numerator.bit_length())//2)
    while value.numerator << (2*b) > value.denominator:
        b -= 1
    while value.numerator << (2*(b+1)) <= value.denominator:
        b += 1
    return b

assert bits(square) == 1562
assert bits(columns*columns*square) == 1555
assert (3**1024).bit_length() == 1624
assert (3**6144).bit_length() == 9739
assert (3**4096).bit_length() == 6493
```

没有新增独立源码/测试工具、改变旧冻结报告或把这些纯算术检查计入既有 pytest 总数。本页由 root 审查后统一提交；当前代理不 commit/push。
