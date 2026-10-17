# SRGG 公开 seed：理想 XOF 字节前缀的条件嵌入

2026-10-16。本文闭合一个此前独立列明的条件引理：**在公开矩阵展开使用理想 byte-XOF、归约能控制同一原始 oracle 接口且在相关查询前初始化时，可以给定一份均匀 Ahat，再生成与其一致的公开 seed/XOF，完整 Setup 实验保留失败后与诚实法则完全相同。** 不是保留 seed 却独立修改 Ahat，也不是求出真实 SHAKE 的逆像。本文不修改冻结的 `srgg-bridge` 或 `srgg-reduction`（后者提交 `63ea9fc`），不实现生产 QRO，不证明底层 MLWE/MSIS、IBS 或完整 QROM 安全。标志保持 `security_claim=none, backend_admitted=false, parameters_are_formal=false`。

## 1. 实际代码所要求的一致性

只读来源为 `experiments/research/candidates/srgg/structured_execution.py` 的 `Execution.setup/public_matrix/Public`，以及 `experiments/research/candidates/wang_pw/hashing.py` 的 `XOFStream/uniform_values`；规范 frame 来自 `src/ibme/core/encoding.py::encode_bytes`。生成报告记录这些文件和新工具的 SHA-256；没有修改任何上述原始文件。

Setup 先读 32 B seed 和独立的 CBD1 witness；随后在下列原始 SHAKE 输入点展开矩阵：

```text
x_sigma = frame(DOMAIN, b"matrix", canonical(all ExecutionParams), sigma).
N = rank^2 * degree.
stream = XOFStream(x_sigma, N*4096).
Ahat = reshape(uniform_values(stream,Q,N)).
```

`frame` 对每个字段使用 uint32 长度前缀，因此对固定 DOMAIN/参数，32 B seed 到原始输入点的映射是单射；matrix、identity 和 message 的域字段不同。`Public` 构造时重新调用 `public_matrix(params,seed)` 检查 Ahat，`Public.to_bytes()` 只编码 params、seed、Bpub。攻击者也能直接重算同一 raw XOF point。因此只替换函数返回值、不替换整个 oracle point，会被立即发现。

`XOFStream` 每次 `.digest(length)` 读取同一个 SHAKE 输出的前缀，内部预取至少 4096 B 并按需增长；它不是每次另抽一条流。下文将 SHAKE **显式建模**为：每个原始输入 x 对应一条独立无限均匀字节流 F(x)，所有长度/offset 读取都投影于这一条流。实际固定 SHAKE 是否可用该模型分析，是模型假设，不由本引理证明。

## 2. 一般拒绝采样与目标条件前缀

令一次候选 word 的范围为 `[0,M)`，`M=2^(8*width)`（有限模型也允许缩小 bit width）；令

```text
K=floor(M/Q), limit=KQ,
R=M-limit, rho=R/M, T=max_trials.
```

真实 `uniform_values` 对每个系数至多读 T 个 word：`word<limit` 时输出 `word mod Q`，否则继续；T 次全拒则抛异常，不继续解析后面的系数。

给定目标向量 `a=(a_1,...,a_N)`，构造**保留失败的目标前缀生成器**。对当前第 i 个系数的每次尝试：

1. 以 rho 的概率选择拒绝，word 均匀取自 `[limit,M)`。
2. 否则接受，独立均匀取 `k in {0,...,K-1}`，word=`a_i+kQ`，开始下一个系数。
3. 第 T 次仍拒绝则整个 Setup 失败，停止；不能换 seed 重试。
4. 完成或失败后，剩余所有字节仍为 fresh iid uniform。

每个具体拒绝 word 的条件概率为 `rho/R=1/M`；每个当前目标的具体接受 lift 概率为 `(1-rho)/K=Q/M`。R=0 时拒绝分支为空，不需要做除零运算。实际数值不是均匀在 `[0,Q)` 的 word：必须保留全部 K 个等概率 lift 和拒绝区字节，否则原始 XOF 可区分。

“目标前缀”不是 `F | Parse(F)=a` 的无条件同义词：后者在定义上已成功；上面仍有失败概率。若先删除失败再强制编程成功，得到的是成功条件实验，必须另付条件化/失败损失。本文采用保留失败的完整实验。

## 3. 完整轨迹和原始 oracle 的精确同分布证明

把轨迹定义为 `(all consumed words, accepted residues, success/abort)`。设某条轨迹在停止前已经接受 j 个系数，总共消耗 l 个 word。

**引理 1。** 给定目标 a，若轨迹已经接受的前缀等于 `a[1:j]`，其目标生成概率为 `Q^j M^-l`；不等则概率为零。相同轨迹在原始 iid word 流中的概率恰为 `M^-l`。

证明：每个拒绝 word 贡献 `1/M`，每个接受 word 贡献 `Q/M`。固定完整 word 序列后，接受、当前系数及 T 次失败的停点都是确定的；没有另一条隐藏解析路径。成功时 j=N，失败时 j<N。证毕。

**定理 2（均匀目标混合的完整 law）。** 若 a 从 `[0,Q)^N` 均匀取，目标生成器的完整轨迹 law 等于诚实 iid word 解析的 law，包含失败。

证明：对于已经接受 j 个系数的任意轨迹，共有 `Q^(N-j)` 份目标 a 与此前缀匹配。对引理 1 平均得到

```text
Q^(N-j) * Q^-N * Q^j * M^-l = M^-l.
```

这同时处理成功和第一个 T 次全拒失败，不需要挑选成功的目标或 seed。成功分支的解析矩阵恰为给定 a。失败分支没有公开矩阵；若分析中保留外部的完整 a，诚实实验可将已解析前缀保留、尚未使用的系数补为独立均匀值，得到相同的辅助变量联合 law。不能把失败时的实际 `Parse(F)=bottom` 写成等于 a。证毕。

现在把停止后的流补为独立均匀后缀。轨迹的 word 序列构成一个有界 stopping-prefix 分割：对任何固定观察长度，较长轨迹投影为已有前缀，较短轨迹补独立均匀字节。由定理 2，任何观察长度的 law 与诚实 iid 流相同，且不同长度相互是同一流的前缀。真实 XOF 缓存预读、Public 重算、攻击者请求短前缀再请求长前缀，都必须读取这个预先一致的流；不能暴露一个前缀后另行重抽与目标兼容的内容。

选择独立均匀 seed sigma，在相关点尚未被观察时，将 F(x_sigma) 初始化为上述流，所有其它原始输入点仍独立均匀。给定外部均匀 Ahat 的挑战可以携带依赖于 Ahat 的其它挑战数据，前提是它们的条件 law 与当前硬度 hybrid 要模拟的公开 Bpub/目标一致，并且不另外依赖原 XOF。成功时构造 `(params,sigma,Ahat,Bpub)` 会通过 `Public` 的同一 oracle 重算检查。失败时整个 Setup 返回 bottom，不先泄露另一个不匹配的 public object。由定理 2，`(Setup result, exposed ideal F)` 联合分布与对应诚实 hybrid 相同。

本结论解决的是**均匀矩阵挑战与公开 seed 一致嵌入的机制**。它不把 Bpub 自动变成均匀，也不替代 CBD1 多列 Module-LWE hybrid、HNF-MSIS 假设、identity image/发钥、FS、strong 新鲜性或它们的运行成本。

## 4. 当前 n512 的所有 XOF Setup 失败与字节预算项

现有点 `n=512,d=2,p=16383,b=31,w=8` 给

```text
Q=13972913866395903,
width=7 B, M=2^56=72057594037927936,
K=5, limit=69864569331979515,
R=2193024705948421,
rho=2193024705948421/72057594037927936 < 1/32,
T=256.
```

解析每个系数的成功率是 `1-rho^256`，与目标值无关。各个系数在 iid 流上依次使用 fresh words，所以 N 系数展开的精确失败率是 `1-(1-rho^256)^N`。以下用精确 Fraction 和整数比较给出严格有理上界，未用浮点下溢删除失败。

| 展开点 | 系数数 N | 最坏实际消费 `7*256*N` | `N*4096` read budget | SHAKE prefix cache 上界 | trial-limit 失败界 |
|---|---:|---:|---:|---:|---|
| 根 public matrix | 2048 | 3,670,016 B | 8,388,608 B | 4,194,304 B | `<=2048*rho^256<2^-1278` |
| 一次 identity target | 1024 | 1,835,008 B | 4,194,304 B | 2,097,152 B | `<=1024*rho^256<2^-1279` |

read budget 已覆盖所有最大尝试路径，因而在此模型内**额外 byte-budget failure 为零**。缓存是同一 oracle stream 的确定前缀预取，不增加独立失败概率。`Public.__post_init__` 的重算也不是第二次独立 hash 试验：第一次成功时，同一点的每个前缀固定，重算必定相同成功。

这些只是 XOF 拒绝/读取相关的全部 Setup 项；不对 OS 随机源异常、内存/算术/库错误或硬件故障指定概率，也不把本引理说成可运行 `2^40` 次服务的容量证明。真实 SHAKE 相对理想 XOF 的模型差异亦不计为一个已证数值。

## 5. 经典预查询：保留 seed，一次性付碰中事件

如果攻击者在 seed 采样前已有最多 q_pre 个经典原始 XOF 输入查询，固定参数的每个不同输入至多对应一个 seed。seed 仍独立均匀取自 256 位，因此

```text
Pr[x_sigma was queried] <= min(1,q_pre/2^256).
```

reduction 可把碰中事件标 bad 并失败，**不重新选 seed**。在未碰中时该点仍是 fresh ideal stream，§3 的条件编程完全适用；故额外分布损失至多此概率。q_pre 可保守使用全部查询数，也须包括归约或先前 Setup 已经暴露的相关点；相同 raw point 的重复长度查询只增加一个 distinct point，但用总数仍合法。q_pre=`2^40` 时上界为 `2^-216`。

该 classical bound 依赖 prehistory 与新 seed 独立，以及原始 frame 单射。更换参数时必须使用完整 canonical ExecutionParams；不能省略一个字段后把另一个 oracle point 当成同点。

## 6. QROM 的初始化法则与未闭合边界

若**严格在任何攻击者量子 oracle query 之前**初始化，且没有与旧 oracle 相关的量子辅助态，§3 给的是整个经典 oracle 函数及 public object 的联合 law 相等。随后对某个已固定函数施加其 coherent query unitary 是一个相同的物理过程；所以任何后续量子区分器的输出 law 也相同。这是初始化时的分布事实，不需要将“已被量子查询的点”重编程。

可以明确给出一个有限前缀 overlay 的理想模型实现论证：固定 `Lmax=7*256*N`，先生成目标条件停止前缀，再以 fresh iid bytes 补到 Lmax，得到 S。对一个底层独立 ideal byte oracle F0，内部读取 `F0(x_sigma)[0:Lmax]`，保存差值 `Delta=F0(x_sigma)[0:Lmax] XOR S`。只向攻击者暴露

```text
F'(x)[j] = F0(x)[j] XOR Delta[j], if x=x_sigma and 0<=j<Lmax;
           F0(x)[j], otherwise.
```

点比较、offset 比较和有限表 lookup 都可实现为可逆计算；coherent 访问只用同一 F'。底层 F0、内部预读内容和 Delta 不另向攻击者暴露。Lmax 后的 F0 后缀独立 fresh，故与上面的完整流一致。该论证明确采用可相干访问的 ideal-byte/offset 接口、长度为多项式的有限前缀以及可控制全部相关 raw-XOF 调用的 reduction；本工具**没有实现这个 QRO**，也没有把固定真实 SHAKE 变成可编程 oracle。

若攻击者已经有量子预查询或与 F0 相关的辅助态，以上初始化论证不再适用；不能以经典 `q_pre/2^256` 代替量子改编损失。需要另给 quantum search/reprogramming 引理和查询接口/成本，本文没有填入一个未经证明的 q 或平方根界。即使初始化条件成立，底层 SIG/IBS 的 FS、分区身份、target Sign、新鲜性及 QROM extraction 等其它义务仍开放，不能由本节宣称完成 QROM IBS 安全。

## 7. H1 raw first-touch、非均匀 latentPair 与成功条件前缀

同一论证须覆盖 `identity_target` 的原始 XOF 点，而不只覆盖 matrix 域。对固定当前 public object，合法身份点为 `frame(DOMAIN,b"identity",public.to_bytes(),id)`，其中 id 满足实际代码的非空、长度上界和规范 frame 要求。第一次匹配点的**任何非空原始输出查询**就应建立 entry，包括仅请求 1 B、任意前缀或采用 offset 模型时仅请求某个后缀字节；Sign/Extract/H1/最终验证的内部首次使用也同样建立。entry 固定该身份的 latent key/pair、目标 h 和完整原始前缀/后缀 tape，后续所有长度读取复用它。若先回答一部分 raw XOF，再等完整 H1 解析时选择 h，便不再是一个 fresh-point 条件编程。

令 H=`dn` 是身份目标的系数数，G_h 是 §2 的**含 abort**目标 kernel。对每个 h，其成功率均为 `s_H=(1-rho^T)^H`，与 h 和 latent key 无关。令 `S` 为解码成功，则

```text
sum_h Uniform(h)*G_h = Raw,
K_h := G_h | S,
sum_h Uniform(h)*K_h = Raw | S,
TV(Raw|S,Raw) = beta_H := 1-s_H.
```

这里 K_h 必须采完整候选轨迹，而不只是模 Q 输出；例如每个系数的拒绝次数 r 在 `0..T-1` 中以 `rho^r*(1-rho)/(1-rho^T)` 取值，再取 r 个均匀 reject words 和一个均匀接受 lift，停止后续 fresh suffix。这是 reduction 在暴露 raw 点之前取条件 tape 的公开数学 kernel，不是把生产 H1 的失败偷偷改成重试。成功条件化删去的原始流质量 beta_H 必须作为 hashbad 支付。

若非目标身份先公开采 latentPair `Y~Dom,h=f(Y)`，h 的 law 是 nu，且 `Law(Y|h)=L_h`，再独立于 Y（条件于 h）取 K_h，那么与 `h uniform,Y~L_h,F~K_h` 的完整联合 TV 恰为 `TV(nu,Uniform)`：对每个 h，条件 key/prefix kernel 的总质量为 1。这包含 key、h 和全部 raw 字节的相关性，不是仅看单个 H1 marginal。再与未条件化诚实 raw law 比较，充分界为

```text
delta_image + beta_H, where delta_image >= TV(nu,Uniform).
```

目标 h 若来自外部均匀挑战，则没有这一个 image 项，但仍需同一成功 kernel 和 beta_H 桥。实际 latentPair 若还存在 sampler/norm/abort 误差，应另外用完整 law 支付；本式没有删去这些失败，也没有替代 fixed-key 接口条件。

对自适应 first-touch，只要上述界逐共同历史统一成立，按不同 identity entry 的总上界 Q_I 可保守累计 `Q_I*(delta_image+beta_H)`，其中纯 hashbad 至多 `Q_I*beta_H`。同一点后来请求更多 prefix/字节不再次支付；所有匹配 raw first-touch 都须计入 Q_I，不能只数 API 的 H1 或 Sign 次数。当前 H=1024 时 `beta_H<=1024*rho^256<2^-1279`。碰到已暴露的点不能重新条件编程；现有 quantum prequery/相干 first-touch 仍受 §6 的未闭合边界限制。

## 8. 新工具、证据与复现

`experiments/research/candidates/srgg/seeded_xof.py` 为纯 Python exact Fraction 工具，不生成私钥，也不调用生产随机源。有限模型枚举完整 word 轨迹、接受前缀及 abort；目标固定时在每次接受处增加 Q 因子，均匀目标混合后逐轨迹恢复原始 iid law。它另将停止后的流续为独立后缀，检查不同观察长度的一致前缀。

```text
python -m experiments.research.candidates.srgg.seeded_xof --output build/outputs/srgg-classical-rom-2026-10-16/seeded-xof.json
python -m pytest -q tests/test_srgg_seeded_xof.py --junitxml=build/outputs/srgg-classical-rom-2026-10-16/seeded-xof.junit.xml
```

测试 **21 passed**。包括：不同 Q/M 的完整轨迹等式、失败前已接受系数的 `Q^j` 因子、256 次全拒的精确质量、q=251 单字节候选的全部轨迹重放通过真实 `wang_pw.hashing.uniform_values`、任意长短前缀/停止后 fresh 后缀、固定目标/均匀目标混合的区别、当前 7 B 的 5 个 lift、全部 raw budget、经典 seed 碰中及有限模型资源上限。

实验是确定性有限枚举和数学算术，不设随机重复次数；无身份/消息/密钥采样、无 Gaussian 或实际密码学攻击，无新依赖。模型明确使用理想 XOF/ROM，实际工具不运行 oracle 服务。Python 3.14.7 / Windows 11 10.0.26200。JSON 与 JUnit 写入上面的新 build 目录；输入及四个源码 SHA-256 记录在 JSON 中。有限测试不是安全证明，§2–6 的一般条件引理和模型边界由正文推导承担。
