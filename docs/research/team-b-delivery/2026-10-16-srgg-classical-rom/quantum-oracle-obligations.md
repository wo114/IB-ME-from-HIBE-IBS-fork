# SRGG 量子 oracle 前提：已核一手定理与尚待匹配的对象

2026-10-16。本页独立记录 QROM 的定理入口与明确阻塞，不更改冻结的 classical-ROM 证明、采样器、参数或生产接口。**本页没有证明当前 SRGG 的完整 QROM 不可伪造性。** `security_claim=none, backend_admitted=false, parameters_are_formal=false, nist_security_category=null`。

## 1. 来源和实际阅读范围

| 一手来源 | 本次核对 | 可支持的范围 |
|---|---|---|
| Grilo–Hövelmanns–Hülsing–Majenz，*Tight adaptive reprogramming in the QROM*，ASIACRYPT 2021，[arXiv 2010.15103v2](https://arxiv.org/abs/2010.15103v2) | PDF p.6–7 的 Fig.1/2、Theorem 1、Proposition 2，及 p.27–28 的多次/side-information 扩展 | 在其明确 reset 游戏中的量子区分界；不是任意相关值的改编定理 |
| Don–Fehr–Majenz–Schaffner，*Security of the Fiat–Shamir Transformation in the Quantum Random-Oracle Model*，[arXiv 1902.07556](https://arxiv.org/abs/1902.07556) | Theorem 2、21、22 及 §5 开头的 unique-response/量子知识提取区别 | measure-and-reprogram、量子 PoK→NMA 的条件路径；普通经典 fork 不能替代这些条件 |
| Zhandry，*Secure Identity-Based Encryption in the Quantum Random Oracle Model*，CRYPTO 2012，LNCS 7417，pp.758–775 | 已核作者[出版物列表](https://mzhandry.github.io/pubs.all.html)的书目和 [原报告链接](https://eprint.iacr.org/2012/076.pdf)，并读到[作者讲义](https://mzhandry.github.io/files/Z12a.slides.pdf) PDF p.28 的 semi-constant theorem | 讲义给出 `O(q^4 lambda^2)` 形式；**未取得完整论文定理条件和常数**，不能据此核准 SRGG 原文的 adapted claim |

前两份 PDF 通过只读 HTTP 获取到内存、以已有 `pdftotext` 定向阅读，未安装依赖或落盘下载。读取字节 SHA-256：GHHM 为 `9a5ea6adeba5dcdf6c80035057aaccdc704aa6ea2940af0320bcfd7eca0abc8d`；DFMS 为 `36e305e50d5f074cfb745d5a470a2757cc252019eae8d7d50a9f0fc8efee3dd1`。Zhandry 作者讲义为 `1f55d4ff81cfa062f0be649cc1a500cea45a4506eb9ec5db6ea424d605b20a36`。没有声称完整读完或重证这些论文。ePrint 原文及 IACR archive 本次均返回 HTTP 403；讲义不能补造全文中未读的假设。

SRGG 冻结原文 §4.5、p.9 的 [33] 正是以上 Zhandry IBE 论文。其 semi-constant 模拟器在目标身份 Sign 上中止，还存在跨身份相同底层 pk 的 strong 新颖性问题；这些游戏差异见冻结 [target-signing.md](../2026-10-16-srgg-reduction/target-signing.md)，不能由讲义的渐近量子界消去。

## 2. 先冻结可相干访问的对象和查询成本

量子模型须明确为有限输入寄存器的 byte/offset oracle：

```text
O_F |x,j,b> = |x,j,b XOR F(x)[j]>.
```

x 是完整 canonical frame；同一 raw-XOF 点的所有 offset/长度访问必须来自同一个固定无限流的有限可访问部分。域分隔、canonical public 参数、seed、identity/commitment/message 编码均是可逆计算的一部分。真实固定 SHAKE 的实现不构成可编程 QRO。

只讨论某个长度上界 L 的前缀时，可将其建模为 row oracle `F_L:x→{0,1}^(8L)`，再另设独立后缀 oracle。一次 byte query 用一次完整 row 读取、受控复制所需 byte、一次 uncompute 来模拟，至多两次 row query；长度受控的前缀查询也需明确相同固定输出寄存器和成本。不能把暴露任意多字节的 query 与单 byte query 混作同一个 q。

对当前 matrix 点，`L=7*256*2048=3,670,016 B` 已覆盖所有有界展开路径。row 虽大仍有限；实际 reduction 的时间、寄存器与查询次数必须包含它。下述定理不允许通过给 oracle 偷换一个小输入/输出模型来忽略这项成本。

## 3. matrix seed：初始化已知结论，预查询另行匹配

[seeded-xof.md §6](seeded-xof.md#6-qrom-的初始化法则与未闭合边界) 的初始化结论保持：在任何相关 oracle 查询和相关量子辅助态产生**之前**，完整经典函数与 public object 的 joint law 相等，后续相干算法不能区分相同的输入 ensemble。标准单次安全游戏若规定先 Setup、再启动持有独立辅助态的攻击者，则这里没有 prequery 损失。不能为了泛化到其它游戏而默认加入不属于该游戏的预查询条件。

已有量子 prehistory 时，GHHM Theorem 1 的**原游戏**为：先设 `O0` 均匀随机，`O1=O0`；每次经典 reprogram 指令给出分布 `p`，抽 `(x,x')~p`，**独立均匀**抽 y，将 `O1(x)=y`，返回 `(x,x')`。D 访问 `O_b`。令 `qhat_r` 为第 r 次指令前的累计 oracle 查询数，`pmax_r=E[max_x p_X^(r)(x)]`，则

```text
|Pr[D in Repro1=1]-Pr[D in Repro0=1]|
 <= sum_r ( sqrt(qhat_r*pmax_r) + qhat_r*pmax_r/2 ).       (AR)
```

这是已核的一手定理公式，不是本项目已有优势界。`x'` 扩展不是任意暴露新 y 的许可；如果把新值 y 本身额外返回而 no-reset world 不相应调整，后续一次 oracle 查询即可检查不一致，不能援引 (AR)。

**待独立核对的 seed 匹配方案。** 仅 reset 完整 matrix row，seed 从 256 bit 独立均匀采样，frame 单射给 `pmax=2^-256`。在每个 world 中，public 矩阵须由该 world 的**当前** row 展开后输出，并保留相同 Setup abort；不能将外部 A 当成任意相关 side information 塞进 (AR)。[seeded-xof.md](seeded-xof.md) 的 conditional-row identity 才负责将 reset world 的 uniform row/decoded A 联合分布改写成“外部 uniform A＋目标条件 row”，失败时不输出未成功解析的 public A。

若这个完整 world/auxiliary-state 匹配确实成立，且 prehistory 的 q_byte 次 byte query 用至多 `2*q_byte` 次 row query 模拟，则 (AR) 候选项为

```text
sqrt(2*q_byte/2^256) + q_byte/2^256.
```

它是**显式附加条件下**的推导，尚未写成实际 MLWE challenge reduction 或量子电路；不能把它登记为当前 IBS 已证总界。它也不同于经典 `q_pre/2^256`。例如 `q_byte=2^40` 时第一项为 `2^-107.5`，这个充分估计不能支持 128-bit 统计差目标；若游戏没有 prequery，本项严格为零，无须调整生产 seed。

## 4. H1：chosen identity 不能直接套高熵位置改编

当前经典 direct-IBS 以“raw point 首次触及”建立 `(latent U,E,Y,h,tape)`。量子对手可对多个身份叠加查询；逐点读取身份并插入 Python dict 会测量输入寄存器，改变对手态。经典 `Q_I*(delta_image+beta_H)` 及 target index 的顺序定义不能直接作为 QROM 结论。

一个可能的全域定义是先固定每个身份的独立随机 tape，再可逆计算公开 bounded `Dom`、h 和对应 raw stream。它须同时满足：

1. H1 相干查询不暴露 latent key/tape；后续经典 Extract/Sign 在同身份拿到**同一** Y 或同一持久失败。有限 sampler 中止、raw/U/HNF 门及其不可逆检查须以可逆计算和显式 bottom 一致实现。
2. 非目标身份的 image 分布 ν 到 uniform 的逐像 TV 不够；需一个明确定理将两个**相关随机函数、量子 prehistory 和经典私钥查询**连接起来。不能按“最多 q 个查询点”枚举叠加身份，亦不能无证据地填 `q*delta` 或某个平方根界。
3. 重复 hash/Extract/Sign 和多身份 alias 的 joint law 必须保持；只比较 H1 的边缘分布会丢掉已发密钥的侧信息。
4. 目标身份的位置是攻击者选择的；一般 pmax 可以等于 1，(AR) 不会因输出 h 很大而变小。高熵 h 的输出空间不等于 reprogram **输入身份**有高熵。
5. 只有在某个 k-wise/量子 PRF 实现的准确量子查询定理及额外经典服务访问数都匹配后，才可用有限 seed 表代替全函数；不能只说“可相干采样”就声称高效、一致和安全。

Zhandry [33] 的 semi-constant 分布不是通用解法：它故意把一组身份都映到同一 challenge pk，恰须重新处理目标签名转发及跨身份 strong 新颖性。原文“adapted claim”的多项式参数也不能从讲义的单 oracle 渐近式猜出。

## 5. H2 和量子提取：两个不同定理前提

**签名位置改编。** GHHM (AR) 可作为候选 H2 桥：message 部分由对手选，承诺 W 部分来自规定 Commit；需要对该分布给出逐历史 `pmax`，且新 hash challenge 是原定理允许的独立 uniform 值。承诺熵、保留的签名 norm 重试、底层模拟器产生的 `(W,c,z)` 相关性及 raw-byte 实现均须匹配。冻结 [native-sig.md §6](../2026-10-16-srgg-reduction/native-sig.md#6-承诺-min-entropy-的条件充分界) 的理想 P1 熵 36351 位并不直接证明该模拟位置/条件态的相同熵；不能先假设模拟签名已成立再用此数值关闭它。

**从 FS 伪造到短核。** DFMS Theorem 2 在其有限均匀 oracle 模型中，以单次测量与改编获得相同输入的一个接受交互 transcript；其界为二次查询损失，并有该版本明列的 additive 项。它不是“得到两个不同挑战和非零响应差”的免费量子 rewind。Theorem 21 另要求底层识别是量子 proof of knowledge；Theorem 22 又调用 naHVZK、承诺熵与 KLS CUR 等条件。

冻结完整 n-bit c 关系已有不同 c、相同 eta 的零差分反例，故不能把普通 two-full-challenge special soundness 当成已成立。即使通过量子 MSIS 假设排除同挑战两响应，CUR 也不自动等于量子 PoK。KLS Theorem 3.3 的 NMA 项仍需独立归约；Theorem 3.4 的 lossy-key/lossy-soundness 路线也需另证，普通 B-public uniform hybrid 不是 lossy-soundness 证书。

## 6. 已完成的商挑战引理与剩余量子义务

写 `c=a+X^(n/2)b`，`chi=eta(c)=a XOR b`。[quotient-challenge.md](quotient-challenge.md) 已证明：完整 uniform c 与独立 uniform `(chi,b)` 的可逆输出重标记；同 chi 的规范化理想 coset/响应 law 相同；固定完整 oracle 的**接受签名域**逐点双射及 exact-triple strong 日志保持；完整 n-bit XOR oracle 的相干 CNOT 共轭身份。该文还给出了对全部准入 center 统一有效、fresh sampler coins 独立于条件量子 reference 时的有限 u 替换费用，并保留 bottom、norm retry 和资源上限。

这些引理已经修复“不同 full c 仍可能零差分”的那项商空间代数障碍；它们没有关闭完整 QROM 游戏。H2 partial-byte/offset raw 包装、额外 Hb 的统一查询和时间费用、全部 finite-P/发钥/FS 的整场条件态替换、coherent H1 chosen-identity 模拟，以及量子提取器和正确 witness relation 仍须分别对齐。商方案的短核 witness 不能冒充原 key 的 preimage witness。[lossy-route.md](lossy-route.md) 另外给出证明用显式 uniform 目标下的条件 lossy-soundness 充分界，当前参数点不满足；它未给出真实 seeded 公钥的 LOSS 嵌入，不能据此关闭 KLS 的 UF-NMA 项。

以上前提文稿可独立审查。当前没有新量子模拟器、量子攻击实验、n512 生命周期或安全等级测试；原始 HIBE 未选定不影响这些 IBS 内部义务，但这些义务也不会因选择某个 HIBE 自动消失。
