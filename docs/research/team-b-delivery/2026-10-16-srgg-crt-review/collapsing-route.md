# SRGG 的公开辅助信息 collapsing 路线：CRT、refinement 与双端 hybrid

2026-10-16；代码基线 `515ca5a`。本页证明若干有明确量词的条件变换，并记录本轮新核对的一手文献。**普通 SIS 已有任意模数的 collapsing 结果；当前复合模数环 HNF 分布、真实服务辅助信息及具体参数与该结果的对应尚未闭合。** 没有修改冻结协议、参数、采样器、接口、H2 包装或证据清单，没有给 collapsing 填入未经证明的数值。

```text
security_claim=none
backend_admitted=false
parameters_are_formal=false
nist_security_category=null
```

## 1. 文献核读范围与目前能够引用的结果

一手来源是 Jiahui Liu、Hart Montgomery、Mark Zhandry，*Another Round of Breaking and Making Quantum Money: How to Not Build It from Lattices, and More*，[arXiv 2211.11994v2](https://arxiv.org/abs/2211.11994v2)，2022-12-30 版本；同时核对 [NTT 作者 PDF](https://ntt-research.com/wp-content/uploads/2023/01/Another-Round-of-Breaking-and-Making-Quantum-Money-1.pdf)。本文简称 **LMZ22**，不把作者 Montgomery 误写为其它作者。arXiv PDF 本轮以内存 HTTP 读取，710070 B，SHA-256：

```text
c73f31e96ef46c095f60a11f697f11b6e3773b5d76b53daf1ba70e41f96a33e1
```

实际定向核读 arXiv PDF p.20–25 的 §7.1–7.3、Problem 4、Theorem 5 及其测量论证；并核对 NTT PDF 的 §5.3–5.4 定义、Appendix B.1–B.4 的 lemma 陈述及归约对象。两个 PDF 的上述分页相差一页；Theorem 5 分别为 arXiv PDF p.22、NTT PDF p.21。没有声称全文或 Appendix B 每个证明均已重证。

Theorem 5 的 `ell=0` 情形明确给普通 SIS 哈希的任意模数 collapsing 结论，其前提包含适当的 plain LWE 困难性和

```text
q / (W * Sigma) = omega(sqrt(log lambda)),       ||y||_2 <= W.       (LMZ-gate)
```

W 是欧氏范数上界，不能把本项目的范数平方上界直接代入 W。该结果改进了 Liu–Zhandry 2019 的模数限制。这里关于旧结果的比较仅按 LMZ22 的原文说明引用；本轮未取得 LZ19 正文，不冒称完成 LZ19 独立核读。

LMZ22 的 §7.1 在标量矩阵空间中抽随机 A，Appendix B 处理 plain scalar LWE / k-LWE、secret distribution 和 modulus switching；本轮核读未找到对 `Z_Q[X]/(X^n+1)` 的 negacyclic block 分布或本项目 seeded public object 的直接实例化定理。因此合数 Q **本身不是否定适用性的理由**；但把环矩阵展开成整数系数矩阵，并不会使它成为普通独立均匀标量矩阵。定理中的矩阵分布、LWE 问题与短域必须继续对应，不能凭任意模数四字跳过这一步。

辅助参考是 DFMS，[arXiv 1902.07556](https://arxiv.org/abs/1902.07556)，实际核读 §5 Definitions 23–24、Theorem 25 及 §6.2 Assumption 27。其 Assumption 27 是有限域上的普通短域线性哈希假设；它不能代替上述环 HNF 对应。关系类型、带坏挑战的 2-soundness、DFMS 条件提取式见已冻结的 [quantum-relation-review.md](../2026-10-16-srgg-bounded-runner/quantum-relation-review.md)。已经完成的 H2 原始字节共轭包装见 [raw-h2-relabel.md](../2026-10-16-srgg-bounded-runner/raw-h2-relabel.md)，这里不重新登记为未证事项。

## 2. 本页实验的量词、aux 和实际排除项

令 `R_Z=Z[X]/(X^n+1)`，n 为至少 4 的二次幂，Q 为奇数，`R_Q=R_Z/QR_Z`。A 有 d 行、`L=(w+2)d` 个环列，`h in R_Q^d`，并令

```text
A=[I_d | Ahat | Bpub],
zeta=1+X^(n/2), zeta*=1-X^(n/2), j=(zeta*,0,...,0)^T,
C=[A | -h], M_h=[2A | Qj-2h] mod2Q,
D={z in R_Z^(L+1): ||z||_2^2 <= Bsig},
g_C(z)=Cz modQ, f_x(z)=M_h*z mod2Q,
t(z)=j*z_last mod2.
```

为避免与 LMZ22 短核向量个数 ell 混用，本页用 L 表示本项目的 A 列数。输入由规范整数系数编码，D 是有限输入集合，范数在系数空间计算。

本页的 keyed collapsing 实验先抽 public key，隐藏生成器秘密；初始 quantum advice 在 setup 前生成且独立于 setup coins。之后对手可以根据全部 public key、允许的公共 oracle 及公开可生成的 aux 准备任意纠缠态。第一阶段输出响应寄存器 Z 和保留寄存器 S，challenger coherently 检查 D、计算并测量哈希像；按世界位 b 决定是否再在规范基测量 Z；第二阶段区分。允许第一阶段自适应选择测得的输出，没有强制诚实响应分布或固定承诺。

aux 的分布由一个明确的公开模拟器 `Aux(pk, public_oracles)` 生成；其随机性可以与对手保留态纠缠，但不得调用隐藏的 setup witness、目标用户私钥或 master trapdoor。公开之后产生的相关性是允许的；独立性约束针对 setup 前 advice 的秘密来源。若希望加入其它身份的 Extract 或签名 transcript，须给出它们相对于每个挑战 public key 的联合模拟，证明及收费后才能扩充本页实验。**不能假定提取 hybrid 自然拿到诚实目标密钥作为 aux。**

下文范数判定的失败保留为显式 bottom/拒绝分支；使用整个实验的非归一化接受质量。不得对罕见的接受事件条件化后把 distinguishing advantage 无偿放大。

## 3. 可证子引理：确定 refinement 和 CRT 不增 advantage

**命题 1（相同 key/aux 模型的确定 refinement）。** 若短域 g_C 是 collapsing，则 `(g_C,t)` 在同一 D 上 collapsing，且每个 refinement 区分器均可给出不增 advantage 的 g_C 区分器。

证明：在 g_C 实验的第一阶段，运行 refinement 对手的第一阶段，先测量并保留 D 的成员标志。仅在通过分支 coherently 计算 t(Z)，测量其输出 T 并保留 T；随后把同一个 Z 交给 g_C challenger，后者重复 D 检查时确定通过。拒绝分支保留两实验约定的同一 reject/bottom 及侧信息，不计算、测量或额外公开 t，因而不对其保留的 Z 额外去相干。在通过分支，g_C 的输出投影、t 的输出投影、D 投影和规范基 Z 测量均在 Z 的同一规范基中对角，故交换先后顺序给相同联合状态。第二阶段按原实验约定把 g_C 值、T 或 bottom 交回原区分器。两个 b 世界分别与 refinement 游戏完全同 law，包括未归一化的失败质量。该构造只测公开函数，不生成 witness，也不改变 setup 分布、aux 来源、公开 oracle 访问次数或 abort 质量。

**命题 2（CRT 输出重标记）。** Q 为奇数时，f_x 在 D 上的 collapsing 游戏与 `(g_C,t)` 完全同构：

```text
f_x(z) modQ = 2*Cz modQ,
f_x(z) mod2 = j*z_last mod2.
```

因为 2 在模 Q 下可逆，`y -> ((2^-1*y) modQ, y mod2)` 是 `R_(2Q)^d -> R_Q^d x R_2^d` 的公开双射，其逆由逐系数 CRT 给出。哈希输出寄存器的双射重标记不改变响应寄存器投影或区分概率。结合命题 1，

```text
Adv_col(f_real; D,Aux) <= Adv_col(g_real; D,Aux).                    (1)
```

如果响应关系是 `f_x(z)=W+Qj*c0(chi)`，或原 full-c 版本，对已测量的公开挑战，等式右边只是公开输出平移。保留 W/challenge 与其它公开寄存器即可同样构造关系 QCUR 实验的条件包装；没有删除 parity 信息，也没有改变 full-c 为商挑战。此处得到的是本节量词下的平均 keyed-family 包装，不是对每个 x、每个含秘密 advice 的 witness-robust QCUR 声明。把它接入提取器还要证明提取器每个测量 hybrid 的 key/aux 都在该量词范围内。

## 4. 真实 Bpub 到 uniform ring-HNF：每端分别收费

先明确一个可供继续证明的 uniform ring-HNF 目标：

```text
C_U=[I_d | U], U uniform in R_Q^(d x ((w+1)d+1)),
same D, same allowed public Aux, same public oracle model.
```

记该 family 在指定时间/查询预算下的 collapsing 上界为 `epsilon_HNF`。这是本页的**条件项**，不是已经由 LMZ22 自动证明的实际数值。

暂只处理显式公开代数分布：`Ahat uniform in R_Q^(dxd)`，`h uniform in R_Q^d` 独立于 Ahat、所有 trapdoor columns 和对手 setup 前 advice。令 F 为公开固定 gadget，真实矩阵满足

```text
Bpub = F - R0 - Ahat*R1 modQ,
R0,R1 in R_Z^(d x wd), each coefficient independently CBD1.
```

这些公式对应冻结 `structured_execution.py` 的 `ExactRing.gadget/build_public`；CBD1 指系数分布，不是对所有 {-1,0,1} 等概率抽样。

令 `k=wd`，定义 k+1 个 public-key hybrids G_i：Bpub 前 i 列替换为独立均匀环向量，其余列保留真实公式。对每个相邻 G_(i-1)/G_i、每个固定测量位 b，区分器 D_(i,b) 收到一个 shared-Ahat decisional Module-LWE 向量挑战

```text
(Ahat,v),
LWE: v=Ahat*s+e, s,e independent coefficient-CBD1,
RAND: v independent uniform in R_Q^d.
```

它把第 i 列设为 `F_i-v`，前列自行抽均匀，后列自行采 CBD1 s/e 并用同一个 Ahat 构造；再独立抽 h，运行 Aux 和 collapsing 实验的 b 世界。因此 LWE 和 RAND 恰对应两个相邻 public-key hybrids。I 首块、环、Q、短域/范数、parity、商挑战/full-c 的结构都保持不变。最后所有非 I 环列（包括 -h）联合独立均匀，正是 C_U。

记 p_(b,i) 为测量位 b、key hybrid G_i 的输出 1 概率。直接三角不等式给出

```text
|p_(0,0)-p_(1,0)|
 <= |p_(0,k)-p_(1,k)|
    + sum_i ( |p_(0,i-1)-p_(0,i)| + |p_(1,i-1)-p_(1,i)| )
 <= epsilon_HNF + sum_i [Adv_MLWE(D_(i,0))+Adv_MLWE(D_(i,1))].       (2)
```

若每端同一第 i 列预算均可界为 epsilon_i，则 (1)–(2) 给

```text
Adv_col(f_real) <= epsilon_HNF + 2*sum_i epsilon_i.                 (3)
```

系数 2 来自 collapsing 的两端分别更换 public key；不能把它吞成一次 hybrid，也不能把 MLWE 损失擅自放进 DFMS 成功率的立方内部。符号 (3) 不代表已经估出 epsilon_i 或 epsilon_HNF。

每个 D_(i,b) 只接收一个经典描述的 `(Ahat,v)` 挑战，运行 collapsing 对手第一、第二阶段各一次，Aux 一次，执行一次公开映射/范数/可选响应测量。它保留对手原来的 public oracle 权限及预算；没有额外 Extract/目标 sk/master-trapdoor oracle。其时间为

```text
T_Aux + T_D1 + T_D2 + T_fill + poly(d,L,n,logQ,logBsig).
```

例如 schoolbook 公开环 matvec 需要 `O(d(L+1)n^2)` 次模标量乘法；这只是模拟开销阶，不是性能实测。使用 QROM aux 时还须给出同一独立 oracle 的相干模拟、query 计数及编程损失，不能把真实 SHAKE 当免费可编程随机 oracle。精确均匀有限抽样可在理想随机带/期望时间 rejection 模型中定义；若归约必须硬 PPT，需给出 bounded rejection 及两端失败损失。近似 Aux/source 在各端的联合 trace-distance 误差应逐端加入 (2)，不能填零或靠后选删除。

## 5. h 和服务分布：不可放宽的两条边界

**独立 uniform h 不能直接改成 adversarially chosen ring target。** 若允许无条件指定 h=0，并且 `Bsig>=2`，令 `z0=0`、`z1=(0,...,0,zeta)`。则

```text
j*zeta=(2,0,...,0)^T,
M_0*z1=Q*j*zeta=0 mod2Q,
||z1||_2^2=2.
```

对 `W=0,chi=0`，这两个公开可知的响应均接受；无需任何私钥 aux 即可准备它们的等权叠加。对该叠加的投影在未测量世界成功率 1，测量响应后成功率 1/2，区分概率差为 1/2。这否定“任意 chosen h 都 collapsing”的加强量词。它不是对真实 H1 的公开伪造：选择身份不等于能任意设置 H1(id)=0；uniform h 模型也不能被单个罕见 target 反例取代。适应性 chosen identity 需要自己在实际 H1 oracle 模型中处理，并收费相应 target 选择/编程/相关性；(3) 不自动覆盖它。

**显式代数 public-key 分布不能直接改名为生产服务分布。** 生产公钥含 seed 和可重算的 SHAKE 展开一致性；显式 Ahat 挑战不自带使其成立的 seed。真实 root 成功条件化、其它身份发钥、签名 transcript 和目标 H1 也可能引入联合相关性。先前已证明的经典 seed/namespace 子引理继续有效；它们不能直接被拿来补一个未经证明的量子 seeded embedding。只有对整个服务视图给出保持上述 aux 量词的联合桥，才可把 (3) 用于该真实服务。没有这种桥时，本页不声称“不能证明”或“已攻破”真实服务，只标记本链覆盖的明确分布。

## 6. 参数 gate：现有整数点不能直接套渐近定理

冻结 n512d2 点来自 [structured-execution-n512-d2w8.json](../2026-10-16-srgg-bridge/structured-execution-n512-d2w8.json)。旧 n2048d3 候选来自 [lossy-route.md §6](../2026-10-16-srgg-proof-followup/lossy-route.md) 及 [finite-search.json](../2026-10-16-srgg-hardness/finite-search.json)。这里只对原值作精确整数核算，不把旧候选提升为新准入参数。

| 点 | Q | Bsig | Q/sqrt(Bsig)（十进制仅示意） |
|---|---:|---:|---:|
| n512,d2,b31,w8 | 13972913866395903 | 238255596480161099521436160 | 905.2435238862 |
| 旧 n2048,d3,b3,w22 | 1682495510936535 | 707692227841418072592395159552 | 2.0000078540 |

可无浮点验证的证书是

```text
n512: 905^2 * Bsig <= Q^2 < 906^2 * Bsig,
Q^2=195242321917718902992738735185409;

old n2048: 2^2 * Bsig <= Q^2 < 3^2 * Bsig,
Q^2=2830791144321591965792797806225.
```

当前 C_U 在 n512 点有 2 个环行、21 个环列，其中 I2 后有 19 个独立均匀环列；系数展开为 1024×10752 的 negacyclic block 矩阵，**不是** 1024×10752 个独立均匀标量。LMZ-gate 在这里应读作 `Q/(sqrt(Bsig)*Sigma)`；增大 Sigma 会减小左边，不能用“增大噪声就更难”替代这项约束。旧 minQ 设计点的比值约 2，尤其不能据它无条件选择增大的 Sigma。n512 的约 905 也仍需要具体 Sigma、相应 LWE 归约与困难性，而不是一个安全等级。

`omega(sqrt(log lambda))` 是渐近 family 条件，不是给固定点选择一个常数 cutoff 后宣布通过。LMZ22 的 plain LWE/Gaussian 条件不能与 (2) 中 composite-Q、CBD1、shared-Ahat Module-LWE 公钥 hybrid 混成同一个已有假设。它们分别服务于 uniform-family collapsing 和真实公钥替换；都要保留其来源及预算。

## 7. ARU14 提供的一般边界，与当前实例的区别

一手来源是 Ambainis–Rosmanis–Unruh，*Quantum Attacks on Classical Proof Systems: The Hardness of Quantum Rewinding*，[arXiv 1404.6898](https://arxiv.org/abs/1404.6898)。本轮实际定向核读 PDF p.1、9–10、19–21；所取 843217 B PDF 的 SHA-256 为

```text
1b98e6967d5e37ffaa6ed765a63ab31bf9cb46dbbff43594c58f0a04b1a07784
```

Definition 1 的 computational strict soundness 对量子 PPT 量化。Theorem 16、Definition 17、Lemmas 18–19 给出**相对于论文 O_all oracle** 的协议分离：具备所列特殊可靠性/计算严格可靠性等性质仍可能发生 total knowledge break。因此不能把普通计算响应唯一性当作通用 relativizing 规则自动替换 DFMS 的 QCUR。这里引用的是明确 oracle 分离，不是所有 nonrelativizing 论证的不可能性，也不是对当前 SRGG 矩阵的攻击。Appendix 的完整证明本轮未读完，不把它写成已重证。

## 8. 交付范围与下一条真正需要的引理

本页已证：同域 deterministic refinement；CRT 的精确输出同构；明确公开 aux 实验中的双端 MLWE hybrid；chosen h=0 的公开量词反例；两组原整数点的 gate 比值。它们都不依赖某个 HIBE，也没有改 IBS 接口。

继续闭合需要的是：给 uniform composite-Q **ring-HNF** 短域 family 建立适用的 collapsing 定理（可以从 LMZ22 重新核其结构扩展，但不能仅写“展开即可”）；证明提取测量 hybrids 的实际服务视图满足该定理允许的 public aux；给对应具体噪声、时间、查询与统计误差的界。重做结构扩展时尤其要核 scalar 随机矩阵分布的替换、复合模数零因子、测量中内积均匀性、任意测得 syndrome、规范整数短域与归约成功质量。没有完成这些工作前，(3) 保持条件式；实际 collapsing/QCUR 数值和完整 QROM/native-strong 声明保持空缺。

验证限于 exact integer 算术、上述代数推导、引用定位与 Markdown 本地链接/格式检查。没有运行量子设备/模拟器，没有新 Gaussian 或 n512 抽样收据；不把纯文稿核验与既有 pytest 数量相加。
