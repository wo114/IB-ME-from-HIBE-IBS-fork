# SRGG native strong：完整游戏、CUR 与 ζ 商挑战差分

2026-10-16。独立只读审查；未改冻结的 bridge、采样器、哈希、接口或参数。本文件给出明确游戏和下述条件引理/反例，不宣称完成 IBS 安全归约。安全标志保持 `security_claim=none, backend_admitted=false, parameters_are_formal=false`。

## 1. 来源和本轮阅读范围

原文为 Jia、Liu、Tang、Wang，*Constructing Efficient Identity-Based Signatures on Lattices*，[DOI 10.1049/ise2/6684889](https://doi.org/10.1049/ise2/6684889)。本轮重新核对本地 `papers/2025_efficient_ibs_jia.pdf` 的 SHA-256：`258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`，并定向目视核读实际 PDF p.4 Definition 3/Theorem 1、p.8 Algorithms 7/8/Theorem 2/G0、p.9 模拟器。没有重新宣称全文及所有引用证明均已读完。

Kiltz、Lyubashevsky、Schaffner 2018 的[正式出版开放阅读版本](https://pure.uva.nl/ws/files/45974860/A_Concrete_Treatment_of_Fiat_Shamir_Signatures.pdf)本轮在线定向核对 Definitions 2.4–2.7、§2.4/3.1、Theorem 3.3、§4.5 的 HNF-MSIS 定义。印刷 p.563/564/566/571/582 对应含库封面的 PDF 第 13/14/16/21/32 页。Theorem 3.3 的完整证明被正式版转引至 full version；本轮没有补造对完整证明的核验。

实现读取范围包括 `algebra.py`、`structured_execution.py`、`cur_obstruction.py`、`qualification_audit.py` 和相应既有测试。下文形式游戏是拟固定的研究目标，不表示新增了可执行安全游戏或生产服务。

## 2. Full-IBS sEUF-ID-CMA 的确切游戏

先固定一套公开参数、一个 mpk 和一套完整失败策略。身份和消息是规范字节串；签名 σ 是具有唯一规范编码的 `(context,z,c)`，不是任意等价 JSON 文本。设 `K` 是服务内部用户密钥缓存，`E` 是攻击者显式请求提取的身份集合，`R` 是实际成功返回的确切三元组集合。

```text
Setup:
    运行一次 Setup；失败则游戏终止且不赢，不筛 root。
    E := empty; R := empty; K := empty。

Extract(id):
    对合法 id，把 id 加入 E。
    调用 IssueOnce(id)，返回固定的已发密钥或规定的失败结果。

Sign(id,mu):
    调用内部 IssueOnce(id)；此内部调用不把 id 加入 E。
    用同一已发密钥和新鲜签名熵运行规定的 Sign。
    若成功返回 σ，则 R := R union {(id,mu,σ)}。
    否则只返回规定的失败结果；不伪造一条成功记录。

Output(id*,mu*,σ*):
    接受 iff id* 不在 E，Verify(mpk,id*,mu*,σ*)=1，
               且 (id*,mu*,σ*) 不在 R。
```

`E` 在本游戏中记录所有合法显式 Extract 请求，沿用原文“未查询目标私钥”的限制；它不等于内部已经为签名缓存过密钥的身份。若要改成只排除成功暴露过密钥的身份，需另外声明这个更强游戏及失败时的归约，不能混写。

`IssueOnce` 对同身份复用同一密钥；发钥失败或完成状态不确定时阻断该身份，不换根、不重新抽取用户密钥。签名只允许规定次数的 norm-rejection 重试，其它采样/熵异常按已固定策略显式返回或终止。本文件没有把独立 n512 执行器说成已有这个持久服务。比较真实与理想游戏时保留失败结果，不能事后只选成功的根、身份或签名请求。

攻击者可以反复请求目标身份的签名，也可以反复请求同一 `(id,mu)`；目标身份可在输出时自适应选择。旧消息上的另一条未返回签名属于合法获胜情形。将 `R` 换成 `(id,mu)` 集合，或禁止目标身份签名，均会削弱这里的目标。

ROM 与 QROM 版本须另标：两者的 Extract/Sign 都是经典查询；区别是攻击者对理想 H1/H2 的经典或量子访问。当前 SHAKE 实现和有限负控不证明随机预言机假设，更不自动提供 QROM 归约。

## 3. 原文 Theorem 2 的具体缺口

原文 p.4 Definition 3 使用 fresh `(id,mu)`；p.8 Theorem 2 虽然文字假设和结论写 sEUF，但 G0 用 `(id*,mu*,.)` 未出现作为赢法，排除了已签消息。它没有直接分析上一节的确切三元组新颖性。

p.9 的模拟器对尚未提取过且落入目标集合 X 的身份签名查询直接中止。完整游戏允许对最终目标身份签名；甚至 ordinary fresh-message EUF 也允许目标身份先签其它消息。因此只替换 G0 的 wildcard 条件不足以修复整个证明。

还须注意半常数改编的跨身份别名：若多个 X 身份被映到同一底层 SIG pk，而 H2 不含身份，则底层 `(mu,σ)` 可能曾由另一个身份的签名查询返回。完整 IBS 的 `(id*,mu*,σ*)` 新颖性不能自动推出底层 `(mu*,σ*)` 新颖性。真实 H1 的身份碰撞事件和改编游戏故意制造的别名不可混为同一个小概率。当前文件不通过修改哈希绕过这个问题。

## 4. 固定验证关系及同挑战 CUR 引理

令 `R_Z=Z[X]/(X^n+1)`，n 为偶数；Q 为奇数。令 t 为 gadget 位数，`M=(2+t)d`，

```text
A = [I_d, Ahat, Bpub] in R_Q^(d by M),
h = H1(mpk,id),
zeta = 1+X^(n/2),   zeta* = 1-X^(n/2),
j = (zeta*,0,...,0)^T,
Abar_h = [2A, Q*j-2h] mod 2Q,
C_h = [A,-h] mod Q,
Rec_h(z,c) = Abar_h*z-Q*j*c mod 2Q.
```

响应域是 `z in R_Z^(M+1)` 且 `||z||_2^2 <= Bsig`，挑战是精确二元多项式 c。这里的范数是展开后的整数系数欧氏范数。定义底层识别验证 `V_h(W,c,z)=1` 当且仅当域检查和 `Rec_h(z,c)=W` 均成立。对该域中每一 `(c,z)` 恢复 W 唯一；这验证了 commitment-recoverable 的代数部分。

**引理 1（CUR 到真实矩阵短核的确定性变换）。** 对相同 h、W、c 的两个不同有效响应 z、z'，令 `Delta=z-z'`，则

```text
Delta != 0,
Abar_h*Delta = 0 mod 2Q,
C_h*Delta = 0 mod Q,
||Delta||_2 <= 2*sqrt(Bsig).
```

证明：同承诺等式相减消去 `Q*j*c`；模 Q 后 `Abar_h=2*C_h`，Q 奇数使 2 可逆。非零来自响应不同，范数来自三角不等式。若现有门 `Q^2>4*Bsig` 成立，则非零 Delta 不可能逐系数全是 Q 的倍数，因为那会有 `||Delta||_2>=Q`。故它同时给出非零模 Q 的短核元素。证毕。

引理不使用 Gaussian 假设。Sigma 和 zeta factor2 影响真实 key/transcript 分布、可允许的 Bsig 和模拟器，但不能替代短核困难性。

既有 `cur_obstruction.py` 的 `Qe` pair 仍保留：当 `sqrt(Bsig)>=(Q+1)/2` 时，首个 2I 块给公开同挑战同承诺响应对。当前 `Q^2>4*Bsig` 通过三角不等式排除整个 `+/-Qe` 范数内 pair 类；排除这一类不是 CUR 证明。原文 Table 4 三行和当前 conditional n512 点不是同组参数，不能互换结论。

## 5. 不同挑战 fork：非零性反例和正确条件

两个接受识别 transcript 具有相同 h、W，但挑战 c、c' 可能不同。写 `Delta=z-z'`、`delta_c=c-c'`，有

```text
Abar_h*Delta = Q*j*delta_c mod 2Q,
C_h*Delta = 0 mod Q.
```

第二式总成立；第一式不是模 2Q 的齐次核关系。更关键的是，`c!=c'` 不保证 `Delta!=0`。

令 `m=n/2`，把 c 写为 `a+X^m*b`，其中 a、b 为 m 位二元多项式。直接使用 `X^(2m)=-1`，得到

```text
(1-X^m)*(a+X^m*b) = (a+b)+X^m*(b-a).
```

故模 2 时两个半块相同，只依赖

```text
eta(c) = a XOR b in F_2^m.
```

乘 zeta* 的模 2 核是 `{a+X^m*a}`，恰有 `2^m` 个元素；每个 eta 等价类也恰有 `2^m` 个二元挑战。

**反例。** 对任意合法公钥和 h，取 `W=0,z=z'=0,c=0,c'=1+X^m`。有 `zeta* c'=2`，所以 `Q*j*c'=0 mod 2Q`，两条识别 transcript 都被接受，但响应差分为零。这个反例不依赖 Bsig 或 Q 大小；`Q>2sqrt(Bsig)` 无法排除它。它不是 CUR 反例，因为 CUR 要求同挑战、不同响应。

**引理 2（商挑战不同时的条件提取）。** 若上述同 W 两条 transcript 满足 `eta(c)!=eta(c')`，则 `Delta!=0`。否则 Delta=0 会推出 `Q*j*delta_c=0 mod 2Q`，即 `zeta*delta_c=0 mod 2`，与 eta 不同矛盾。于是引理 1 的模 Q 短核结论和相同范数界成立；模 2Q 一般仍是非齐次关系。证毕。

若 c' 是独立均匀的新 n 位挑战，则对任意固定 c，`Pr[eta(c')=eta(c)]=2^-m`；若明确均匀选择 c'≠c，则该概率为 `(2^m-1)/(2^n-1)`。这些是未按接受事件条件化的挑战计数，不能未经分析就写成“两次 fork 均成功后坏事件的条件概率”。攻击者可选择只在某个 eta 类上接受。任何 ROM/QROM fork 或知识误差界都须明确处理这一点；本文件没有给完整 fork 成功定理。

同一真实 H2 对固定 `(mpk,W,mu)` 返回唯一 c，因此同消息、同 W、不同 c 的两条识别 transcript 不可能同时成为该真实预言机下的有效 FS 签名。它们可出现在改预言机的 fork 世界；不能把上述反例误报为已完成的同消息 FS 伪造。

### 5.1 一个严格受限、可直接证明的经典 effective-fork 引理

以下是本文件给出的条件概率引理，不引用一个未经核对的通用 fork 定理，也不推广到量子重绕。固定 pk。设经典可重跑算法 A 仅通过 lazy-uniform H2 得到独立均匀的 n 位新回复，最多建立 q>=1 个新 H2 entry。重查旧 entry 返回相同值；没有签名预言机或外部 H2 编程。其它随机性合并为固定随机带 r。A 成功输出一条接受签名且已经查询其最终 `(mpk,W,mu)` 的概率为 epsilon；最终输入对应唯一的新 entry 索引 I。未查询最终输入而猜中完整 n 位 c 的情形不包含在这个 epsilon 中，须在应用时另界。

Fork 算法先运行 A；若失败则失败。若成功且 I=i，就用相同 r 和前 i-1 个 H2 新回复重跑 A，从第 i 个新回复起重新独立采样。仅当第二次也成功且最终索引仍为 i 时，才保留两条 transcript。则产生相同 W、不同 eta 挑战的两条接受 transcript 的概率至少

```text
max(0, epsilon^2/q-epsilon*2^(-n/2)).
```

证明：对每个 i，令 P_i 为 r 和前 i-1 个新回复的联合前缀；令 `p_i(P_i)` 为从此处独立抽取全部后缀后“成功且 I=i”的概率。可把不足 q 次的回复用不公开的 dummy 值补齐，故各前缀是同一个预采样实验的边缘分布。两次后缀给定 P_i 后独立，因此两次都成功且最终索引同为 i 的概率为 `E[p_i(P_i)^2]`。各 i 的第一条成功事件互斥，且

```text
sum_i E[p_i] = epsilon,
sum_i E[p_i^2] >= sum_i E[p_i]^2 >= epsilon^2/q.
```

第一条不等式来自方差非负，第二条来自 Cauchy–Schwarz。重跑在第 i 次新查询前状态相同，所以该次查询输入也相同；两次最终索引都是 i 时得到相同 W 和 mu。

现在固定整个第一次成功运行及其 i。第二次第 i 个新回复仍是未条件化的独立均匀 n 位值，其 eta 与第一次相同的概率为 `2^(-n/2)`。即使再要求第二次成功且 I=i，交集概率也不大于这个数。对第一次成功的所有 i 求和，坏 eta 对的总概率至多 `epsilon*2^(-n/2)`。从两次成功总概率中减去它，得到所示界。引理 2 随后给非零模 Q 短核和 `2sqrt(Bsig)` 范数界。证毕。

这个引理处理接受筛选，并没有声称坏 eta 在“两次均接受”条件下仍为 `2^(-n/2)`。应用到带签名查询的 strong 分支前，必须先证明经典签名模拟及其编程 transcript 可转换到这里的新 entry 模型，或者另给适合该模型的 fork 引理；直接把 q 代入 QROM 查询数不成立。它也没有完成公钥分布到 HNF-MSIS 的嵌入。

### 5.2 带可重放签名编程的经典扩展

上一引理可以扩展到一种明确的经典实验；不能只说“有签名模拟器，所以同样适用”。固定底层 SIG 的 pk 和目标 h，维护完整规范输入 `x=(mpk,W,mu)` 的不可覆盖哈希表。每个表项首次建立时固定 owner，后续查询只读取它：

- `free`：正常 lazy H2 查询建立，回复是独立均匀的 n 位值；包括攻击者公开调用、攻击者内部已知密钥签名的 H2 调用，以及其范数重试。
- `sign`：仅目标 h 的外部 Sign 模拟器建立；程序保存确切 `(x,c,z)`，并实际返回对应的有效规范签名。此点此前必须不存在；若已存在，整个实验中止，不覆盖、不合并 owner。

所有其它随机性合并为随机带 r，独立于全部 `free` 回复。给定 r 和已经出现的 free 回复序列，攻击者、已知密钥子程序、目标 Sign 模拟器、编程、失败策略和 owner 表都是确定且可重跑的。可用足够长的预采样随机带表示变长抽样；不要求程序在不同后缀下消耗相同数量的签名随机数。每次重跑都从空表和同一初态开始，不能沿用第一次运行的后缀表。若应用于多项式时间困难性归约，抽样、重放的时间和熵上限也须另核；理想 Gaussian law 本身不提供高效采样器。

设一条成功事件还要求最终验证输入在输出前已经是 `free` owner，设其无条件概率为 b，最多建立 q>=1 个 free 表项。每条成功运行有唯一的最终 free-entry 索引 I。重跑时只保留前 I-1 个 free 回复，重新独立采样第 I 项及其后缀；全部 r 保持相同。则产生两条相同 W、mu、h 且 eta 不同的有效 transcript 的概率至少

```text
max(0, b^2/q-b*2^(-n/2)).
```

证明沿用 §5.1，但现在 `p_i(P_i)` 的成功事件同时包含“模拟器从未中止、最终 owner=free、最终索引 i”。给定 `P_i=(r,c_1,...,c_(i-1))`，两个自由后缀仍独立；所有编程是前缀/后缀和 r 的确定函数，碰撞中止也只是成功指示函数的一部分。因此 `sum_i E[p_i^2]>=b^2/q`。第 i 个 free 查询前的状态与完整输入相同，其新回复条件于该前缀严格均匀，坏 eta 交集总概率至多 `b*2^(-n/2)`。此处没有先按“未来无碰撞/成功”重新条件化随机带，故模拟器的自适应编程不会破坏这一步。引理 2 给出非零短核。证毕。

q 不是只数攻击者显式查询的 `q_H`：必须加入所有内部已知密钥签名/重试产生的新 H2 输入，按实际冻结的次数上界填充。其它独立预言机的随机性可以收入 r，但必须确实独立于 free H2 回复。若允许覆盖表项、对已有点改 owner、复用第一次运行的后缀状态，或模拟器读取尚未抽取的 free 后缀，此证明不适用。QROM 相干查询也不属于这个离散经典重放模型。

这个扩展是实验到短核的条件引理；它没有证明签名模拟与真实 FS 的距离，也没有产生真实矩阵的困难性嵌入。两项应由外部证明分别支付，不能把它们藏进 b。

## 6. 零响应的精确理想 RO 事件

取公开 `z=0,W0=0`，对一个此前未查询的新消息 mu 计算 `c=H2(mpk,W0,mu)`。签名 `(z,c)` 被接受当且仅当 `eta(c)=0`。范数为零，且恢复不再依赖 h，因此一旦该条件成立，同 mpk 下每个合法身份都满足验证关系。

在 H2 是独立均匀 n 位理想随机预言机且规范消息输入互不相同的模型中，单条新消息的这一事件概率精确为 `2^(-n/2)`；k 条不同新消息至少一次成功的概率为 `1-(1-2^(-n/2))^k`。这给出无需发钥或签名查询的有限猜测攻击事件。n512 的每个独立新消息概率是 `2^-256`；它不是“已实跑 n512 攻击”，不是整体安全上界，也没有在此转换成 NIST 等级或未经核定的量子搜索成本。

现有 n8 的公开 fixed-point 枚举负控必须保留。诚实签名的错身份拒绝、一次随机响应拒绝、一次 n512 随机负控拒绝，都不能排除本节事件。n8/n512 的事件概率不应用同一个“8 位/512 位挑战”口号替代精确 eta 计数。

## 7. 需要匹配的真实矩阵分布

引理 1/2 的目标是 `C_h=[I_d,Ahat,Bpub,-h]`。它不是任意均匀系数矩阵：Bpub 来自 CBD1 陷门关系，h 来自实际 key-generation/H1，Ahat 由公开 seed 的 XOF 展开。

KLS §4.5 已明确使用 HNF-MSIS 的 `[I|U]` 表示；因此 identity 块本身不是无法归约的理由。还需核 U 的分布、环/模数、范数和攻击者侧信息。当前欧氏界蕴含系数无穷范数界 `||Delta||_infinity <= floor(2sqrt(Bsig))`，但不是自动得到某套已估计参数的困难性。

**条件引理 3（仅单个底层 SIG 公钥的分布桥）。** 假设 Ahat 是显式均匀 `R_Q^(d by d)`，`R0,R1` 是独立 CBD1 的 `d by td` 矩阵，`Bpub=F-R0-Ahat*R1`，h 是独立均匀 `R_Q^d`。若每列对应的 shared-Ahat decisional Module-LWE（相同 n、Q、CBD1 secret/error）与均匀不可区分，则 td 个逐列 hybrid 可把 Bpub 换成独立均匀矩阵。常量平移 F 与取负保持均匀。于是任何只接收该公钥的 CUR 对生成器，经引理 1 给出该维度 HNF-MSIS 短核解，优势至多由这 td 项 MLWE 区分优势和相应 HNF-MSIS 求解优势控制。若 h 仅有公开、逐 A 一致的近均匀界，再加其统计误差。证明是逐列替换后对同一验证关系的确定性后处理；不涉及 Gaussian 签名模拟。证毕。

这条条件引理不能省略以下实际义务：

- 当前 Ahat 来自公开 seed；保留 seed 却独立替换为显式均匀 Ahat 会被重算 XOF 立即区分。须给合法的 seed/XOF 随机预言机嵌入及其 ROM/QROM 损失，或明确假设真实 seeded 矩阵分布的困难性。不能仅称为普通 PRG 输出伪随机。
- h 若来自 `f_A(Y)`，需使用实际 mixed 域和范数/失败策略的 image-regularity 证明；不能把 h 和隐藏 Y 的联合分布直接换成独立均匀 h。
- 本条件引理没有 Extract/Sign 查询。完整 IBS 中其它身份密钥、签名和状态相关的侧信息必须由真正模拟器产生；直接接入 master R 或秘密 y 会使困难性问题改变。
- 要固定 Q 的合数结构、环次数、CBD1 版本、矩阵维度、范数和每个 hybrid 的数量，才可进入正式攻击估计。原文/KLS 对其它参数的困难性不能自动填到这里。

## 8. 真实 strong 伪造的分支与 KLS 前提

对上一节完整游戏中的获胜 `(id*,mu*,sigma*)`，查看此前所有相同 `(id*,mu*)` 的成功签名，并从每条签名恢复 W。

若 W* 等于其中某个 W，则真实 H2 唯一性给 `c*=c`；确切三元组新颖性给 `z*!=z`。这正是引理 1 的 CUR pair，不需再 fork。若不存在相同 W，则没有可直接相减消去承诺的旧签名；无论 mu* 是否签过，差分都会残留 `W*-W`。旧消息的新承诺分支不能直接交给普通 fresh-message EUF 游戏。它需要真实的签名模拟/UF-NMA 或其它已证明归约。

KLS Theorem 3.3 覆盖多次随机化签名，并将底层 sUF 优势分成 UF-NMA、承诺熵、naHVZK 和 CUR 项；其时间开销含 `kappa_m*QH*QS`。这是可用的条件路线，不能用只允许每消息签一次的定理替换。[定理原文](https://pure.uva.nl/ws/files/45974860/A_Concrete_Treatment_of_Fiat_Shamir_Signatures.pdf#page=21)

| 前提 | 当前需要实际提供的对象 | 不足以替代它的证据 |
|---|---|---|
| commitment-recoverable | 本文明确响应/挑战域上的唯一 Rec | 忽略非法域的单条方程 |
| naHVZK | 只用 pk 的完整 `(W,c,z)` 模拟，按来源定义处理 abort，非 abort 挑战均匀 | z 的边缘近 Gaussian、shape 相加或 norm 尾界 |
| commitment min-entropy alpha | P1 输出 W 的逐合法 key 界及来源允许的坏 key 概率 | key 或 signature 的 entropy |
| UF-NMA | 对真实公钥分布的无签名查询 FS 伪造困难性；ROM/QROM 分列 | 单次负控拒绝、未证明适用的经典 fork |
| CUR | 同 W、同 c 的两响应困难性和匹配矩阵分布 | 仅排除 Qe；或 different-c fork 的零差分 |
| full IBS 转移 | 目标身份签名、跨身份别名、确切三元组新颖性、固定发钥与失败模拟 | 只改原文 G0 的 wildcard 条件 |

基础定义详见 [KLS Definitions 2.4–2.7](https://pure.uva.nl/ws/files/45974860/A_Concrete_Treatment_of_Fiat_Shamir_Signatures.pdf#page=13)。本轮给出了游戏与条件代数/分布桥；上述其它归约前提不能由这些条件引理自动闭合。

### 8.1 强伪造的 owner 分支与统一短核提取

若先有正确的经典 single-index IBS-to-SIG 归约，则非目标身份的签名是底层 SIG 攻击者内部的已知密钥算法；只有目标 h 的外部签名使用上述 Sign 模拟器。这样可以按整个哈希表的 owner 分支，无须把“新 W”误当成“新消息”。完整输入含 mu，故不同消息即使 W 相同也是不同 entry；同一消息也可能有多个不同 W。

设在这个尚待外部证明与真实游戏接近的模拟实验中，目标 strong 伪造的概率为 epsilon_sim。按输出前的表分成：

1. 最终 entry 是 `sign`，该成功事件概率为 a。取建立该 entry 时实际返回的有效 `(z_i,c_i)`。表的唯一性给 `c*=c_i`，固定目标 h 和相同 x 给相同 W。强新颖性及规范编码单射给 `z*!=z_i`，所以直接用引理 1 抽取短核，成功概率为 a，不需要 fork。
2. 最终 entry 是 `free`，该成功事件概率为 b。使用 §5.2 的经典重放，成功概率至少 `max(0,b^2/q-b*2^(-n/2))`。
3. 最终 entry 尚不存在。条件于完整输出和既有表，尚未暴露的 H2 回复仍均匀；验证要求等于输出中固定的**完整** c，故本分支成功概率至多 `2^-n`。这里不是只猜 eta；即使恢复式只读 eta，FS 验证仍比较完整 n 位挑战。

因此 `a+b>=epsilon_sim-2^-n`。前两个提取器都输出同一固定 pk/h 的矩阵 `C_h` 的非零短核、满足相同 `2sqrt(Bsig)` 范数界。一个无需预知 a、b 的具体求解器先公平选择执行其中一个，成功率至少

```text
(a + max(0,b^2/q-b*2^(-n/2)))/2.
```

令 `t=max(0,epsilon_sim-2^-n)`，还可取保守统一下界

```text
max(0, t^2/(8q)-t*2^(-n/2)/4).
```

证明：若 `a>=t/2`，直接分支的 a 已不小于 `max(0,t^2/(4q)-t*2^(-n/2)/2)`，因为 `t<=1,q>=1`；若 `a<t/2`，则 `b>t/2`。当后一个目标界为正时，二次函数 `u^2/q-u*2^(-n/2)` 在 `u>=t/2` 上递增，故 fork 分支达到该界；目标界非正时取零即可。再付公平选择因子 1/2。这个界只是为明确可执行的分支选择，不是最优归约损失。

**必要的失败和记录条件。** `sign` owner 必须有同目标 h、合法范数、已经实际返回的规范签名作证。若模拟器先编程一个有效 transcript，随后返回失败却继续游戏，那么攻击者之后输出该 transcript 可能仍有 strong 新颖性，却与留存响应完全相同，无法给 CUR。一个精确模型反例是模拟器对 `(W=0,mu)` 编程 `c=0`、保存 `z=0`，只返回 bottom；攻击者再查询此点，输出 `(0,0)`，它有效且从未成功返回，但差分为零。这个反例说明“曾编程”不等于“曾签过”，不是声称真实服务已经发生了该故障。

因此一种充分的理论处理是：任何模拟器 norm 失败、程序碰撞或基础设施失败都把该**整次**实验记为失败，并把与真实游戏的差异单独计入；或者给更细的证明，确保每个未返回编程点的命中概率及其差分都被正确处理。不能只删除失败日志后继续套 CUR。若规范签名存在同一 `(z,c)` 的多个合法编码，强新颖性也不足以推出响应不同，必须先修规范域或另证其影响。

本节仅在 fixed-pk 的经典模拟实验内闭合 owner 分支。实际 single-index 发钥分布/失败、签名模拟距离、commitment entropy 的碰撞界、seeded 矩阵困难性和 QROM 仍是分别列明的义务。不能将 conditional `epsilon_sim` 或所得矩阵短核写成已完成的真实 IBS 安全定理。

## 9. 验证范围和后续证据入口

本文件自身只做定向来源检查和一般数学推导，没有采样新的 root/key/signature、没有估计 source Table 4 的实际可塑性概率，也没有跑巨大挑战攻击。冻结的 n512 生命周期只证明那一次诚实运行和有限负控。源三行 CUR pair、条件性 Q 平移以及小挑战公开伪造的既有记录均不删除。

本阶段新增 `strong_structure.py`/对应测试由 root 实现，本审查只读交叉核对。

```powershell
python -m pytest -q tests/test_srgg_strong_structure.py --junitxml=build/outputs/srgg-reduction-2026-10-16/strong-structure-independent-tests.junit.xml
```

独立结果为 **14 passed，0 failed，0 skipped，0.22 s**。测试对 n2/n4/n8 的全部二元挑战分组，另以独立 schoolbook 负循环乘法核 ζ、模 2 kernel 和 n512 的显式零差分反例；这些都是公开精确代数，没有抽取用户秘密或执行巨大攻击。已核 `build/outputs/srgg-reduction-2026-10-16/strong-structure.json` 的源码 SHA-256 与当前模块匹配。n512 的 `effective_challenge_bits=256` 是 eta 商类计数，不能称作安全强度。

另只读核对 [target-signing.md](target-signing.md) §6：在其明确的完美 SampleDom/像分布、经典 H1 和规范签名单射假设下，第一次 X 身份可共享挑战 pair；第二个 X 身份前完整 transcript/固定 key/sign 可以耦合，自适应 fresh-label 概率由 `beta_Q(delta)<=binom(Q,2)*delta^2` 控制。`delta=epsilon_0/(2Q^2)` 的常数计算与 `epsilon_0^2/(8Q^2)` 下界一致。single-index 的 `epsilon/Q` 对照基于完整诚实 transcript 的 law 与隐藏 J 无关、最终身份首次触及编号唯一，以及目标签名转发的新鲜性；Q 必须计入内部 H1 首用和最终验证。未发现这一条件经典论证的新跳步，但它没有闭合实际 SRGG 的分布前提、抽样失败或 QROM。

另只读独立检查 [native-sig.md](native-sig.md) 的完成平方、逐 c 归一化恒等式、ζ 对偶尺度、完整 joint-TV/全 bottom 映射，以及 conditional-head Schur/commitment entropy 充分界；在该文明确前提内未发现新的数学跳步。审查发现 small-shape 分支不能把 normalizer relative error 当概率封顶为 1，该工具作者已改为 vacuous `null`，有有限 majorant 时保留不封顶数值；当前 deep 数值不受此修正影响。独立运行 `python -m pytest -q tests/test_srgg_native_sig.py --junitxml=build/outputs/srgg-reduction-2026-10-16/native-sig-independent-tests.junit.xml` 得 **28 passed，0 failed，0 skipped，0.23 s**。已重算其 `native-sig.json` 的全部 source SHA-256 和输入 SHA-256，均匹配当前文件，三个安全标志仍为 `none/false/false`。这是定向代码/数学交叉核查，没有新增密码学实例或验证未闭合的 FS/QROM 前提。

另只读核对 `classical_cost.py`：`owner_fork_cost` 先扣假设完整模拟 TV 与完整 c 猜测，再应用 §8.1 的统一**提取成功概率下界**；不是安全优势上界。碰撞账本只使用已证理想 commitment 熵的前 512 位并取保守 table/attempt 并集，未将 finite sampler TV 按表大小放大。默认公开输入 `native-sig.json` 的 schema、input/source SHA-256 均匹配；free-entry 数明确是示例预算，不是内部查询计数证明或实测容量，完整距离的组合仍标作假设。初版 n2/q2 重放模型的理论下界恒为零，本审查指出后，作者已补 n4/q2 的四个严格正 fork 下界模型、n4/q1 的严格正统一下界，以及真实小表的重查、owner 不可覆盖、碰撞/范数失败不编程检查。对修正后的版本独立运行 `python -m pytest -q tests/test_srgg_classical_cost.py --junitxml=build/outputs/srgg-reduction-2026-10-16/classical-cost-independent-final.junit.xml` 得 **20 passed，0 failed，0 skipped，0.29 s**。这些有限模型核对概率计数与实验前提，不实例化哈希攻击、真实 IBS 模拟距离或困难性假设。

另定向独立审查 [classical-fs.md](classical-fs.md) §3、§6：先对真实 W 的已有 entry 碰撞付费，再将整个独立 interactive joint 经过同一 gate/program/log 映射，TV 只付一次。norm-fail 与 fresh 的交集由未条件化 interactive 拒绝率 eta 控制，已有 entry 的任意挑战行为已经归入碰撞项；首次 norm-reject 整局 bad 的损失可以按 q_S L 保守累计，未将实际重试成功条件 law 误认为一次 Sim。隐藏 J 的 (5) 在完整诚实 R 与 J 独立、d_t 对共同历史统一且与 J 无关时，可先丢弃“此前仍耦合”的非负指示，再用条件均匀性取 1/Q_I；(6)(7) 没有额外再除一次 Q_I。未发现该条件推导的新跳步。此判断要求给定同一公开 A/参数的新身份 pair law 和 conditional key/abort 对应；仅 h 的边缘近均匀不足以填写完整 Delta_global。实际混合发钥、身份像、有限资源和 seeded 挑战 Gen 的完整对应仍按该文保留为条件，没有由本次文稿审查升级为已证实际归约。
