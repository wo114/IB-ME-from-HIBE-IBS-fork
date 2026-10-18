# 独立身份整行分布的量子比较：保留固定密钥和 raw tape

2026-10-16，基线 `f3831ac`。本页证明一个一般随机函数分布引理，并明确其 SRGG
应用边界。它回答原 [quantum-oracle-obligations §4.2–3](../2026-10-16-srgg-proof-followup/quantum-oracle-obligations.md)
所列问题中的一部分：不能把经典首次触及数直接用于量子查询，但可以在独立整行
模型中付显式的平方根损失，同时保留后续经典私钥查询的相关性。

没有实现量子 oracle、选择目标身份或证明完整 QROM/native strong。
`security_claim=none, backend_admitted=false, parameters_are_formal=false,
nist_security_category=null`。

## 1. 精确的独立整行模型

固定有限输入集合 I、有限行编码集合 Y 和一个共同 root r。对每个 i 独立抽一行，
P 世界用 `P_(r,i)`，R 世界用 `R_(r,i)`。允许分布随 root/i 变化；同一 i 的重复
访问永远读同一行。给攻击者标准 XOR row oracle

```text
O_T |i,z> = |i,z XOR T(i)>.
```

行编码定长且单射，不够长度填零；非法输入在两世界相同处理。初始 advice 可以
依赖共同 root 的公开部分，但不得另外依赖隐藏 table/抽行 coins。攻击者的全部
table 相关预处理、经典读行以及量子读行都计入 q。其它共同随机 oracle、固定
root 秘密、任意共同后处理可纳入相同环境，前提是它们不另行读取 table 而不收费。

假设逐 root、逐 i 有

```text
TV(P_(r,i),R_(r,i)) <= delta <= 1.                         (1)
```

这不是“只看 h 边缘”的假设。Y 必须包含以后模拟 API 真正使用的整行状态，例如
固定 key 或失败、同一 raw tape、身份绑定及必要的持久变化。若环境依赖未包含的
耗时/耗熵轨迹，则 (1) 必须扩到这些轨迹；不能只凭边缘 key TV 使用本页。

## 2. 公共重叠混合与一般量子界

**定理。** 在上述模型中，任意至多 q 次 row-query 算法的最终事件概率差至多

```text
min(1, 4q sqrt(delta)).                                    (2)
```

证明：对固定 r/i，记 `delta_i=TV(P_i,R_i)`。若 `0<delta_i<1`，令

```text
C_i(y)=min(P_i(y),R_i(y))/(1-delta_i),
P_i=(1-delta_i)C_i+delta_i B_i,
R_i=(1-delta_i)C_i+delta_i D_i.
```

`B_i,D_i` 是非负归一化的剩余 law。delta_i=0 时两边均取 C_i；delta_i=1 时
C_i 任意，混合不使用它。逐 i 独立抽 `C(i)~C_i` 和 `flag_i~Bernoulli(delta_i)`，
flag 与整个 C table 独立；flag=1 时另抽对应 B_i 或 D_i 替换该行。得到的两份
污染 table 分别恰有 P、R 的独立逐行 law。没有要求坏行可由公开数据识别。

先比较 P 与 C。固定 C、全部 flag 和替代行，对第 j 次查询前的全 C 算法态
`|psi_j^C>`，令 w_j 为其输入寄存器落在 flag=1 的总质量。两 oracle 只在
这些行可能不同，故 `||(O_P-O_C)psi_j^C||<=2 sqrt(w_j)`。对整个电路逐项
望远镜展开、后缀 unitary 保范数，得到最终向量距离至多 `2 sum_j sqrt(w_j)`。

固定 C 时，全 C 查询态不依赖 flags。于是

```text
E_flags[w_j | C]
 = sum_i delta_i ||Pi_i psi_j^C||^2 <= delta,
E_flags sqrt(w_j) <= sqrt(delta).
```

平均向量距离至多 `2q sqrt(delta)`；纯态 trace distance、混合凸性和数据处理
给 P/C 的最终事件差同样上界。R/C 用相同论证，再三角不等式即得 (2)。测量和
自适应控制可纯化，提前退出用 controlled dummy 查询补齐。证明没有按查询时
“真正触及的点”读取或测量身份寄存器。证毕。

若另有 **逐行 measure 的 minorization** `P_i >= (1-a)R_i`，则可以直接以
R 为共同基线，P 用独立 Bernoulli(a) 污染构造，得更紧充分界

```text
min(1, 2q sqrt(a)).                                        (3)
```

只有普通 TV 时不能无证据地用 (3) 代替 (2)。本页不声称常数/查询损失最优。
这些界在 `q sqrt(delta)` 不小时可能无用，不能只把它称为 negligible。

## 3. raw byte 与固定发钥 API 如何计为行查询

为固定当前 public 的每个规范身份 i，概念行可以只存：

```text
(raw H1 bytes on the declared finite accessible offsets,
 canonical fixed key OR persistent failure,
 the fields actually needed by the common deterministic wrapper).
```

实际成功 key 有公开 norm/维度上界，错误类别及 raw offsets 有限，故可给有限
定长行编码；无须存无限 Gaussian latent U。潜在 U/E/Y 只用于定义推前 law。
其它 raw 输入、H2、matrix 使用同一共同 oracle，保持其输入域重叠规则。

一次 raw H1 byte/offset XOR query 可用一次 row read，把所需字节受控 XOR 到
目标寄存器，再一次 row read uncompute。身份/frame/offset 判定及非法输入
处理采用确定可逆电路，代价 **至多两次 row query**。一次首次 IssueOnce 也可
两次 row query 获取规定 key/失败，交给原封不动的公共状态包装。缓存命中无需
再次抽行；保守再读原行也合法。Sign 的后续 fresh coins、H2、范数重试和日志
作为共同后处理，内部第一次 IssueOnce 必须计入。

因此在没有其它 table 入口时，一个明确充分预算是

```text
q_row <= 2(q_raw_H1 + N_first_issue),
event distance <= min(1,8(q_raw_H1+N_first_issue) sqrt(delta)). (4)
```

这里 raw query 可叠加多个身份；不能用“至多 q 个不同身份”的经典说法解释它。
真实服务若从已发历史继续，必须把建立历史的相关查询计入 q，或另证明相同
条件 table law。仅让两侧历史 key 的边缘相同不够。

本段是访问模型的模拟和计费论证，不是 Python 的量子电路实现。不预分配所有
身份的 table；若要把某个 reduction 实现成严格 PPT，还需独立给有限表/高阶
独立函数及其采样、查找和相干成本，不能由本页声称已实现。

## 4. SRGG 可直接使用的 ideal latent 比较

固定 public A，沿用
[direct-ibs §2](../2026-10-16-srgg-classical-rom/direct-ibs.md) 的公开 latent
抽取和完整门。记 P 先抽 `(U,E,Y)`、`h=AY`，R 先抽 uniform h 再按相同
`Law(U,E,Y|AY=h)`；两边施加同一 raw/final gate、同一规范 fixed-key/bottom
映射。设 image law 为 alpha、`TV(alpha,Uniform)<=epsilon_image`。

raw H1 使用 **含解码失败** 的 `G_h`，条件于 h 后独立于 latent pair。同一
`sum_h Uniform(h) G_h = Raw` 的完整轨迹等式已在
[seeded-xof §2–3](../2026-10-16-srgg-classical-rom/seeded-xof.md) 证明。
失败行仅返回同一 raw tape，后续真实 H1 解析/发钥失败时才按 API 规则抛错；
没有向量子 byte 查询新增一个可见中止。

于是理想行在施加共同映射前拥有完全相同的条件 kernel，只有 h 的混合权重不同，
整行 TV 恰为 epsilon_image；施加门/raw/key/失败映射后至多此值。独立身份按
各自 fresh coins 预抽整行，所以 §1–3 给

```text
ideal independent-Dom H1 table vs ideal uniform-target H1 table
 <= min(1, 4 q_row sqrt(epsilon_image)).                    (5)
```

这保留固定 key 与 raw tape 的关系，因此后续经典 Extract/Sign 并非免费遗漏的
aux。没有只拿 h 边缘结论然后假设密钥独立，也没有强迫 G_h 成功后忘记 beta_H。
若另选成功条件 K_h，则须另核完整 raw law 和失败桥，不能将其当 G_h 使用。

冻结 n512 深配置的旧 normalizer 证书向上取整到 256 位，逐像相对误差最多取
`epsilon=2^-256`，image-TV 可保守取 `1/(2^256-1)`。直接放入 (5) 会在
`q_row=2^40` 得到略大于 2^-86 的充分界，不能支持 128-bit 统计损失目标。
**这部分可以用更精确的同一数学界修复，不须改变算法或参数。**

### 不受旧 dyadic 舍入地板限制的更紧界

冻结 `integrated-bridge.json` 的 `query-bounded-deep/full_kernel_reference` 给出
全系数核维数 D=10240、normalized width squared 的有理下界

```text
2743170229059331836356996390910923440928709410816
 / 17389460791654761125644185556327238195876720573 >= 157.
```

仍使用旧 GSO 到全核 smoothing 的递归 theta 证明，但用 `pi>4 ln2` 代替旧的
`pi>2 ln2`。前者由 `pi>3` 与 `ln2<3/4` 得到；后一个严格不等式也可对凸函数
1/t 在 [1,2] 作梯形积分直接验证。令

```text
a=2^-628, t=2a/(1-a^3), x=D*t,
epsilon_new=x/(1-x).
```

因为 `k²>=1+3(k-1)`，一维双边非零 theta 质量小于 t；递归系数求和后，
全核 dual mass 至多 `(1+t)^D-1 <= D*t/(1-D*t)`。原全类 GSO/Poisson 论证的
其它条件没有变化。精确整数计算给

```text
epsilon_new < 2^-613,
epsilon_new/(1-epsilon_new) < 2^-613.                       (6)
```

这不是从旧的已舍入 TV 上界逆推更小误差，而是以同一已核 GSO 输入重新推导
未舍入的 theta 有理上界。原证据不覆盖或改写；新收据另存。

此外，对每像的 coset mass 有 `c(1-epsilon)<=Z_h<=c(1+epsilon)`；把均匀 E 的
有限平移平均后，依然有

```text
K alpha_h >= (1-epsilon)/(1+epsilon).
```

P/R 在 latent、raw G_h、门和 key/bottom 的条件 kernel 上相同，故这给出整个
行的 measure minorization，而非仅 h 的边缘。用 (3) 和 (6)，

```text
a_bad=2epsilon_new/(1+epsilon_new) < 2^-612,
ideal-row comparison <= min(1,2 q_row sqrt(a_bad)),
q_row<=2^40  => ideal-row comparison < 2^-265.              (7)
```

[verify-image-precision.py](verify-image-precision.py) 和
[image-precision.json](image-precision.json) 逐项验证 GSO 原输入、(6) 以及 (7) 的
平方不等式，完全使用 Fraction/整数、零熵；不是量子实验或安全估计。这个改善只
减少相同理想分布比较的保守证明损失，没有性能改善主张，也没有改变采样分布。

有限实际发钥先通过共同 uniform-H1/raw 函数下、每次经典 Issue/Sign 的新鲜
coin kernel 作 cq 比较，按实际调用数线性付误差，见
[honest-service-law.md](honest-service-law.md)。不能把有限 sampler 的较大 TV
偷偷替换成 (6) 的 ideal image 数字；若直接换整个有限随机函数，仍须重新用
其完整行误差代入 (2)。

## 5. 当前不能据此省略的工作

实际发钥到本节 latent 行的对应，要对共同 root 下每个 h 的 **key、失败及与 raw
tape 的联合 law** 有界。若实际 sampler 在访问固定 h 后使用 fresh 独立随机带，
且全部可达 root 的局部证书统一成立，可以先预抽该行，再做独立行比较。若有
共享源 cap/历史依赖，须证明 cap 在指定全路径范围内不会触发，或把依赖作为
共同后处理且把其使用的轨迹也纳入行。未建模的故障/时间/熵侧信道不能填零。

本页的整行独立性 **不适用于** semi-constant 目标分区：多个身份被人为映到
同一个外部 h_star 时，行已非独立。也不证明自适应目标身份编程、目标 Sign 的
相干改编或实际辅助态下的 ring-HNF collapsing。需要一个完整的 target/hardness
模拟器才能连接这些环节；(5) 不是它。

seed/public 若在量子预查询后才产生，先按
[seed-prehistory.md](seed-prehistory.md) 的 joint 实验处理。初始化时分布相同的
函数能相干查询，不意味着先前任意 oracle advice 可以免费重置。

本页为普通数学证明和源码访问对应，无新抽样、身份/消息样本或量子设备运行；
不新增 pytest 计数，不更改四个未准入标记，native strong 目标保持原定义。
