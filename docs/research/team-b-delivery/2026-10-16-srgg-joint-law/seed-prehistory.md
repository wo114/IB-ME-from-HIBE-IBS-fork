# 未来公钥的完整 seed 切片：经典与量子预查询界

2026-10-16，代码核对基线 `f3831ac`。本页证明一个独立的小引理，覆盖 matrix、
identity、message 三种原始输入，包括尚未登记的未来 public。它修补
[namespace 审查 §4](../2026-10-16-srgg-crt-review/classical-namespace-review.md)
没有数值化的预查询项；不改生产代码，不证明完整 H1 模拟或 IBS 安全。

```text
security_claim=none
backend_admitted=false
parameters_are_formal=false
nist_security_category=null
```

## 1. 实际输入为什么各自至多属于一个 seed

只读来源为 `structured_execution.py::public_matrix/identity_target/message_challenge`、
`Public.to_bytes`、`_canonical`，及 `src/ibme/core/encoding.py::encode_bytes`。
记 `D` 为实际 DOMAIN，`C` 为实际规范 JSON，`F` 为统一理想 byte-XOF。

```text
x_A = frame(D, "matrix", C(params), seed),
P   = C({schema: SCHEMA, params: params, seed: seed.hex(), b: B}),
x_1 = frame(D, "identity", P, id),
x_2 = frame(D, "message", P, C(W), message).
```

定义一个数学标签函数 `label(x)`：完整、恰好消费的长度前缀 frame 若属于上述
matrix 语法，且最后字段恰为 32 B，则返回该字段；若属于 identity/message
语法，且其 public 字段是具有唯一字段的规范 JSON、schema 正确、seed 字段是
规范小写 64 位 hex，则返回解码的 seed；否则返回 bottom。其它字段可以只作
语法检查，形成包含全部真实合法点的上集，不必求解矩阵或验证陷门。

这不是在生产代码中加入一个宽松 public parser。它只为分析划分 oracle 输入。
长度前缀唯一分割、不同第二字段、完整 JSON 的唯一 seed 字段共同保证每个原始
x 至多得到一个标签。把 seed 字符串藏在消息、身份或 B 的其它位置不改变标签；
非规范重复字段不会产生第二个标签。

令 `S_s={x: label(x)=s}`。这些集合两两不交，且包含 seed 为 s 的全部未来合法
matrix/H1/H2 点，不论未来 B、身份、消息及 commitment 如何选择。相同 seed
和不同参数/B 的点也归入同一切片，故本页不需先假设 B 均匀或列举未来 public。
offset、长度和输出目标寄存器不改变 x 的标签；零长度读取可保守计为查询。

本页只固定有限可访问的输入、offset、输出寄存器上界。byte-XOF 的同点不同
offset 必须来自同一固定流；不是为各类入口另设独立 oracle。

## 2. 经典：一次计费即可覆盖未来 H1/H2

攻击者在新 seed 抽取前作至多 q 次经典原始查询。预历史可以自适应，包含已有
public、重算、其它参数和其它 public 的点。设 t 为其中出现的不同非 bottom
标签数。新 seed s 在全部预历史和旧 F 之外独立均匀取自 256 位，则

```text
Pr[预历史碰中 S_s] = E[t]/2^256 <= min(1,q/2^256).             (1)
```

证明：固定完整预历史，标签集合已固定且大小为 t；独立均匀 s 恰落入此集合的
概率为 t/2^256。最后对预历史平均即可。B 或未来合法 public 不须先产生。

在未碰中事件，S_s 内所有流尚未被读取，与外部预历史独立；可以在此时一次性
初始化整个切片，而不改变诚实 law。随后用同一 oracle 计算新 Setup/public，
保留 Setup abort，并继续服务所有入口。因此若归约遇到碰中就保留一个显式
bad/失败，额外经典距离至多 (1)。不重抽 s，不按不同 public 再收费。

这个 t 包含 **H1/H2 点携带的 seed 标签**，不是只数 matrix 点。特别地，先
查 `identity_frame(P_guess,id)` 而不查 matrix 点也已覆盖。同一 slice 的多个
offset/public/domain 请求只增加一次 t，用总 q 则仍是合法保守界。
q=2^40 时 (1) 为 2^-216；这只是 seed 预查询项，不是 IBS 的安全位数。

## 3. 量子：整个切片独立刷新的一般混合界

本节给出保守、可直接证明的界，不调用单点 adaptive-reprogramming 定理。
seed s 仍独立于 F 和整个预历史；初始量子 advice 可以任意，但须独立于 F、s。
与 F 的既有相关性必须由计入 q 的预查询形成；不能免费提供完整旧 F 的副本。

预处理 A 使用至多 q 次实际 raw-XOF XOR query。一次 query 可以叠加 x、offset
及准入长度，具有固定有界输出寄存器；oracle 不改变 x。不同 point 的流独立。
两个实验为：

- Keep：用 F 运行 A；之后抽 s，保留 F，用它生成后续 public/abort 和继续实验。
- Refresh：同样先用 F 运行 A；之后抽 s，把 **整个 S_s** 的流换成独立 fresh
  流得到 G，用 G 生成后续 public/abort 和继续实验。S_s 之外逐点保持 F。

后处理可以公开 s、任何由当前 oracle 生成的 public，访问当前 oracle，持有 A
的全部保留态，并最终输出任意事件。两侧采用相同后处理和局部随机 coins。
不先筛选 Setup 成功或其它罕见事件。

**命题。** 两实验的最终事件概率差至多

```text
epsilon_seed_slice_Q <= min(1, 2q/sqrt(2^256))
                     = min(1, 2q*2^-128).                     (2)
```

证明：在相同母空间抽独立均匀 F、s，再独立刷新 S_s 得 G。G 的边缘是均匀
oracle，且独立于 s，故 Keep 也可写成“用 G 预处理，后续继续用 G”。对每个
固定 F、G、s，比两份预处理态 `A^F|a>` 与 `A^G|a>`。中间测量、经典 randomness
及自适应调度均可纯化并保留记录；不足 q 次的路径以 controlled dummy 调用补齐。

令 `|psi_i^F>` 为 A 全程使用 F 时第 i 次查询前的纯态，`Pi_s` 投影到 query
输入的 x 属于 S_s 的子空间，`w_i(F,s)=||Pi_s psi_i^F||^2`。F/G oracle 在
S_s 之外完全相同，而两个 unitary 之差的算子范数至多 2，所以

```text
||(O_F-O_G)|psi_i^F>|| <= 2 sqrt(w_i(F,s)).
```

对整个 q-query 电路逐项望远镜展开，使用全 F 前缀和全 G 后缀，并由 unitary
保持范数得到

```text
||A^F|a>-A^G|a>|| <= 2 sum_i sqrt(w_i(F,s)).
```

固定 F 时，`psi_i^F` 不依赖之后独立抽取的 s，且切片两两不交，故
`sum_s w_i(F,s)<=1`。由 Cauchy-Schwarz/Jensen，

```text
E_s sqrt(w_i(F,s)) <= sqrt(E_s w_i(F,s)) <= 2^-128.
```

平均纯态向量距离至多 `2q*2^-128`。纯态 trace distance 不超过相应向量距离，
混合时 trace distance 凸，任意相同后处理及最终测量都不增 trace distance。
可把当前 G、s、所有共同随机性保留为证明中的经典寄存器，两侧应用同一后处理；
这同时覆盖后续 disclosure、Setup 的显式失败和继续的 oracle 查询，得到 (2)。
证毕。

没有给每个 H1/H2 点单独乘一个个数；切片可以包含大量未用点，也无需实际把
所有流写成一个巨大 row。证明中仅要求 oracle 在 S_s 外相同，不要求实现整域
预分配。q 按当前 byte/offset oracle 的调用计数，未偷换成一次读取整个切片。
这是理想模型中的信息论混合界，**没有新量子电路实现或运行实验**。

这个通用界比已核的 GHHM 单点充分界保守，不能称为最紧界。例如 q=2^40 时
(2) 为 2^-87，而不是 128 位保证。它的用途是覆盖完整未知未来 public 的切片。
更紧的完整切片定理需要另证其游戏、访问方式和模拟成本，不能直接把 GHHM 的
单点 row 结论改名。标准 Setup-before-adversary 游戏中 q=0，此项严格为零。

## 4. 刷新以后能接什么，不能接什么

若整个新切片使用独立、统一的理想 F，matrix 点上的
[条件前缀引理](../2026-10-16-srgg-classical-rom/seeded-xof.md)可以继续使用：
外部 uniform Ahat 与其 conditional tape 必须恢复 **当前完整切片、public、
其它挑战数据及失败的联合 law**；其余切片点仍按同一理想模型服务。刷新定理
本身只给 uniform 切片，不允许无证据地换成非均匀 image 或依赖隐藏 witness
的所有 H1 答案。若外部挑战还带信息，必须满足原条件引理的 joint-law 前提。

本页付的是在生成当前 public 之前，诚实随机 seed 与旧 oracle 相关性的距离。
它不付、也不重付后续 **同一已公开 seed 下** chosen-identity H1 编程、目标
Sign 模拟、aux 中其它身份密钥、目标 h 相关性或 ring-HNF collapsing 的费用。
这些问题不会因为 slice 在更早时刻 fresh 就自动解决。

多个 Setup 若要逐次套用，必须逐次独立抽新 seed，并计累计全部 oracle 相关
预处理查询，包括之前 Setup/内部展开形成的相关性；或单独证明保留旧切片的
更细混合。不能只数“最近一次 Setup 之后的攻击者查询”而忽略已有 oracle advice。
恢复旧 root 或攻击者选 seed 都不是本页的新 seed 实验。

整个实验保留成功/失败，不条件化成功。若后续决定只报告成功条件分布，必须
另外核成功概率与条件化损失，不把 (1)/(2) 原样当作条件分布界。本页没有改动
四个未准入标记、参数、签名字节、接口、固定服务或冻结证据。
