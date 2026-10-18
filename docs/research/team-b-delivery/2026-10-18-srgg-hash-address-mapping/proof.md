# SRGG H1/H2 地址与有限拒绝的经典耦合（WIP）

范围仅为独立 SRGG IBS 的原 Table 4 三行。冻结来源是 `papers/2025_efficient_ibs_jia.pdf`，SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。论文 Table 3（PDF p.6）定义全局 `H:{0,1}*→R_Q^d`、`H̄:{0,1}*→{0,1}^n`；Algorithm 2 p.7 使用 `H(id)`，Algorithm 7–8 p.8 使用 `H̄(w,μ)`。本文件的耦合引理是**额外的经典理想 oracle 条件推导**，并非论文已给出的实际 SHAKE 或 QROM 定理。

## 源码地址逐项对应

| 论文对象 | 代码输入与输出 | 固定公钥下的对应界限 |
|---|---|---|
| `H(id)∈R_Q^d` | `paper_algebra.identity_target`（行 34–41）：`_frame(DOMAIN,b"identity",public.to_bytes(),identity)` 经 `XOFStream` 与 `uniform_values` 产生 `d*n` 个模 `Q` 系数。`paper_backend.py` 的 Extract/Sign/Verify 分别在行 158/178/208 调用。 | 固定规范 `public` 时，不同 `identity` 形成不同地址；理想独立字节、无 256 次耗尽的分布由下文引理控制。 |
| `H̄(w,μ)∈{0,1}^n` | `paper_algebra.message_challenge`（行 43–49）：`_frame(DOMAIN,b"message",public.to_bytes(),_canonical(commitment),message)`；`shake_256.digest((n+7)//8)`，在 `n=512` 时直接取 64 字节，以逐字节低位优先顺序给出 512 位。Sign/Verify 在 `paper_backend.py` 行 184/209 调用。 | 固定规范 `public` 时，不同规范 `(w,μ)` 有不同地址；理想位串模型下位重排不改均匀分布。此处没有模 `Q` 拒绝采样。 |
| `Â←XOF(seed_Â)` | `paper_algebra.public_matrix`（行 24–31）用标签 `b"matrix"`、规范参数记录、32 字节种子，产生 `d²*n` 个系数。 | 与前两种标签地址不重叠；它不等同于一个信息论随机矩阵的具体 SHAKE 声明。 |

`structured_execution._frame`（行 51–52）为每段调用 `src/ibme/core/encoding.py:46–60` 的 uint32 大端长度前缀编码；`_canonical`（行 47–48）对已规范化的对象作排序 JSON 编码。`paper_objects.PublicKey.to_bytes`（行 79–81）编码参数、种子和 `B`；其构造器行 60–73 重新核对 `Â=public_matrix(params,seed)`，解码器行 83–94 拒绝非规范重编码。`identity` 长度为 1–4096 字节，`message` 最多 65536 字节。以上说明有效对象域内的地址可区分，不能据此声称真实 SHAKE 在不同地址的输出密码学独立。

**多公钥差异。** 实现地址是 `H1(P,id)` 与 `H2(P,w,μ)`，而论文写全局 `H(id)`、`H̄(w,μ)`。即使在理想 oracle 中，对固定一个、不依赖 H1/H2 的公钥，前者各自的边缘分布可重命名为后者；对两个不同公钥，同一个 `id`（或同一 `(w,μ)`）在实现中访问不同地址并得到独立输出，而原文全局函数对该输入只给一个输出。因此**跨公钥联合游戏不等价**。当前经典单公钥重命名不得直接用于多用户、多公钥或 QROM 归约。

## 有限 H1 耗尽的条件引理

**前提。** 固定一个有效公钥 `P`、原 Table 4 的 `n=512`、`Q=15744063` 和 `d∈{2,3,4}`。经典对手至多触及 `N` 个互异 H1 framed 地址，可根据此前所有完整回答自适应选择新地址；重复地址使用同一已缓存回答。假设不同 framed 地址有独立无限均匀字节带，其他共享随机性可耦合，且两实验在首次 H1 失败前以相同逻辑运行。此处的 `N` 是互异 H1 地址数，不是所有调用次数；实际缓存、故障和服务路径是否满足该实验前提须另核。

**结论。** 单个三字节候选的拒绝概率为 `r=(2^24−Q)/2^24=1033153/16777216`。每个系数至多 256 次尝试，耗尽概率精确为 `p=r^256<2^-1024`。令理想 H1 继续读取直到第一次接受，有限实现则在第 256 次未接受时中止。两实验完整经典 transcript 的总变差距离满足

`TV(T_finite,T_ideal) ≤ Pr[first H1 exhaustion] ≤ N*d*n*p`。

**证明。** `wang_pw.hashing.uniform_values`（行 37–49）在 `Q` 下宽度是 3，接受域 `0,…,Q−1`，每个剩余类恰有一个被接受的三字节代表。候选独立时首次接受的剩余类均匀。对于一个 H1 地址，读取各系数的字节带顺序推进；无限拒绝采样的停止时刻后，未读取字节仍独立，因此 `d*n` 个输出系数独立均匀。给有限与理想实验使用相同字节带及其余随机带；在所有已读取系数未耗尽时，二者读取位置、回答、下一地址选择和 transcript 完全相同。对每个新的地址，条件于共同历史，其每个未读取系数的 256 个候选仍为新鲜均匀字节，所以首次耗尽的条件概率至多 `d*n*p`。对至多 `N` 个互异地址按自适应轨迹并合，得到 `N*d*n*p`。由耦合不等式得到 TV 界。每系数的流预算 4096 字节，而 256 次最多用 768 字节，不会先触及该预算。证毕。

例如 `N=1` 时三行上界分别为 `1024p`、`1536p`、`2048p`，均严格小于 `2^-1013`、`2^-1013`、`2^-1013`；[既有预算](../2026-10-18-srgg-oracle-budget/proof.md)把**一份矩阵加一份 H1 地址**合计为 `(d²n+dn)p`，与本引理的纯 H1 计数不同。若连矩阵标签的首次理想展开也纳入同一耦合，额外加 `d²n*p`，前提仍是理想独立字节。

不能把结论改写为“条件于整个运行无失败，两份 transcript 完全同分布”。自适应对手可以仅在首个 H1 回答为某固定值时访问第二地址；该分支多承受一次耗尽概率，按全局无失败条件化会重新加权首个回答。证明使用**无条件耦合至首次失败**，不需要这句错误的条件同分布主张。

## 安全声明与剩余条件

这里没有修改哈希函数、参数、原语或安全游戏。真实实现是 SHAKE-256，不是所设理想字节带；`actual_SHAKE_distribution_to_ideal_RO_TV_upper=null`，`full_RO_or_QROM_game_bound=null`。原文 Theorem 2 的 QROM 编程、跨公钥联合游戏、底层 SIG 安全及完整服务 law 均未由本引理闭合。原 Table 4 仍是研究输入：`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。无新增随机实验；身份/消息长度是上段代码入口限制，重复次数为 0；本文件仅核算理想 oracle 数学模型，不用测试替代证明。
