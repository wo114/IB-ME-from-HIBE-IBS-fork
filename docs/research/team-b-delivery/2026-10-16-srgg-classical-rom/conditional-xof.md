# SRGG：保留失败的有界条件 raw-XOF 生成器

2026-10-16。本项将 [seeded-xof.md §2–3](seeded-xof.md) 的 `G_h` 数学 kernel 实现为可执行、全路径有界的经典工具，补 [direct-ibs.md §7/9](direct-ibs.md) 的一项实现前提。**输入外部指定的规范目标系数，完整保留原来的每系数 256 次拒绝失败；没有额外 helper 拒绝、中止或 TV 项。** 生成的原始字节可经未改的 `wang_pw.hashing.uniform_values` 解析；首次只查 1 B、前缀或 offset 时也固定完整解码轨迹，之后复用同一字节流。

标志保持 `security_claim=none, backend_admitted=false, parameters_are_formal=false, nist_security_category=null`。工具采用经典、可控制相关原始接口的理想 byte-XOF 模型；没有编程真实 SHAKE，没有实现 QRO、成功条件 kernel `K_h` 或整个 adaptive reduction。旧 `seeded_xof.py`、两个冻结批次和生产原语均未修改。

## 1. 对应实现与精确输入

新增 [conditional_xof.py](../../../../experiments/research/candidates/srgg/conditional_xof.py) 和 [独立测试](../../../../tests/test_srgg_conditional_xof.py)。读取固定 bridge JSON 的参数，只做整数/Fraction 算术，不依赖 Sage。

接口为：

```python
generate_trajectory(q, targets, *, rng=None, max_trials=256, max_bytes=...) -> Trajectory
ConditionalPoint(q, targets, *, rng=None, max_trials=256,
                 max_bytes=..., raw_query_budget=None)
point.read_at(offset, size)   # 同一点任意 offset
point.prefix(size)            # 同一点 [0,size)
point.read(size)              # 顺序 parser 使用
conditional_certificate(q=..., count=..., ...) -> dict
```

`targets` 必须为显式 list/tuple，长度 `1..2^20`，每个值为字面整数 `0<=a<q`；模数、维数、次数、offset、长度和容量拒绝 bool/浮点。支持 `2<=q<=2^128`，候选宽度严格沿用原 parser 的 `ceil(bit_length(q−1)/8)`，大端整数字节，不裁切高位。默认 `T=256`；可配置的较小 T 仅用于有限模型测试，不能冒充生产次数。

`Trajectory` 保存原始 word、已接受目标前缀和 `success`。解码失败的返回值为 `success=False`，不是重抽、换目标或换 seed。已接受前缀是诊断辅助变量；原 parser 在失败时仍抛自己的异常，不输出部分系数。诊断字段和内部熵不另暴露给密码学攻击者；raw 接口只返回请求的字节。

## 2. 无 helper 拒绝的单 word 推前

设 `M=2^(8w), K=floor(M/q), L=Kq`。针对当前目标 a，每轮只读一个均匀 `x in [0,M)`，令

```text
g_a(x) = x,                  if x>=L;
         a+q*floor(x/q),      if x<L.
```

拒绝候选保持原样。对每个接受 lift `a+kq`，恰有 `kq,...,(k+1)q−1` 共 q 个源 word 映到它；因此

```text
Pr[g_a(x)=r] = 1/M,   for each r in [L,M),
Pr[g_a(x)=a+kq] = q/M, for k=0,...,K−1.
```

这正是 `G_h` 的候选 law，连同拒绝/接受判定。**取整除法只选择 lift，未把候选均匀取模 q 当成均匀采样器。** 被丢弃的 q 个 preimage 标签不是 raw 输出，攻击者也不获得这些内部源随机数。

R=`M−L` 为零时同一公式仍成立：没有拒绝区、每次接受，原始 trial-abort 概率为零。无需单独引入 `randbelow(K)`，无需无界循环、最大耦合抽样或额外 Bernoulli helper。因此 helper 新增拒绝/中止严格为 0，每个输出 word 恰消费 w B 熵。

## 3. 完整轨迹、失败与 fresh suffix

顺序处理 N 个目标。每个目标最多 T 个候选；首次接受就进入下一个目标，T 次全拒就停止整个解析。设一条轨迹停止前消费 l 个 word，接受 j 个系数。若其已接受前缀与外部目标匹配，则生成概率为

```text
q^j M^(-l).
```

否则概率为零。其停止规则和每次拒绝 word 与旧数学 kernel 完全相同，故**对每份固定目标，实际工具与理想 `G_h` 的完整 law 相等，包括第一次 T 次全拒**。

外部完整目标均匀时，兼容目标共有 `q^(N−j)` 份；平均后每条轨迹质量为 `M^(-l)`，恰等于原始 iid 字节流的解析 law。失败分支尚未用到的外部目标仍保留为独立均匀辅助变量；不能把失败时 `Parse=bottom` 写成 `Parse=targets`。外部目标不均匀时只是相应的条件 kernel 混合，不能声称 raw 流均匀。

所有源 bytes 必须独立均匀，且在程序内部。停止位置是一个有界 stopping time。完成或失败后，工具从**同一源的当前未读位置**继续取原始均匀字节，不重新初始化、不复用旧字节、不对 suffix 再作目标映射。因此停止后的 suffix 独立于既有轨迹。把任意固定观察长度投影到该固定轨迹并补 fresh suffix，得到与数学 `G_h` 相同的观察 law；均匀目标混合后等于诚实 raw iid law。该一般结论由推导承担，测试只核有限实例。

## 4. 首次 raw 触及与有界读取

`ConditionalPoint` 代表**一个**已识别、允许初始化的经典 raw point。构造后不消费熵；零长度查询也不触及。首次有效非空查询，无论请求 1 B、前缀或只查某 offset，都先生成完整有界解码轨迹并固定缓存，然后才返回请求字节。需要读到停止位置之后时，顺序扩展同一源的 fresh suffix；缓存内重查不消费熵，顺序 parser 和 offset/prefix 返回同一流的投影。

原始 trial-abort 不使 raw 查询提前返回一个可观察的特殊错误：失败轨迹仍缓存并可继续查询，只有实际 parser 使用这些 bytes 时发生其原有失败。重复 raw 查询也不重复支付独立的失败概率。输入/越界查询在新增熵消费前拒绝；真实熵源的短读、错误类型或异常使该点阻断，禁止自动重选。对 OS/库/内存等工程异常没有赋予一个未经证明的概率。

工具没有负责识别 matrix/identity/message 的 frame，也没有实现身份索引、latentPair、哈希表、seed 碰中、恢复服务或 fork。归约合成方仍须保证：

1. 在第一次有效 raw 触及前确定相应外部目标，并生成此点；不能先输出 bytes，再另选目标。
2. 所有属于同一规范 raw point 的调用都转发到同一个实例，重算 public 也复用它；其它点按事先固定规则服务。
3. 只可初始化允许的 fresh point。已有经典 seed 预查询及量子查询的损失不由本类消除。
4. 原始 decoder 失败时保留 hashbad，并按上层规定处理，不能因已经有 latent key 就忽略失败或偷偷更换点。

本项实现的是 `G_h`，**不是** `K_h=G_h|success`。在 [seeded-xof.md §7](seeded-xof.md) 的成功条件路线中，不可直接把它当 `K_h`。可以走含失败的扩展实验，将同一原始失败标为 bad，并在成功事件分析中一次支付 beta；或另实现已证明且有界的 `K_h`。本工具没有删掉 beta，没有宣称 image/finite sampler/服务误差已经合成。

## 5. 全路径熵和缓存上限

条件轨迹最多消费 `Lmax=N*T*w` B。若 raw 接口允许最大访问端点 Braw，则为覆盖所有查询，给点分配的硬熵 cap 为

```text
Bpoint = max(Lmax, Braw).
```

因为同一位置的一字节转换恰读一个源字节，查询最大端点 E 后实际累计源消费为 `max(Ltraj,E)`，不会是两者之和。缓存输出长度也至多该值；另存的 Python word/int/tuple 与辅助结构会产生额外内存开销，本证书**不是**峰值内存实测。程序对 `Bpoint>public_max_bytes` 在熵消费前拒绝，本工具公开最大 cap 为 256 MiB。没有概率性截短；已准入路径的额外 byte-cap abort 和相对理想 `G_h` 的完整 TV 都为零。

默认 Braw=`N*4096`，与当前 matrix/H1 的原 `XOFStream` read budget 对齐。证书另标明 Braw 是否覆盖完整 bounded decoder；缩小 Braw 可以只允许部分 raw 观察，不能据此声称所有 decoder 路径可读。这里的缓存为精确所需字节，生产 SHAKE 的 doubling cache 只影响另一个实现的预取内存，不改变原始接口或失败 law。

冻结研究点 `n=512,d=2,w_gadget=8,Q=13972913866395903`；raw word 为 7 B，K=5，

```text
rho = 2193024705948421 / 2^56,
beta_N = 1-(1-rho^256)^N <= N*rho^256.
```

| 点 | N | 轨迹最坏熵 B | 默认 raw/query 与整点硬 cap B | 原始失败 dyadic 上界 |
|---|---:|---:|---:|---|
| matrix/Ahat | 2048 | 3,670,016 | 8,388,608 | `<2^-1278` |
| identity/H1 | 1024 | 1,835,008 | 4,194,304 | `<2^-1279` |

两项都覆盖全部原 256 次路径；helper 额外 abort=0、相对理想 `G_h` 的 TV=0 是算法恒等式，表中原始 hash failure **仍然非零**。不同新点的上层 query 总预算和全局资源限额仍由归约调用方收费；不把重复 prefix 查询当新点，不把一次点的 cap 当整个 `2^40` 查询服务的容量证明。

## 6. 本轮运行与证据

Windows Python 3.14.7 与指定 WSL Ubuntu-24.04 / Sage 10.9 / Python 3.13.15 分别运行：

```text
python -m pytest -q tests/test_srgg_conditional_xof.py tests/test_srgg_seeded_xof.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_conditional_xof.py tests/test_srgg_seeded_xof.py
```

两端各 **61 passed**：新增 40 项、冻结回归 21 项；不能相加成 122 个不同检查。独立 exact-law 检查包括：所有 word 的 lift/reject 原像计数；有限多系数含 abort 的完整轨迹混合；实际 65,536 条两字节输入的运行 law；真实未改 parser 重放；保留完整 256 次失败和同源后续 suffix；首次 1 B/prefix/offset、零长度/缓存一致性；当前 7 B 多 lift；不准入/短熵阻断和超长 dyadic JSON。

一次 OS 安全随机源的小维真实抽样使用 q=129、4 个目标（总 4 字节目标），逐字节重放实际 parser，属于运行样例；不是统计分布估计或攻击测试。其它概率证据是精确枚举/整数运算，不设随机重复次数；没有身份/消息/Gaussian/密钥抽样，未运行 n512 条件轨迹。

零熵大规模证书命令（输出必须不存在）：

```text
python -m experiments.research.candidates.srgg.conditional_xof --output build/outputs/srgg-conditional-xof-2026-10-16/conditional-xof-final.json
```

报告记录输入 frozen bridge 的 SHA-256、四份相关源码 SHA-256 和实际 Python/系统环境；路径在 ignored build 下，由 root 统一选择交付收据。证书构建没有建立随机源，`actual_entropy_bytes=0, draw_performed=false`。不升级为正式参数、困难性结果、IBS/组合安全或 QROM 结论。
