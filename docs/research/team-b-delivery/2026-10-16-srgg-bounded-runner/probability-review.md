# SRGG：有界 Run/E 的概率拼接、完整 H2 轨迹与资源审查

2026-10-16。本文独立审查冻结 `classical_runner.py`，以及新增
`bounded_classical_runner.py` 的本地显式公钥经典实验。前者 SHA-256 为
`04c068b44204a362d7855aa214b1a10ed2b24c1144a4eaa3f8a54560914f77e1`。
新增精确算术实现为 [bounded_classical_cost.py](../../../../experiments/research/candidates/srgg/bounded_classical_cost.py)。
下面闭合的是明确前提下同一个有限 Run 到实际 owner 分支提取器 E 的概率关系，
以及准入资源配置的额外 global-byte-cap 项；不填补生产游戏或困难性对应。

`security_claim=none, backend_admitted=false, parameters_are_formal=false,
nist_security_category=null`。

## 1. 固定的条件实验

固定一个公开实例 `omega=(A,h_star)`，其中
`A=[I_d|Ahat|B]`。目标 `h_star` 的独立均匀性是 IBS 对应所需的外部前提，
构造器从单个输入值不能检验它。以下局部 fork 引理对任一固定合法 h 都成立。
把独立隐藏身份索引 J、攻击者随机带、所有非 free-H2 的 labeled tapes 合为 r。
合法 callback 只能调用文档中的 oracle 方法和有界 `attacker_rng.read`；
不能访问、修改 `.coins/.free/.identities` 等内部对象，也不能额外读取时间、OS 随机数
或带外状态。Python wrapper 没有为任意恶意 Python 代码提供沙箱。

给定 r 与依次首次建立的 free H2 全部 n-bit 回复，Run 是确定程序，包括：
有限 Gaussian/均匀采样、raw H1 的完整轨迹、范数重试、失败/阻断、所有 owner 和
成功返回的规范三元组。至多有 q>=1 个 free entry；q 包含 known-key Sign 的内部
H2、失败范数尝试、公开查询和最终验证。它不是仅外部的 qH。

要求 free 回复独立均匀，并独立于 r；第二轮第 I 个及其后回复独立刷新。
传入可重复的测试 RNG 或互相相关的自定义 source 不会自动满足此前提。
source、算术与库的条件模型须明确；本文不为基础设施故障赋零概率。

## 2. raw H2 的整点 law 与首触及

令 `Bc=ceil(n/8)`。冻结 `_entry` 在任一有效规范 `(W,message)` 的首次非空
raw/composite 访问上固定完整挑战 c，并固定 owner。原始源的前 Bc 字节被 `_pack`
替换其前 n 位为 c；字节中未使用的高位和所有后续 suffix 保持独立 uniform。
因此有精确恒等式：

```text
Uniform(c) × Uniform(unused high bits,suffix)
  = Uniform(all raw bytes at this canonical H2 point).
```

目标 Sign 的 programmed c 使用同一个给定 c 的条件 kernel；只有真正未触及的点
才允许编程。已有 free/sign entry 永不被覆盖。raw 查询先读后缀、只读 1 B 或
offset 都已固定同一个 c，后续重读一致；零长度查询不建立 entry。首次仅读 suffix
可能没有暴露 c，但仍可作为 fork 的第 I 个点：其输入在抽取 c 之前已经确定。
重放时同一 r 保留独立 suffix，刷新该整点 c，不把部分字节当作多个挑战。

`finish` 在最终 Verify 前保存 owner。原来未触及的最终点，其验证 c 是独立的完整
n-bit uniform；故在任何确定的输出与既有表下，成功概率至多 `2^-n`。
若最终验证因 entry cap 停止，该分支成功率为零，不会提高此界。
不能把这个猜测费改成有效商挑战的 `2^(-n/2)`。

本恒等式只覆盖固定 proof-public 的 typed、合法 H2 点。不同 mpk、无效 wire/frame、
matrix-seed 预查询以及生产 SHAKE 到理想 XOF 的模型对应不属于此等式。

## 3. 同一 Run 的 free-owner 二阶矩

记本轮目标 native-strong 成功的无条件质量分别为：sign-owner a、free-owner b、
输出前未触及 u。令 `p=a+b+u`，则 `u<=2^-n`。令 `m=n/2`、`kappa=2^-m`。

在第 i 个 free 首触及之前的完整证明前缀为
`P_i=(r,c_1,...,c_(i-1))`。程序不够 q 次时可预采样未公开 dummy 回复。
定义 `s_i(P_i)` 为从该前缀独立抽后缀后“free-owner 成功且最终索引 I=i”的概率。
所有失败，包括有限采样 abort 和预算内的规范阻断，均留在此概率空间：

```text
sum_i E[s_i]=b,
Pr[both runs succeed with the same final free index]
  =sum_i E[s_i^2] >= sum_i E[s_i]^2 >= b^2/q.       (1)
```

第一步用相同 r、相同前 i−1 个 free 回复重跑，所以第 i 个查询前的状态和完整输入
相同，即使它是 known-key Sign 内部或 partial raw 查询。两轮均在最终索引 i 成功时，
两条 transcript 的 W 和 message 相同；最终身份名可以不同，只要仍为第 J 个身份，
其目标 h 都是同一 h_star。

环中的 `eta(c)=c_low XOR c_high` 有 `2^m` 个均匀商类。固定整个第一次成功运行，
第二次第 I 个全新回复在未按第二次成功条件化之前满足
`Pr[eta(c_I')=eta(c_I)]=kappa`。再要求第二次成功只会减少交集，故所有坏 eta 对的
总无条件质量至多 b*kappa。与 (1) 合并得到

```text
Pr[free fork gives two successes with different eta]
  >= g_q(b):=max(0,b^2/q-kappa*b).                    (2)
```

这不是“两次成功后 eta 仍均匀”的错误论断。攻击者只接受一个 eta 类时，(2) 可为零。
不同 eta 保证响应差分非零；仅 `c!=c'` 不足够。代码随后显式核非零、范数和核方程，
因此 (2) 所计的事件都会被实际提取器接受。

有限 sampler 的失败已是同一 Run 的 law，不能在把其成功率 p 送入 (1) 后，
再为第二轮无依据地扣一次完整 finite TV。若改走“先理想 fork、再换成两次有限运行”
的路线，则必须另证其联合轨迹桥；本文选择直接对实际有限 Run 使用 (1)。

## 4. 实际 owner 决策不需要公平分支硬币

实际 `fork_extract` 先运行一次，看到 sign-owner 就直接差分，看到 free-owner 才重放。
sign 见证必须是同一目标 h、同一个 W/message、真正成功返回的规范签名。
native-strong exact-triple 新颖性迫使最终响应与见证不同，因此此分支成功质量为 a。
它与 (2) 的首轮 free 事件不交，故实际 E 满足

```text
Pr[E succeeds | omega] >= a+g_q(b).                   (3)
```

旧 [direct-ibs.md §6](../2026-10-16-srgg-classical-rom/direct-ibs.md) 给公平选一个
提取器的有效保守界；它不等于这里实际代码的分支策略。式 (3) 消除了该额外的 1/2。
这不是对底层算法或困难性作性能/安全优化声明。

给定 `t=max(0,p-2^-n)`，可精确优化所有 `a,b>=0,a+b>=t`。g 在 [0,1] 非减，
故最小值可取 `a+b=t`，再最小化 `t-b+g_q(b)`：

```text
tau=q*(1+kappa)/2,
Psi_q(t) = max(0,t^2/q-kappa*t),       0<=t<=tau;
         = t-q*(1+kappa)^2/4,         tau<t<=1.       (4)
```

证明：b<=q*kappa 时目标为 t−b，递减；其后为
`t+b^2/q-(1+kappa)b`，配方后在 `b=tau` 最小。
因此最优 `b=min(t,tau)`，得到 (4)。因为 `kappa<=1`，tau 不小于 q*kappa，
两段之间没有遗漏。整数 q>=2 时 tau>1，所以默认 q=128 只需第一支。
q=1 不能省第二支：例如 n=2、t=1，取 a=1/4、b=3/4，(3) 只有 7/16；
错误套第一支会报 1/2。

Psi 从零段过渡到二次段时右导数为 kappa；在 tau 处两边导数都为 1，
之后线性。因此它在 [0,1] 凸且非减。
`H(p):=Psi_q(max(0,p-2^-n))` 也凸且非减。先固定每个 omega 使用 (3)(4)，再有

```text
Pr[E succeeds] >= E_omega[H(p_omega)]
               >= H(E_omega[p_omega]) >= H(p0).       (5)
```

这样平均 setup/独立均匀 h 的 p0 不会被错误地当作每个实例的点态成功率。

## 5. ε_IBS 到同一有界 Run：全部显式前提

采用 [direct-ibs.md §4–5](../2026-10-16-srgg-classical-rom/direct-ibs.md) 的独立 J
母空间、完整 latent/失败 law 和逐历史 kernel 前提。令 QI 包含所有内部及最终
H1/raw 首用，NS 包含全部实际签名尝试，MH 包含所有相关 H2 entry。
可以使用以下条件分子，随后仅除一次 QI：

```text
Lnum = Delta0 + Delta_issue + Delta_bad + Delta_alias
     + QI*(epsilon_image+delta_pub)
     + NS*(MH*2^-alpha+delta_zk+eta_sign+delta_sim+delta_known)
     + Delta_overlay,
p0=max(0,(epsilon_IBS-Lnum)/QI).                       (6)
```

`bounded_classical_cost.IBSLedger` 要求上述每项显式给出，其中
`commitment_collision` 是已核逐尝试 `MH*2^-alpha` 的概率上界。
Delta0 与 `delta_known` 是诚实→理想、理想→公开有限 Sign 的不同端点，不能合并后
漏掉第二端。全局账本的上界之和超过 1 时保留该确切和，p0 自然截成零。
未知项使用 None，输出下界保持 null；不因为某个示例次数为零或测试通过而擅自补零。

`Premises` 的所有字段必须显式给出；任何 False/None 均不返回声称可用的 p0/E 下界。
即使全部 True，也只是**调用者的条件假设**，工具不认证其真实性。尤其包括：

- 与 J 无关的共同诚实轨迹、逐可达历史的统一界及完整带标签失败。
- 规范 native-strong 日志，目标独立均匀，经典 ideal free H2 及完整 raw 首触及。
- 可重放的攻击者/非 free coins、两轮源字节包络、指定 source/算术条件模型。
- ε_IBS 与 Run 使用同一有界 oracle/失败接口。无界攻击者被新 query/coin cap
  截断的损失，不能因有确定资源上界而填零；需证明其本来就在预算内或另付费用。

满足全部前提时，由 (5)(6) 得 `Pr[E succeeds]>=H(p0)`，其中 q 默认取 128。
这闭合条件的局部概率拼接，不证明生产服务→诚实 R 的完整 Delta0。
持久状态的条件对应另见 [service-law.md](service-law.md)。

## 6. 两轮 source-byte 包络：独立逐项核对

新增 Runner 继承冻结算法方法，换用独立的有界构造器/coins 实现。
令 `BI=Bu+Be+BH1`，`BS=max(Bz+Bc,L*(BP+Bu_sign))`，
`BR=max(Braw,Bc)`，则一轮非 free 的源字节上界为

```text
Bnf=QI*BI+qS*BS+H2entries*BR.                           (7)
```

该式覆盖每个身份的公开 U/E0 及全部 raw H1，包括目标被保守多算的 U/E0；
每次 Sign 只走 target Sim 或 known-key 分支，所以用 max；
范数重试至多 L，sampler/source 异常不会变成额外重试。
每个 H2 source 的初始 Bc 及随后延长，合计只到最大读取端点 BR；
前 n 位虽被覆盖，这些原 source bytes 仍实际消费，已在 BR 中保留。

新 free 回复只在 H2 entry cap 检查后发生。一旦构造失败，轮状态被吸收阻断；
即使失败前已抽挑战但尚未插 entry，每轮也至多 H2entries 次新挑战。
故一轮 free 源至多 `H2entries*Bc` B。重复查询、零长度 raw 和 sign-owner
不多抽一个 free challenge。攻击者另有每轮 BA 的固定累积上限。

对每个非 free label ell，设两轮分别需要前缀长 `x1_ell,x2_ell`。
惰性重放只产生 `max(x1_ell,x2_ell)`，所以

```text
bank.used = sum_ell max(x1_ell,x2_ell)
          <= sum_ell x1_ell+sum_ell x2_ell <= 2*(Bnf+BA).
all_source <= 2*(Bnf+BA)+2*H2entries*Bc.                 (8)
```

不同后缀触及不同 labels 或延长相同 label 都由此并集覆盖。相同 attacker label
实际至多 BA，但这里保守收 2BA。label/Python 容器有额外内存开销，不增加源字节；
式 (8) 不是峰值 RAM、OS 随机源实现成本或 CPU 时间上界。

冻结 n512/d2/w8/b31/p16383/r²64、QI8/qS8/H2entries128/L16 的确切值为：

| 项 | B |
|---|---:|
| 公开 U / E0 / H1 每身份 | 11,104,872 / 524,288 / 4,194,304 |
| known-key P / u 每尝试 | 11,020,294 / 642,980 |
| target z / c 每调用 | 13,744,738 / 64 |
| 一轮非 free Bnf | 1,627,875,392 |
| 两轮非 free | 3,255,750,784 |
| 两轮 attacker 上限 | 2,097,152 |
| 两轮 free H2 独立源上限 | 16,384 |
| 全部源合计上界 | 3,257,864,320 |
| 全局 budget，4 GiB | 4,294,967,296 |
| 为 free 预留后 bank cap | 4,294,950,912 |

bank cap 大于 `2*(Bnf+BA)=3,257,847,936`，并为 free 源独立预留了 16,384 B。
第一轮已用字节不超过一轮上界，第二轮 `register_run` 的 headroom 预检也不会
在合法轨迹上额外失败。每轮 attacker 和 free 源自身均有硬计数，不依赖 wrapper
外部攻击者自觉报告。单次源请求仍至多 256 MiB，未修改冻结生产 sampler 的 cap。

因此，对准入参数、合法 callback 和规定 source/算术条件模型，新增配置的额外
global entropy cap abort 上界恰为零。sampler 原有 abort、H1 解码失败、norm gate、
实际超出已定义 attacker/query 预算、损坏/抛错 source、分配失败或超时不在这个零项里。
默认 bound 是最坏路径证书，未实际分配/抽取 3.26 GB。
外部独立 uniform h helper 的 917,504 B 上限在 fixed-input Run 外，不能漏算为免费。

## 7. 提取对象与尚未授予的结论

两分支均实际验证并输出整数系数 Delta：

```text
Delta!=0, [I|Ahat|B|-h_star]*Delta=0 mod Q,
||Delta||²<=4*Bsig.
```

Q 奇数使从模 2Q 响应方程约去 2 合法；现有 `Q²>4Bsig` 进一步排除非零的
Q 倍数平凡解。该短核的环矩阵分布仍须与所声明的 HNF-MSIS 对应。
若另外满足 direct-ibs 的显式矩阵/seeded embedding 与 shared-Ahat hybrid 前提，
可将其公平界 F 换成本文 H，在完整 E 之后应用 MLWE hybrid；
不能将 MLWE 损失放进 fork 平方，也不能因此称生产 IBS 或 QROM 已安全。

未闭合项仍包括：完整生产 Delta0、无效/多 mpk/raw matrix oracle law、seeded
embedding、完整时间/堆内存、实际环/复合 Q/CBD1 困难性及正式参数、QROM。
本页未抽新 root/key/signature，未运行攻击；一般概率证明不是功能测试的推论。

## 8. 独立算术验收与复现

新测试 [test_srgg_bounded_classical_cost.py](../../../../tests/test_srgg_bounded_classical_cost.py)
独立枚举 owner 质量分割、用配方的可达最小值核 q1 尾段，检查跨全部断点的凸组合，
比较冻结公平界，并保留“一个 eta 类接受”时零有效 fork 的精确计数。
逐项检查账本端点、任何 None、任何未假设前提和巨大分母的十六进制往返。
字符串概率只允许有界整数或分子/正分母；先检查长度/语法/组件数字与保守 bit 界，
才调用 Fraction。monkeypatch constructor guard 证明科学计数、空白、过长分子/分母
等在构造前拒绝，避免 `1e-1000000000` 先分配巨大整数。
int/Fraction 仍支持独立的 262,144-bit 上限；不修改全进程十进制转换限制。

```text
python -m pytest -q tests/test_srgg_bounded_classical_cost.py --junitxml=build/outputs/srgg-bounded-runner-2026-10-16/bounded-cost-windows-final.junit.xml
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_bounded_classical_cost.py --junitxml=build/outputs/srgg-bounded-runner-2026-10-16/bounded-cost-sage-final.junit.xml
```

最终 Windows Python 3.14.7 为 **121 passed，0.30 s**；指定 WSL Ubuntu 24.04.4 LTS /
Sage 10.9 / Python 3.13.15 为 **同 121 项 passed，1.38 s**，两端均无失败、跳过或
pytest warnings。硬件为 Intel Core Ultra 7 255HX/x86_64；这不是性能基准。
较早两端各 87 项通过的 first 收据是字符串边界补全前开发依据，保留但不替代最终结果。
上述为公开精确算术，不抽身份、消息、密钥或 Gaussian，重复次数是确定性 case 数，
不做统计显著性或安全强度推断。旧 cost、冻结 runner、原收据均未改写。
