# SRGG 商挑战：coset law、强新颖性双射与有限 u 费用

2026-10-16。本项保持真实 full-c 哈希、签名字节、参数和后端不变，只构造证明用的商挑战对象。完成下列代数/分布引理及一组有限验证，**不宣称 QROM 不可伪造性或量子知识提取已完成**。安全标志仍为 `security_claim=none, backend_admitted=false, parameters_are_formal=false, nist_security_category=null`。

来源是冻结实现 `structured_execution.py` 的 `ExactRing.response/recover`、`Execution.sign`，以及 [native-sig.md](../2026-10-16-srgg-reduction/native-sig.md) 的交互 law 和 [strong-games.md](../2026-10-16-srgg-reduction/strong-games.md) 的完整游戏。本页的商等价推导是本项目分析，不假称原论文已有同样归约。可引用量子定理及其未匹配前提见冻结 [quantum-oracle-obligations.md](quantum-oracle-obligations.md)。

## 1. ζ 的整数像格和 binary 商

固定 `R_Z=Z[X]/(X^n+1)`，n 为偶数的二次幂，`m=n/2`、`ζ=1+X^m`、`ζ*=1-X^m`。把系数向量分为等长两半，整数乘法是

```text
ζ(u0,u1)  = (u0-u1, u0+u1),
ζ*(v0,v1) = (v0+v1, v1-v0),
ζ*ζ=2I,  ||ζu||²=2||u||².
```

因此

```text
ζZ^n = {v in Z^n : v0 = v1 mod 2},
η(v) = (v0+v1) mod 2,
ker η = ζZ^n.
```

像格的反向包含不能省略：两半同奇偶时，`u=((v0+v1)/2,(v1-v0)/2)` 是唯一整数逆像。于是对 binary c、c'，

```text
η(c)=η(c') iff c-c' in ζZ^n.
```

写 `c=a+X^m b`，定义 `χ=η(c)=a XOR b`。映射 `g(c)=(χ,b)` 在全部 n-bit 向量上是可逆线性变换，逆为 `c=(χ XOR b)+X^m b`，且 g 自逆。因此 full uniform c 对应独立 uniform χ、b，各为 m bit。

## 2. 理想 u：整个 coset law 只依 χ

对固定 full c，取

```text
u ~ D_(Z^n),r,-ζ*c/2,
v = ζu+c.
```

u 到 v 是 `Z^n` 与 `c+ζZ^n` 的双射，且

```text
u+ζ*c/2 = ζ*v/2,
||u+ζ*c/2||²/r² = ||v||²/(2r²).
```

因此 v 的**规范化** law 是 `D_(c+ζZ^n),sqrt(2)r,0`。分母是该 coset 的离散 Gaussian 总质量；同 χ 的 coset 恰相同，所以全部概率及其归一化也相同。这里没有把离散分母替换为连续积分，也不是只证明某个指数相等。

对同 χ 的 c 和规范 lift `c0=(χ,0)`，更具体的耦合为

```text
u0 = u + ζ*(c-c0)/2 in Z^n,
ζu0+c0 = ζu+c.
```

这给每个 coset 点的一一对应；等式中没有浮点、舍入或概率近似。

## 3. 同一 P、规范 lift 与重试/失败

固定任意满足既有准入的实际已发 key y。保持原来的、在 c 之前产生的 P 与承诺 `W=Abar_h P mod2Q`，令 `ybar=(y,1)`。响应为

```text
z=P+ybar*v.
```

由 §2，条件于每个 P、同 χ 的任意 full c，z law 完全相同。**P 不必在此等价中换成理想 Gaussian**：原有限 StructuredSampleF、其既有失败和同一已发密钥可以原样保留。

证明用商识别协议先由原 P1 产生 W；收到 χ 后，用 c0 及理想 u0 构造同一 coset law 的 v、z。完整 full-c 协议收到 `(χ,b)` 后的响应投影，与商协议相同。范数门只读 z，因此拒绝和成功的 law 也相同。逐尝试保留相同失败策略、最多 L 次 norm retry；P 或其它原语的异常直接传播，不改成整次重试。每一次失败尝试已经访问过的 hash 点也留在同一 oracle 中，不丢弃整条历史。

理想 u 本身没有有限 rejection/budget abort；从真实有限 u 换到它的费用在 §6 支付。上述等价既没有只条件化到成功签名，也没有借此免除原 P 的所有其它证明义务。

## 4. 固定 oracle 的接受域双射与 native strong

冻结恢复关系为

```text
Rec_h(z,c)=Abar_h*z-Q*j*c mod2Q,
j=(ζ*,0,...,0)^T.
```

若 c−c'∈ζZ^n，则 `Q*j*(c-c')=0 mod2Q`，故 Rec 只依 χ。固定 public、身份、消息和完整随机函数 F。把 F 的输出逐点用 g 重标记为独立的 `(Hχ,Hb)`。它们的域仍为原来 `(mpk,W,mu)`，**不加入身份**。

定义分析用商签名 `σq=(z,χ)`，验证先用 c0 恢复 W，检查原范数门并要求 `Hχ(mpk,W,mu)=χ`。原签名仍为 `σ=(z,c)`，须匹配全部 full F。

```text
strip(z,c) = (z,η(c)),
lift(z,χ)  = (z, (χ XOR Hb(mpk,W,mu), Hb(mpk,W,mu))),
             W=Rec_h(z,c0).
```

对每一个**接受的**原签名，χ 和 W 相同，而其 `c_high` 必须等于唯一的 Hb 值，因此 lift(strip(σ))=σ。反之，对每个接受的 σq，其 lift 满足 full F 检查，且 strip(lift(σq))=σq。这是固定 oracle 下接受域的逐点双射，不是只比较分布。

strip 对任意未验候选并不单射：例如 `c=0` 与 `c'=ζ` 同 χ。这个反例不破坏上面的结论，因为固定同一 `(mpk,W,mu)` 时，二者至多一个能通过 full F 检查。

对成功返回日志中的每个 `(id,mu,σ)` 逐一 strip，保留 id、mu。由接受域单射，最终通过验证的 exact 三元组是否已经返回，在两游戏中完全一致；同消息的新签名仍是 strong 伪造。失败签名不新增成功记录，重复身份和重复消息也保留原策略。这样没有把 strong 赢法降为 fresh-message，也没有制造跨身份底层签名别名。

签名 oracle 等价须使用 §3 的 law：商签名成功后在其恢复 W 处取 Hb 并 lift；失败轨迹保持同一 P/Hχ 表及重试策略。仅接受域双射本身不能证明任意两个 signing algorithms 相同。

## 5. 量子 H2 输出重标记：可证的 oracle 身份

先固定完整 n-bit output 接口 `O_F|x,t>=|x,t XOR F(x)>`。g 是可逆线性 CNOT 层，对每个基态均有

```text
g(g(t) XOR F(x)) = t XOR g(F(x)).
```

所以 `O_(g∘F)=G O_F G^-1`，需要一次原 query；由线性性，对任意与外部 reference 纠缠的叠加态同样成立。全函数 F 均匀时，Hχ 与 Hb 是独立均匀随机函数。反向以两个独立 oracle 逐一 XOR 输出可实现 joint oracle，至多两次调用。这是 oracle 等式，**不是安全提取或改编定理**。

若攻击者只拿到原 raw-XOF 的部分 byte/offset，必须补同一 n-bit 前缀、相干重标记与独立 suffix 的明确包装及 query/time 计费，不能把仅修改解码后 H2 返回值当成完整原始 oracle 等价。n512 的前缀为 64 B，χ、b 各 32 B；原代码的位/字节排列是确定置换，可以在 G 的前后执行，不改变分布。工具测试检查基态 CNOT 身份，没有实现 QRO 或这个 byte 包装。

## 6. 真实有限 u 的费用，含 bottom 与资源

保守的主证明路径仍把真实 u_batch 换成理想 product Gaussian，**保留费用**。从未改的冻结 n512 [执行收据](../2026-10-16-srgg-bridge/structured-execution-n512-d2w8.json) 读取：n512、r²=64、deep profile、L=16，整组 u 的有限 kernel TV `δu` 为原 `scalar_kernel_tv_including_aggregate_exact`，已包含既有拒绝和 aggregate cap 中止。

Sign 请求是经典的，H1/H2 允许量子查询。对每个已选定的经典 center 输入，若有限/理想输出 kernel 的 TV≤δu，给该经典输入附上任意相同的量子 reference 后，两个 cq 输出的 trace distance 仍≤δu：逐块迹范数求和恰是经典 L1 质量差，reference 密度矩阵迹范数为 1。后续相同 oracle unitary、norm gate、输出与重试由数据处理不会放大此项。因此在 uniform-center 假设与原熵条件下，最多 qS 个经典 Sign、每次 L 次尝试给

```text
Delta_finite_u <= min(1,qS*L*δu).
```

这里的“uniform-center”指 TV 界对**全部准入 center 统一有效**，不要求 center 本身服从均匀分布。每次 fresh sampler coins 还须独立于同一条件下携带的量子 reference。这里不要求在量子叠加 center 上运行 Gaussian。它也不自动处理 H1 的 coherent latent-key 函数；两种接口不能混同。理想 u 另需理论上可采，或使用已证有限到理想 hybrid 的虚拟游戏；本项没有生成一个可运行无限精度的 sampler。

收据的有限 u **每尝试硬字节 cap 为 642,980 B**，不是实际平均用量或速度；原最坏全 scalar path cap 是 260,259,840 B。qS=2^40、L=16 时，本项算术 `qS*L*δu<2^-138`。它只覆盖 u replacement；不是整个 IBS 统计界、安全优势或实测容量。没有把证书读取时间当成采样性能。

**冻结有限 sampler 的附加一致性观察。** `WideScalarGaussian.checked_inputs` 把 center 写成整数 shift＋fractional，后续 support、relative weights、拒绝次序只读 fractional；sample 返回 shift＋value。同 χ 时上述 u 与 u0 的中心之差为整数。两边 center 均准入时，注入相同 byte stream，逐标量输出恰按该整数平移，所有读取大小、尝试计数和 bottom 完全一致；相同固定 batch cap 也保持。新增小维 Sage 测试覆盖 16 个 full c 的真实有限抽样及强制 abort。这个事实支持一个 finite→finite 商等价，但本页通向**理想商识别**的主路径仍支付 δu，不将其从总账中删去。

本项保留有限 P，不会让后续 KLS 前提免费成立：若使用原理想 P1 的 36351-bit 承诺熵，仍需其正确整场 P hybrid 或单独的 finite-P 逐 atom 证明，不能从 additive TV 直接继承该熵。

## 7. 非零差分前进一步，量子 PoK 和 H1 仍需证明

同 W 下两个接受商识别 transcript 的 χ 不同。若响应 z=z'，恢复等式迫使 `Q*j*(c0-c0')=0 mod2Q`，即 `ζ*(c0-c0')=0 mod2`，所以 η(c0)=η(c0')，矛盾。故 Δ=z−z' 非零；模 Q 消去 Qj 项，再用 Q 奇数可逆的 2，得到 `[A,-h]Δ=0 modQ`，且 `||Δ||≤2sqrt(Bsig)`。现有 Q²>4Bsig 排除 Δ 非零但全为 Q 倍数。商挑战由此修复“不同 full c 仍可能零差分”的那个经典代数障碍。

它尚不是量子 PoK：两个不同 χ 的接受响应必须由适用量子 extractor 产生，普通 rewind 和 CUR 碰撞抵抗不能保证这一点。若选用 DFMS 的量子 PoK 路线，还须准确规定 knowledge relation 和可提取 witness；诚实 key y 是 preimage，而上述 Δ 是短核，二者类型不同，不能直接把“提取短核”填成原 secret-key witness。也可寻找直接针对短核输出的量子识别安全定理，但须核其 collapsing/unique-response 等实际假设及损失。

KLS 的 UF-NMA 项、lossy 方案的 lossy soundness、以及 H1 chosen-identity 的量子模拟仍单独开放。§5 的相干输出变换和 §4 的 strong 双射只减少这些问题的输入对象，不提供已有量子提取器，不解决原文半常数目标 Sign 或跨身份新颖性缺口。失败攻击和有限代数穷举不能承担这些证明。

## 8. 新工具、测试和复现

新增 `quotient_challenge.py`、`test_srgg_quotient_challenge.py` 是独立研究工具。纯 Python 工具使用 exact int/Fraction，给 n2/4/8 共 828 个 coset 指数恒等检查，及 n2/4 的 8 个固定 oracle 表/范数门接受域双射检查，全部非空；测试另用独立 schoolbook 环乘法、全部小挑战/输出寄存器基态、完整小响应枚举与 strong 日志检查。有限表是代数夹具，不冒充真实 IBS 的 ROM/QROM 运行。

```text
python -m experiments.research.candidates.srgg.quotient_challenge --output build/outputs/srgg-qrom-quotient-2026-10-16/quotient-challenge.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_quotient_challenge.py --junitxml=build/outputs/srgg-qrom-quotient-2026-10-16/quotient-challenge-sage.junit.xml
```

最终指定 WSL Sage 10.9 / Python 3.13.15 **34 passed**；工具 JSON 在 Windows Python 3.14.7 生成，记录环境、输入收据和源码 SHA-256。全部有限表与指数检查取熵 0；Sage 测试只对 n4/r²64、16 个 full challenge 使用显式测试随机源做平移一致性检查，另有同流强制拒绝，未运行 n512 抽样。没有新主密钥、身份、消息、签名服务或量子攻击实验；本模型 identity/message 固定，字节长度和随机重复次数不适用。原始 JUnit/JSON 写入上述新目录，不覆盖冻结收据。
