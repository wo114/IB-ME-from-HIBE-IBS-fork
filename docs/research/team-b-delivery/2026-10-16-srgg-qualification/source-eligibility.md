# SRGG 底层 strong 路线与采样来源资格

日期：2026-10-16。基线：`47a0341`。本文件是定向来源审查与精确推导，不是安全准入证书。当前继续保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。

结论：找到明确覆盖随机化 Fiat–Shamir 的条件性 strong 定理；SRGG 仍缺该定理的实际前提映射。ζ 的 factor2 有可重现的系数空间推导，但不能仅凭形状相加继承原文的离散分布定理。源 Table 4 三行还存在对应识别协议的公开 CUR 碰撞，以及满足可观察范数条件时的同消息签名可塑性；未运行源 n512 的诚实签名，未估计该条件的成功概率，故不宣称无条件破坏源方案。

## 1. 来源、版本与读取范围

| 来源 | 可追溯版本与位置 | 本轮资格 |
|---|---|---|
| Jia、Liu、Tang、Wang，*Constructing Efficient Identity-Based Signatures on Lattices* | [DOI 10.1049/ise2/6684889](https://doi.org/10.1049/ise2/6684889)；本地 `papers/2025_efficient_ibs_jia.pdf`；SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152` | 定向核对 p.3 §2.2、p.4 Definition 3/Theorem 1、p.6 Table 3、p.8 Algorithms 7/8/Theorem 2、p.9 §5.1/Table 4；公式经图片目视复核 |
| Peikert，*An Efficient and Parallel Gaussian Sampler for Lattices*，作者稿 | `papers/2011_peikert_parallel_gaussian_author.pdf`；SHA-256 `39ae6ea450a98267ab7f3ac682e4daae4a91ec8aed9432dca666e05eefd46163` | 定向核对 PDF p.7 §2.4、p.9 Theorem 3.1、p.11 Lemma 4.1、p.12 Algorithm 1/Theorem 4.2；支持 shape 约定与理想卷积/舍入背景，尚未覆盖当前有限实现 |
| Devevey 等，G+G | [ePrint 2023/1477](https://eprint.iacr.org/2023/1477)；元数据列 2023-11-13 修订 | 元数据可读，PDF 请求返回 403；正式出版预览与 HAL 页面亦未取得可审阅全文。不声称已读完整 G+G strong 证明 |
| Kiltz、Lyubashevsky、Schaffner，*A Concrete Treatment of Fiat-Shamir Signatures in the Quantum Random-Oracle Model* | [正式出版版本，DOI 10.1007/978-3-319-78372-7_18](https://doi.org/10.1007/978-3-319-78372-7_18)；[UvA 开放阅读 PDF](https://pure.uva.nl/ws/files/45974860/A_Concrete_Treatment_of_Fiat_Shamir_Signatures.pdf) | 在线核对 Definitions 2.4–2.7、§3.1、Theorems 3.3/3.4；无本地下载或全文归档。Theorem 3.3 的正文证明指向 full version，本轮只核定理陈述及其接口前提 |

SRGG/Peikert 页码均为本地 PDF 实际页码。KLS 的 UvA PDF 有一页库封面，PDF 第 14、16、21 页分别为印刷 p.564、566、571。

作者公开的 [GplusG 仓库](https://github.com/jdevevey/GplusG) 是参数估计辅助程序；其存在不能替代原始安全证明，也不能当作完整协议实现的证据。

**模数读取纠正。** 高清核对 SRGG p.8 后，Algorithm 7 line 6 的矩阵域为 `R_(2Q)`，line 7 明确 `w=Abar*p mod 2Q`，与 Algorithm 8 一致。此前低分辨率误读成 `mod Q` 的说法已撤回；不得据此制造 Algorithms 7/8 之间的模数冲突。gadget 的 q、IBS 的 Q、响应关系的 2Q 仍须分别映射。

## 2. ζ：能证明的精确部分

采用原文 §2.2 的密度约定：

```text
ρ_(Σ,c)(x) = exp(−π (x−c)^T Σ^(-1) (x−c)).
```

Σ 为 density shape。相应连续高斯的真实协方差为 `Σ/(2π)`；离散高斯的实际二阶矩一般不严格等于此量。

令 `R=Z[X]/(X^n+1)`，n 为偶数，采用标准系数内积；令 J 为乘 `X^(n/2)` 的负循环系数算子。则

```text
J² = −I,                  J^T = −J,
Mζ = I+J,                 ζ*=1−X^(n/2),
Mζ Mζ^T = (I+J)(I−J)=2I, ζ^(-1)=ζ*/2.
```

对 Algorithm 7 的 `u←D_(R,r,−c/ζ)`，令 `t=ζu+c`。映射是 R 到陪集 `ζR+c` 的双射，并且

```text
||u+c/ζ||² = ||ζ^(-1)t||² = ||t||²/2.
```

所以 t 的精确离散概率质量与 `exp(−π||t||²/(2r²))` 成比例，即陪集 `ζR+c` 上 shape 为 `2r²I` 的离散高斯。这一结论包含陪集归一化常数；不能把不同 c 下的归一化常数假定相同，也不能把 t 的实际 covariance 写成精确的 `2r²I/(2π)`。

令 `W=M_[y;1]`。若目标响应 shape 是 `Σbar`，则连续形状相加所要求的扰动 shape 是

```text
Σbar_p = Σbar − 2r² WW^T.
```

原文 Table 3 字面减去 `r²WW^T`；代码明确采用 factor2。把所有 shape 统一除以 `2π` 不会消除这个相对因子。当前只确认该代数关系，不声称已经证明完整离散卷积、HVZK 或原论文勘误。

### 两种可重新推导的选择

| 选择 | 固定什么 | 必须重核什么 |
|---|---|---|
| 当前研究解释 | 保留 `u` 的 shape `r²I` 与 Algorithm 7 响应式；扰动采用 factor2 | 证明离散卷积/陪集质量界及 challenge-dependent 归一化误差；重核正定、舍入、尾界、no-abort transcript 分布 |
| 另一候选解释 | 若坚持 factor1 扰动，则把 `u` shape 改为 `r²I/2` | 这是宽度/协议解释变更；须重新证明平滑条件、采样分布和安全对应，不能悄悄替换当前实现 |

为避免把不同 r 的用途混同，暂写 `r_u` 为上面的 u 宽度、`r_round` 为随机舍入宽度。至少须有

```text
Σbar_p − r_round² I ≻ 0,
λ_min(Σbar) > 2r_u² ||W||₂² + r_round²     （一个充分条件）.
```

正定只保证这一几何步骤可定义。还须界最终离散输出的误差、范数中止后分布和跨查询总预算。有限精度连续阶段是有限支撑，与理想连续密度的 TV 为 1；误差证书应作用于最终随机舍入后的离散输出或适当耦合，不能直接给连续阶段填随精度收敛的 TV。

代码映射：`algebra.py` 的 `zeta/zeta_star/response_from_values`；`geometry.py` 的 `signature_geometry(noise_factor=2)`；`runtime.py` 的半整数精确中心与 u 抽样；`full_sampling.py` 的 Cholesky shape 到 `Σ/(2π)` 换算。当前研究配置只接受 factor2。

## 3. r：必要反例与一个独立的充分证书

原文 p.9 确为 `Qs=2^40`、`ε=1/sqrt(Qs*256)=2^-24`；256 是普通整数。其维度取 `D=(2+w)*5*512=10240`。按 §2.2 的 shape-width 字面解释，`r=1.16` 不满足平滑的必要条件

```text
2D exp(−πr²) ≤ ε.
```

这是来自最短对偶向量的严格反例，不是安全攻击。数值 `sqrt(ln(2D/ε)/π)/sqrt(2π)≈1.16004` 提示物理标准差/shape width 混用的可能性，但未经作者确认，而且该表达式自身只是必要下界。

以下给出本文件独立推导的、仅对 `Z^D` 的充分证书，避免把必要下界当充分界。令

```text
θ(r) = sum_(k in Z) exp(−πr²k²),       t=exp(−πr²).
ρ_(1/r)(Z^D\{0}) = θ(r)^D−1.
```

对整数 k≥1，`k²≥1+3(k−1)`，于是

```text
θ(r) ≤ 1 + 2t/(1−t³).
```

取 **shape width r=3**。由 `π>3.14` 与 `ln 2<0.7`，有 `9π>40 ln 2`，故 `t<2^-40`。进而

```text
a := 2t/(1−t³) < 3*2^-40,
D*a < 30720*2^-40 < 2^-25,
θ(r)^D−1 ≤ exp(D*a)−1 < 2D*a < 2^-24.
```

最后一步可由 `exp(x)≤1/(1−x)`（0≤x<1）得到；这里 x<2^-25。`ln 2<0.7` 亦可直接用 `exp(0.7)>1+0.7+0.7²/2+0.7³/6+0.7⁴/24>2` 核对。因此 r=3 在上述约定下给出严格的 `Z^10240` 平滑充分值。

这只闭合一个单位格的平滑条件，不是整套 SRGG 正式参数。若采用该宽度，必须统一重新计算 `σ=br`、所有 master/signature shape、谱范数、γ、q/Q 条件、尾界与中止预算；不能仅替换 r，也不能给它贴 NIST 等级。

## 4. 已找到的明确 strong 条件定理

KLS2018 Theorem 3.3（印刷 p.571）覆盖随机化 FS：在 no-abort HVZK 误差 `εzk`、commitment min-entropy `α` 等前提下，量子 strong 优势满足

```text
Adv_sUF-CMA_FS(A)
 ≤ Adv_UF-NMA_FS(B) + QS*2^(-α+1)
   + κm*QS*εzk + Adv_CUR_ID(C),
Time(B)=Time(C)=Time(A)+κm*QH*QS.
```

`κm` 是最大签名尝试数。CUR 的 Definition 2.7（印刷 p.564）要求难以产生同一 `(W,c)` 的两条不同有效响应。Theorem 3.4 可进一步以 lossy-key indistinguishability 和 lossy soundness 界 UF-NMA，但这些也是待映射的条件。[定理来源](https://pure.uva.nl/ws/files/45974860/A_Concrete_Treatment_of_Fiat_Shamir_Signatures.pdf#page=21)

这是一条具体的 **conditional strong 路线**，并非普通 EUF 自动升级。Theorem 3.1/3.2 的 one-query-per-message 版本不能代替这里的 full randomized signing 接口；本文件不引入 PRF 去随机化或消息签名缓存。

SRGG 的相应识别协议可自然定义为

```text
V(pk,w,c,z)=1  iff  Abar*z−Q*c*j = w (mod 2Q), ||z||₂≤γ,
c in {0,1}^n,     z in R^((2+w)d+1).
Rec(pk,c,z)=Abar*z−Q*c*j mod 2Q.
```

固定规范的模数代表和 wire 编码后，该恢复式提供确定的 commitment。这是运用 commitment-recoverable FS 表示的代数基础；仍须核对整个有效域与规范编码的映射。[KLS §3.1，印刷 p.566](https://pure.uva.nl/ws/files/45974860/A_Concrete_Treatment_of_Fiat_Shamir_Signatures.pdf#page=16)

要给当前 SRGG 使用 Theorem 3.3，还需分别给出：真实公钥/密钥分布、完整 no-abort simulator 与 `εzk`、承诺 min-entropy、UF-NMA 的具体假设归约、CUR、以及有限采样/设置/发钥/签名失败与总查询预算的对应。它们不能由正定测试或有限攻击未成功替代。

## 5. CUR：精确归约，以及源参数的公开反例

### 5.1 同承诺同挑战的差分

若 z≠z' 是相同 w,c 的有效响应，则

```text
Δ=z−z'≠0,        Abar*Δ=0 mod 2Q,        ||Δ||₂≤2γ.
```

这给出到 **真实 Abar 分布的短核关系** 的精确变换。不能直接将它叫作 uniform standard MSIS：Abar 的前块是 `2I`，其余块含 `2A,2B`，末列为 `Qj−2h`，模数 2Q 为合数；h 来自身份 hash/PSF 的解释，B 来自陷门。需要一个明确的分布变换/归约，或把相应 structured relation 写成额外假设。不得把“已得到短核向量”直接改写成“已归约到已估计的 standard MSIS”。

### 5.2 已知 2I 核向量给出的 CUR 对

这一结构还有一个不用任何困难性假设的检查。令 e 是响应首个 `2I_d` 块中第一个多项式的常数系数单位向量；令 e_out 为对应输出单位向量。对任意奇 Q，取

```text
c=0,
z_plus = ((Q−1)/2)*e,
z_minus=−((Q+1)/2)*e,
w=(Q−1)*e_out mod 2Q.
```

则二者是不同的合法整数系数向量，且

```text
z_plus−z_minus=Qe,
Abar*z_plus=Abar*z_minus=w mod 2Q,
max(||z_plus||₂,||z_minus||₂)=(Q+1)/2.
```

因此，在上述自然识别协议及 `γ≥(Q+1)/2` 的条件下，公开构造直接违反 CUR。核对原文 Algorithm 7 line 10 与 Algorithm 8 lines 2–4，z 的域为相应 R 向量，验收项为 commitment/hash 与范数；没有额外奇偶或有界单系数条件排除该对。`c=0` 属于其指定的二进制挑战空间。

源 Table 4 的 `Q=15,744,063` 给出

```text
z_plus  =  7,872,031 e,
z_minus = −7,872,032 e,
w       = 15,744,062 e_out,
threshold = 7,872,032.
```

三行所列 γ 为 `42,086,491.7`、`63,653,172.0`、`86,573,930.5`，全部越过该阈值。故它们不能经这个 ID/CUR 路线取得 strong 结论。当前有界研究 Config 要求严格 `Q²>4*signature_bound_squared`，排除了这条显然的 Qe 碰撞，但没有因此证明剩余 CUR。

**结论边界：** 这是 underlying ID 的 CUR 反例；它未寻找满足 `c=Hbar(w,μ)` 的消息，因此不是已完成的 FS/IBS 伪造。失败一个 strong 充分条件不等于证明 strong 不可能；其它证明或协议变更需各自给出。无论如何，不应在源三行参数上调用 KLS Theorem 3.3 并把 CUR 项略掉。

### 5.3 从已有效签名得到的条件性 strong 可塑性

与上一节直接构造 `c=0` 的识别响应不同，本节以一条**已经有效**的 FS/IBS 签名 `(z,c)` 为输入，保持消息、身份、公钥上下文和 c 不变。令 v 是第一个 `2I` 块中的任意单个系数，e 为该系数的单位向量，令

```text
shift = −Q  if v>0;  +Q if v≤0,
z' = z+shift*e.
```

有 `z'≠z`，且 `Abar*(z'−z)=2*shift*e_out=0 mod 2Q`。因此对**任意原挑战 c**，恢复的承诺 w 完全相同，原来的 `c=Hbar(w,μ)` 也原样成立，**无需寻找新的 hash fixed point**。剩余的必要检查是新响应的范数和既有对象域：

```text
||z'||² = ||z||² + Q² − 2Q|v|.
```

只要原签名有效且该值不超过 `B=floor(γ²)`，就得到同身份、同消息、同上下文的另一条有效签名。一次签名查询后输出这条新签名，或确认它不在此前已返回的签名集合中，即满足 strong 赢法的新签名要求。普通 fresh-message 赢法不允许用这条已签消息。

一个不依赖所选 v 大小的、可直接从公开签名检查的充分条件是

```text
||z||² ≤ B−Q².
```

它不是必要条件：较大的 |v| 还能降低新范数。对源 Table 4 的字面十进制 γ，纯整数门限如下；`Q²=247,875,519,747,969`：

| 源行 | `B=floor(γ²)` | 保证该变换成功的 `||z||²` 上限 `B−Q²` |
|---|---:|---:|
| PARAM-I | 1,771,272,783,614,168 | 1,523,397,263,866,199 |
| PARAM-II | 4,051,726,305,661,584 | 3,803,850,785,913,615 |
| PARAM-III | 7,495,045,442,218,830 | 7,247,169,922,470,861 |

这些是**观察到有效签名以后**的条件门限。它们不证明每条有效签名都满足 margin，不估计诚实分布落入 margin 的概率，不构造源 n512 的诚实签名，也不据此宣称源参数上的无条件 strong 攻击已经运行成功。

当前 Config 的严格 `Q>2sqrt(B)` 排除所有这种单系数 ±Q 平移后的范数内 pair，而不只排除 5.2 的对称例子：若 z,z' 均在范数球内且 `z'−z=±Qe`，三角不等式给

```text
Q=||z'−z|| ≤ ||z'||+||z|| ≤ 2sqrt(B),
```

与 gate 矛盾。此结论不证明其它短核向量不存在，也不证明整个 strong 安全性。

`coefficient_malleation` 输入公开系数 v 与旧范数平方，返回精确新系数、新范数和条件检查；`transform_response` 对展平的公开响应修改首个系数，保持输入不变。两者都不验证原签名或读取私钥。调用者须先确认原签名有效，并使用同一消息/身份/上下文/c；工具明确保留这一前提。

## 6. 到整个 IBS 的第二层缺口

即使将来底层 SIG 的 sEUF 资格闭合，SRGG p.8 Theorem 2 仍须单独适配：定理文字假设/结论使用 sEUF，而其 G0 赢法排除已签过的 `(id*,message*,.)`，是 fresh-message 限制。strong IBS 应排除返回过的确切三元组，并允许对已签消息产生另一条未返回的有效签名。

不能只删改 G0 一行就算证明完成：需要验证分区身份、签名模拟、PSF 发钥分布、量子随机预言机改编和最终伪造转移在该赢法下仍成立。固定发钥服务与 HNF 后密钥分布/失败策略也要属于相同模型。KLS 的底层定理不自动完成这一步。

## 7. 本文件的可交付结论

| 项目 | 当前能核定的结论 |
|---|---|
| Alg.7/8 的 2Q | 已目视确认一致；撤回旧误读 |
| ζ | 精确算子与离散陪集密度推前已给出；factor2 全分布/安全继承待证 |
| r | 字面 r=1.16 的必要条件失败；r=3 有独立 `Z^10240` shape-width 平滑充分证书；整组参数未准入 |
| 底层 strong 来源 | KLS Theorem 3.3 是明确条件定理；当前前提尚未全部映射 |
| CUR / strong 可塑性 | 源三行有公开 CUR 对；有效签名满足精确新范数门限时可同消息变换；未测源诚实签名成功率；当前 Config 排除单系数 ±Q 范数内 pair |
| 全部 IBS strong | fresh-message 到 strong 的游戏与归约改编仍未完成 |

核验使用公开参数和精确整数算术，不读取私钥、不运行源 n512 后端、不作资源/困难性估计。已有小挑战公开伪造负控应继续保留。本文件既不把源数字当安全实例，也不把 Kyber/NIST 比较目标当已获等级。

可执行审计为 `experiments/research/candidates/srgg/cur_obstruction.py`，schema `/2`。它以纯整数输出上述 pair、条件性同消息变换、精确平方范数门限、Table 4 三行结果与现有 Config gate；不改变生产验证器。模数/响应系数绝对值最多 4096 bit，平方范数最多 8192 bit，展平响应最多 65536 个系数，拒绝偶 Q、bool 和非精确整数；范数不得为负，响应系数允许为负。门限以下只表示该 pair 或变换不适用，不表示已经证明 CUR。

```powershell
python -m experiments.research.candidates.srgg.cur_obstruction --modulus 15 --gamma-squared 64
python -m experiments.research.candidates.srgg.cur_obstruction --modulus 15 --gamma-squared 144 --coefficient 3 --old-norm-squared 9
python -m pytest -q tests/test_srgg_cur_obstruction.py
```

本地结果：58 passed。测试通过真实 `recover_commitment` 独立交叉检查 CUR pair，并对 n=2、n=4 的全部二进制挑战检查变换前后承诺一致，包含正/负/零 v 和非零其它公共块。另覆盖范数门限前一整数与等号、充分 margin 非必要、Config 的 `Q²−4B=1` 边界、有限整数类的 triangle 排除、资源 cap 和 CLI JSON。它们是代数/实现证据，不是整个方案的 strong 安全证明。
