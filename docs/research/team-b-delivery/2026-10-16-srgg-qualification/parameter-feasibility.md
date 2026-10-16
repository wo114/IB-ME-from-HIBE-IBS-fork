# SRGG 独立参数的条件筛选与扩维可行性

日期：2026-10-16。对应代码：
`experiments/research/candidates/srgg/formal_candidates.py`；
测试：`tests/test_srgg_formal_candidates.py`。

本材料完成与 HIBE 无关的整数约束筛选和资源计数。**没有交付正式安全参数、
NIST 等级或可运行的大参数 IBS 后端**。`Candidate` 是独立的研究输入，
没有扩大现有 `Config`、`Params`、对象或采样器的接受范围。

## 原文与实现的条件边界

选定原文：Jia 等，DOI `10.1049/ise2/6684889`，仓库
`papers/2025_efficient_ibs_jia.pdf`，已核对版本 SHA-256：
`258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。
使用的是该版本相关页的定向阅读，不把本次参数核对描述为全文复现。

| 证据位置 | 原文事实或工程观察 | 对参数筛选的影响 |
|---|---|---|
| 原文 p.4，Theorem 1 | 要求奇数 `q > max(2γ, s1·ηε(Z^m))`，结论写 EUF-CMA | 把该 q 映射为 IBS 的 Q 仍是条件解释；只检查 `Q>2γ` 不能满足整个定理 |
| 原文 p.8，Theorem 2 | 要求底层 SIG 满足 sEUF-CMA | 尚不能把第 1 定理结论直接升级成这个前提 |
| 原文 p.9，§5.1 | `n=512,p=16383,b=31,w=2,Q=15744063`；引用 `r≈1.16`，提取查询上界 `2^40` | 密度宽度与物理标准差的归一化须澄清 |
| 原文 p.10，Table 4 | γ 分别为 `42086491.7,63653172.0,86573930.5` | 三行在临时 `q=Q` 解释下都不满足 `Q>2γ`；`2Q` 既是偶数且仍小于这些 `2γ` |
| `source_correspondence.py` | ζ 系数算子乘转置为 `2I`，HNF 修复满足精确关系及一般范数界 | 本筛选显式使用 factor2；未解决原表格对应、修复后密钥分布和归约 |
| `geometry.py/runtime.py/full_sampling.py` | 现实现展开系数稠密有理矩阵、精确 LDL、连续 SampleF 后逐系数离散舍入 | 大维度参数不可以通过放宽 n 常量直接运行 |

`formal_candidates.py` 保留原文三行的核对结果，并另给条件候选。
二者没有混成同一参数集；未计算困难性攻击成本，`nist_security_category=None`。
老师允许对标 Kyber/NIST，解释为统一目标与资源参照；ML-KEM 是 KEM，
其等级不能移植给 IBS。标准参照：[FIPS 203](https://doi.org/10.6028/NIST.FIPS.203)。

## 已实现的精确约束

以下统一用密度 `exp(-π x^T Σ^-1 x)`。连续高斯的物理协方差是
`Σ/(2π)`；代码中的平方宽度均为这个 Σ 的参数。这里没有猜测原文表格应乘哪个因子。

记 `L=(2+w)d`、`Dext=L n`、`Dsig=(L+1)n`。CBD1 陷门每个系数绝对值至多 1，
每个 n 维负循环块的 Frobenius 范数平方至多 `n²`，所以

```text
||M(R)||op² ≤ ||M(R)||F² ≤ 2 d² w n²
||[M(R); I]||op² ≤ 2 d² w n² + 1 = Croot.
```

若完整用户向量系数范数平方至多 U，则

```text
||M(y)||op² ≤ ||M(y)||F² = n ||y||² ≤ n U
||[M(y); I]||op² ≤ n U + 1 = Cuser.
```

因此当前 factor2 解释下，下列整数条件足以让残差形状严格大于 `r² I`：

```text
min(master_first_squared,master_second_squared) > b² r² Croot + r²
min(signature_first_squared,signature_second_squared) > 2 r² Cuser + r².
```

这是一套保守的充分条件，允许真实见证满足更紧的谱范数界。
它不声称复现原文推荐参数，也不保证完整算法的抽样分布。
最小特征值的上述下界确保所需 Schur 补正定；小参数测试另外调用现有精确
`master_geometry/signature_geometry`，检查实际 LDL pivots。

HNF 修复将近似向量头部加上无符号误差 `e∈[0,p)`，再居中模 Q。
居中只会降低每个头部系数的绝对值，因此若近似完整向量满足假定的平方范数上限 Braw，
修复后完整向量满足确定性上界：

```text
U = 2 Braw + 2 d n (p-1)².
```

**Braw 是本筛选的条件输入**，当前后端没有执行这项 raw cap 检查。
没有给出提取分布落在 Braw 内的概率；该上界不识别 HNF 后的密钥分布。
候选生成器暂用 `Braw=16·Dext·master_squared`，这只是公开的研究 cap 选择。
因子 16 不带高斯尾概率保证，不作为推荐参数。签名 cutoff 暂用目标 shape 的 trace，
与当前 `Config` 的计算方式一致；同样未证明实际中止概率。

`Q>2γ` 全程用 `Q²>4·signature_norm_squared_cap` 的整数比较，
不先取 γ 的向上取整。若 provisional q/Q 映射后来不成立，这一 gate 应按真实定理改写。

## 独立的 Z^D smoothing 充分证书

实现了一项不依赖浮点数的充分界，仅用于标准整数格：

```text
a = 2^(-2 r²)
t = 2a/(1-a³)
x = D t
rho_(1/r)(Z^D \ {0}) ≤ x/(1-x),  当 x<1.
```

依据是 `π>2 ln 2`、`k²≥1+3(k-1)`，以及
`(1+t)^D-1 ≤ Σ_{k≥1}(Dt)^k`。所有比较用 `Fraction` 精确进行。
这是针对所声明欧氏密度的标准整数格 dual Gaussian mass 上界，
**不是 SampleF 连续 ticket、有限精度、卷积误差、整个服务或论文归一化的证书**。
当 `x≥1` 时报告界不可用，没有把失败当作 smoothing 条件必然不成立。

默认研究候选选 `r²=64`、`D=Dsig`、目标 ε=`2^-80`；三行均满足这个保守充分条件。
这项条件本身不分配用户数、签名数、gadget 及其它误差项的总预算。

## 有条件候选及其成本

候选生成器使用 `n=512,p=16383,b=31,w=8,r²=64`，模块秩取 2、3、4，
宽度按上述全见证界加 1 选取，然后传播假定 Braw 至 U。
`Q=13972913866395903`。三个候选的整数几何条件、provisional Q gate 和
Z^D smoothing 充分界均通过；所有正式安全标志仍为 none/false/false。

有限枚举 `w=2..8` 时，三个秩在该候选生成规则下首个算术通过点均为 `w=7`；
`w≤6` 因 `Q>2γ` gate 失败。这是特定 cap 和宽度规则的枚举结果，
不表示安全、性能或参数尺寸最优。报告保留 w=8 作为固定研究点。

| 秩 d | Dext | Dsig | 一份 Dsig² 矩阵按每条目 64 字节的载荷场景 | 一次完整形状 LDL 的有理更新次数 | 同一环方阵的系数数 |
|---:|---:|---:|---:|---:|---:|
| 2 | 10,240 | 10,752 | 7,398,752,256 B | 207,165,061,376 | 225,792 |
| 3 | 15,360 | 15,872 | 16,122,904,576 B | 666,413,386,496 | 492,032 |
| 4 | 20,480 | 20,992 | 28,202,500,096 B | 1,541,736,668,416 | 860,672 |

上述内存只是**单份矩阵载荷场景**，不含 Python/Sage 对象开销、行容器、
同时存活的 target/perturbation/residual/Schur 矩阵、逆矩阵和有理数增长。
它不是实测峰值，也不是受证明保护的内存上下界。
代码另外报告每条目 16、2048 字节场景，便于审查敏感度。
LDL 更新数精确对应当前 `positive_pivots` 循环，为 `D(D-1)(D+1)/6`；
每次更新含有理乘、除、减；该计数不包含其它矩阵运算。

当前 dense Gram 初始化另需 `D²·Dlower` 次标量乘法。
环多项式 schoolbook 乘法需 `n²` 次系数乘积；报告分别列出公钥关系、
签名 commitment 和 response 秩一更新的真实矩阵维度。
没有将运算次数换算成未经实测的秒数。

三个 w=8 候选还都超过现有 scalar Gaussian 的平方宽度上限 `10^12`，
其中 d=2 的签名平方宽度约为 `2.216×10^22`。
即使逐个放开 dense 维度门，当前 `Config`、OnlineScalarGaussian、
SampleF 资源门及对象编码仍不能执行这些研究点。
报告给出的固定宽度打包字节仅是明确声明的假想编码载荷，
不计 JSON/framing/参数快照，不冒充现有 wire 或编码下界。

## 可执行的扩维路线

1. **先保持协议与 sampling law，替换形状表示。**
   保存 `d×wd` 环陷门和签名见证 y，利用 Σ 为分块对角减低秩 Gram 的形式，
   实现环矩阵或线性算子。闭包运算包括环共轭转置、乘法和 Schur 补；
   同一个 L×L 环方阵需 `L² n` 个系数，展开为系数矩阵则需 `L² n²` 条目。
   上表的结构存储正好相差 n=512 倍，但这个计数不证明运行时间也改善相同倍数。
2. **以小参数稠密精确版本作为比较基线。**
   对全部单位向量和真实整数向量，比较结构 matvec 与旧矩阵；比较二次型、
   共轭转置、conditional center 及 Schur 结果。先在 n=2/4/8 精确对应，
   再扩大到 n=16/32/64。共享 backend/wire 接入前冻结该层的输入输出契约。
3. **连续因子分解可研究频域路线，但不可直接宣称离散分布保持。**
   负循环算子在适当复嵌入下可按频率处理；必须保持共轭配对、实系数恢复、
   shape 正定和有限精度误差。连续样本变回系数空间后再执行原逐系数
   Gaussian rounding；不能把频域格上的独立离散舍入当作原整数格舍入。
   若改用精确环逆元，需另管分母和有理数增长，不能预先许诺统一 8192-bit 界。
4. **独立扩展 scalar-width 和熵资源契约。**
   在线 scalar rejection 可以避免枚举全部支持，但必须重新生成大宽度的 radius、
   interval、quantization、acceptance、abort 与 tape 证书。
   参数快照需固定这些门；提取一旦 pending/failed，不可为了获得较短密钥偷偷重抽。
5. **最后运行 n=512 实体生命周期与资源测量。**
   使用生产随机性和单独的测试随机性跑提取、签验、固定发钥恢复和异常路径；
   记录 CPU/软件版本、重复次数、内存峰值、熵、实际中止及签名尺寸。
   对象编码须单独设计并检验；当前 JSON 上限不应通过忽略字段或截断数据绕过。
   这些完成后仍须补完整 TV、strong premise、攻击估计和归约损失；不依赖 HIBE 的工作可继续。

## 复现命令与实际验证

在仓库根目录设置 `PYTHONPATH=src;.` 后：

```powershell
python -m experiments.research.candidates.srgg.formal_candidates --output build/outputs/srgg-conditional-candidates.json
python -m pytest -q tests/test_srgg_formal_candidates.py
```

本轮 Python 测试在 Windows 通过，**15 passed**；仅做整数/Fraction 算术、
小维度精确形状对照和条件边界测试，无 Sage 依赖，无密钥或签名采样，
没有执行 n=512 实体密码算法、采样分布实验或困难性估计。
参数、cap 选择和条件都包含在 JSON 中，可离线复核。

本筛选研究模型包含原方案的 hash oracle 前提，对应 QROM/strong 归约仍未核闭。
这里没有消息/身份生命周期实验及其长度或重复统计；不能用算术测试代替该类实验，
也不能将测试通过写作 LWE、SIS、IBS 或最终 IB-ME 的安全证明。
