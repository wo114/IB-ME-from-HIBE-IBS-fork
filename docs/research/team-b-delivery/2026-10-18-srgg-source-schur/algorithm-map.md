# SRGG Algorithms 3–4：原文逐步骤采样与现有代码映射

日期：2026-10-18。本文是本地原稿与现有实现的定向核对，不是新的安全归约或性能验收。范围限 SRGG 自身，不涉及 HIBE。

**初始盘点结论：旧小维后端已经实现逆序多项式块 Schur 和每环连续 Gaussian／离散 Gaussian 舍入；`06080ef` 基线的 Table 4 原参数路径调用的是另一种联合扰动采样。** 新固定根 joint-law 证据不能替代原参数规模的 Algorithms 3–4 逐步骤运行。两条既有路径及其失败证据均应保留。本轮随后新增的独立 source-Schur 实现见第 6 节；第 3–5 节保留初始盘点的历史状态和行号。

## 1. 实际使用的原文证据

选定论文为 Jia、Liu、Tang、Wang，*Constructing Efficient Identity-Based Signatures on Lattices*，DOI `10.1049/ise2/6684889`，仓库 [冻结 PDF](../../../../papers/2025_efficient_ibs_jia.pdf)。本次重新核对文件 SHA-256：

```text
258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152
```

本次阅读位置为实际 PDF 第 3 页 §2.2–2.3、第 5 页 §4.2.1、第 6 页 Table 3、第 7 页 Algorithms 1–6、第 8 页 Algorithm 7。第 7 页同时进行了文本提取与页面渲染检查；不声称此次重新审读完整安全证明或所有引用论文。

以下区分“原文步骤”“代码行为”和“实施建议”。已有 Table 4 小数、两种 Gaussian 解释及模代表约定继续以 [原参数 SOURCE_MAP](../2026-10-16-srgg-paper-baseline/SOURCE_MAP.md) 为准。

## 2. 原文控制流及必须保留的量

用实现的 density shape 记号，令

```text
κ = PaperParams.r_squared, ν = b²κ,
a1 = PaperParams.master_first_squared,
a2 = PaperParams.master_second_squared,
T = [R; I], Σp = diag(a1 I_(2d), a2 I_(wd)) − ν T T*,
l = a2 − ν,
K = a1 I_(2d) − (ν a2/l) R R*.
```

每个条目是 `K_R` 的环元素，整个系数空间每个环条目占 n 维。星号表示系数算子的实伴随；在环表示中需要负循环共轭和模块转置，不能只交换模块行列。§4 首段说明用环元素代表其系数乘法矩阵，所以原式中的转置必须与该矩阵语义一致。

Algorithm 3 的顺序必须是：

1. 从 `D_(Z^(wdn), l I)` 抽离散下块 `p2`，并分成 wd 个环元素；这一步不是连续 Gaussian。
2. 按 `c=−ν/l · R p2` 计算精确条件中心，初始上块形状取 K。
3. 对 `i=2d−1,…,0`，把当前中心分成 `(c_head,c_i)`，把当前形状分成 `[[A,B],[B*,f]]`。
4. 调用环级 `SampleF(f,c_i)` 抽 `p_i`，再按 `c_head+ B f^−1(p_i−c_i)` 和 `A−B f^−1 B*` 更新下一步中心、形状。
5. 按原环顺序组装 `p1=(p_0,…,p_(2d−1))`，最后返回 `(p1,p2)`；不能将实际抽样顺序误当输出顺序。

Algorithm 4 的结构是：先抽 n 维连续标准 Gaussian，再用该环形状减固定 rounding shape 的平方根生成连续位移，最后对 n 个系数分别调用固定 κ 的真实离散 Gaussian 舍入。§4.2.1 明确说明 `SampleZ(c')` 是 n 次独立调用，中心为各系数、方差/宽度参数固定；作者称使用 table-based 方法再加 rejection，但省略具体细节。

在本仓库 `exp(−π(x−c)*Σ^−1(x−c))` 密度约定下，用通常物理协方差为 I 的 `Z~N(0,I_n)` 时，等价连续位移应为

```text
L Z,   L L* = (M(f) − κ I_n)/(2π),
```

随后抽 `x_j ~ D_(Z,κ,c_j+(LZ)_j)`。分母 `2π` 属于记号对应，不能遗漏，也不能重复换算 Table 4。本文不以此消除 Table 4 “Std. dev.”和 §2.2 density width 的来源解释问题。

**不能静默修补的原文差异：**

- 第 7 页 Algorithm 4 line 2 经过渲染确认实际印为 `sqrt(d−r²)`，而输入及 Ensure 使用 f；把此处 d 解释为输入形状 f 是须注明的符号解释，不是 OCR 自动修复。
- 第 5 页 §4.2.1 prose 的下块和条件式写 r²，而 Table 3／Algorithm 3 使用 gadget width σ²、且 Table 3 定义 `σ=br`。本次主映射采用 Table 3 与 Algorithm 3 的一致公式，即 ν=b²κ；不把 prose 的不同字面式悄悄混入同一实现。
- 原文 r 是报告的近似值；模代表、Gaussian 归一化、ζ factor1/factor2 等已有歧义仍保留。恢复逐步骤采样不能单独解决签名分布或 strong 结论。

## 3. 已有实现的实际深度

以下行号依据本次核对版本，入口均在 `experiments/research/candidates/srgg/`，底层 GPV 另列。

| 代码位置 | 实际行为 | 与原文逐步骤的关系 |
|---|---|---|
| [runtime.py:15](../../../../experiments/research/candidates/srgg/runtime.py#L15) `sample_geometry` | 离散下块；条件中心；`sample_p(...,block_size=degree)` 抽上块；拼回上下块 | 已有 Algorithm 3 外层流程，发钥与签名实际调用它 |
| [geometry.py:122](../../../../experiments/research/candidates/srgg/geometry.py#L122) `_geometry` | 完整系数空间 shape、`center_operator`、上下块 Schur、精确正定门 | 对应原 shape；以 dense QQ 矩阵展开，规模受限 |
| [full_sampling.py:302](../../../../experiments/research/candidates/srgg/full_sampling.py#L302) `_SamplePPlan` | 从最后一个环系数块开始，精确 `B f^−1` 和 Schur，抽样时逐步更新有理中心 | 对应逆序模块 Schur；每个环已经展开成 n×n 系数块 |
| [full_sampling.py:233](../../../../experiments/research/candidates/srgg/full_sampling.py#L233) `_SampleFPlan` | `shape−κI` 精确 LDL；有限精度 Cholesky 除 `sqrt(2π)`；midpoint/Box–Muller；精确 dyadic 连续位移；有限离散舍入 | 已有 Algorithm 4 风格连续＋舍入叶子；不是作者省略的 table 实现或逐随机位重现 |
| [sampling_error.py:47](../../../../experiments/research/candidates/srgg/sampling_error.py#L47) 及 `sample_p_class` | 后加的数值、有限核和 Schur normalizer bias 条件界 | 不能因为旧 sampler docstring 仍写 TV 未认证就遗漏此工作；其 `build_report` 仍限定旧 Config，不是 Table 4 逐层证书 |
| [perturbation.py:28](../../../../experiments/research/candidates/srgg/perturbation.py#L28) `MasterPerturbation` | 把完整 Σp 交给 coefficient-GPV | 明确标为非 literal Algorithm 4，不能当作逐步骤复现 |
| [online_mp12_reference.py:190](../../../../experiments/research/online_mp12_reference.py#L190) `OnlineNonSphericalSampler` | 逆 shape 的 metric Gram–Schmidt、逆序整数坐标 Gaussian | GPV 底层；不是环级连续 Gaussian 后舍入 |
| [structured_samplef.py:136](../../../../experiments/research/candidates/srgg/structured_samplef.py#L136) `StructuredSampleF` | isotropic joint 扰动、精确环平方根级数、连续位移和舍入 | 保留的结构化替代路线；没有 Algorithm 3 的离散 p2 与逆序 Schur |
| [paper_samplef.py:158](../../../../experiments/research/candidates/srgg/paper_samplef.py#L158) `PaperSampleF` | anisotropic joint 扰动、有理 whitening、实际 witness 的 Fourier 小矩阵界和环平方根级数 | 当前 Table 4 真实运行路径；目标 shape 对应不等于原文控制流对应 |
| [paper_backend.py:102](../../../../experiments/research/candidates/srgg/paper_backend.py#L102) `_master_plan/_sign_plan` | 调用 `PaperSampleF`，发钥和签名沿此路径执行 | 将此入口的真参数运行标成“Algorithms 3–4 逐步骤已经完成”不准确 |
| [structured_geometry.py:163](../../../../experiments/research/candidates/srgg/structured_geometry.py#L163) `conditional_apply/conditioned_center` | 环算子表达已经保留原条件 shape、中心 | 可复用的算术组件，但没有可调用的逐环 f 取出、逆元、Schur plans 和原顺序采样 |

完整仓库文件清单没有 `joint_sampling.py`；现有 joint 路线就是上述 `structured_samplef.py`、`paper_samplef.py`。`reduction_samplers.py` 是独立 product/reference 抽样，不是遗漏的 correlated Schur 后端。

精确无限连续核下，Cholesky 因子和对称平方根给同一连续 Gaussian；有限 midpoint normal 不具精确旋转不变性，因此不能据此声称两个有限 sampler 或作者实现逐随机位相同。类似地，理想逆序离散 Schur 链的 Gaussian normalizer bias 需保留，不能以同一指数二次型直接断言它精确等于 joint Gaussian。

## 4. Table 4 的实际规模与旧路径阻塞

共同 `n=512,w=2`，原 source 参数不作更换。

| 原表 | 环级上块叶数 2d | 上块系数维数 2dn | 下块系数维数 wdn | master 总维数 | signature 总维数 |
|---|---:|---:|---:|---:|---:|
| PARAM-I, d=2 | 4 | 2048 | 2048 | 4096 | 4608 |
| PARAM-II, d=3 | 6 | 3072 | 3072 | 6144 | 6656 |
| PARAM-III, d=4 | 8 | 4096 | 4096 | 8192 | 8704 |

每个环级 SampleF 叶子自身是 512 维。dense full master 分别有 `16,777,216 / 37,748,736 / 67,108,864` 个系数矩阵条目；仅上块也有 `4,194,304 / 9,437,184 / 16,777,216` 个。若仅按每个条目 8 字节的非本实现 float64 储存下限计算，full 分别为 `128 / 288 / 512 MiB`，上块为 `32 / 72 / 128 MiB`；真正 Sage QQ 对象、分子分母和临时矩阵的费用明显不同，**上述不是 RSS 实测或运行时间估计**。

环级初始上块只需 `16 / 36 / 64` 个多项式，即 `8192 / 18432 / 32768` 个系数槽；利用这一表示保留原算法循环不会改变论文步骤，但精确逆元/Schur 的有理系数位数仍可能增长，不能从槽数断言时间已可用。

旧 dense 完整路径至少有以下独立检查，不能只把一个 `MAX_DIMENSION` 调大就算补全：

1. [algebra.py:32](../../../../experiments/research/candidates/srgg/algebra.py#L32) 的 `Params` 首先拒绝 `degree>8`、`rank>2`、`p>257`；Table 4 的 n=512、p=16383 已越界。
2. [config.py:53](../../../../experiments/research/candidates/srgg/config.py#L53) 限制整个签名系数维数不超过 128。
3. [geometry.py:14](../../../../experiments/research/candidates/srgg/geometry.py#L14)、`module_operator` 和 `checked` 限制 dense 行列／系数算子不超过 128。
4. [full_sampling.py:32](../../../../experiments/research/candidates/srgg/full_sampling.py#L32) 把 `max_dimension` 的选项范围本身上限设为 128；shape、scalar-vector 分别检查上块和下块。单个 n512 环叶子也越界。
5. 同文件 line 255 的有理 reserve 为 `factor_denominator_bits+2*ticket_bits+(leaf_dimension+2)*precision_bits+32`。在 n512、旧默认 192/128 bit 时，仅后三项就为 **98,976 bits**，而 `rational_bits` 上限为 8192；扩大维数仍会拒绝。
6. 签名下块的部分原表 shape 还越过旧 `OnlineScalarGaussian` 的 `10^12` 宽度上限；原参数路径已有 `WideScalarGaussian`，但这不是原参数逐层计划已经实现的证据。宽度、中心、总熵及中止预算都应在新计划中实际检查。

这些是源码可核验的门和尺寸算术；本次没有尝试绕过检查或运行 Table 4 dense 样本。既有 `resource_probe.py` 的小维公开 SPD 测量也不能冒充此规模原文采样的实测。

## 5. 建议采用的忠实实现边界

最直接路线是独立原参数 `source-Schur` 后端：复用旧路径的控制流和既有精确负循环共轭、Gaussian 内核及对象；在环级实现 Algorithm 3 的 `f^−1`、`B f^−1`、Schur 和实际条件中心，逐环调用 Algorithm 4 风格叶子。保持已冻结 joint 后端及其公共上下文，不以默认替换覆盖旧证据。

若使用精确 QQ 环商作为参考，形状、中心和 Schur 等式能够直接比较。原 Table 4 默认解释各 shape 共享同一个公开 `c≈2π` scale；可以将该 scale 从归一化形状中显式提出，使 Schur 的 ratios 中相消，减少无关有理分母的传播。必须在实际 leaf displacement 和 rounding 中放回相同 scale；这只是表示选择，不能改 Table 4 数值或把有理 π midpoint 换成未经声明的实常数。

环级叶子可以用正 canonical embeddings 的平方根生成连续 displacement，或用正确 coefficient-space 因子；这属于实现 Algorithm 4 的算术方法，须证明其确实对应同一个 f，并单独保留有限精度误差。用 embedding 表示做原顺序模块 Schur也可以保持控制流，但近似逆元和后续自适应中心误差不能沿用“exact QQ Schur”的旧证书。不得只把全维联合 SampleF 更名为 Schur。

初始盘点中需真实补齐、不能由已有 joint 证书代替的内容如下；第 6 节记录本轮新增对应，不表示这些工作仍全部未实现：

- Table 4 原 shape 下的离散 lower-block Gaussian 类和完整有限熵／失败处理。
- 环级逆元、逐层 Schur 与条件中心；保留全部环／系数维度和原输出顺序。
- 每环连续 displacement、固定 κ 的离散舍入及数值/对象资源检查。
- 实际 source-Schur 路径的发钥、签验、恢复、失败收据与明确 source 对应；签名沿 Algorithm 7 的形状和已记载 factor1 约定，不擅改 ζ 或提高 γ。
- 逐叶有限误差与 Schur normalizer bias 的新参数对应；若尚未完成，写未闭合，不能直接搬用 joint-law 总界。

按用户新约束，每个困难点先走主路线，至多再作一种替代尝试；仍失败则保存具体 guard、输入、失败或资源证据，标记阻塞并转往后续独立项，最后统一汇报，不扩成无界优化搜索。

## 6. 本轮新增的 source-Schur 路径及只读复核

本轮在 joint 基线之外新增以下文件；本文作者仅作只读复核和映射文档，不负责这些文件的实现或实验执行。

| 新路径 | 具体对应 | 本次能确认的边界 |
|---|---|---|
| [paper_ring_schur.py](../../../../experiments/research/candidates/srgg/paper_ring_schur.py) `RingSchurPlan` | 正公共 shape scale 提出后，精确 QQ 环商的逆元、逆序 Schur、条件中心；还原实际 pivot scale | exact reference，不消费熵；本身不采样、也不认证正定或完整资源上界 |
| [paper_schur_fourier.py:85](../../../../experiments/research/candidates/srgg/paper_schur_fourier.py#L85) `FourierSchurPlan` | 按相同逆序模块步骤逐 canonical embedding 做有向区间 Schur；取有界 dyadic gain；每次条件中心更新后量化 | exact reference 超资源时本轮唯一的数值替代；保留原 shape 与控制流，但不称有限 law 与 exact chain 相同 |
| [paper_schur_samplef.py:20](../../../../experiments/research/candidates/srgg/paper_schur_samplef.py#L20) `RingSampleF` | 每环 midpoint normal、`sqrt((f−κ)/(2π))` 负循环 Fourier 因子、有限固定 κ 离散舍入 | Algorithm 4 风格 ring leaf；不是全维联合平方根，也不是作者省略的 table sampler 逐位复现 |
| 同文件 `PaperSchurSampleF` | 先离散 p2，再初始化精确条件中心，按 stages 抽上块；最终按环索引把 `(p1,p2)` 展平 | 原 Algorithm 3 顺序；独立 lower/rounding batch 与 normal ticket 总熵上限、显式中止 |
| [paper_schur_backend.py](../../../../experiments/research/candidates/srgg/paper_schur_backend.py) `SourceSchurBackend` | 继承既有发钥／签验／对象流程，单独替换 master/sign 的采样计划入口 | 原 Table 4 `PaperParams`、factor1 和 γ 不变；保留 joint 基线，来源／执行证据须标明实际 backend |

本次源码核对的具体数学对应如下。

- `forward` 采用正号 DFT 与 `exp(πij/n)` twist；`inverse` 采用负号 DFT、除 n 和反 twist。因此 forward 的第 k 个值是 `f(exp(πi(2k+1)/n))`。实系数频率配对为 `k↔n−1−k`，`conjugate_extension` 的反序共轭补全与此一致。
- 初始化上块 `diag(a1)−(νa2/l)RR*`、每层 `gain=B/f`、形状 `A−gain·B*`、中心 `c_head+gain·(p_i−c_i)` 的方向一致；source-Schur 不把模块转置当作环伴随。
- 实数 pivot 频谱取 `sqrt((f−κ)/(2π))`，只作一次 density 到物理 normal covariance 的换算。随后离散舍入继续使用同一 κ，不改变 Table 4 输入。
- setup 的根筛选先针对原 `Σp−κI`，以有向区间 LDL 认证负方向才抛出原 backend 接受的 `WitnessGeometryError`；区间不确定或后续资源不足给不同错误，不以这些分析失败静默重抽根。
- 固定 coarse 误差／公开资源元数据不导出实际谱、pivot、gain、中心或 witness。类的私有 plan repr 已屏蔽。原始对象和审计异常输出还须按实际调用路径另验，不能仅凭 repr 屏蔽推得整个服务无泄露。
- 有限 lower 成功路径有明确标量支持；每叶运行时检查位移幅度；条件中心 envelope 用 gain 的系数 L1 上界、叶残差幅度及量化余量逐层推进。这里只认证有界运行／失败处理逻辑，**没有把数值 invariant abort 的概率设为零**。

新路径明确保留 `numerical_chain_to_exact_chain_tv_upper=null`、`finite_center_numerical_tv_upper=null`、`full_target_integer_tv_upper_including_abort=null`，且 `joint_sampler_law_certificate_reused=false`。区间 pivot 正定、gain 系数 enclosure、诚实签验成功和有限协方差样本均不能填补这些 TV 字段，也不能消除来源歧义。

本轮已只读核验三份 source-Schur 生命周期收据，实际 `backend_class` 都是 `experiments.research.candidates.srgg.paper_schur_backend.SourceSchurBackend`。`paper_audit.audit` 向 `FixedIssuer` 显式传入该 backend，重启与恢复也沿同一类；默认 `paper_audit` 入口仍是 joint，不能省略实际 sampler 选择。公开元数据已经分别记录逆序 `sampling_order` 和原索引升序 `output_order`，与抽样及返回语义一致。

| 实际收据 | master/signature 维数 | 功能检查 | setup/extract 调用 | 原生 strong 探针 |
|---|---:|---|---|---|
| [PARAM-I](param-i-lifecycle.json) | 4096 / 4608 | `functional-pass`，37/37 | 1 / 1 | eligible 0，accepted 0；本轮没有可用候选，不能称安全通过 |
| [PARAM-II](param-ii-lifecycle.json) | 6144 / 6656 | `functional-pass`，37/37 | 1 / 1 | eligible 1，accepted 1，保留反例 |
| [PARAM-III](param-iii-lifecycle.json) | 8192 / 8704 | `functional-pass`，37/37 | 1 / 1 | eligible 1，accepted 1，保留反例 |

每组使用 `DeterministicRandom TEST ONLY`，身份 5 B、消息 32 B、生命周期重复 1 次；包含发钥、签验、严格对象/绑定检查、固定服务缓存重启不读熵、密钥恢复后重新签名及有限攻击。两次成功签名包含原文 norm retry；不是每次签名都只试一次。所有 sampler 均记录 `parameter_widths_changed=false`、总 TV 未闭合、未借用 joint 证书。实际环境、字节数、各阶段时延和攻击细节以各自 JSON 为准，不把这些 Python/Sage 单次时延当作作者 C 实现的公平 benchmark。

[exact-preflight.json](exact-preflight.json) 保存了 PARAM-I 原宽度下、公开确定 CBD1 fixture 的一次 45 秒 bounded exact preparation timeout，未消费熵、未产生真实根或生命周期样本。收据明确保存了导入源码快照和哈希：运行过程中只做过一次最终 pivot 不再求无用逆元的清理，因此 timeout 归属于记录的导入版本，**不能归因于最终测试版本或据此声称精确环算法普遍不可用**。按本轮尝试上限，不重试该路线；保留 exact reference，使用唯一 Fourier-Schur 数值替代继续其它独立项。

以上真实功能结果不填补新的 chain-TV、Schur normalizer bias、签名分布、正式困难性或 native strong 缺口。继续保持 `security_claim=none`、`parameters_are_formal=false`、`backend_admitted=false`、`nist_security_category=null`。

最终集成又在独立 `SourceSchurBackend.sign` 安装了包含 perturbation 和全部 u 抽样的整次尝试 cap；旧 `paper_backend.py` 恢复为原字节，旧绑定 guard 没有放松。七份 `*-bounded-final-lifecycle.json` 才是最终实现的执行回执；上表三份为此前未安装整次 cap 的原始成功回执，原样保留。最终覆盖两种解释各三组及一次系统随机数，每轮仍为 37 项功能检查；具体安全反例和次数见 [README_zh-CN.md](README_zh-CN.md)。公开失败 JSON/终端已去除任意异常 payload 和 traceback，并有两条 sampler 选择的定向测试。新增耗熵包络只改变显式资源中止，不解决本节列出的分布与安全缺口。
