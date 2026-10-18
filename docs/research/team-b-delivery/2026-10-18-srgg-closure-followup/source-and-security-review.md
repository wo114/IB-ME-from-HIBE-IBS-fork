# SRGG 原文条件与当前实现：定向来源复核

基线：`e38b2ea90ba7457ef496822d68db062beee92fff`。来源为仓库冻结的 Jia–Liu–Tang–Wang, *Constructing Efficient Identity-Based Signatures on Lattices*, DOI `10.1049/ise2/6684889`，[`papers/2025_efficient_ibs_jia.pdf`](../../../../papers/2025_efficient_ibs_jia.pdf)，SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。本审查只核 PDF pp.3–4、6–10 中下列公式、定义、算法和参数表；不声称审完全文或复现作者的 C 程序。页码为 PDF 页码。下表的“作者主张”“代码/执行事实”“未闭合”是三种不同证据。

| 项目 | 论文原文 | `e38b2ea` 的代码与执行证据 | 判断 |
|---|---|---|---|
| 表 4 数值 | §5.1 p.9、Table 4 p.10：`n=512,p=16383,b=31,w=2,q_gadget=961,Q=15744063`；`d=2/3/4`，三组主/签名宽度及 `γ` 如表 | [`paper_profiles.py`](../../../../experiments/research/candidates/srgg/paper_profiles.py)、[`paper_parameters.py`](../../../../experiments/research/candidates/srgg/paper_parameters.py) 保存三行原数值。最终七份 `*-bounded-final-lifecycle.json` 在 [`2026-10-18-srgg-source-schur`](../2026-10-18-srgg-source-schur/) 中，覆盖两种宽度解释各三组和 PARAM-I 系统随机数，均为 37/37 功能检查 | 原数值、流程和单次研究运行已有证据；论文 Table 5 安全值、Table 6–7 的 C/ANS 性能没有由此复现 |
| Gaussian 记号与 `r` | §2.2 p.3 定义 `ρ_(Σ,c)(x)=exp(−π(x−c)^TΣ⁻¹(x−c))`；Table 3 p.6 与 §5.1 p.9 写 `r=η_ε(Z^((2+w)(d+1)n))≈1.16`，`ε=1/√(Q_s·256)`、`Q_s=2^40` | [`paper_parameters.py`](../../../../experiments/research/candidates/srgg/paper_parameters.py) 明列“表列物理标准差 → density shape 约 `2πs²`”和“字面 density shape `s²`”两种解释；默认前者，未改表中 `1.16`。[`parameter-closure.json`](../2026-10-17-srgg-parameter-closure/parameter-closure.json) 和 [`completion.md`](../2026-10-17-srgg-parameter-closure/completion.md) 保存必要门计算 | `Σ` 的密度定义与表头“标准差”如何统一，论文未给有限实现所需的精确舍入值。不能将默认代码解释说成作者已确认的唯一解释 |
| 原顺序 SampleP/SampleF | Algorithms 3–4 p.7：先离散抽下块，再逆序环 Schur；叶子连续 Gaussian 后按系数调用离散 `SampleZ`。Algorithm 4 的输入是 `f`，第 2 行却印为 `√(d−r²)` | [`paper_schur_samplef.py`](../../../../experiments/research/candidates/srgg/paper_schur_samplef.py) 执行离散下块、逆序环叶子、有限 Box–Muller/Fourier 位移及固定宽离散舍入；按输入 `f` 解释该行。[`paper_ring_schur.py`](../../../../experiments/research/candidates/srgg/paper_ring_schur.py) 是精确 QQ 参考；[`paper_schur_fourier.py`](../../../../experiments/research/candidates/srgg/paper_schur_fourier.py) 是原规模的一次数值替代 | 算法控制流已补；`d/f` 是明确排印歧义。作者省略了表驱动 `SampleZ` 的细节（p.7），因此不能声称逐位复现作者采样器 |
| 原生 strong | Definition 3 p.4 明定 EUF-ID-CMA；Theorem 1 p.4 给底层 EUF-CMA 条件结论。Theorem 2 p.8 文字写从 SIG `sEUF-CMA` 推 IBS `sEUF-ID-CMA`，但 p.8 的 G0 赢法要求 `(id*,μ*,·)` 未在已签列表，属于新消息限制 | [`paper_validation.py`](../../../../experiments/research/candidates/srgg/paper_validation.py) 对原验证器做同身份、同消息、同 challenge 的公开 `Q` 响应平移。最终回执中默认 II/III 和三组字面 density 有通过原 `γ` 并验签接受的替换；默认 I 两轮无 eligible 候选 | 这些是实际运行的 native-strong 反例，不是新消息 EUF 伪造。Theorem 2 的文字与 G0 游戏需澄清，不能把源定理文字直接登记为当前 strong 安全证明 |

## 平滑与数值分布的具体边界

§5.1 的 `d=4` 代入给 `m=(2+w)(d+1)n=4·5·512=10240`，来源分组给 `ε=2^-24`。若将报告的 `r=1.16` 当作**精确** density-shape 宽度，最短对偶向量质量已经违反必要条件；若当作精确物理标准差，修正后的 `2πr²` shape 在同一 `m=10240` 处也有严格必要条件失败证书，见 [`completion.md`](../2026-10-17-srgg-parameter-closure/completion.md) §2 与 [`rounding-budget.json`](../2026-10-17-srgg-parameter-closure/rounding-budget.json)。这说明当前**精确实现数字**不能以该平滑条件准入；论文写的是近似到两位小数的 `r≈1.16`，所以不能据此推断作者内部未公开的更精确值也失败。较小的六个 master/sign 局部归一化维度通过 `2^-24`，不替代 `m=10240` 的来源门，也不证明整条链。

§4.2.1 p.5 正文说下块形状为 `σ₂²−r²`，而 Algorithm 3 p.7 第 1 行写 `σ₂²−σ²`；当前代码跟随 Algorithm 3，并用 Table 3 的 `σ=br`。这个来源差异与前述 Gaussian 归一化独立，应在获得作者解释或完整数学对应前保持为显式分支。[`paper_parameters.py`](../../../../experiments/research/candidates/srgg/paper_parameters.py) 的双解释与原数值不应被静默合并。

新 source-Schur 路径的 [`paper_schur_fourier.py`](../../../../experiments/research/candidates/srgg/paper_schur_fourier.py) 对 pivot、gain 和正定性给区间检查，并按 dyadic 系数量化 gain/自适应中心；[`paper_schur_samplef.py`](../../../../experiments/research/candidates/srgg/paper_schur_samplef.py) 将有限 normal ticket 输出舍入成整数。这些检查能支持有限运行的形状和资源不变量，**尚未给出**数值链相对精确逐环链的统一 TV。一个有限 ticket 连续位移本身不能在连续 TV 下逼近理想连续 Gaussian；比较必须落到最终整数输出（含中止原子），且对每个被接受根、每个可达自适应中心和每次调用历史统一成立。回执的 `numerical_chain_to_exact_chain_tv_upper`、`finite_center_numerical_tv_upper`、`full_target_integer_tv_upper_including_abort` 为 `null`，`joint_sampler_law_certificate_reused=false`；这些空值与已通过的功能测试相符。

即便获得上述逐叶有限核界，Algorithm 3 的理想**逐环**离散 Gaussian 链也不因指数中的二次型相同而自动等于一次性 joint 离散 Gaussian。各叶子的离散归一化量随先前抽样改变，连乘后对 joint 权重产生历史相关倾斜；须给其统一比值/TV 界，再走发钥 HNF、签名和完整服务历史。旧 [`sampling_error.py`](../../../../experiments/research/candidates/srgg/sampling_error.py) 与旧 joint 路线的证书不能直接填入这条新的 Table 4 source-Schur 链。当前只可报告“有限功能实现、分布对应未闭合”。

## 模数、ζ 与安全游戏

Theorem 1 p.4 显示条件是**奇数** `q > max(2γ,s₁η_ε(Z^m))`。Table 3 p.6 的 gadget `q=961`、IBS `Q=15744063`，Algorithms 7–8 p.8 的承诺/验签关系在 `2Q` 上。三行 `Q<2γ`，`2Q` 既为偶数也小于 `2γ`；把三个模数中的任一个仅改名都不能建立 Theorem 1 的使用资格。`s₁` 在定理到签名宽度的映射还需独立核查；这些只是必要的字面门检查，不能断言不存在其它证明路线。来源和数值见 [`parameter-closure.json`](../2026-10-17-srgg-parameter-closure/parameter-closure.json)。

Table 3 p.6 给 `ζ=1+X^(n/2)`、`ζζ*=2`；Algorithm 7 p.8 的 `u←D_(R,r,−c/ζ)` 和 `z=p+[y;1](ζu+c)` 意味着 `ζu+c` 在陪集 `ζR+c` 上具有 `2r²` 的 Gaussian **密度形状**。同一 Table 3 印出的签名扰动 shape 却只减去 `r²[y;1][y;1]^T`；代码 [`paper_schur_backend.py`](../../../../experiments/research/candidates/srgg/paper_schur_backend.py) 的 `noise_factor=1` 忠实保留该字面选择。精确系数算子关系可核，但“factor1 与 factor2 导出相同响应法则”未获证明。整体换算 `2π` 不消除相对因子 2。不要把源文字的 strong 主张、实现的字面 factor1、以及另一条 factor2 研究证明拼成一个已闭合定理。

对 native strong，验证式中的前块 `2I` 使任意首块单位向量 `e` 满足 `Abar·(Qe)=0 mod 2Q`。若已签响应 `z` 与 `z±Qe` 都满足原文 `||z||≤γ`，承诺、challenge、消息不变，另一响应依然通过 Algorithm 8；[`paper_validation.py`](../../../../experiments/research/candidates/srgg/paper_validation.py) 在真实后端上检查的正是这个条件。成功回执足以否定这些运行对“所有同消息替换都被拒绝”的主张；未命中的 PARAM-I 样本没有安全含义。若继续追求原生 strong，应先正面处理这一反例及 Game G0 的定义，再谈 reduction 与正式参数。

本复核不改变协议、宽度或旧回执，也不把论文自报的安全强度转写为项目正式等级。当前仍应保留 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。按“一个主方法、至多一个替代”的工作节奏，数值 TV 或作者符号解释一旦暂时无法闭合，就记录具体失败和所需前提，推进 HNF/CRT/资源等其它独立项；不要围绕单一歧义反复改原参数。
