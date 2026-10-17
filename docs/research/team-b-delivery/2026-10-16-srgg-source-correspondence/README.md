# SRGG 论文、代码与参数对应核验

本批完成来源定位、可复现的精确检查和参数筛选器修复。SRGG 仍是研究实现；此次没有完成正式参数准入、总 TV 证书、强不可伪造证明或 HIBE 组合。基线为 `ca211fcc6bd93e07f797e3be1476d205fad0b463`，沿用 PR #37。

## 来源与核验范围

主要依据：Jia、Liu、Tang、Wang，*Constructing Efficient Identity-Based Signatures on Lattices*，DOI [10.1049/ise2/6684889](https://doi.org/10.1049/ise2/6684889)。本地冻结版本为 `papers/2025_efficient_ibs_jia.pdf`，SHA-256 为 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。

页码均指 PDF 实际页码，与印刷页一致。本批针对性核对 §2.2、Definition 3、Theorem 1、§4.2、Table 3、Algorithms 2/3/7/8、Theorem 2 和 §5.1/Table 4，不声称逐一复核全文及全部所引安全证明。PDF 公式经过渲染目视核对，不能只依赖文字提取。

归一化另参考本地 Peikert 作者稿 `papers/2011_peikert_parallel_gaussian_author.pdf`，SHA-256 为 `39ae6ea450a98267ab7f3ac682e4daae4a91ec8aed9432dca666e05eefd46163`，PDF p.7 §2.4、p.9 Theorem 3.1、p.11 Lemma 4.1、p.12 Theorem 4.2。这些是连续扰动与随机舍入的理论依据，尚未成为有限实现的误差证书。

原文 [26] 的 [G+G ePrint 2023/1477](https://eprint.iacr.org/2023/1477) 元数据本轮可访问，PDF 请求返回 403；本批不据摘要或检索结果声称已核验它的完整强安全证明。[33] 的具体 QROM 改编证明亦未在本批闭合。

## 对应结果

| 核验项 | 原文位置 | 实际代码 | 当前结论 |
|---|---|---|---|
| ζ 与扰动形状 | p.6 Table 3；p.8 Alg.7 | `algebra.zeta/zeta_star`、`geometry.signature_geometry`、`runtime.sign_attempt` | ζ 的系数算子乘转置是 `2I`；Table 3 减去 factor1，代码明确采用 factor2 解释，完整分布定理对应未闭合 |
| 模数 | p.4 Theorem 1；p.6 Table 3；p.8 Alg.7/8；p.9 Table 4 | `Params.modulus`、`signing_matrix`、`recover_commitment` | gadget q、IBS Q、签名 2Q 必须区分；源参数三行在条件性 `q_theorem=Q` 解读下均不满足 `q>2γ`，不能通过改叫 2Q 解决 odd-q 要求 |
| HNF 恢复 | p.5 §4.2；p.7 Alg.2；p.8 Alg.7 | `extract_with_gadget → extract_tail → SigningKey.full_vector → reconstruct_vector` | 精确方程与一般范数界已核；恢复后的密钥分布、陷门独立性和范数筛选偏差未证 |
| 强不可伪造 | p.4 Definition 3/Theorem 1；p.8 Theorem 2/G0 | 研究后端和已有公开小挑战伪造负控 | Theorem 1 仅 EUF；Theorem 2 假设 sEUF，但展示的赢法使用 fresh-message 条件，不能直接记为 strong 证明 |
| 高斯归一化 | p.3 §2.2；p.6 Table 3；p.9 §5.1 | `full_sampling` 的 `Σ/(2π)` 约定 | 原文 `r≈1.16` 若按字面 shape 宽度使用会失败；物理标准差解释是待确认推断 |

### ζ 的精确部分

在 `R=Z[X]/(X^n+1)`，令 `ζ=1+X^(n/2)`。有 `ζζ*=2`、`ζ⁻¹=ζ*/2`，且系数算子 `Mζ Mζᵀ=2I`。因此把 `u←D_(R,r,−c/ζ)` 映射成 `ζu+c`，得到陪集 `ζR+c` 上的离散高斯密度形状 `2r²I`。这不是说离散高斯的真实协方差恰好等于 `2r²I/(2π)`。

按统一的密度形状约定，响应中 `W(ζu+c)` 的形状贡献是 `2r²WWᵀ`，其中 `W=M_[y;1]`。代码采用 `Σbar−2r²WWᵀ`；原文 Table 3 字面为 `Σbar−r²WWᵀ`。统一换算 `2π` 无法消除相对系数 2。此为已定位的解释差异，未取得作者勘误，不据此改写原文定理，也不擅改现有签名协议。

### q、Q 与源参数

源参数 `n=512, p=16383, b=31, w=2, q_gadget=961, Q=15744063`，三行 `γ` 分别为 `42086491.7、63653172.0、86573930.5`。`Q>2γ` 和 `2Q>2γ` 全部失败；此外 2Q 是偶数。

Theorem 1 的模数是奇数 q，公共矩阵本来就定义在模 2q 上。把它映射到 IBS 时，`q_theorem=Q` 是自然的条件性读法，但矩阵/环版本、J 结构、平滑条件和协议性质仍需证明对应，不能只替换字母。该定理还要求 `q>s1·ηε(Z^m)`、维度不等式、扰动正定、尾界及相关协议性质。通过代码的 `Q²>4B` 只通过一个研究配置检查，不能满足全部定理条件。这里未给出对论文安全参数的新伪造攻击。

### HNF：已闭合的代数与未闭合的分布

若原始提取向量 `raw=(raw0,t)` 满足 `A raw=h−e mod Q`，各误差系数在 `[0,p−1]`，恢复为

```text
restore=(center_Q(raw0+e),t),       A restore=h mod Q,
||restore||₂ ≤ ||raw||₂+(p−1)√(dn),
||restore||₂² ≤ 2||raw||₂²+2dn(p−1)².
```

范数界不需要无 wrap 假设：居中取模不会增加对应整数的绝对值，再用三角不等式。发生 wrap 时，整数首块差可以是 `e−kQ`，只在模 Q 意义下等于 e。可执行负控展示 `Q=15, raw0=(7,7), e=(4,4)`，恢复首块为 `(-4,-4)`；精确方程依然成立。

确定性 HNF 映射可以对两个已明确指定的输入分布使用 TV 数据处理，但不会自动把参考分布的推前认定为理想 exact-preimage Gaussian。还需连接真实近似提取、HNF、范数准入/中止和 PSF `SamplePre/SampleDom` 的分布。持久固定服务保证成功发钥不悄悄重抽；pending/failed 阻断是工程扩展，仍须计入安全模型的失败预算。

### r 的归一化疑点

原文确为 `Qs=2^40, ε=1/√(Qs·256)=2^-24`；256 是普通整数。按其 p.3 的 `ρ_s(x)=exp(−π||x||²/s²)` 约定，`D=(2+w)·5·512=10240`，平滑的必要条件包括 `2D exp(−πr²)≤ε`。字面取 `r=1.16` 明显失败。

审计工具用严格但较松的有理界复核：`π<22/7` 给 `πr²<5`，且 `exp(5)<3^5=243`，所以最短对偶向量项之和 `>2D/243>ε`。这是对字面数值的条件性反例，不是足够平滑参数证书。必要宽度 `sqrt(ln(2D/ε)/π)≈2.90778` 再除 `sqrt(2π)` 得 `≈1.16004`，提示标准差/shape 混用的可能性；作者尚未明确确认，不直接据此替换参数。

### 安全游戏与有限实现

普通 EUF 要求新消息；strong EUF 还允许对已签消息提交另一条未返回的有效签名。原文 Definition 3 排除已查询的 `(id,message)`，Theorem 2 的 G0 排除任何 `(id*,message*,.)`，与 strong 赢法存在差别。Theorem 2 的文字前提因此仍须补强依据，不能从 Theorem 1 的 EUF 自动继承。

有限票据/有限精度的连续阶段输出落在有限集合，与理想连续高斯的 TV 为 1。后续应界定经过离散随机舍入后的最终输出误差或适当耦合，不能为连续阶段直接填一个随精度变小的 TV。已有经验均值、协方差和精度分歧诊断仍只属于数值实验。

## 本次代码修复

`parameter_screen` 升为 schema `/2`：

1. 用精确整数 `Q²>4B`，修复对 `Q²−4B=1` 的合法配置误判。
2. 允许后端本来支持的空消息。
3. 将 u 的抽样从误标“均匀”改为离散高斯，列出每次完整尝试与最大签名尝试的逻辑抽样数及连续正态票据数。
4. 移除未经推导的 `2^-mass_bits`/精度误差“上界”，保留目标 bit 数和待实例化证书。
5. 移除虚称的 packed 下界，分开记录真实 wire 夹具和系数域/数量；SK 只保存 tail，MSK 陷门系数是 CBD1 支持。
6. 明确当前 setup 不做范数拒绝；零系数 shape 夹具的尺寸不代表所有有效对象都在 wire 上限内。

新工具 `experiments/research/candidates/srgg/source_correspondence.py` 输出有版本摘要的来源 ledger、ζ 精确算子、HNF wrap/无 wrap 夹具、源参数条件检查和字面平滑反例。它不读取真实密钥，不生成签名，不作性能或安全估计；更换论文版本需重新审阅。

## 复核与交付

结果见 [validation.json](validation.json)、[source-correspondence.json](source-correspondence.json)、[parameter-screen.json](parameter-screen.json) 和 [MANIFEST.json](MANIFEST.json)。输出也保存在 `build/outputs/srgg-source-correspondence-2026-10-16/`。测试收据是本地证据，不代表远端 CI 全部通过。

```powershell
python -m experiments.research.candidates.srgg.source_correspondence --output build/outputs/srgg-source-correspondence-2026-10-16/source-correspondence.json
python -m experiments.research.candidates.srgg.parameter_screen --output build/outputs/srgg-source-correspondence-2026-10-16/parameter-screen.json
python -m pytest -q tests/test_srgg_source_correspondence.py tests/test_srgg_parameter_screen.py tests/test_srgg_algebra.py tests/test_srgg_geometry.py tests/test_primitive_spec_audit.py
```

指定 WSL Sage 环境中运行：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_*.py tests/test_primitive_spec_audit.py --junitxml=build/outputs/srgg-source-correspondence-2026-10-16/sage-regression.junit.xml
```

本轮真实研究回归沿用默认 `n=8,d=1,p=257,b=31,w=3,Q=7656287`、身份上限 256 B、消息上限 4096 B、16 个身份槽、最多 16 次签名尝试；测试使用各自固定的测试熵。源参数 n512 只做公开算术检查，未在当前有界后端运行。采用 ROM/QROM 是原文定理模型；本地哈希实现与功能/攻击测试不建立该模型的安全归约。全部保持 `security_claim=none, backend_admitted=false, parameters_are_formal=false`；小挑战公开伪造反例继续保留。

后续需由原语负责人和统筹核定 ζ/归一化解释与强游戏前提，再补最终离散输出、HNF 后密钥分布及失败预算的定量对应。困难性估计和大维正式参数仍未完成，Kyber/NIST 仅为比较目标。
