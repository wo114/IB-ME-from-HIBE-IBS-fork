# SRGG 原文 Setup 正定门：精确矩证书

本批仅核对 Jia–Liu–Tang–Wang 原文 Algorithm 1 的数学正定重试，不改变参数或发钥、签名算法。依据是仓库冻结的 [`2025_efficient_ibs_jia.pdf`](../../../../papers/2025_efficient_ibs_jia.pdf)，SHA-256 为 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。Table 3（PDF 第 6 页）给出扰动宽度与小高斯宽度；Algorithm 1（第 7 页）从系数分布 χ 抽取陷门 `R`，构造 `Σp`，重试直到 `Σp ≻ r²I`；§5.1、Table 4（第 9–10 页）给出 `n=512`、`w=2`、`b=31`、`d=2/3/4` 三行。实现沿用论文打印的 `r≈1.16`，并分别记录“表格标准差”和“字面密度宽度”两种高斯记号解释；作者的未打印精度及最终记号对应仍未确认。

令 `a=2d`、`c=wd`，本表恰有 `a=c=4/6/8`。对 χ 的每个系数，实际原始抽样取两个独立公平位之差，故 `P(-1,0,1)=(1/4,1/2,1/4)`。记 `h=b²r²`，原文正定门的 Schur 补严格等价于

```text
||M(R)||₂² < T,
T = (σ₁²-r²)(σ₂²-r²-h) / [h(σ₂²-r²)].
```

其中 `M(R)` 是实系数域上的负循环算子。两种高斯解释把 `σ₁²`、`σ₂²`、`r²` 同乘一个正的密度形状比例，代入后该比例从 `T` 完全抵消，因此三行各只有一个精确阈值。这是正定门的等价式，不是完整采样或安全条件。

用单位酉负循环 Fourier 变换，`M(R)` 分解成 512 个复矩阵块；多项式在 `ζ_j=exp(πi(2j+1)/512)` 的特征值是 `Σ_h χ_h ζ_j^h`，不额外乘或除 `√512`。实系数给出共轭成对块，故只需对 256 块做并集界。单个块的每个条目 `Z` 由独立 χ 系数生成。因为 χ 的分布对取负不变，系数向量的带符号循环移位表明 `Z` 的分布对乘以原始 1024 次单位根不变；在本证书使用的矩阶 `k≤28` 内，不平衡混合矩消失。再由 `E exp(tχ)=(1+cosh t)/2` 与逐项系数不等式 `2(2m)!≥4^m m!`，得到 `E|Z|^(2m)≤m!(512/2)^m`。逐条目比较迹展开中的非零项，就得到同尺寸、独立复高斯条目、二阶矩为 256 的 Wishart 迹矩上界。

证书以精确整数和有理数计算该 Wishart 矩。令 `H_x(k,r)=∏_{j=0}^{k-r-1}(x+j)∏_{j=1}^{r}(x-j)`，则

```text
E Tr[(GG*)^k] = 256^k/k! · Σ_{r=0}^{min(a,c,k)-1}
                 (-1)^r C(k-1,r) H_a(k,r) H_c(k,r).
q = 256 · E Tr[(GG*)^k] / T^k.
```

迹矩的 hook 公式还由小阶置换直接枚举作独立测试。Markov 不等式及 256 块并集给出每次**数学正定门拒绝概率** `q_true=P(Aᶜ)≤q`，其中 `A={Σp≻r²I}`。下表小数仅便于阅读；精确分数由证书输出和测试复算。

| 原文行 | 块尺寸 | `T` 约值 | `k` | `q` 上界约值 | 64 次独立重试的数学中止上界 |
|---|---:|---:|---:|---:|---:|
| PARAM-I | 4×4 | 6246.722948 | 17 | 0.205518504 | `< 2^-146` |
| PARAM-II | 6×6 | 8926.269269 | 22 | 0.095132911 | `< 2^-217` |
| PARAM-III | 8×8 | 11555.616682 | 28 | 0.046673365 | `< 2^-282` |

以上 64 次结论以每次重新抽取独立、均匀来源的 χ 系数为前提，且仅限原文**数学正定谓词**。若无限重试，理想输出根的分布恰是原始 CBD1 根分布 `μ` 对 `A` 条件化，`TV(μ,μ|A)=q_true≤q`；若最多重试 64 次并把中止作为独立结果，其输出律为 `(1-q_true^64)(μ|A)+q_true^64·abort`。数值 `q` 不够小，不能把原始与条件化根说成可忽略接近。

当前有限 Fourier／区间／级数后端的成功集记为 `B`。区间判断可靠时 `B⊆A`，但正定而区间无法判定、后续数值准备或资源失败可导致异常；这些路径并非原文数学重试。`e=P(A\B)` 尚无上界，所以不能把表中的 `q^64` 直接写作当前后端的 Setup 中止上界，也不能把这六个固定根证书推广至**全部**实际接受根。证书将实际后端成功集与论文正定集的分布距离、区间不确定概率、实际故障／中止、全部接受根的有限 source-Schur 误差保留为 `null`。

复算需仓库指定的 WSL Sage 环境：

```bash
cd /mnt/c/Users/A/.codex/worktrees/srgg-fixed-service/IB-ME-from-HIBE-IBS
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_setup_acceptance
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_setup_acceptance.py
```

这项证书不涉及 HIBE，不构成采样器整链 TV、困难性估计、IBS 安全归约或正式参数准入。安全标记仍为 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。

完整推导和条件化分布范围见 [`proof.md`](proof.md)，精确有理回执见 [`setup-acceptance.json`](setup-acceptance.json)。测试环境与限制记录在 [`validation.json`](validation.json)，交付字节哈希见 [`MANIFEST.json`](MANIFEST.json)；可在仓库根目录运行 `python docs/research/team-b-delivery/2026-10-18-srgg-setup-acceptance/verify_delivery.py` 复核。
