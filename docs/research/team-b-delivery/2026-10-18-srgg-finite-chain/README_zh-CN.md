# SRGG 原表有限逐环采样：固定根分布证书（整体 WIP）

本批沿用 Jia、Liu、Tang、Wang，*Constructing Efficient Identity-Based Signatures on Lattices*（DOI `10.1049/ise2/6684889`）的 Table 4 三组输入：`n=512, p=16383, b=31, w=2, q=961, Q=15744063, d=2/3/4`。原 PDF 固定在 [`papers/2025_efficient_ibs_jia.pdf`](../../../../papers/2025_efficient_ibs_jia.pdf)，SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。只处理独立 SRGG IBS；没有选定或接入 HIBE。原论文的 `r≈1.16` 和 Gaussian 记号仍保留“表中物理标准差”和“字面密度宽度”两种显式解释，不替作者补定唯一版本。

**新结论限定在六个可重放的成功固定 Setup 根及每根一把 Alice 密钥。** 对每个根的主密钥扰动和签名扰动，已把当前 512-bit 票据、768-bit MPFR、256-bit 中心量化的实际 source-Schur 采样器，与同一有理参数和同一逐环顺序的**数学 Algorithms 3–4** 整数输出（含中止）比较。上界来自全部票据的数值包络、标量核和熵帽证书、中心 Lipschitz 与小位移反集中，不是抽样频率估计。证明及前提见 [`proof.md`](proof.md)，六根回执见 [`finite-fixed-root.json`](finite-fixed-root.json)。

| Table 4 行 | 有限→数学 Algorithm 3–4，master / sign | 数学卷积及理想 Schur 两段再合并：有限→联合离散 Gaussian，master / sign |
|---|---|---|
| PARAM-I | 两解释均 `≤2^-72 / ≤2^-71` | 表中标准差解释 `≤2^-26 / ≤2^-25`；字面密度解释 `<0.6781 / <0.8964` |
| PARAM-II | 两解释均 `≤2^-72 / ≤2^-71` | 表中标准差解释 `≤2^-25 / ≤2^-24`；字面密度解释 `<0.8174 / <0.9667` |
| PARAM-III | 两解释均 `≤2^-71 / ≤2^-70` | 表中标准差解释 `≤2^-25 / ≤2^-24`；字面密度解释 `<0.8964 / <0.9893` |

联合界由**三段不同的比较**相加：本批有限→数学 Algorithm 3–4；新增卷积比较（数学 Algorithm 4→理想逐环离散核）；上批理想逐环→理想联合 Schur 归一化界。各段来源、前提和精确有理预算保存在 [`joint-fixed-root.json`](joint-fixed-root.json)。标准差解释的联合结果约 `2^-24` 至 `2^-26`，仍不足以支持大量调用或正式安全强度。字面密度解释在 `n=512,r²=1.3456` 下，原全中心 theta 充分式给 `n·t>1`，无法签发卷积界。按你允许的两次换路上限，第一次改用逐坐标 normalizer 乘积界，得到了**恰为 1 的平凡整链上界**；可复算回执见 [`literal-product-fallback.json`](literal-product-fallback.json)。第二次改用 Algorithm 4 连续 Gaussian 下的 Fourier 均方界，在已经核验每叶理想 Schur 谱下界为 64 的固定根上，给 4–16 叶链一个严格小于 1、但约为 `0.678–0.989` 的弱上界。证明在 [`proof.md`](proof.md)，精确有理数见联合回执。这并非实测 TV，也不足以支持安全声明；未再尝试第三条路线或改动原 `r`。

这里的“表中标准差”代码形状使用 512-bit 有向 `π` 端点之和构造的**有理近似**；证书的数学目标是这一当前实现解释。它没有证明作者未公开精确 `r`、真实 `π` 或源码省略的 `SampleZ` table 实现逐位相同。原文 p.5 §4.2.1 的下块 `σ₂²−r²` 与 p.7 Algorithm 3 的 `σ₂²−σ²`、Algorithm 4 输入 `f` 与其第 2 行的 `d`、p.6 Table 3 的 `ζζ*=2` 与签名扰动 factor 1，以及 p.4 Theorem 1 的模数条件，均仍按[上批来源复核](../2026-10-18-srgg-closure-followup/source-and-security-review.md)列为冲突或待作者澄清。p.4 Definition 3／p.8 Game G0 的新消息排除与 theorem 的 strong 字样也未对齐；已有同消息验签替换反例保留，不能被这份分布证书抵消。

六轮固定根核验每轮一次 Setup 和一次 5 B 身份 `Alice` 发钥，只为取得 master/sign 的实际固定几何；**本批没有发送消息、运行签验或重测服务生命周期**。此前独立 source-Schur 生命周期使用 32 B 消息，见[上一批交付](../2026-10-18-srgg-source-schur/README_zh-CN.md)，不得将其次数并入本批分布证书。随机源为可重放的 `DeterministicRandom` 测试夹具；TV 推导另以独立均匀字节及正确舍入、无外部故障的 MPFR 实数 primitive 为前提，种子重放不证明该前提。当前环境为 Windows WSL2、Sage 10.9 / Python 3.13.15，主机 Intel Core Ultra 7 255HX、约 31.4 GiB 内存；ROM 用于原 IBS 对象流程，本批没有重跑其安全游戏。原表输入不是本项目已准入的正式参数，也不是教学替代参数。

复核命令（仓库根目录，在指定 WSL `~/miniconda3/envs/sage` 环境）：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_schur_finite_chain.py tests/test_srgg_paper_schur_convolution.py tests/test_srgg_paper_schur_literal_fallback.py tests/test_srgg_paper_schur_literal_fallback_audit.py tests/test_srgg_paper_schur_literal_moment.py tests/test_srgg_paper_schur_joint_bound_audit.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_schur_finite_chain_audit --output build/recheck-srgg-finite-new.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_schur_literal_fallback_audit --output build/recheck-srgg-literal-product-new.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_schur_joint_bound_audit --finite-report docs/research/team-b-delivery/2026-10-18-srgg-finite-chain/finite-fixed-root.json --output build/recheck-srgg-joint-new.json
python docs/research/team-b-delivery/2026-10-18-srgg-finite-chain/verify_delivery.py
```

输出路径必须尚不存在。验证和哈希清单见 [`validation.json`](validation.json)、[`MANIFEST.json`](MANIFEST.json)。**所有可接受 Setup 根的条件分布、完整发钥／签名／故障历史、结构攻击成本、原文强不可伪造冲突和作者 C/ANS/1000 次性能均未闭合。** 目前 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`；功能测试与固定根 TV 上界不能代替正式安全证明，也不宣称 NIST 等级。
