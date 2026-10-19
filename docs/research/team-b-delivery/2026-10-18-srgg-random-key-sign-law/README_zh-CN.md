# SRGG 原表随机发钥后签名分布审计（WIP）

**论文：**Huiwen Jia、Ying Liu、Chunming Tang、Lin Wang，*Constructing Efficient Identity-Based Signatures on Lattices*，DOI 10.1049/ise2/6684889。本地冻结 PDF 的 SHA-256 为 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。

本包核对“**随机发出**的密钥”的分布与先前“**冻结的一把** Alice 密钥”签名界之间的缺口。在原论文 Table 4 六行中，均可精确构造一个规范尾向量：它属于数学发钥参考分布的支持，却使签名 Schur 矩阵非正定；未修改的后端因此拒绝准备签名计划。见[推导与边界](proof.md)和[六行回执](random-key-sign-law.json)。这并未估计有限发钥器抽到该向量的概率。

对一次发钥后最多 `s` 次自适应签名，条件式耦合界为 `TV <= min(1, delta_issue + beta_bad + s epsilon_good)`；`beta_bad` 必须是**同一理想发钥参考**下坏密钥的质量，`epsilon_good` 必须统一约束所有好密钥的完整签名调用。当前两者均为 null，故随机发钥后签名历史 TV 仍为 null。不能把冻结密钥的 epsilon 直接代入。

参数保持原表 `n=512,p=16383,b=31,w=2,Q=15744063,d=2/3/4`，并保留两种显式 Gaussian 记号解释；未改宽度、范数、算法和采样分布。每行重放一把确定性可接受 Setup 根，构造一个 Alice（5 B）的**合成**规范密钥；它不是实际发钥样本。本包不签消息。环境版本记录在回执中；身份目标使用 ROM。确定性种子仅是测试夹具，不是概率证据。

在仓库根目录按规定 WSL Sage 环境运行：

```text
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_random_key_sign_law.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_random_key_sign_law --output build/new-random-key-sign-law.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python docs/research/team-b-delivery/2026-10-18-srgg-random-key-sign-law/verify_delivery.py
```

复算请用新路径，不覆盖冻结回执。清单约束选定源码、测试和证据；六行重放前先核验既有交付。功能重放不能替代密码学证明。本包仍标记 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。所有可接受 Setup 根、故障历史、正式证明前提、坏密钥质量及实际结构攻击成本仍未闭合。
