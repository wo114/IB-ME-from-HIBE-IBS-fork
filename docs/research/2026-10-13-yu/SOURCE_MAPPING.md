# Yu Figure 5 与本轮代码对应

## 固定来源

1. Qing Yu, Shengli Liu, Yiming Li. *Identity-based signature and identity-based matchmaking encryption from lattices*. Theoretical Computer Science 1082 (2026), 116152. DOI：<https://doi.org/10.1016/j.tcs.2026.116152>。仓库原文件：[2026_ibs_ibme_yu.pdf](../../../papers/2026_ibs_ibme_yu.pdf)，SHA-256 `f10d8672d952d9923a00c883a7d65feb36a15fb67fbef1c52ee64254f5301948`。
2. Abhishek Banerjee, Chris Peikert, Alon Rosen. *Pseudorandom Functions and Lattices*。本轮取得并核对的是作者网站 **2011-09-29 版，26 页**，不是把会议版页码套入作者版。URL：<https://web.eecs.umich.edu/~cpeikert/pubs/prf-lattice.pdf>；SHA-256 `c216374a14b27e0650cc2189f0939024dd2f895d7b2821ce4d9c32af0216ac00`。会议记录是 EUROCRYPT 2012, LNCS 7237, pp.719–737，DOI：<https://doi.org/10.1007/978-3-642-29011-4_42>。

本轮针对 Yu PDF 第 6–7、11–13 页及引用信息做算法对应，Figure 5 位于第 12 页，已渲染图像核对；不能仅靠 PDF 文本提取，因为算法图会被漏掉。BPR 主要核对 §2 式 (2.1)、§5.1 Definition 5.1/式 (5.1)、§5.2、§5.3 Theorem 5.2。这里不声称重新证明或重新完整审计两篇全文。

## 一、Figure 5 的真实路径

| 原文步骤 | 实现 | 核验方式 |
|---|---|---|
| TrapGen | `trapdoors.generate_root` → 既有 `chkp_genbasis.gen_basis` | AP09 完整整数核格基，检查包含关系和行列式；不是公开消元基替身 |
| 两组独立均匀公开块 | `standalone.setup` | 无偏拒绝式均匀整数采样；每块 `n×w`，`w=n⌈log₂q⌉` |
| `Eval_pub(PRF(·,id),...)` | `bpr.compile_key_circuit` → `evaluation.eval_public` | 数值 PRF、NAND 求值、独立 Sage 运算交叉对照 |
| 随机 `r_hat` 和匹配电路 | `keygen` / `equality_circuit` | 均匀比特，匹配函数真值表；不把 `r_hat` 错当成真实 PRF 密钥的输出 |
| 第一层 DelTrap + RandBasis | `trapdoors.issue_basis` | 追加 `w` 列、完整格基委派、真实 GPV 驱动的 RandBasis、显式后处理 |
| 新 `z`、`r_tilde` 及第二条电路 | `sign` | 输入顺序严格为 `identity || message || z`；固定分段长度 |
| 第二层 DelTrap + 零原像 | `trapdoors.sample_zero` | 追加一个 `n×w` 块；不再随机化一层基；真实离散高斯原像 |
| 非零、范数、模方程 | `sign` / `verify` | 精确整数平方范数；模 q 方程；验签只用公开输入 |
| 同一身份重复签名 | `Authority` | 固定发出的用户密钥，多条消息调用；公开验签独立于服务缓存 |

本轮保留签名向量的有符号整数表示。不能先把每个坐标规约到 `0..q−1`，再用那个向量计算高斯长度和声称保持原采样分布。编码域标识、分段长度和定宽有符号坐标由解析器检查；没有借助哈希改变原方案的身份或消息输入空间。

## 二、真实 PRF 如何变成密钥输入电路

BPR 作者版式 (5.1) 的矩阵构造为：

`F(A,S₁,…,Sₖ; x) = floor((p/q)·(Aᵀ·S₁^{x₁}···Sₖ^{xₖ} mod q)) mod p`。

这里的 `A` 是 **BPR 密钥的一部分**，不要和 Yu 系统公钥中的格矩阵 `A` 混淆。代码使用 `q=2^b,p=2`，所以 floor 舍入就是保留规范余数的最高位。采用 floor 是 BPR 式 (2.1) 后明确允许的选择。矩阵乘积保持下标顺序；平衡乘积树只改变括号，不交换矩阵。

Yu 图中的 PRF 密钥空间是均匀比特串，BPR 定理中的 `S_i` 则来自离散高斯。为明确连接两者，本轮有限实现的密钥比特编码为：

- `A` 的各系数使用 `b` 个均匀比特；
- 每个 `S_i` 系数使用 `B` 个均匀随机带比特，经公开、确定的 CDT 映射为离散高斯近似；
- 使用输入 `x` 选取因子，再进行二进制矩阵模乘和最高位舍入。

高斯表来自仓库已有区间算术构造，未调用拒绝采样。将累计整数质量按 `floor(2^B·cdf/total)` 量化，最后端点是 `2^B`，因此每个合法密钥都有定义。单系数总变差上界为原表尾界、原表区间/量化界、`(support_count−1)/2^B` 之和；整个密钥再乘以 `k·n²` 并截断到 1。这个证书不是 PRF 的计算安全证明。

在真实 Yu `Setup` 中不生成一把隐藏的 BPR 密钥；系统只生成公开矩阵块，用来同态计算上述“密钥作为变量”的电路。显式 PRF 秘密比特仅出现在独立数学对照测试里。

## 三、明确不自动继承的结论

1. BPR 作者版 §5.2 对矩阵多乘积给出 TC1 上界，提到预处理可能降低深度；其讨论把矩阵预先固定，而 Yu 的调用把密钥作为电路输入。本轮有限编译器没有建立满足 Yu 参数推导的 NC1 家族；不能以“有一张电路”代替该条件。
2. 本轮 NAND 实现核对 `A_C=A·R_C+C(x)⊗G (mod q)`。私有整数见证使用粗界 `(w+1)^depth`；没有证明 Yu Lemma 7 的 `O(4^d·m^{3/2})` 谱范数界，不能将两个界互换。
3. `RandBasis` 后的确定性 LLL 是实现扩展。对包含失败符号的分布，使用同一确定映射不会增加总变差；这不等于证明与原论文理想输出完全同分布，也不能丢掉失败后再声称同一界。
4. AP09 小配置的近均匀界没有得到非空保证。所有高斯、秩、范数和资源失败都单次传播；没有调小宽度、放宽采样器上限或按秘密基临时选择公开宽度。
5. 本轮只做 Yu 的 IBS。原文随后给出的 IBS+IBE 构造不等同本项目的 Wang HIBE+IBS 接入，本轮没有实现或宣称那一部分组合。

这些条目是可执行代码与理论准入之间的明确边界。用户当前要求优先补独立代码，因此本轮不以重写基础安全归约、确认正式安全位数或接入其它模块为完成条件。
