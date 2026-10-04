# 项目论文库

登记日期：2026-10-04。已固定第二、第三轮直接审查的五篇原文。摘要说明研究内容，不代表本项目已验证定理或批准后端。PDF 保留作者及出版方声明；TeX 源码均未取得。固定文件指纹见 [manifest.json](manifest.json)。

## 2010_lattice_basis_delegation_agrawal.pdf

- 标题：Lattice Basis Delegation in Fixed Dimension and Shorter-Ciphertext Hierarchical IBE
- 作者：Shweta Agrawal、Dan Boneh、Xavier Boyen。
- 年份：2010，CRYPTO 2010，LNCS 6223，pp. 98–115。
- 来源与版本：[作者 PDF](https://crypto.stanford.edu/~dabo/pubs/papers/latticehibe.pdf)，18 页；从此前已核验缓存复制归档，未修改内容。关键 Theorems 3、4 将完整证明指向另一个 full version，该证明不在当前文件内。
- 一句话主题：通过模可逆的小整数矩阵在固定维度委派短格基，以 dual Regev 加密构建两层可用的 ROM HIBE 参考算法。
- 文件：[PDF](2010_lattice_basis_delegation_agrawal.pdf)。
- TeX 源码：无。
- 当前审查：[两层算法与参数规范](../docs/research/2026-10-04/ABB10两层HIBE算法与参数规范.md)。

## 2023_tightly_secure_ibs_foo.pdf

- 标题：Tightly Secure Lattice Identity-Based Signature in the Quantum Random Oracle Model
- 作者：Ernest Foo、Qinyi Li（原文注明按字母顺序排列）。
- 年份：2023，ACISP 2023，DOI `10.1007/978-3-031-35486-1_17`。
- 来源与版本：[Griffith 作者接受稿](https://research-repository.griffith.edu.au/server/api/core/bitstreams/bea45f34-cb40-47b4-b6da-4bde6690f252/content)，22 页（含仓储封面）；从此前已核验缓存复制归档。不是本轮取得的出版终稿或修订稿。
- 一句话主题：用秘密种子固定发钥和签名随机性，以一个格向量及一个分支比特构造 IBS，并给出 ROM/QROM 归约；本项目审查发现游戏间多消息分支关联需要澄清。
- 文件：[PDF](2023_tightly_secure_ibs_foo.pdf)。
- TeX 源码：无。
- 当前审查：[接入与证明审查](../docs/research/2026-10-04/FooLiIBS接入与证明审查.md)，当前状态为暂缓准入。

## 2011_lattice_trapdoors_micciancio.pdf

- 标题：Trapdoors for Lattices: Simpler, Tighter, Faster, Smaller
- 作者：Daniele Micciancio、Chris Peikert。
- 年份：ePrint 2011；通常简称 MP12，发表于 EUROCRYPT 2012。
- 来源与版本：[ePrint 2011/501 元数据](https://eprint.iacr.org/2011/501)、[PDF](https://eprint.iacr.org/2011/501.pdf)。当前下载文件 41 页，首页日期 2011-09-14；元数据历史只列 2011-09-18 received。未自行指定额外版本编号。
- 一句话主题：以 G-trapdoor、扰动高斯与 gadget 陪集采样产生规定分布的 SIS 原像，并给出委派与有限质量约束，是新后端采样工具的主要依据。
- 文件：[PDF](2011_lattice_trapdoors_micciancio.pdf)。
- TeX 源码：无（本次来源只提供 PDF）。
- 本轮核验范围：§§2.3–2.4、4.2、5.1–5.5 的相关定义、算法和引理；未完成整篇精读。

## 2021_short_ibs_pan.pdf

- 标题：Short Identity-Based Signatures with Tight Security from Lattices。
- 作者：Jiaxin Pan、Benedikt Wagner。
- 年份：2021，PQCrypto 2021，DOI `10.1007/978-3-030-81293-5_19`。
- 来源与版本：[ePrint 2021/970 元数据](https://eprint.iacr.org/2021/970)、[PDF](https://eprint.iacr.org/2021/970.pdf)。30 页，从 2026-10-03 已有研究缓存原样复制；本轮元数据最新日期仍为 2021-12-03（页面写 last of 2 revisions），未凭此推断版本号，也未声称本轮重下载 PDF。
- 一句话主题：以身份盐和消息盐转换非自适应 IBS；其安全实验每次签名重新发钥，固定密钥服务需额外适配证明。
- 文件：[PDF](2021_short_ibs_pan.pdf)。
- TeX 源码：无。
- 本轮核验：§§2、3.1、3.2，PDF 7–13；视觉复核 Figure 1/5 与 ROM 证明所在 PDF 8、12、13。
- 当前审查：[固定密钥接入审查](../docs/research/2026-10-04-round3/Wang与PanWagner固定密钥接入审查.md)及[本项目条件归约草案](../docs/research/2026-10-04-round3/固定密钥转换条件归约草案.md)。

## 2022_identity_matchmaking_wang.pdf

- 标题：Identity-based Matchmaking Encryption with Stronger Security and Instantiation on Lattices。
- 作者：Yuejun Wang、Baocang Wang、Qiqi Lai、Yu Zhan。
- 年份：ePrint 2022；发表于 Theoretical Computer Science，DOI `10.1016/j.tcs.2024.115048`。
- 来源与版本：[ePrint 2022/1718 元数据](https://eprint.iacr.org/2022/1718)、[PDF](https://eprint.iacr.org/2022/1718.pdf)。21 页，从 2026-10-03 已有研究缓存原样复制；本轮元数据最新日期仍为 2025-03-03（last of 2 revisions），没有自行编号或声称新下载。
- 一句话主题：固定的两层匿名 HIBE + 自适应 IBS 通用构造，用较短 SIS 原像签名改善密文尺寸；基本 IBS 本身只有非自适应安全结论。
- 文件：[PDF](2022_identity_matchmaking_wang.pdf)。
- TeX 源码：无。
- 本轮核验：Lemma 2.6、Definition 6、Construction 1、Lemma 4.2、Figure 4/5 与 Theorem 5.1，PDF 7、9–10、12–19；视觉复核 PDF 10、16–18。
- 当前审查：[固定密钥接入审查](../docs/research/2026-10-04-round3/Wang与PanWagner固定密钥接入审查.md)。普通隐私与加强认证的具体后端前提尚未闭合。
