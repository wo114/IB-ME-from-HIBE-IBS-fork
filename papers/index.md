# 项目论文库

登记日期：2026-10-04。本轮只归档直接参与第二轮审查的三篇原文。摘要说明研究内容，不代表本项目已验证定理或批准后端。PDF 保留作者及出版方声明；TeX 源码均未取得。固定文件指纹见 [manifest.json](manifest.json)。

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
