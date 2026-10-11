# 项目论文库

算法可用程度、源码与参数情况统一见[现行算法总表](../docs/ALGORITHM_CATALOG.md)。本索引记录来源与归档，不把取得论文等同于实现或安全准入。

2026-10-10 用户提供 GKR、SRGG 和 Yu 三篇完整 PDF，已原样复制并核对标题、页数、SHA-256；历史下载失败记录保留，新状态见 [用户提供稿指纹](user-supplied-manifest-2026-10-10.json)。这些获取状态更新不等于完成算法/参数审查或安全准入。同轮另从 HAL 取得 Sageloli 完整稿，候选基础包记录于 [统一入口](../docs/research/2026-10-10-foundations/README.md)。

## 2023_shorter_faster_ibs_sageloli.pdf

- 标题：Shorter and Faster Identity-Based Signatures with Tight Security in the (Q)ROM from Lattices。
- 作者：Éric Sageloli、Pierre Pébereau、Pierrick Méaux、Céline Chevalier；ACNS 2023，DOI `10.1007/978-3-031-33488-7_24`。
- 来源：[HAL hal-04107694v1](https://hal.science/hal-04107694v1)，提交日期 2023-05-26；73 页，包含仓储封面和完整附录。文件 SHA-256 为 `0e92f184828bc8643a774e9c334b14689346387981e766c311c596239ef73e3e`；不是本轮取得的出版社30页稿。
- 一句话主题：用非齐次原像签名减少一次消息委派，并给出 SIS/Ring-SIS 两条 IBS 路线。
- 本轮速读范围：§5–8 的算法/游戏/表格和 Appendix E；固定密钥游戏适配、尺寸单位与有限实例继续单独核对，未重证基础定理。
- 文件：[PDF](2023_shorter_faster_ibs_sageloli.pdf)。获取尝试见 [记录](candidate-fetch-2026-10-10.json)，TeX 源码未取得。

## 2026_ibs_ibme_yu.pdf

- 标题：Identity-based signature and identity-based matchmaking encryption from lattices。
- 作者：Qing Yu、Shengli Liu、Yiming Li；Theoretical Computer Science，2026，DOI `10.1016/j.tcs.2026.116152`。
- 来源：用户提供的出版 PDF，26 页；下载目录原文件保留，仓库复制件逐字节一致。
- 一句话主题：研究固定密钥服务下的标准模型 IBS 与 IBME；本项目先调查其独立 IBS，保持已选 Wang HIBE+IBS 通用构造。
- 文件：[PDF](2026_ibs_ibme_yu.pdf)。TeX 源码：未取得；全文算法及参数核验待做。

## 2025_adaptive_hibe_goyal.pdf

- 标题：A Note on Adaptive Security in Hierarchical Identity-Based Encryption。
- 作者：Rishab Goyal、Venkata Koppula、Mahesh Sreekumar Rajasree；CRYPTO 2025 / [ePrint 2025/291](https://eprint.iacr.org/2025/291)。
- 来源：用户提供 PDF，34 页；以文件指纹固定本地版本，不推断未核实的数字修订号。
- 一句话主题：从选择性 IBE 编译自适应 HIBE，并研究完全匿名扩展；具体底层原语与工程成本待核对。
- 文件：[PDF](2025_adaptive_hibe_goyal.pdf)。TeX 源码：未取得；本次只完成归档。

## 2025_efficient_ibs_jia.pdf

- 标题：Constructing Efficient Identity-Based Signatures on Lattices。
- 作者：Huiwen Jia、Ying Liu、Chunming Tang、Lin Wang；IET Information Security，2025，DOI `10.1049/ise2/6684889`。
- 来源：用户提供出版 PDF，12 页；已有在线审查现在可用本地完整公式复核。
- 一句话主题：将原像采样与椭球 G+G 签名结合成 SRGG-IBS，区分离线/在线计算。
- 文件：[PDF](2025_efficient_ibs_jia.pdf)。TeX 源码：未取得；底层强结论/参数映射的既有待核条件未因下载完成自动关闭。
- 历史获取：2026-10-08 出版社直取曾返回403；该失败已由2026-10-10用户提供完整PDF解决，不再重复登记为“未取得”。当时核对Definition 3、§4.5 Theorem 2和Tables 1/4/5/6；作者 C 原型仍未确认公开源码，尺寸/底层条件问题另核。

登记日期：2026-10-04。已固定第二、第三轮直接审查的五篇原文。摘要说明研究内容，不代表本项目已验证定理或批准后端。PDF 保留作者及出版方声明；TeX 源码均未取得。固定文件指纹见 [manifest.json](manifest.json)。

2026-10-08 补充三份组合选型资料；采用独立 [新增资料指纹](portfolio-manifest-2026-10-08.json)，不改原五篇冻结 manifest。原文筛选不表示完整证明或后端已经准入。

同日后续扩大 HIBE 与直接 IBS 调查，新增五份固定 PDF；指纹、下载失败及在线阅读状态分别记于 [调查清单](survey-manifest-2026-10-08.json)。优先级见 [实施计划](../docs/research/2026-10-08-selection/文献复核与后续实施计划.md)。

2026-10-09 为 CHKP T2 增补 AP09/GPV08 作者全文，并定位 MG02 ToBasis 原始出处；指纹、版本、阅读范围和未取得的第 7 章见 [T2 来源清单](chkp-t2-sources-2026-10-09.json)。没有把来源归档视为采样算法已实现。

## 2009_generating_shorter_bases_alwen_peikert_full.pdf

- 标题：Generating Shorter Bases for Hard Random Lattices；Joel Alwen、Chris Peikert。
- 版本：2010-07-10 作者全文，18 页；AP09 指 STACS 2009 初版年份，不与 12 页会议版混用。
- 来源：[作者公开 PDF](https://sites.cc.gatech.edu/fac/cpeikert/pubs/shorter.pdf)，原样归档。文件：[PDF](2009_generating_shorter_bases_alwen_peikert_full.pdf)。
- 本轮核对：§2.1–2.4、§3.1–3.2、§3.3 开头；重点 Theorems 3.1/3.2、Algorithm 1 和有限常数缺口，不声称全篇精读。TeX 未取得。
- 用途：CHKP GenBasis 的来源及子算法选择门槛；正式实现与有限质量证书尚未完成。

## 2008_gpv_trapdoors_full.pdf

- 标题：How to Use a Short Basis: Trapdoors for Hard Lattices and New Cryptographic Constructions；Craig Gentry、Chris Peikert、Vinod Vaikuntanathan。
- 版本：2008-08-25 作者全文，41 页。
- 来源：[作者公开 PDF](https://sites.cc.gatech.edu/fac/cpeikert/pubs/trap_lattice.pdf)，原样归档。文件：[PDF](2008_gpv_trapdoors_full.pdf)。
- 本轮核对：PDF 9–17 的 ToBasis 转述、Gaussian 引理、Lemma 3.1、Theorem 4.1 和 §4.1–4.2；未审查全部密码构造，TeX 未取得。
- 用途：一般列基 SampleD/标量 SampleZ 的明确算法和有限误差推导，不是 MP12 G-trapdoor 的同义名称。

## MG02 ToBasis：已定位，原章节未取得

- Daniele Micciancio、Shafi Goldwasser，Complexity of Lattice Problems: A Cryptographic Perspective，2002。
- [Chapter 7: Basis Reduction Problems](https://link.springer.com/chapter/10.1007/978-1-4615-0897-7_7)，pp.125–142；GPV08/CHKP 引用 Lemma 7.1，p.129。
- 出版社提供订阅访问；[作者样章入口](https://cseweb.ucsd.edu/~daniele/papers/book.html)只有第 1 章。不创建伪全文文件，不声称读过原证明。
- 当前可核对的转述是 GPV08 Lemma 2.1（PDF 9）和 CHKP Lemma 2.1（PDF 11）；输入、后置条件与后续补全门槛见 [T2 契约](../docs/research/team-chkp/T2-算法来源与采样契约-2026-10-09.md)。

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

## 2006_generic_ibs_galindo.pdf

- 标题：On the Generic Construction of Identity-Based Signatures with Additional Properties。
- 作者：David Galindo、Javier Herranz、Eike Kiltz；ASIACRYPT 2006。
- 来源：[IACR 官方归档](https://www.iacr.org/archive/asiacrypt2006/42840177/42840177.pdf)，16 页；原样保存。
- 一句话主题：由主机构签发身份与用户公钥的认证，把普通签名转成仅用主公钥/身份即可验证的 IBS。
- 本次核对：§3、Theorem 1，PDF 第 5 页；完整 BNN 原始归约与缓存服务的映射待精读。
- 文件：[PDF](2006_generic_ibs_galindo.pdf)。TeX 源码：未取得。

## 2024_ml_dsa_fips204.pdf

- 标题：Module-Lattice-Based Digital Signature Standard，FIPS 204。
- 作者/发布方：NIST，2024；65 页官方 PDF，原样保存并固定指纹。
- 来源：[NIST](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)。
- 一句话主题：规范 ML-DSA 的模格签名算法、参数与编码，可作为认证型 IBS 的普通签名组件。
- 本次核对：算法接口与参数/尺寸 Tables 1/2，尺寸见 PDF 第 26 页；没有宣称标准本身证明完整 IBS/IBME。
- 文件：[PDF](2024_ml_dsa_fips204.pdf)。TeX 源码：未取得。

## 2020_falcon_spec_fouque.pdf

- 标题：Falcon: Fast-Fourier Lattice-based Compact Signatures over NTRU，Specification v1.2。
- 作者：Pierre-Alain Fouque 等；首页日期按原文保留 01/10/2020，67 页。
- 来源：[Falcon 原始规范](https://falcon-sign.info/falcon.pdf)，原样保存。
- 一句话主题：在 NTRU 格上用快速 Fourier 采样实现 GPV 签名，提供较小的公钥/签名与具体编码规则。
- 本次核对：§§2.2、2.7、3.11、3.13；尺寸 Table 3.3，PDF 第 51 页；保密签名编码注意事项见 PDF 第 48 页。
- 文件：[PDF](2020_falcon_spec_fouque.pdf)。TeX 源码：未取得。

## 2010_bonsai_trees_cash.pdf

- 标题：Bonsai Trees, or How to Delegate a Lattice Basis。
- 作者：David Cash、Dennis Hofheinz、Eike Kiltz、Chris Peikert。
- 年份与版本：EUROCRYPT 2010，期刊 2012；本次固定作者全文首页 2011-06-14，36 页，不自行指定 ePrint 版本号。
- 来源：[作者 PDF](https://sites.cc.gatech.edu/fac/cpeikert/pubs/bonsai.pdf)。
- 一句话主题：扩展并随机化格基进行委派，给出完整 HIBE、匿名填充以及 ROM 和标准模型的自适应转换。
- 本轮核对：§5.1–5.4，尤其 PDF 第 21–22 页匿名说明 / Theorem 5.2、第 29 页 Theorem 5.4 / Corollary 5.5。
- 文件：[PDF](2010_bonsai_trees_cash.pdf)。TeX 源码：未取得。

## 2010_lattice_hibe_standard_agrawal.pdf

- 标题：Efficient Lattice (H)IBE in the Standard Model。
- 作者：Shweta Agrawal、Dan Boneh、Xavier Boyen。
- 年份与版本：2010 研究；本次取得合并 EUROCRYPT/PKC 初步结果的 40 页作者全文，不与 CRYPTO 固定维度论文混用。
- 来源：[作者 PDF](https://crypto.stanford.edu/~dabo/pubs/papers/latticebb.pdf)。
- 一句话主题：以左右陷门构造标准模型 IBE，并分别扩展自适应 IBE 与选择性 HIBE。
- 本轮核对：§2.1、§7/§8，PDF 第 34 页 Theorem 33；未宣称 §7 自适应结论适用于 §8 HIBE。
- 文件：[PDF](2010_lattice_hibe_standard_agrawal.pdf)。TeX 源码：未取得。

## 2024_quantum_safe_hibe_zhao.pdf

- 标题：Quantum-safe HIBE: does it cost a LATTE?
- 作者：Raymond K. Zhao、Sarah McCarthy、Ron Steinfeld、Amin Sakzad、Máire O'Neill。
- 版本：IEEE TIFS 作者接受稿，封面记 2023 advance online；ePrint 起于 2021，发表/归档版本须分开。文件含仓储封面共 17 页。
- 来源：[Queen's 作者归档](https://pureadmin.qub.ac.uk/ws/portalfiles/portal/549983007/Quantum_Safe_HIBE.pdf)、[论文入口](https://eprint.iacr.org/2021/222)。
- 一句话主题：实现并优化 NTRU/RLWE HIBE 的委派、采样与解密，提供原文安全估计和性能记录。
- 本轮核对：算法、§IV 安全/精度分析及尺寸/性能表；没有找到可直接用于本项目的匿名定理，不把 ID-IND-CCA 等同于匿名。
- 文件：[PDF](2024_quantum_safe_hibe_zhao.pdf)。未下载/编译其 C 代码；TeX 源码未取得。

## 2020_ideal_lattice_hibe_zhang.pdf

- 标题：Adaptively Secure Efficient (H)IBE over Ideal Lattice with Short Parameters。
- 作者：Yuan Zhang、Yuan Liu、Yurong Guo、Shihui Zheng、Licheng Wang。
- 年份：2020，Entropy 22(11), 1247，DOI `10.3390/e22111247`，19 页。
- 来源：[出版社 PDF](https://mdpi-res.com/d_attachment/entropy/entropy-22-01247/article_deploy/entropy-22-01247.pdf)。
- 一句话主题：把身份按段处理以减少环格 HIBE 公共参数，并给出自适应安全与开销分析。
- 本轮核对：§2.1、§4.1–4.3；PDF 第 10–11 页委派/私钥类型和 Theorem 4 条件存在实施疑点，暂未准入。
- 文件：[PDF](2020_ideal_lattice_hibe_zhang.pdf)。TeX 源码：未取得。

## 2024_ibs_without_trapdoors_luo.pdf

- 标题：Identity-Based Signature from Lattices without Trapdoors。
- 作者：Pingbin Luo、Xinjian Chen、Willy Susilo、Qiong Huang。
- 年份与版本：ICICS 2024 官方会议公开 PDF，20 页；不是本项目重写的 ML-DSA 包装。
- 来源：[会议 PDF](https://icics2024.aegean.gr/wp-content/uploads/2024/08/150570198.pdf)。
- 一句话主题：用两次拒绝采样签名实现身份公钥委派，给出不需陷门原像采样的直接 IBS 和模格压缩实例。
- 本轮核对：§2.2、§3.2 Algorithms 5/6 / Theorem 1、§4 Algorithms 13–16 / MLWE-MSIS 条件；重复身份签名的缓存解释待确认。
- 文件：[PDF](2024_ibs_without_trapdoors_luo.pdf)。未找到该后端的公开源码；TeX 源码未取得。

## 2011_peikert_parallel_gaussian_author.pdf

- 标题：An Efficient and Parallel Gaussian Sampler for Lattices。
- 作者/版本：Chris Peikert，2011-04-13 作者版，19 页；原样保留，非 MG02 第七章。
- 来源：[作者公开 PDF](https://sites.cc.gatech.edu/fac/cpeikert/pubs/pargauss.pdf)；[本地 PDF](2011_peikert_parallel_gaussian_author.pdf)；[文件指纹与阅读范围](chkp-t2-source-supplement-2026-10-10.json)。
- 本轮用于：PDF 16 的 Lemma 5.4，ToBasis 显式步骤、完整格和逐项 GS 不增；没有改用此论文的并行向量采样算法。
- 限制：不采用该证明中有问题的三角整数矩阵奇异值推断，不宣称谱/普通列范数不增。未取得 MG02 第七章或此稿 TeX，未声称全篇精读。
- 实施/证据：[CHKP T2 续作](../docs/research/team-chkp/T2-真实采样实现与未闭合项-2026-10-10.md)，整体仍 WIP。

## 2016_ntru_ibs_xie.pdf

- 标题：Efficient identity-based signature over NTRU lattice。
- 作者：Jia Xie、Yu-pu Hu、Jun-tao Gao、Wen Gao；FITEE 2016，17(2):135–142，DOI `10.1631/FITEE.1500197`。
- 来源：[Springer 官方 PDF](https://link.springer.com/content/pdf/10.1631/FITEE.1500197.pdf)；[本地原始 PDF](2016_ntru_ibs_xie.pdf)，8页、548574字节。
- SHA-256：`0797847601224a3743cdf1597cad74aa31cfa966c5b466e4b945af07762a0559`；[获取与代码检索清单](ntru-ibs-fetch-2026-10-11.json)。
- 本轮核对算法/参数相关章节与部分页面，不声称全篇证明已审；具体困难假设、参数文字冲突和上游 IBE 代码边界见[来源记录](../docs/research/2026-10-11-catalog/ntru-ibs-sources.md)。已纳入原生 NTRU IBS 候选，尚无本仓库完整实现；未确认原作者 IBS 代码。

## 2015_ideal_lattice_trapdoors_lai.pdf

- Russell W. F. Lai、Henry K. F. Cheung、Sherman S. M. Chow；Inscrypt 2014，出版2015，LNCS8957:239–256；[DOI](https://link.springer.com/chapter/10.1007/978-3-319-16745-9_14)。
- 标题：Trapdoors for Ideal Lattices with Applications；[本地 PDF](2015_ideal_lattice_trapdoors_lai.pdf)由用户于 2026-10-11 提供，原样复制，18 页、226438 字节。
- SHA-256：`0985cb1d8cc760a18070a38d30b8de5b532bca52b5c06e05e65b2d712bdf338c`；首页标题/作者与末页参考文献已核。Ghostscript 2022 文件生成时间不是论文年份；具体发行版本未认证。
- 较早[作者上传网页正文](https://www.academia.edu/87100350/Trapdoors_for_Ideal_Lattices_with_Applications)的 §5.1–5.2/定理10已选读；PLWE、INDr匿名与HIBE描述仍需按 PDF 完成模型/公式映射。没有完成全篇证明审查或准入参数核验。
- [获取和代码清单](ideal-lattice-fetch-2026-10-11.json)、[具体来源与限制](../docs/research/2026-10-11-catalog/ideal-lattice-sources.md)。作者 `lattice_lib` 固定版本仅确认为通用 Sage 格工具，未确认对应完整 HIBE 实现或数值参数包。
