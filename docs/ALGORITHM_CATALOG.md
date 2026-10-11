# HIBE / IBS 算法与候选总表

更新：2026-10-11。按[统一框架](../ARCHITECTURE.md)分别管理 HIBE、IBS 模块，再装配兼容组合。本文登记 **19 条候选/模型路线：8 条 HIBE、11 条 IBS**，覆盖原[17 条基础目录](research/2026-10-10-foundations/catalog.json)及新补充的两条原生路线；这不是 19 个完整后端，也不是 19 个不同困难假设。

当前任务和外部包进度以 [PROJECT_STATUS.md](PROJECT_STATUS.md) 为准；本文用于选模块、找原文与代码、识别接入缺口。**最终三组完整组合尚未锁定，第三套 HIBE 不再强制属于 Module-LWE。** 普通签名转换成 IBS 的两个条目保留原 ID，BNN-Falcon / BNN-ML-DSA 不再重复计数。

## 1. 如何读这张表

| 状态 | 本文含义 |
|---|---|
| 可运行研究后端 | 本地有真实算法和公开接口/生命周期，可用于标明限制的研究测试；不表示正式安全准入 |
| 已有组件 | 有实际代数、采样、状态或生命周期代码；尚缺完整原语或共同接口 |
| 有外部源码 | 核实作者/官方仓库存在；本项目未编译、接入或复跑的部分明确列出 |
| 仅候选 / 模型对照 | 有原文、算法映射或计数材料，未实现完整后端 |
| 暂缓 | 有具体参数、语义或模型问题，保留证据及已有代码，不从比较资料删除 |

“全文已取得”“有数值参数”“代码存在”“实跑通过”“满足组合前提”分别记录。除非单列外部来源，表中实现状态均指当前仓库；本轮是目录与源文件核对，没有重跑这些密码算法。

## 2. HIBE：8 条路线

| ID / 算法 | 假设与论文模型 | 原文与参数状态 | 实现及接入状态 |
|---|---|---|---|
| `abb-rom` — ABB10 CRYPTO 固定维度 HIBE | 普通 LWE，经典 ROM；匿名/两层条件按选定算法映射 | [18 页作者稿](../papers/2010_lattice_basis_delegation_agrawal.pdf)、[算法核验](research/2026-10-04/ABB10两层HIBE算法与参数规范.md)。完整 BasisDel、模可逆 SampleR 与逐层宽度仍需有限实例 | **已有教学后端与公共代数组件**。`src/ibme/hibe/abb10.py` 可以运行，但与忠实固定维度论文实例有差别，不能改名升级为正式 ABB10 |
| `chkp-rom` — CHKP 两层匿名 ROM HIBE | 普通 LWE，经典 ROM；匿名填充、固定同址解封装状态是具体条件 | [作者全文](../papers/2010_bonsai_trees_cash.pdf) §5.1–5.3；[当前交接](research/team-chkp/README.md)。真实参数、采样宽度、噪声及资源条件未同时闭合 | **已有真实研究组件，优先继续**。根基/扩展/随机化/叶采样/缓存等代码、第七步外部包及已并入的 [first_suite 有限 DelTrap 对照](research/2026-10-11-first-suite-compact/README.md)；独立 n=1 原型含公开种子恢复反例。尚无完整公开 `HIBEBackend`，不能登记真实 CHKP+Luo 已通 |
| `latte` — LATTE NTRU/RLWE HIBE | NTRU 结构陷门与 Ring-LWE 密文路线；完整定理依赖待逐项对应。IND-CCA 标签不能代替匿名性 | [作者接受稿](../papers/2024_quantum_safe_hibe_zhao.pdf)；作者源码含具体参数，详见下节 | **有作者 C 源码；已做局部标量 C 诊断，未完整 HIBE 运行/接入**。[固定版本诊断](research/2026-10-11-public-reuse/README.md)复现缓冲区使用问题，修订未正式准入；实际 Delegate 与两层参数存在；Wang 组合要求的匿名性质尚未核实，暂作工程候选 |
| `gkr2025` — Goyal–Koppula–Rajasree 自适应 HIBE 编译器 | 标准模型论文路线；一般编译器依赖 PKE、OTSE、garbling、可委派 PRF；匿名 LWE 扩展另含 lockable obfuscation | [34 页用户完整稿](../papers/2025_adaptive_hibe_goyal.pdf)已取得；已定位 §3/Theorem 3.1 与匿名扩展。无本项目有限参数闭环 | **仅候选，复杂编译器储备**。无完整后端；须先明确匿名扩展和电路/对象规模，不能简化成一套普通矩阵公式 |
| `zhang2020` — Zhang 等理想格 HIBE | Ring-LWE 路线；自适应声明、匿名性及模数条件待完整映射 | [19 页原文](../papers/2020_ideal_lattice_hibe_zhang.pdf)；§4.1–4.3 的私钥类型、委派及 SamplePre 输入仍有实施疑点 | **暂缓完整实现**。只有可复用公共环算术基础；先澄清短向量/可委派陷门类型，不能自行补造缺失算法 |
| `abb-standard-selective` — ABB 标准模型选择性 HIBE | 普通 LWE，标准模型选择性身份；§7 自适应 IBE 不等于 §8 自适应 HIBE | [40 页作者稿](../papers/2010_lattice_hibe_standard_agrawal.pdf) §8/Theorem 33；参数条件待独立实例化 | **模型对照**。没有完整后端；不能直接登记为满足当前自适应匿名组合前提 |
| `chkp-standard` — CHKP §5.4 变体 | LWE 及可容许哈希条件，标准模型条件路线；匿名扩展范围另核 | [同一 CHKP 原文](../papers/2010_bonsai_trees_cash.pdf) §5.4/Theorem 5.4/Corollary 5.5；额外维度与归约成本未闭合 | **模型对照**。不能用 ROM 实现切一个开关就算消除随机预言机；不与 `chkp-rom` 参数共用结论 |
| `lai-ideal-hibe` — Lai–Cheung–Chow，理想格陷门 HIBE | 原文 PLWE 与 INDr-ID-CCA 声明含收件人匿名性；选读 §5.1–5.2/定理10，尚需具体两层模型映射 | Inscrypt 2014／出版2015；[18 页 PDF](../papers/2015_ideal_lattice_trapdoors_lai.pdf)由用户提供并原样归档，标题/作者已核。符号参数不能直接当有限可运行配置 | **新增文献候选**。[来源核验](research/2026-10-11-catalog/ideal-lattice-sources.md)未确认对应作者 HIBE 代码；已查 lattice_lib 仅通用格工具。实施前仍需按 PDF 核准算法、公式和参数 |

### LATTE：本轮已确认的外部代码

作者 [GitLab 仓库](https://gitlab.com/raykzhao/latte) 的 [README.adoc](https://gitlab.com/raykzhao/latte/-/raw/master/README.adoc)明确对应 TIFS 2024 论文。通过公开项目 API 和源码核实目录 `latte_1` 至 `latte_4`；以 `latte_3` 为可接手入口：

- [delegate.c](https://gitlab.com/raykzhao/latte/-/blob/master/latte_3/delegate.c)具有真实委派实现；代码中相关求解分支只处理 `l=1`，不据此宣称任意深度。
- [param.h](https://gitlab.com/raykzhao/latte/-/blob/master/latte_3/param.h)给出 `N=1024`、`L=2`、`Q=68718428161`，另列各层宽度、范数与精度。这是作者代码配置，不是本项目已核安全参数。
- [Makefile](https://gitlab.com/raykzhao/latte/-/blob/master/latte_3/Makefile)链接 GMP、MPFR、MPC、XKCP、quadmath；目录有 `keygen.c`、`extract.c`、`encrypt.c`、`decrypt.c`、`test.c`。[许可证](https://gitlab.com/raykzhao/latte/-/blob/master/LICENSE)为 BSD Zero Clause。

原目录调查只读取网页/API/源码；本次合并同时取得上游独立 [LATTE 标量 C 探针证据](research/2026-10-11-public-reuse/latte-buffer-evidence.json)，固定源码 revision 为 `18cfbf9a671fca34785583b58ab9f28e3be21a3c`。该探针已实际编译/运行并复现新 Box–Muller 缓冲未被读取的问题，不是完整 HIBE 复现或统计分布验收；生产补丁未准入。后续完整复现仍须核对匿名适配、依赖和全算法测试。

## 3. IBS：11 条路线

| ID / 算法 | 假设与模型/固定密钥条件 | 原文与参数状态 | 实现及接入状态 |
|---|---|---|---|
| `luo-matrix` — Luo 2024 矩阵 IBS | SIS 主定理，经典 ROM；公开主密钥关系还须筛查 LWE 式恢复路径；固定身份服务条件单列 | [原文](../papers/2024_ibs_without_trapdoors_luo.pdf) §3；现有参数网格未通过完整筛查，[扩参暂停决策](research/2026-10-11/IBS版本决策-模格版主线.md) | **可运行研究后端，当前暂缓扩参**。[luo.py](../src/ibme/ibs/luo.py)、[矩阵参考](../src/ibme/ibs/luo_reference.py)保留；不能为填“纯 SIS”一栏恢复不合格参数 |
| `luo-module` — Luo 2024 模格 IBS | MLWE + MSIS，当前按经典 ROM 条件引用；不自动升级 QROM。固定身份与重复签名语义需对应论文 | 同一原文 §4 Algorithms 13–16；[专属契约](specs/luo-ibs.md)。外部已交有明确前提的总中止界及研究候选；引用条件与正式参数尚未全部准入 | **可运行研究后端，Luo 当前主线**。[模块实现](../src/ibme/ibs/luo_module.py)、[compact codec](../src/ibme/ibs/luo_module_codec.py)及教学 HIBE 完整接线已有；两个格式不是两个 IBS。外部新提交/实验见[项目状态](PROJECT_STATUS.md) |
| `srgg2025` — Jia 等 SRGG 椭球 G+G IBS | MLWE/MSIS 及底层 sEUF-CMA 条件；论文 QROM 结论有前提，不能由代数测试继承 | [12 页完整稿](../papers/2025_efficient_ibs_jia.pdf)已取得；原稿宽度记号、ζ 尺度、q/Q/2Q 和底层条件仍待处理 | **已有组件**：公开关系、HNF 重建、协方差及[有限误差高斯 gadget](research/2026-10-10-srgg-sampling/README.md)。缺完整扰动卷积、XOF/哈希、固定身份服务和 Sign/Verify；未取得作者 C 原型 |
| `yu2026` — Yu–Liu–Li 标准模型 IBS | SIS + PRF；若选 LWE-PRF 须额外记录 LWE。原文有固定密钥服务模型；实现适配仍需核对 | [26 页完整稿](../papers/2026_ibs_ibme_yu.pdf)已取得；§3.1 游戏、Figure 5/Theorem 3 已定位，无有限完整配置 | **已有同态组件**：[gadget/NAND/匹配电路参考](../experiments/research/candidates/yu/homomorphic_reference.py)、[独立证据](research/2026-10-10-yu/README.md)。未实现真实 PRF、完整范数增长、委派/采样或 IBS 后端 |
| `sageloli-sis` — Sageloli 等矩阵 IBS | SIS，论文 ROM/QROM 路线；安全游戏 OSign 每次 KeyExt，与长期固定身份密钥服务的对应待核 | [73 页 HAL 完整稿](../papers/2023_shorter_faster_ibs_sageloli.pdf) §5/§6、Figure 5/6、Table 2；复合模数 `q=3^k` 参数未准入 | **仅候选与参数计数**。未核得作者完整实现；复合模数陷门与 SampleD 须先实现单体，不能套现有素数域工具 |
| `sageloli-rsis` — Sageloli 等 Ring-SIS IBS | Ring-SIS，论文 ROM/QROM 路线；固定密钥游戏缺口与矩阵条目分别处理 | 同一原文 §7、Figure 7/8、Table 4、Appendix E；[单位账本](research/2026-10-10-foundations/sageloli-units.json)保留原标签与 bit/byte 换算 | **仅候选与环基础**。原文部分实例签名为 MB 量级；尚无真实 wire 或 IBS，不预设能装入当前 64 KiB 载荷 |
| `foo-li` — Foo–Li 固定种子 IBS | SIS；原文 ROM/QROM，项目修复只按经典 ROM 条件分析。身份/用户种子、固定随机带与腐化语义必须一起对应 | [原文](../papers/2023_tightly_secure_ibs_foo.pdf)、[条件归约与修复路线](research/2026-10-04-round7/FooLi经典ROM证明补全与修复路线.md)；有限参数与安全准入未完成 | **已有研究生命周期**：[runtime reference](../experiments/research/foo_li_runtime_reference.py)。不是共同 IBSBackend；不得把 `sign_raw` 或旧教学配置登记为完整安全 Sign |
| `wang-pw` — Wang 基本 IBS + Pan–Wagner 转换 | SIS；基本 IBS 仅非自适应，转换/固定密钥服务按经典 ROM 条件核验；两个盐本身不是安全证明 | [Wang 原文](../papers/2022_identity_matchmaking_wang.pdf)、[PW 原文](../papers/2021_short_ibs_pan.pdf)、[固定服务审查](research/2026-10-04-round3/Wang与PanWagner固定密钥接入审查.md) | **仅完整转换候选**。已有教学 SIS 不等于转换后的自适应 IBS；真实原像、有限参数、状态与公开适配仍缺 |
| `cert-ml-dsa` — BNN 认证转换 + ML-DSA | 底层 ML-DSA 模格假设及通用转换条件；具体模型、多用户/腐化与查询损失须映射，不自动继承完整 IBS 的 QROM 或安全等级 | [BNN 重述/通用构造](../papers/2006_generic_ibs_galindo.pdf) §3/Theorem 1、[FIPS 204](../papers/2024_ml_dsa_fips204.pdf)有确定底层参数；转换后对象/参数未冻结 | **有普通签名外部源码，完整 IBS 未实现**。保留原条目，不另增“BNN-ML-DSA”；须实现机构证书、用户公钥/消息签名、固定身份状态与严格解析 |
| `cert-falcon` — BNN 认证转换 + Falcon | Falcon 为 NTRU 结构格上的 SIS 签名，再加转换条件；不把 NTRU 当成与 SIS 完全不相关的保证 | [Falcon v1.2](../papers/2020_falcon_spec_fouque.pdf)及上述转换原文。Falcon-1024 可作工程候选，完整 IBS 未准入 | **有官方普通签名源码，完整 IBS 未实现**。适合独立并行接入；保留原 `cert-falcon`，不另增“BNN-Falcon”。普通签名、转换 IBS、完整 IBME 分别验收 |
| `xie-ntru-ibs` — Xie–Hu–Gao–Gao 原生 NTRU IBS | 原文定义的 NTRU 格 SIS／γ-SVP，经典 ROM 的存在不可伪造声明；Extract 保存同一身份秘密。组合前提仍需逐项核验 | [8 页官方 PDF](../papers/2016_ntru_ibs_xie.pdf)已归档；§3 四算法及表2数值可读，但模数/可逆性文字有需澄清差异，不能直接冻结参数 | **新增候选，尚无本库后端**。[来源与代码核验](research/2026-10-11-catalog/ntru-ibs-sources.md)未确认原作者 IBS 实现；已取得 DLP 上游 IBE/陷门参考代码，不是本方案代码 |

### 已有组件的具体边界

SRGG [第二轮记录](research/2026-10-10-srgg-sampling/README.md)包含真正有限误差离散高斯 gadget 和小环重建，而完整 SampleP/签名分布仍未完成。Yu [记录](research/2026-10-10-yu/README.md)包含同态等式与电路，不含实际 PRF 和完整签名。两者不能再写成“只有论文”，也不能写成“完整 IBS 已实现”。

Sageloli 的 [计数工具](../experiments/research/sageloli_parameter_units.py)纠正 bit/byte 阅读口径；附录计数不是序列化实测。固定发钥服务的适配问题并不因原文标题含“tight / QROM”而消失。

### Sageloli 作者代码再检索（2026-10-11）

本次重新查了精确题名、作者名与 GitHub 组合检索，并检查 [ePrint 2023/489](https://eprint.iacr.org/2023/489)、[Méaux 作者出版页](https://pierrickmeaux.com/index.php/publications/)和 [Pébereau 的 LIP6 出版页](https://www.lip6.fr/actualite/personnes-fiche.php?ident=P1750)。检查到的入口提供论文或出版记录，未确认该 IBS 的作者完整源码；Pébereau 个人主页本次读取失败。这是有范围的检索结果，不是源码不存在的证明。仓库已有完整 PDF 和参数计数工具，后者不替代作者 IBS 实现。

### 可复用的普通签名源码

- **Falcon**：[官方参考源码入口](https://falcon-sign.info/impl/falcon.h.html)列出 `keygen.c`、`sign.c`、`vrfy.c`、`codec.c`、`test_falcon.c` 及 Makefile；API 明确支持 COMPRESSED/PADDED/CT 格式。保密载荷场景需按用途选择格式并实测完整 IBS，不能只比较裸 Falcon 签名。本轮未编译或运行。
- **ML-DSA / Dilithium**：[作者官方仓库](https://github.com/pq-crystals/dilithium)有 `ref/`、`avx2/`、测试与 Makefile；README 指向 FIPS 204。接入时仍须固定提交，并核对所选版本与 FIPS 204 的算法、编码、上下文和测试向量，不能默认任意历史 Dilithium 版本都等同 ML-DSA。本轮未编译或运行。

## 4. 现在怎么分配模块

以下是基于已存代码和明确缺口的实施建议，不是速度、安全等级或最终三套的排名。

| 工作包 | 直接可做的内容 | 该包不能替代的工作 |
|---|---|---|
| 共同框架 | 已实现独立选择/装配、能力与容量预检、组合测试驱动；新增算法复用[公共入口](FRAMEWORK_USAGE.md)，三位队员按[分工文件](workplans/三人方案分工与统一框架交付.md)认领 | 不把装配成功写成新密码算法或正式安全组合 |
| CHKP + Luo 各自推进 | 保留现有 owner；CHKP 补真实参数/采样及公开后端，Luo 补自身参数与条件，同时准备接线 | 当前真实研究接线仍是教学 ABB10 + Luo；Luo 模格不是纯 SIS |
| BNN 转换共享实现 | 一份机构认证/固定身份状态/三元组编码框架，分别接 ML-DSA 和 Falcon，做替换攻击和完整容量测试 | 两种普通签名 KAT 不等于 IBS 或 IBME 验收；共享代码不默认共用秘密密钥 |
| 环 HIBE | 先利用 LATTE 已确认源码做有限两层复现；并行核对匿名条件和 Lai 原稿 | 无匿名依据时只能报告 HIBE 工程对照，不能接入后宣称 Wang 组合安全 |
| 环 SIS / 原生 NTRU IBS | Sageloli 先核固定服务、有限参数与载荷；Xie 路线先按新原稿提取四算法和参数 | 不能拿 SRGG 的 MLWE/MSIS 填 Ring-SIS，也不能把 Falcon 直接称原生 IBS |
| 已有组件与模型储备 | SRGG、Yu、Foo–Li按精确未完成单元认领；GKR、标准模型变体、Zhang 保留模型/语义核验 | 一个候选阻塞不暂停其它独立模块；不重新实现已有组件凑进度 |

每个组合单独填 `HIBE 算法/假设`、`IBS 算法/假设`、参数、包装、模型、实现/安全状态。尤其 **CHKP + Luo 模格 = 普通 LWE HIBE + MLWE/MSIS IBS**；复用 CHKP 配 Falcon 转换能增加 IBS 和完整组合种类，不增加 HIBE 算法数。环、模、NTRU结构的覆盖如实报告，按真实组合结果再选最终三组。

## 5. 更新与来源

- 原 17 条 ID 保持可追溯：[目录 JSON](research/2026-10-10-foundations/catalog.json)、[基础卡](research/2026-10-10-foundations/候选基础卡与队友接手任务.md)。其中旧“下一步”按[当前状态](PROJECT_STATUS.md)执行，不重新成为全项目任务排序。
- 论文获取以[论文库](../papers/index.md)及文件指纹为准；旧抓取失败记录不能覆盖后来已取得的 GKR/Yu/SRGG 全文。
- 新增 Lai 与 Xie 两项已有本日来源记录：Xie 官方 PDF、Lai 用户提供的 18 页 PDF 均已归档；完整代码和参数不因文献取得自动视为可用。
- 目录更新不改变安全标记：当前相关研究实例保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`，实际可执行的研究任务仍可按 G-run 推进。
