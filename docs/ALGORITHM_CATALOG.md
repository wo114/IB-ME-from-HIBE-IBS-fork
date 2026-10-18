# HIBE / IBS 算法与候选总表

更新：2026-10-15（补A的真实ABB默认接入、结构化MP12 H/G变体与12组合，C1/C2框架实跑及CR资格；其它条目保留各自核验范围）。按[统一框架](../ARCHITECTURE.md)分别管理 HIBE、IBS 模块，再装配兼容组合。本文登记 **19 条候选/模型路线：8 条 HIBE、11 条 IBS**，覆盖原[17 条基础目录](research/2026-10-10-foundations/catalog.json)及新补充的两条原生路线；这不是 19 个完整后端，也不是 19 个不同困难假设。

当前任务和外部包进度以 [PROJECT_STATUS.md](PROJECT_STATUS.md) 为准；本文用于选模块、找原文与代码、识别接入缺口。**最终三组完整组合尚未锁定，第三套 HIBE 不再强制属于 Module-LWE。** 普通签名转换成 IBS 的两个条目保留原 ID，BNN-Falcon / BNN-ML-DSA 不再重复计数。

> 2026-10-18 状态：路线、来源与接口信息继续有效；10-15 之后的完成状态（Sageloli 完整后端 PR34、SRGG 默认/structured/paper 三档与持久服务 PR37、CHKP 出版版目标 PR38 等）以 [PROJECT_STATUS](PROJECT_STATUS.md) 的模块表和实现证据为准。本表的逐条状态标记未全部重刷，读到“已有组件/仅候选”时先核对该模块的最新交付。

## 1. 如何读这张表

| 状态 | 本文含义 |
|---|---|
| 可运行研究后端 | 本地有真实算法和公开接口/生命周期，可用于标明限制的研究测试；不表示正式安全准入 |
| 已有组件 | 有实际代数、采样、状态或生命周期代码；尚缺完整原语或共同接口 |
| 有外部源码 | 核实作者/官方仓库存在；本项目未编译、接入或复跑的部分明确列出 |
| 仅候选 / 模型对照 | 有原文、算法映射或计数材料，未实现完整后端 |
| 暂缓 | 有具体参数、语义或模型问题，保留证据及已有代码，不从比较资料删除 |

“全文已取得”“有数值参数”“代码存在”“实跑通过”“满足组合前提”分别记录。除非单列外部来源，表中实现状态均指当前仓库；本次新增LATTE公共组合、系统随机CLI与原状态安装恢复；CHKP等旧批次保留其原版本范围，不累加为本轮实跑。

A本批另完成[默认ABB与结构化H/G](research/team-a-delivery/2026-10-15-framework-and-structured/README.md)：`abb-rom` 与 `mp12-structured-hg` 分别执行六种IBS共同验收，共12配置404检查；新结构化profile属于CHKP-ROM路线下明确区分的MP12实现选择，**不新增论文算法、路线或困难假设计数**。CLI与安装证据区分ABB每次新解密256个原像和结构化固定叶零熵恢复。两组参数均可公开攻击；三条GKR/标准模型储备按用户要求暂缓，不新增后端或验收结论。

## 2. HIBE：8 条路线

| ID / 算法 | 假设与论文模型 | 原文与参数状态 | 实现及接入状态 |
|---|---|---|---|
| `abb-rom` — ABB10 CRYPTO 固定维度 HIBE | 普通 LWE，经典 ROM；匿名/两层条件按选定算法映射 | [18页作者稿](../papers/2010_lattice_basis_delegation_agrawal.pdf)、[算法核验](research/2026-10-04/ABB10两层HIBE算法与参数规范.md)；BasisDel/SampleR等已有真实研究实例，正式宽度/归约与困难参数未准入。 | **独立完整研究HIBE及默认框架接入已实现**：[abb_rom](../src/ibme/hibe/abb_rom/)、[原整链/2×2](research/team-a-delivery/2026-10-14-abb-complete/README.md)、[默认CLI/六种IBS组合与安装](research/team-a-delivery/2026-10-15-framework-and-structured/README.md)。旧abb10.py仍是另列教学实现。当前q26/n1可公开恢复消息，none/false/false；正式参数/整体条件化及失败界仍待。 |
| `chkp-rom` — CHKP 两层匿名 ROM HIBE | 普通 LWE，经典 ROM；adaptive-identity IND-CPA 与跨层匿名填充分开映射，固定同址解封装状态是具体条件 | [作者全文](../papers/2010_bonsai_trees_cash.pdf) §5.1–5.3；[当前交接](research/team-chkp/README.md)。[出版版核验](research/team-a-delivery/2026-10-17-chkp-published-target/README.md)确认深度2定理使用`2m`，现作者稿/后端使用`3m`全LWE叶，不能直接继承；当前n=2实例也已被公开数据唯一恢复seed | **可运行研究后端，真实统一组合和CLI验收已通过**：[六方法与对象](../src/ibme/hibe/chkp/__init__.py)、[契约](specs/chkp-hibe.md)。MP12根转完整基、原CHKP RandBasis、四个真实叶各256目标/32 B seed；已接入Luo C64B compact + Hybrid + BYTEAUTH。[12阶段收据](research/2026-10-12-chkp-closure/README.md)保留根父复用与原失败来源。n6144/q80仅为完整数值目标，出版版路线、正式困难参数、资源和组合安全仍未准入；独立[first_suite DelTrap](research/2026-10-11-first-suite-compact/README.md)继续作为不同算法profile对照 |
| `latte` — LATTE NTRU/RLWE HIBE | NTRU 结构陷门与 Ring-LWE 密文路线；完整定理依赖待逐项对应。IND-CCA 标签不能代替匿名性 | [作者接受稿](../papers/2024_quantum_safe_hibe_zhao.pdf)、固定作者代码`18cfbf9`；保留原LATTE-3数值，接收者匿名性及修订后分布/模型未准入。 | **独立研究HIBE已实现**：[六方法/五类对象](../src/ibme/hibe/latte/__init__.py)、[契约](specs/latte-hibe.md)、[C1交付](research/team-c-delivery/2026-10-14-latte-hibe/README.md)。真实N1024/q68718428161同根两次Delegate、四叶、32 B带噪声、2×2与恢复通过；COSAC缓冲修复保留原版差异。[默认登记/CLI、10配置338检查与原状态安装复放](research/team-c-delivery/2026-10-15-c-framework/README.md)已通过；匿名/采样总误差/正式参数仍none/false/false。 |
| `gkr2025` — Goyal–Koppula–Rajasree 自适应 HIBE 编译器 | 标准模型论文路线；一般编译器依赖 PKE、OTSE、garbling、可委派 PRF；匿名 LWE 扩展另含 lockable obfuscation | [34 页用户完整稿](../papers/2025_adaptive_hibe_goyal.pdf)已取得；已定位 §3/Theorem 3.1 与匿名扩展。无本项目有限参数闭环 | **仅候选，复杂编译器储备**。无完整后端；须先明确匿名扩展和电路/对象规模，不能简化成一套普通矩阵公式 |
| `zhang2020` — Zhang 等理想格 HIBE | Ring-LWE、原文Theorem5标准模型IND-ID-CPA；匿名性映射未建立 | [19页原文](../papers/2020_ideal_lattice_hibe_zhang.pdf)PDF5/10—12；[CR资格表](research/team-c-delivery/2026-10-15-zhang-qualification/README.md)固定PDF指纹与类型/条件；[2026-10-18 实施判定](research/team-c-delivery/2026-10-18-zhang-implementability/README.md)逐页渲染核对 | **原文不足以实施HIBE**：Extract/Derive 输出短原像而 Decrypt 当作格陷门，深度1即断；SK 打印 `2m` 与 `(l+1)m` 冲突；归约只对 `l=1` 自洽；Theorem 2／4 的 `q ≤ …` 方向反。未实现后端，不自行补造 Derive |
| `abb-standard-selective` — ABB 标准模型选择性 HIBE | 普通 LWE，标准模型选择性身份；§7 自适应 IBE 不等于 §8 自适应 HIBE | [40 页作者稿](../papers/2010_lattice_hibe_standard_agrawal.pdf) §8/Theorem 33；参数条件待独立实例化 | **模型对照**。没有完整后端；不能直接登记为满足当前自适应匿名组合前提 |
| `chkp-standard` — CHKP §5.4 变体 | LWE 及可容许哈希条件，标准模型条件路线；匿名扩展范围另核 | [同一 CHKP 原文](../papers/2010_bonsai_trees_cash.pdf) §5.4/Theorem 5.4/Corollary 5.5；额外维度与归约成本未闭合 | **模型对照**。不能用 ROM 实现切一个开关就算消除随机预言机；不与 `chkp-rom` 参数共用结论 |
| `lai-ideal-hibe` — Lai–Cheung–Chow，理想格陷门 HIBE | 原文 PLWE 与 INDr-ID-CCA 声明含收件人匿名性；选读 §5.1–5.2/定理10，尚需具体两层模型映射 | Inscrypt 2014／出版2015；[18 页 PDF](../papers/2015_ideal_lattice_trapdoors_lai.pdf)由用户提供并原样归档，标题/作者已核。符号参数不能直接当有限可运行配置 | **资格核验WIP，非HIBE实现**：[精确非单位/委派类型反例与15项无skip测试](research/team-c-delivery/2026-10-15-lai-qualification/README.md)。标签单位域、Algorithm7/9类型及两层公开参数仍需澄清，未自行补造Derive；通用lattice_lib不是作者HIBE。 |

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
| `luo-module` — Luo 2024 模格 IBS | MLWE + MSIS，当前按经典 ROM 条件引用；不自动升级 QROM。固定身份与重复签名语义需对应论文 | 同一原文 §4 Algorithms 13–16；[专属契约](specs/luo-ibs.md)。外部已交有明确前提的总中止界及研究候选；引用条件与正式参数尚未全部准入 | **可运行研究后端，Luo当前主线**。[模块实现](../src/ibme/ibs/luo_module.py)、[compact codec](../src/ibme/ibs/luo_module_codec.py)已有；显式C64B compact与真实CHKP/Hybrid/BYTEAUTH的完整接线和CLI已通过，教学HIBE接线保留为历史对照。两个格式不是两个IBS；参数与实跑边界见[项目状态](PROJECT_STATUS.md) |
| `srgg2025` — Jia 等 SRGG 椭球 G+G IBS | MLWE/MSIS及底层sEUF-CMA条件；原文QROM结论不能由功能测试继承 | [12页缓存原稿](../papers/2025_efficient_ibs_jia.pdf)；主噪声按Table3，签名采用明确ζ一致factor2解释，未宣称作者勘误 | **完整研究IBS已实现**：[五方法/真实采样/固定缓存与恢复](research/team-b-delivery/2026-10-13-srgg-full/README.md)。32次真签验及恢复通过；默认已登记，本轮LATTE公共组合34检查通过。n8挑战仅8bit、公开固定点伪造可行；连续数值总误差、HNF分布、强结论及正式参数仍未准入 |
| `yu2026` — Yu–Liu–Li 标准模型 IBS | SIS+PRF；选LWE-PRF需额外记录LWE；固定服务、NC1/Lemma7和正式参数待核 | [26页原文](../papers/2026_ibs_ibme_yu.pdf)Figure5/Theorem3；[条件审计](research/team-b-delivery/2026-10-15-yu-backend/CONDITIONS.md) | **独立共同IBSBackend已合入PR28**：[完整五方法/对象/issuer交付](research/team-b-delivery/2026-10-15-yu-backend/README.md)。定向550项Sage通过；q3公开可伪造，1—4 B输入容量由descriptor明确阻止Wang组合；默认登记和正式准入待办 |
| `sageloli-sis` — Sageloli 等矩阵 IBS | SIS，论文 ROM/QROM 路线；安全游戏 OSign 每次 KeyExt，与长期固定身份密钥服务的对应待核 | [73 页 HAL 完整稿](../papers/2023_shorter_faster_ibs_sageloli.pdf) §5/§6、Figure 5/6、Table 2；复合模数 `q=3^k` 参数未准入 | **已有真实采样数学探针**：[三进制陷门／全局扰动／8列委派／一次签名原像／宽度核验](research/team-b-delivery/2026-10-13-sageloli-probes/README.md)。H1/H2、盐、对象、五方法及恢复仍待；调试norm过弱，不计完整IBS或安全后端 |
| `sageloli-rsis` — Sageloli 等 Ring-SIS IBS | Ring-SIS，论文 ROM/QROM 路线；固定密钥游戏缺口与矩阵条目分别处理 | 同一原文 §7、Figure 7/8、Table 4、Appendix E；[单位账本](research/2026-10-10-foundations/sageloli-units.json)保留原标签与 bit/byte 换算 | **已有环真实采样数学探针**：[结构CBD／9个多项式列委派／Schur数值扰动／签名原像](research/team-b-delivery/2026-10-13-sageloli-probes/README.md)。总TV、对象／完整IBS和真实wire仍待；原文MB计数不当实测，不预设当前载荷可装入 |
| `foo-li` — Foo–Li 固定种子 IBS | SIS；原文ROM/QROM，项目修复只按经典ROM条件分析；固定随机带/腐化语义待闭合 | [原文](../papers/2023_tightly_secure_ibs_foo.pdf)、[条件归约](research/2026-10-04-round7/FooLi经典ROM证明补全与修复路线.md) | **独立共同IBSBackend已合入PR27**：[五方法/四对象/固定服务交付](research/team-b-delivery/2026-10-15-foo-li-backend/README.md)。定向294项Sage通过；q3公开伪造/上下文负控保留；默认registry、实际HIBE组合及正式准入待办，none/false/false |
| `wang-pw` — Wang 基本 IBS + Pan–Wagner 转换 | SIS；基本 IBS 仅非自适应，转换/固定密钥服务按经典 ROM 条件核验；两个盐本身不是安全证明 | [Wang 原文](../papers/2022_identity_matchmaking_wang.pdf)、[PW 原文](../papers/2021_short_ibs_pan.pdf)、[固定服务审查](research/2026-10-04-round3/Wang与PanWagner固定密钥接入审查.md) | **已有完整研究签名链**：[B交付](research/team-b-delivery/2026-10-13-wang-pw/README.md)、[真实MP12采样/转换/五方法/规范恢复](../experiments/research/candidates/wang_pw/)。q17调试档可公开伪造，正式参数、固定服务安全映射、默认registry/安装和真实HIBE配对仍待；不是旧教学SIS加两个盐 |
| `cert-ml-dsa` — BNN 认证转换 + ML-DSA | 底层 ML-DSA 模格假设及通用转换条件；具体模型、多用户/腐化与查询损失须映射，不自动继承完整 IBS 的 QROM 或安全等级 | [BNN 重述/通用构造](../papers/2006_generic_ibs_galindo.pdf) §3/Theorem1、[FIPS204](../papers/2024_ml_dsa_fips204.pdf)；[严格转换契约](specs/certified-ibs.md) | **完整独立IBS已实现**：[C2交付](research/team-c-delivery/2026-10-14-cert-mldsa/README.md)，五方法、机构证书/用户公钥/消息签名、固定身份/pending、严格恢复及可选BackendSpec。246项专项含210官方向量；三个参数的同根双用户/新签名/零熵恢复与安装通过。[默认登记、真实LATTE三档配对/CLI及原状态安装恢复](research/team-c-delivery/2026-10-15-c-framework/README.md)已通过；强UF/量子模型和正式准入待办；三参数不计三算法 |
| `cert-falcon` — BNN 认证转换 + Falcon | Falcon 为 NTRU 结构格上的 SIS 签名，再加转换条件；不把 NTRU 当成与 SIS 完全不相关的保证 | [Falcon v1.2](../papers/2020_falcon_spec_fouque.pdf)及上述转换原文；固定作者20211101源码与round3 KAT，不等同FN-DSA/FIPS206 | **完整独立IBS已实现**：[C2交付](research/team-c-delivery/2026-10-14-cert-falcon/README.md)，共用原转换核心，512/1024各有独立格式/ID、固定服务、严格恢复与可选descriptor。237项无skip含200官方向量/Gaussian自检；两档实物/恢复/隔离安装通过，完整签名2322/4447 B。[默认登记、真实LATTE两档配对/CLI及原状态安装恢复](research/team-c-delivery/2026-10-15-c-framework/README.md)已通过；强UF/量子/正式准入仍待，none/false/false；两参数不计两算法 |
| `xie-ntru-ibs` — Xie–Hu–Gao–Gao 原生 NTRU IBS | 原文定义的 NTRU 格 SIS／γ-SVP，经典 ROM 的存在不可伪造声明；Extract 保存同一身份秘密。组合前提仍需逐项核验 | [8 页官方 PDF](../papers/2016_ntru_ibs_xie.pdf)已归档；§3 四算法及表2数值可读，但模数/可逆性文字有需澄清差异，不能直接冻结参数 | **原稿冲突已可执行核验，新增修订研究核，非共同后端**：[C3交付](research/team-c-delivery/2026-10-15-xie-study/README.md)含真实NTRU/GPV/拒绝链、严格对象/纯公开验签、53项无skip、两档系统随机/恢复/安装。单位/基坐标/GPV修订明确命名；教学参数有公开伪造，不继承原稿安全定理，不登记IBSBackend或HIBE组合，none/false/false。 |

### 已有组件的具体边界

SRGG和Yu的2026-10-10记录只覆盖当时的采样/同态组件，保留为历史证据。后续SRGG已补完整研究五方法，Yu与Foo–Li也已交共同五方法、对象和固定服务；当前实现范围按上表及各自最新交付，正式参数/模型和公共接入分别判断。

2026-10-13 SRGG新增真实相关扰动/提取组件；原始近似方程与HNF精确方程分别验收。分布参考替代、literal SampleF、重建后的key分布及完整IBS仍分开判断，详见B交付。

同日后续完整SRGG实现已接入数值连续Gaussian/固定r随机舍入、原文下块与上块Schur、XOF/挑战和完整签验；组件历史范围不被覆盖，当前新增完整范围见上述独立交付。

Sageloli 的 [计数工具](../experiments/research/sageloli_parameter_units.py)纠正 bit/byte 阅读口径；附录计数不是序列化实测。固定发钥服务的适配问题并不因原文标题含“tight / QROM”而消失。

### Sageloli 作者代码再检索（2026-10-11）

本次重新查了精确题名、作者名与 GitHub 组合检索，并检查 [ePrint 2023/489](https://eprint.iacr.org/2023/489)、[Méaux 作者出版页](https://pierrickmeaux.com/index.php/publications/)和 [Pébereau 的 LIP6 出版页](https://www.lip6.fr/actualite/personnes-fiche.php?ident=P1750)。检查到的入口提供论文或出版记录，未确认该 IBS 的作者完整源码；Pébereau 个人主页本次读取失败。这是有范围的检索结果，不是源码不存在的证明。仓库已有完整 PDF 和参数计数工具，后者不替代作者 IBS 实现。

### 可复用的普通签名源码（原目录调查，后续实现见上表）

- **Falcon**：[官方参考源码入口](https://falcon-sign.info/impl/falcon.h.html)列出 `keygen.c`、`sign.c`、`vrfy.c`、`codec.c`、`test_falcon.c` 及 Makefile；API 明确支持 COMPRESSED/PADDED/CT 格式。原目录调查未编译；后续C2已固定v1.2并完成原生KAT、完整认证IBS和本轮LATTE组合。完整尺寸按交付收据，不能只比较裸签名。
- **ML-DSA / Dilithium**：[作者官方仓库](https://github.com/pq-crystals/dilithium)有 `ref/`、`avx2/`、测试与 Makefile。原目录调查未编译；后续C2已固定具体源码及FIPS204对应/KAT，再完成认证IBS和本轮LATTE组合。不能默认任意历史Dilithium版本都等同ML-DSA。

## 4. 现在怎么分配模块

以下是基于已存代码和明确缺口的实施建议，不是速度、安全等级或最终三套的排名。

2026-10-12 A 新增[MP12 变体研究后端](research/team-a-delivery/2026-10-12-hibe-reference/README.md)，ID `mp12-chkp-reference`：真实计算型根/DelTrap、六方法和一条 Luo/Hybrid/BYTEAUTH 配对已实跑，[安装、默认可选登记及CLI](research/team-a-delivery/2026-10-12-installed-api/README.md)也已通过。原CHKP研究功能另由PR14完成；两者正式安全准入仍未完成，不自动新增困难假设/原算法计数；n2 参数已被公开攻击，Sage/native依赖、正式维度/资源与变体模型继续核验。

2026-10-12 的具体 owner、P0—P3 顺序、第一批产物与材料责任统一见[三人交付计划](workplans/三人方案分工与统一框架交付.md)。目录中的 19 条均已分配；原生论文路线优先，认证转换为可并行的工程对照，LATTE/Lai 先过匿名/委派核验。全部就绪池做可行配对比较，再选三个报告重点，本文不另发布一套冲突排序。

| 工作包 | 直接可做的内容 | 该包不能替代的工作 |
|---|---|---|
| 共同框架 | 已实现独立选择/装配、能力与容量预检、组合测试驱动；新增算法复用[公共入口](FRAMEWORK_USAGE.md)，三位队员按[分工文件](workplans/三人方案分工与统一框架交付.md)认领 | 不把装配成功写成新密码算法或正式安全组合 |
| CHKP + Luo 研究接线已完成 | 两个独立后端通过同一装配入口完成C64B compact + Hybrid + BYTEAUTH真实验收：组合44项，CLI独立setup 8项/2命令及导入状态59项/15命令；最大应用消息3924 B | 导入CLI复用已生成密钥，不重计根父叶；正式参数、资源和组合归约另行闭合。Luo模格不是纯SIS，n=2 CHKP已有公开唯一seed恢复负控 |
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
