# 研究报告三组代表组合与参数冻结

选择基线：`6f04f2b73f69c96d4e8bea1d161655af39254d70`，2026-10-19。

报告正文固定采用 **A：LATTE＋BNN/ML-DSA-44、B：LATTE＋SRGG PARAM-I compact、C：Lai C2＋Sageloli RSIS v3 PARAM-I**。三组都已有真实完整 IB-ME 运行，统一保留 Hybrid 和 BYTEAUTH。A 用于现场主演示，B 解释原生 IBS 接入，C 解释另一条 HIBE 与环 IBS 的目标规模实现。

这是报告代表的选择，不是三个性能冠军。**目前不能认定三组分别具有已测的性能优势**，尤其 C 的主要价值是结构覆盖与目标规模验证；还没有速度、通信量或多用户优势证据。若作品必须声称“三组各有性能优势”，现有数据不足，不能通过改名补齐。所选三组是 **2 种 HIBE、3 种 IBS、5 个独立原语后端、3 个完整组合**，不写成三种 HIBE；没有新增算法计数。

本交付只完成选型、参数与证据冻结，不重跑密码实验，不改旧作品报告、新报告正文或 PPT。[当前进度](../../PROJECT_STATUS.md)继续发布后续任务；本文件保存本次选择依据。

## 选择理由与代价

| 代表 | 已有证据支持的价值 | 主要代价及适用场景 |
|---|---|---|
| A：LATTE-3＋BNN/ML-DSA-44 | 完整流程有三根重复基准、安装 CLI、跨进程恢复及 Web 实跑；底层普通 ML-DSA 有固定向量覆盖，适合作为可复现的工程基线 | IBS 通过证书转换得到，不算原创原生 IBS；完整系统不因底层标准签名而成为标准认证方案。用于现场交互和共享框架说明 |
| B：LATTE-3＋SRGG 论文 PARAM-I compact | 保持与 A 相同的 HIBE 算法，展示原生 MLWE/MSIS IBS；论文参数已完成完整功能矩阵和三根重复，compact 保留完整数学签名 | 发钥中位数 21.884570 s、warm 加密 7.594920 s；没有 Web 预设。现有安装验收的预算不同，不能继承为本冻结配置的安装通过。用于原生 IBS、参数解释与编码比较 |
| C：Lai C2＋Sageloli RSIS v3 PARAM-I | 真正更换 HIBE；C2 与 v3 论文规模均已实际运行，完整组合的四种身份情形已测；保留结构化环算术而非旧 v2 展开外推 | 解密慢、密钥和密文大，仅单根批次；不适合等待式现场交互。用于结构扩展与资源边界说明，宜预先运行并展示原始收据 |

选择顺序为：真实完整运行、避开已有公开攻击的调试参数、参数与源码可追溯、对报告提供不同解释价值，最后看演示与资源代价。不设主观加权总分，不把不同安全组的速度混排。三组尚未完成相同条件的全套验收，具体欠项见下表。

如果把“控制变量比较”作为唯一目的，A＋B＋Lai C2/ML-DSA 更整齐，但不能同时展示 Sageloli 环 IBS；如果沿用 LATTE/ML-DSA、Falcon、Luo 三组，演示材料最成熟，但仍只有一种 HIBE。本次按工程基线、原生 IBS、另一 HIBE 的报告结构取舍，保留这些组合做辅助对照。

## 冻结的实际配置

完整配置直接从已通过的执行收据复制，没有重新选择默认值：

| 代表与完整 Suite | HIBE 参数 | IBS 参数／格式 | Hybrid 载荷／胶囊预算 | 64 B 身份时应用消息容量上限 |
|---|---|---|---|---:|
| [A-latte-mldsa44.json](suites/A-latte-mldsa44.json) | LATTE-3：N=1024，q=68718428161；seed32；2 个父身份，每父最多 2 个子身份 | cert-ml-dsa，ml-dsa-44；最多 16 个 IBS 身份；reference | 64 KiB／4 MiB | 59,191 B |
| [B-latte-srgg-I-compact.json](suites/B-latte-srgg-I-compact.json) | 同 A | srgg2025-paper，PARAM-I；n=512、rank=2、p=16383、base=31、digits=2、Q=15744063、γ=42086491.7；factor1、table-standard-deviation；compact | 128 KiB／4 MiB | 65,364 B |
| [C-lai-c2-sageloli-I.json](suites/C-lai-c2-sageloli-I.json) | Lai C2：n=2048、q=274877976577、k=39、l=2、p=2、σ=2、σr=1；seed32 | Sageloli RSIS v3 PARAM-I：d=2048、k=65、l=132、q=3^65；reference | 8 MiB／4 MiB | 3,924 B |

容量上限是公共装配层的保守计算，不表示已经逐个长度实跑。外部身份上限都是 64 B，Hybrid 内层身份为 86 B，HIBE 加密的 seed 恰为 32 B。所引性能批次的应用消息都是 32 B；8 MiB 是 C 的内部明文载荷预算，不能写成应用消息上限。LATTE 固定数学版本为 `IBME/LATTE3/COSAC-FIX/1`，Suite 内后端版本为 `latte3-cosac-fix-v1`，两个标识不混用。

SRGG 的采样标准差冻结为主密钥 `2843.9/1023.0`、签名 `843088.2/310891.6`，r=1.16；不自动切换另一种 Gaussian 解释。Sageloli 身份／签名宽度平方为 `2720281532542`／`270116709797628319132317`，r²=49、盐 32 B、最多两个已发身份、签名尝试帽 64、tail/mass bits=256/320。其完整数字参数已在 Suite 中保存。Lai C2 必须显式选择，`lai-a-256-v1` 版本名不表示实际使用 n256。

| 代表 | Suite SHA-256（规范 ASCII JSON） |
|---|---|
| A | `10a23d28bfdf9b2e18b140149561c43d62f2649feb78b72510d350b419233346` |
| B | `37a0d413d5daed2c407c03b4b4f1a1fe4b6454e786e9cea3dfe8676a60ce9c97` |
| C | `9a3c66cfd5073721bf135466197522352010ecbc6a10a6794c710e9b10423c82` |

[selection.json](selection.json)保存三组配置摘要、完整输入／样本口径、由原始 JSON 提取的观测、容量、来源文件哈希和辅助对照。Suite JSON 可由 `ibme.assembly.SuiteConfig.from_dict` 加载；现有 CLI 使用各项选择参数，不能把这些文件当作不存在的 `--suite` 参数传入。

## 可直接引用的观测

| 代表 | 完整加密／解密时间 | 完整密文 wire | 样本及环境 |
|---|---|---|---|
| A | warm 中位数 0.211125／0.280116 s | 142,051—142,146 B | 3 个独立 CSPRNG 根，9 对 warm，9 次恢复后解密；Ultra 9 275HX，Sage 10.9／Python 3.13.14，OMP4／BLAS1 |
| B | warm 中位数 7.594920／0.201444 s | 149,191—149,291 B | 3 个独立 CSPRNG 根，9 对 warm，9 次恢复后解密；i9-14900HX，Sage 10.7／Python 3.12.13，OMP4／BLAS1 |
| C | 单次加密 98.972055 s；单次诚实解密 424.980337 s，含实际委派 393.037574 s | 4,555,436 B | 四个 IBS 组合共享 1 个 HIBE 根与 2 个一级钥，各组独立 IBS 根、各 1 次加密；最多 6 个并发解密进程；Ultra 9 275HX，Sage 10.9／Python 3.13.14，OMP1／BLAS1 |

A、B 每组还有 3 次 cold 加密，各 12 个完整密文尺寸观测；warm 观测共享各自根，不是 9 个独立根。A、B 进程树 RSS 采样最大值分别 480,243,712／506,789,888 B，采样可能漏峰。C 所选诚实解密进程内核生命周期峰值为 1,248,882,688 B；共享准备进程中 Sageloli 恢复阶段进程树采样已达 3,015,589,888 B，不能只用解密峰值表示全流程内存。C 的完整发送者钥为 144,089,680 B，接收者钥为 20,439,584 B。

**此表逐组报告观测，不计算跨组加速比或等安全排名。** C 与 A/B 同时改变算法、预算、线程及样本结构，不能用本表把差值归因到某一个原语。A 已有的运行位置消融属于部署优化，不混入这张算法选择表。

数据入口：[A 基准](../../research/2026-10-18-full-system-baseline/README.md)、[B 基准与功能矩阵](../../research/2026-10-19-srgg-paper-latte/README.md)、[C 四组合收据](../../research/2026-10-19-lai-c2-combinations/README.md)。本批没有重新抽样或执行密钥生成。

## 辅助对照与未选路线

| 路线 | 本次用途／未选入正文三组的理由 |
|---|---|
| LATTE＋BNN/Falcon-512 | 已有完整重复基准、CLI 和 Web；较紧凑的工程备选。与 A 共用 HIBE 和 BNN 转换，放辅助比较，不新增 HIBE 或宣称 NTRU-IBS |
| LATTE＋Luo 模格 default／C64B | 已有完整研究运行与重复基准，可用于原生 IBS 对照；换参数不增加算法数，不从旧默认或较小配置继承目标等级 |
| LATTE＋Sageloli v3 PARAM-I | 已有 15 步 CLI、34 项同根检查及仓库外恢复；作为 C 到 LATTE 的桥接对照。它的安装验收不能代替 C 的安装验收 |
| Lai C2＋ML-DSA／SRGG | 同批已经真实运行，连接 A/B 与 C；仅保持 IBS 算法不变，预算、机器和样本条件仍需核齐，不能直接作纯 HIBE 性能消融 |
| SRGG PARAM-I reference、PARAM-II／III | 前者是签名编码对照，后两者是参数档位，不新增 IBS；六份完整功能配置已有，II/III 尚无同样的多根性能证据 |
| Sageloli PARAM-II | 独立 IBS 已实跑；完整组合和性能验收未由现有材料补齐，不计第二个已测完整目标组合 |
| ABB-ROM／CHKP-ROM | 已有完整研究代码，但现有小参数有公开攻击，目标规模完整组合尚未交付；保留队友在途工作，不能用调试配置占目标代表名额 |
| Wang＋PW、Foo–Li、Yu、Sageloli 矩阵 SIS | 各自研究实现、公共接入、容量和目标参数的状态不同。现有 Wang/PW 小参数和最新数值原型不能充当目标完整 IBS；其余也不能凭组件或参数工具列为已完成的目标完整组合 |
| Zhang／Xie 及暂缓的三条储备 HIBE | 不因本次选型新增完整实现或恢复暂停工作 |

B 的 compact 基准 wire 为 149,191—149,291 B，reference 为 171,097—171,231 B，可以并列报告这两个实际范围。两种格式不是同一随机根的配对样本，不能把计时差写成压缩加速，也不能把格式数写成方案数。

## 验收边界和下一阶段输入

| 代表 | 本冻结配置已有 | 尚未由现有证据完成 |
|---|---|---|
| A | 重复基准；精确配置的 CLI／安装恢复；Web 实跑 | 所选消息长度与边界扫描；同一发布版本的干净环境再现 |
| B | 精确 128 KiB Suite 的 34 项功能检查、三根基准及新进程恢复 | **精确 128 KiB Suite 的安装 CLI/wheel 验收**、Web 衔接、同条件比较及必要长度扫描 |
| C | 精确 C2＋v3 配对；22 项准备检查与 4 项新进程身份检查，共 26 项；四组合计 104 项 | 精确配置安装 CLI/wheel；空消息／必要长度边界；有效外层认证下的内层签名负例；受时间盒约束的重复评测及演示安排 |

SRGG 已有安装 CLI 使用 64 KiB，其摘要是 `ba8894280100ef750ece4f6a4dd7f596983e1804c91f5ecc631749db2ebf72da`，与 B 不同；只记辅助证据。C 的每次解密确实重新执行无缓存 Lai 委派，恢复后委派仍需新熵，不宣称整条解密零熵。C 已有独立 IBS 负例，不把它写成尚未执行的“重封装有效外层／无效内层”实验。

后续实验应围绕这三份 Suite 开展，变更任何参数或预算都另记摘要；仍可接收队友已在途的交付，但只有实跑证据足以改善当前选择时才替换代表。不为凑齐三种 HIBE 启动新的长参数搜索或无界采样。当前选择完成后，下一项是收口上述必要验收与可比较数据，不是宣称最终作品已全部完成。

## 理论引用与参数声明

| 部件 | 报告应分别记录的困难假设／构造 | 依据 |
|---|---|---|
| LATTE HIBE | NTRU 结构陷门、Ring-LWE 密文路线 | [契约](../../specs/latte-hibe.md)与固定作者代码；保留 COSAC 修订及实际采样说明 |
| BNN/ML-DSA IBS | BNN 证书转换条件、底层 ML-DSA 的模块格假设 | [原参数卡](../2026-10-18-main-showcase-cards/README.md)；标准普通签名不自动赋予整个 IBS／IB-ME 标准等级 |
| SRGG IBS | 论文 MLWE/MSIS 与底层签名条件 | [论文参数契约](../../specs/srgg-paper-assembly.md)；factor1 与 Gaussian 解释保持冻结 |
| Lai C2 HIBE | 论文 PLWE 路线 | [契约](../../specs/lai-hibe.md)；二进制身份、Derive 类型解释、Klein/GPV 无 perturbation、非单位 tag 失败及尝试帽均保留 |
| Sageloli RSIS v3 IBS | 论文环 SIS 路线及 ROM/QROM 引用条件 | [v3 契约](../../specs/sageloli-ring-ibs.md)；固定身份服务、有限精度／FFT 采样边界仍按原交付记录 |

这些是逐部件的假设与版本说明，不合并成“三个独立困难假设”或“三种安全等级”。按照用户确认的工作前提，安全性及 HIBE 身份匿名性引用论文并区分工作假设，不新增补充证明任务；实际实现差异和已知失败继续披露。所有配置保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`，不新增 NIST、QROM 或标准模型整体安全声明。未选择已知公开可伪造的调试参数。

## 只读复核

仓库根目录执行，不需要 Sage 或私有状态：

```text
python docs/deliveries/2026-10-19-report-three-selection/verify.py --self-test
```

配置与容量再核对（使用项目 WSL Sage 环境、既有原生引擎及 `PYTHONPATH=src:.`）：

```text
python docs/deliveries/2026-10-19-report-three-selection/verify.py --assembly --self-test
```

`--assembly`只重建配置并检查当前登记／容量；缺少 Sage／原生依赖时明确失败，不跳过容量检查，也不把预检当作实跑。五个负例分别修改算法数、计时、SRGG 预算摘要、C 的重复验收标志和来源哈希，必须全部拒绝。原始运行的 provider／Git 绑定继续由各来源批次自己的校验器负责。

本批实际结果：Windows Python 3.14.0a5 下 [59 项只读检查及 5 个拒绝负例](verification-portable.json)通过；规定 WSL Sage 10.7／Python 3.12.13、既有同源原生引擎与 Hybrid 依赖下，[含装配检查的 68 项及同 5 个负例](verification-assembly.json)通过，三组 `preflight_ok/runtime_available` 均为 true。68 项包含前述 59 项，不能相加计数；预检没有产生新密钥或完整密文。

另重新执行以下原收据校验器，均 exit 0：

```text
python -O docs/deliveries/2026-10-18-main-showcase-cards/evidence/verify.py
python -O docs/research/2026-10-19-srgg-paper-latte/verify.py --historical
python -O docs/research/2026-10-19-lai-c2-combinations/verify.py
python -O docs/research/2026-10-19-sageloli-ring-integration/verify.py
```

分别核对 392 项参数卡、SRGG 原 204 项功能／1824 条基准 provider／154 条安装 provider、Lai 582 项范围／来源、Sageloli 696 项证据。它们复核历史执行记录，不是本批重跑这些密码实验。此次修改范围为本目录交付文件，以及 `docs/PROJECT_STATUS.md`、`docs/ALGORITHM_CATALOG.md` 的选择入口；未改运行算法或默认参数。
