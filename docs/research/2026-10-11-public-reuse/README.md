# 公开代码复用：qFALL 完整基、CHKP 扩展与原生 GPV 试验

日期：2026-10-11。用户要求先看目前进展，再找公开实现并结合推进。本轮已审阅合并 PR #7 的最终六份 IBS 决策/证据文档，并实际接通公开组件的研究路径。完整 CHKP/IBME、安全参数和生产入口仍为 WIP。

## 已有进展与本轮解决的具体问题

基点 `8a1099f` 已接通 AP09 根—父级 RandBasis—叶原像—32bit缓存；两种教学输入的128个原像方程通过，但真实噪声196/384个bit错误，256位置仍拒绝。此前“当前192维门槛下参数空交集”针对现有有限实现/充分条件，不是CHKP理论不可能。

本轮保留该参考路线，建立明确独立的 `SAGE-DGS-PUBLIC-COMPARISON/1`：

```text
公开固定测试流生成 A_bar、R
  → qFALL 原版 gadget 与 MP12 完整短基转换
  → Sage 独立核验 A·B=0、det(B)=q^n及GS
  → 已交付 CHKP ExtBasis
  → 原生GPV抽零原像、选满秩向量、已交付 ToBasis
  → 独立精确核验的Sage LLL、终层 ExtBasis
  → Sage原生整数Gaussian，抽256个不同位置的原像
  → 真实连续Gaussian取整噪声，核对共享前导位相位
```

它实际复用公开代码与现有工作；没有修改队友`chkp_*`算法、原有限采样器192维/10^12/随机带/32缓存上限、生产HIBE/IBS/协议或CLI。新原生比较范围明确限制256维/256位置，旧参考对不适配输入的拒绝保留。256位置是新比较批次，**没有调用或冒充旧FixedLeafCache，也没有形成可恢复密钥/wire**。

## 公开实现核对与采用决定

| 代码 | 核对与复用结论 |
|---|---|
| [qFALL-tools](https://github.com/qfall/tools)，[论文2026/069](https://eprint.iacr.org/2026/069) | 固定Git提交`b8eb4842fb80c36f7f3494930ea316472cb75793`；MPL-2.0。提供MP12 G-trapdoor、完整短基转换、GPV/扰动原像函数。实际通过公开API复用gadget和`gen_short_basis_for_trapdoor`；原库代码未修改。它是原语工具集，未确认提供完整CHKP HIBE |
| [Sage整数DGS](https://doc.sagemath.org/html/en/reference/stats/sage/stats/distributions/discrete_gaussian_integer.html) / [GPV文档](https://doc.sagemath.org/html/en/reference/stats/sage/stats/distributions/discrete_gaussian_lattice.html) | 本机Sage10.9已有编译实现。本轮使用整数采样API，配精确列基GPV；原始整数DGS文件含BSD许可声明，Sage整体及依赖许可保留。`uniform+online`、MPFR192、tau12；没有复制或修改Sage源文件 |
| [LATTE](https://github.com/cqs-technology/latte) | MIT，论文对应C工程，固定提交`18cfbf9a671fca34785583b58ab9f28e3be21a3c`。其通用COSAC标量代码存在实际缓冲区问题，已复现；本轮隔离为审计来源，不采用该函数作采样后端。完整LATTE、匿名适配及性能仍未在本机验收 |
| [HIBE-Gaussian-Sampling](https://github.com/jnortiz/HIBE-Gaussian-Sampling) | 核对默认及master的HIBE头文件：Setup/IdealTrapGen与采样研究，没有完整委派/加解密接口；未确认明确整体许可。本轮没有复制或编译它 |
| [qFALL-schemes](https://github.com/qfall/schemes) | 有DualRegev IBE等原型，公开清单未给完整HIBE；保留工程参考，单层IBE不计完整CHKP |
| [samkumar/hibe](https://github.com/samkumar/hibe) | README明确为Boneh–Boyen–Goh方案的Go实现，属于双线性配对路线，不计格基CHKP候选 |

本轮检索范围为论文入口、GitHub仓库与源码；尚未确认可以直接接入的完整CHKP匿名HIBE成品，不将检索未发现写成所有公开渠道均不存在。原型复用与论文安全定理适用性分别核验；有许可和源码也不自动安全。

## 同组实际结果

输入均为公开教学/诊断配置，`n=1`，每个配置只用一个预定公开测试流。R每项为两个独立测试bit之差，理想模型下P(0)=1/2、P(±1)=1/4，匹配qFALL的PlusMinusOneZero配方；它是MP12允许的有界陷门分布，未冒充离散Gaussian。A_bar为有界拒绝抽样的规范余数；程序明确只接收公共测试fixture，无法作为生产发钥接口。

| q / m_bar / k | 根/父/叶维度 | s1² / s2² | 原像方程/实测范数 | 两轮有噪声bit正确/错误 | 条件噪声预算 | 诊断总时长 |
|---|---|---|---|---|---|---|
| 17 / 8 / 5 | 13 / 26 / 39 | 62320 / 252769920 | 256/256、256/256 | 239/273 | 失败 | 0.780 s |
| 257 / 16 / 9 | 25 / 50 / 75 | 226200 / 1809600000 | 256/256、256/256 | 275/237 | 失败 | 3.834 s |
| 1073741827 / 48 / 31 | 79 / 158 / 237 | 2441960 / 63276067520 | 256/256、256/256 | **512/0** | 本轮条件通过 | 491.433 s |

原父級RandBasis分别在26、50、158个向量后完成，固定最多D_parent+32次尝试； norm/rank ABORT不重试。上述时间含原始基转换、完整性/GS核验、采样、选秩/ToBasis、规约及相位，不是公平性能基准，也没有记录内存峰值。

全部使用**同一行**的真实取整噪声`alpha=4/q`，即连续密度宽度`q*alpha=4`；噪声有限工具采用tail64/mass96/precision160。每轮仅抽D_leaf+256个误差，共两轮；源profile/certificate和计数均随[机器结果](chain-results.json)保存。位输入为交替0/1，没有应用消息或实际H/G身份映射。768/768原像方程与范数检查通过；小模数510个错误保留，不能用它们的无噪声代数结果替代解码。较大行512/512只是有限有噪声相位验收，未形成密文序列化、匿名性或完整HIBE契约。

在较大行，旧有限GPV构造器仍因237>192而拒绝。新比较源通过独立明确范围执行，没有回退/关闭旧检查。根GS²实测180；先验公共上界采用MP12完整基转换引用和保守Frobenius界`10*(1+m_bar*n*k)=14890`，父/叶宽度按原C1-exec及RandBasis成功时上界传递，未按所测秘密GS临时缩宽。实际基包含关系、完整行列式及GS再次独立检查。

## 为什么仍不能宣布正式参数

1. n=1只有诊断意义；没有实际LWE安全成本。alpha通过条件正确性不构成困难性结论。
2. 原生Sage/DGS使用明确测试seed和Sage随机状态，生产CSPRNG API未实现；有限标量/整链TV及最坏熵/标量拒绝上界均为null。tau12与MPFR192不是现有有限采样证书的替代品。
3. MP12公共分布仍不合格。按理想独立均匀A_bar/R配方的保守LHL并集界，三个根的TV上界分别1、约0.564、约0.06055；固定公共seed不等于此理想模型。较大行的数值仍远不足密码学小误差，不按根方程通过放行。
4. 独立Sage LLL仍无统一资源/失败证书。原生完整批次没有存入固定bit地址缓存；重复派生与进程恢复须由真正T3/T4实现。
5. H/G、bit/字节HIBE接口、身份匹配/匿名契约、密钥绑定/wire及完整Wang/BYTEAUTH攻击验收尚未完成；没有新增完整安全实例或A+B<C结论。

## LATTE 源码审计的可复现反例

原始`latte_1/sample_z.c`在Box–Muller步骤向r_bm填入16 B，随后从旧比较缓冲区r读取两个uniform量。我们保留原文件和MIT声明，以固定比较字节及两组不同的新Box–Muller字节执行原函数；结果均为1。仅改两处读取地址的对照分别为1、26；每次均3次熵调用。两个新字节输入对原函数无影响这一事实已被C执行确认。

[源码证据](latte-buffer-evidence.json)是熵流反例；不是分布实测、完整LATTE攻击或对照修改的安全批准。原文件在`experiments/research/reuse/vendor/latte/`原样归档，函数摘取和改址只在`test-results/`生成的诊断C文件执行。未向外部作者发消息、开issue或发布修改。

## PR #7 复核边界

队友在本轮期间补充计划与第八步报告，最终头提交`066bac0`已审阅并合并；GitHub确认MERGED，最终合并`2b337e2`，早一批合并为`3948c0f`。Luo模格作为首套研究主线，与现有代码一致；矩阵参数扩展暂停，其他算法仍保留为后续比较材料。六份原始报告按原文保存，未据此关闭安全准入。

原始报告有三点须与实际代码/证据分开：**估计器无有限输出不能推断平凡可解或不存在参数；IBS缓存没有实现CHKP叶缓存式FAILED墓碑；3924+89仅是envelope，完整IBS输入还含接收者与规范域/长度开销，冻结最坏合计为4096 B。** 旧464 passed等是历史批次，不作为本次全仓库结果。外部驱动脚本/完整JSON未随PR提供，原始机器上的SHA一致性未在此机独立重验。论文sketch和教师对引用口径的判断不能自动消除未验证条件，项目none/false保持。

## 下一轮可直接接手的工作

队友可使用本轮原始代码/结果，先确定GenBasis是否采用MP12完整基转换，再对应既有CHKP抽象前提。对正式n/根近均匀误差目标、CSPRNG、原生采样的参数/误差/资源作统一准入；保留有限参考作差分基线。不要只放大维度或把测试seed当生产随机性。

随后冻结H/G和256bit私有地址/系数/wire预算，落实一级RandBasis、终层SampleD、失败墓碑及恢复。主AI接已有32 B Hybrid/IBS/BYTEAUTH与磁盘事务，做完整契约和攻击验收。LATTE保留另一算法的重要比较工程，匿名条件和全工程编译另行安排；本轮没有默认改换整个HIBE或重做基础安全证明。

编译/复跑命令、全部修改文件、环境、参数和源码/库/测试报告指纹见[audit.json](audit.json)。全部保持`security_claim=none,backend_admitted=false,parameters_are_formal=false`，模型为经典ROM研究引用；测试不能代替安全证明。原education公开伪造/冒名两个认证漏洞仍未修复。
