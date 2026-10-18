# A：CHKP 3m 父委派、大模数与分块运行原型

**工程结论：完整扰动、紧凑父 R 和无稠密求逆的真实3m链已可实跑；这次表示/工作区改造仍不足以让既有正式目标在本机落地。** n4096/q77那组目标的父 R 按本原型固定宽度编码仍为523197481026 B，尚不含公开矩阵与计算工作区。本机Windows物理内存33778278400 B，现原型的打包底层仍驻内存，入口会拒绝该目标；没有生成目标私钥，也没有把大q子工具成功写成正式参数可运行。

代码提交 `11483c2`（`feat(hibe): prototype compact 3m delegation with bounded matrix blocks`）、`6b5305a`（`feat(bench): record complete suite cold cached and restored measurements`）、`a9fd70a`（`fix(bench): restore reference states with an explicit fixed scope`）、`c9bbb7f`（`fix(hibe): reject mismatched delegation domains before sampling`）。运行数据固定于`a9fd70a`；最后的c9bbb7f只加强错误模域/维数的入口拒绝、增加2项测试并更新CI说明，不改变合法输入的采样/表示。算法、参数、编码及有限算术说明见[原型契约](../../../specs/mp12-blocked-3m-prototype.md)。本批保持作者稿3m；不新增论文后端计数，不切换2m，GKR/ABB标准模型/CHKP标准模型继续暂缓。

本批概况见[结构化审计](audit.json)，PR整体文件见[变更清单](files-changed.txt)及[公开文件指纹](manifest.json)。PR同时保留前序已确认的78e2d1e/5679158工作前提与3m选择、8e6e216的PR39接收盘点；本批没有重写这些决定或增加理论证明门槛。

## 已做的工程改造

1. 真实MP12根/Algorithm4父委派/Algorithm3叶采样接入既有最高256位q的binary gadget工具；端到端整数运算不经过uint64。完整H宽度仍为m，叶仍为3m，256个固定G位置都实际采样。
2. 父R用声明坐标界决定的有符号固定宽度二进制保存，全部随机扰动坐标保留。父对象不保留主R、其生成随机带或祖先引用；新wire/参数上下文显式版本化。
3. 列块执行R及Rᵀ乘法，逐列生成父R；叶接受指数用固定点候选、**精确整数残差**和定向区间核验，未展开完整核基或稠密Schur逆。没有相信浮点逆、对角近似或输出补零。
4. 根/父/固定叶均独立严格恢复，检查上下文、身份、维度、陷门/256叶方程和范数。失败占用目录与pending保留，未自动重抽；新进程恢复禁止熵与采样。

原型结束于实际固定叶及对象恢复，尚未登记为共同HIBEBackend；**没有新增大q KEM、Hybrid、CLI或完整IB-ME运行声明**。现有structured HIBE v1/v2及其完整小参数路径保持原样，不能把本批原型和既有完整后端拼称同一目标参数配置。

## 同参数旧实现对照

两者均n2/q1099511627689、根平方宽16、epsilon/tail/abort192、mass320、precision384、m84、叶252维、完整256位置、两级身份各86 B；使用各自新的系统随机根和H/G上下文，因此不比较输出字节相等。分块原型native块缓存上限64 MiB/矩阵。每条路径1次，未并行跑其它密码学测量；不据此给稳定加速比或尾部概率。

| 阶段 / 存储 | 旧exact-Schur/JSON | 分块/packed |
|---|---:|---:|
| 根生成 / s | 0.055633 | 0.101867 |
| 父委派 / s | 2.907243 | 4.705295 |
| 叶采样器准备 / s | 1.458084 | 0.127236 |
| 256叶原像 / s | 62.040780 | 47.542963 |
| 全流程RSS最大观察 / MiB | 284.91 | 222.24 |
| 根私有对象 / B | 941 | 1552 |
| 父私有对象 / B | 38764 | 23366 |
| 固定叶对象 / B | 543401 | 258714 |
| 单独公开上下文 / B | 1634 | 1689 |

分块路径父委派在此样本更慢、根对象更大，收益没有遍及所有阶段。新旧上下文/对象组帧不同：旧根JSON从小前缀和R重建公开矩阵，新根/父packet含完整公开矩阵，新叶通过外部公开上下文恢复，旧固定叶内嵌上下文。表中报告实际文件边界，不把较短元数据当作密码学原创，也不把原语工具结果写成完整IB-ME加速。

新父R自身的同一组实际整数，紧凑JSON十进制记号36580 B、packed21186 B，约1.727倍；这个同值比较不受新旧采样随机性影响。[新路径收据](evidence/n2-q40.json)给出全部逐阶段数据。

旧实现原始探针在**全部采样和持久化成功后**，恢复调用漏传`expected_scope`而报TypeError。[原失败记录](evidence/reference-original-failure.json)保留，generation.pending仍保留。`a9fd70a`只修正探针并只读重放既有四份状态，[新进程恢复收据](evidence/reference-restored.json)验证256个固定原像、0熵、0新根/父/原像及原文件不变；没有重采失败槽。旧对照的数值来自原已完成阶段，不能把其失败恢复行算为成功用时。原异常前未捕获provider指纹，该事实在源码核对中单列，后续恢复有独立指纹。

## 80位q的实际规模阶梯

q固定为已证明素数604462909807314587353111。n2/n4/n8分别取根平方宽16/32/64，`qα=max(4,floor(2sqrt(n))+1)`，完整同组宽度及条件噪声判据在入口核对；这组只是研究执行输入，**不是n4096目标参数的替代或已安全准入配置**。每n实际一根、一父、一叶256原像；原像范数失败或熵/算术失败均中止，不自动重抽。

| n / 3m叶维数 | 根 / s | 父 / s | 叶准备 / s | 256叶原像 / s | 最大RSS观察 / MiB | 状态 |
|---|---:|---:|---:|---:|---:|---|
| 2 / 492 | 0.225458 | 17.057774 | 0.313620 | 125.438903 | 227.48 | [通过](evidence/n2-q80.json)，含零熵恢复 |
| 4 / 984 | 0.626995 | 70.438041 | 0.289798 | 402.719377 | 233.63 | [通过](evidence/n4-q80.json)，含零熵恢复 |
| 8 / 1968 | 2.501472 | 327.139582 | 0.302098 | 1362.320358 | 249.59 | [通过](evidence/n8-q80.json)，含零熵恢复 |

n8整条原型耗时约28.3分钟，父对象1395766 B，固定叶2519706 B；同一父R的packed1290306 B、十进制JSON2669128 B，约2.069倍。三个n的RSS观察保持在227—250 MiB量级，但采样耗时明显增长；该观察只说明本原型小规模的实际成本，不外推目标参数的速度或认为更小工作区足够解决目标存储。

原始表中的严格恢复为各生成进程内重新加载；之后又分别启动全新进程重放四套完成状态，均0熵/0新根/父/原像、256叶检查、原文件不变：[n2/q40](evidence/fresh-restore-n2-q40.json)、[n2/q80](evidence/fresh-restore-n2-q80.json)、[n4/q80](evidence/fresh-restore-n4-q80.json)、[n8/q80](evidence/fresh-restore-n8-q80.json)。这些只读复放没有重新计入上述生成耗时；c9bbb7f入口修正后还对[原n8状态复放](evidence/post-guard-restore-n8.json)，没有换钥或改旧wire。

## 既有正式目标：仅重算表示字节数

完整输入来自[原3m目标投影](../2026-10-16-target-parameters/evidence/complete-targets.json)，保留原n/q/根宽度/噪声与宽度链，没有重选安全参数或重做攻击估计。公共标量radius实际构造，所有巨大矩阵仅计数，**没有分配或执行**。详见[字节投影](evidence/target-byte-projections.json)。

| 原n/q位数 | 父R项数 | 每项固定B | packed父R / B | packed父公开矩阵 / B | 单叶256原像packed / B |
|---|---:|---:|---:|---:|---:|
| 128 / 59 | 60899328 | 4 | 243597378 | 15990850 | 41975874 |
| 512 / 67 | 1247019008 | 5 | 6235095106 | 325582914 | 189923394 |
| 2048 / 74 | 24209522688 | 5 | 121047613506 | 6375342146 | 956301378 |
| 4096 / 77 | 104639496192 | 5 | 523197481026 | 26508001346 | 2236612674 |

旧209278992384 B是“每个JSON整数只算一位数字加分隔”的**乐观下界**，不是该目标已生成私钥的实际JSON文件。新的523 GB是当前公共坐标界固定5 B的编码计数；两者含义不同，不能说紧凑编码把同一实际文件从209 GB扩大至523 GB。新编码消除了Python整数/JSON文本等开销，但仍有约1046亿个父R坐标；消除Schur逆也不消除这些坐标。本机32 GiB量级内存仍不足，out-of-core、公开块去重及获准的更小父陷门表示均未实现；本批不保证它们能解决问题，也不将n8时间外推为目标运行时间。

## 验证、复跑和剩余范围

- 固定`11483c2`的A完整专项 **206 passed/0 skipped**，207.08 s：[JUnit](evidence/strict-sage.xml)、[命令/源指纹](evidence/strict-sage.json)。包括既有实际HIBE/噪声/固定状态/装配及新增完整协方差逆对照、80位整数与严格codec。WSL未找到Git，CI receipt的revision为unavailable；其实际捕获的源指纹逐项对应`11483c2`，不把unavailable写成自动采到提交号。
- `a9fd70a`新增磁盘失败占用定向测试 **1 passed/7 deselected**，6.84 s：[JUnit](evidence/failure-slot.xml)，证明父委派失败保留pending、根状态且原目录拒绝重发。不是第二轮完整207项回归。
- `c9bbb7f`入口修正完整core定向 **15 passed/0 skipped**，6.47 s：[JUnit](evidence/final-boundaries.xml)。覆盖原core13项和新增同模/符号/行数拒绝前0熵、乘法全长检查2项；未把它冒称重新跑了完整209项。
- Windows CI目录重跑 **25 passed/0 skipped**，0.85 s（前次1.02 s）。完整系统统一基线另有[3套LATTE+BNN-ML-DSA实际重复测量](../../2026-10-18-full-system-baseline/README.md)，不将它与A教学参数排名。
- a9fd70a远端 **46成功+2预期手动未执行**：[检查快照](evidence/remote-a9fd70a.json)，其中Sage A专项 **207 passed**，330.74 s：[日志摘要](evidence/remote-a9-A-summary.json)。这是该固定提交的结果，不能当作后续提交已通过。
- [公开源码核对](evidence/source-check.json)：978个provider出现记录、160个不同提交/文件对及17份原CI源指纹与记录Git blob相同，核对过程0秘密状态读取；旧对照异常前未采provider单列，不补造指纹。

环境Core Ultra9 275HX，Windows物理内存33778278400 B，WSL `/proc/meminfo` MemTotal为16092848 KiB；指定WSL conda Sage10.9/Python3.13.14、Linux6.18.33.2，OMP=4/OpenBLAS=1。时间含算法输入检查/方程验证，持久化和恢复单列；RSS为10 ms进程树采样下界，内核累计高水位也保留。页缓存不清空，随机数为系统CSPRNG，私钥、原像、随机带、完整密文均留在ignored `test-results/`，未进Git。字节计数不等于RSS。

复跑时使用全新私有目录；恢复使用原完成目录，禁止删除失败pending重跑：

```sh
PYTHONPATH=src:. OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=1 \
~/miniconda3/envs/sage/bin/python -m experiments.research.blocked_3m_probe \
  --private-directory test-results/a-3m/new-n4 --n 4 --cache-bytes 67108864 \
  --source-commit a9fd70a
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.blocked_3m_probe \
  --private-directory test-results/a-3m/new-n4 --restore-only
```

公开来源核对在Windows仓库根运行`python docs/research/team-a-delivery/2026-10-18-3m-feasibility/evidence/check-sources.py`，只读公开收据和Git对象，不打开秘密状态。完整框架/安装/负例沿用既有验收，本批未重跑新大q完整IB-ME、仓库外安装或正式目标密钥生成。

按用户确认的论文安全/匿名工作前提继续工程，理论材料沿用原文引用；不新增证明任务。保留ROM、研究/教学参数与none/false/false；功能结果不能证明安全等级。A整体仍WIP：下一步必须先解决正式尺寸父R的表示/资源问题，再决定大q完整KEM/对象/CLI接入，随后才能与其它同目标完整系统比较。三条储备路线保持暂缓。
