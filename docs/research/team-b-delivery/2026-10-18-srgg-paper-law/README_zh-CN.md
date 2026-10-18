# SRGG 原论文参数：固定根发钥分布与资源续审

本批推进 SRGG 独立 IBS 与 HIBE 无关的部分：把当前有限扰动采样、原论文 gadget 和 centered-HNF 发钥连接到明确的参考向量分布，并用原 Table 4 三组参数各完成一次固定根发钥检查。新增的是分布分析、证书与审计工具；本批没有修改原论文后端算法、公共接口或默认数值精度，也没有替换参数、重抽根以通过分析门。

目前得到三条**有条件的、固定根上的有限发钥向量分布界**。这不等于原论文全部定理前提成立，也不构成正式安全参数准入、完整 IBS 安全归约或 NIST 安全等级。

## 来源、参数与运行口径

冻结来源为 [`2025_efficient_ibs_jia.pdf`](../../../../papers/2025_efficient_ibs_jia.pdf)，SHA-256：

```text
258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152
```

沿用 Table 3、Section 5.1 与 Table 4 的输入；各行共同使用 `n=512`、`p=16383`、`b=31`、`w=2`、`q_gadget=961`、`Q=15,744,063`、字面舍入值 `r=1.16`。表中四个高斯宽度及原始范数门如下。

| 论文行 | 模秩 d | master 第一/第二宽度 | signature 第一/第二宽度 | γ |
|---|---:|---:|---:|---:|
| PARAM-I | 2 | 2843.9 / 1023.0 | 843088.2 / 310891.6 | 42086491.7 |
| PARAM-II | 3 | 3399.4 / 1065.3 | 1046714.2 / 384614.5 | 63653172.0 |
| PARAM-III | 4 | 3867.7 / 1089.9 | 1238066.0 / 448859.2 | 86573930.5 |

参数输入一致不能写成逐步骤完整复现。现有 `PaperSampleF` 使用 joint sampler、有理 whitening 和精确环平方根级数；它与原论文逐层 Schur 机制及作者 C 实现不同，代码仍保留 `legacy_sequential_schur_law_equal=false`。本批推进的是该实际采样实现至明确目标分布的对应，没有复现作者 ANS 熵编码、C 程序、1000 次中位 cycles 或论文尺寸/性能结果。[既有 SOURCE_MAP](../2026-10-16-srgg-paper-baseline/SOURCE_MAP.md) 中的机制、来源和验收缺口继续有效。按原论文一致性与完整度优先的要求，后续仍须补齐这些对应，不能用参数表一致或新的分布上界抹平。

真实发钥实验明确采用 `table-standard-deviation` 解释：在密度 `exp(-π(x-c)ᵀΣ⁻¹(x-c))` 下，把表中物理标准差转换为 shape，连续协方差为 `Σ/(2π)`。当前使用已修正的精确二进制区间端点转换；512 位 π 区间及其有理中点定义保存在各收据中。作者是否采用该解释仍未确认，不能把本实验解释当成原文歧义已经解决。`literal-density-width` 分支继续保留在资源预检和先前归一化报告中。

每行身份为 5 字节 `Alice`，真实发钥重复次数为 1；本次发钥审计没有签名消息，`message_bytes=null`。它使用 `DeterministicRandom TEST ONLY` 重放既定种子，ROM 身份哈希保留。环境为 x86_64、WSL2 Linux 6.18.33.2、Python 3.13.15、Sage 10.9；可移交命令使用指定 WSL 环境 `~/miniconda3/envs/sage`。这些是原论文研究参数，不是教学替代参数，但也未通过正式安全准入。单次执行、功能检查和有限攻击结果均不能代替安全证明。

## 三组真实固定根结果

最终收据为 [PARAM-I](PARAM-I-issuance.json)、[PARAM-II](PARAM-II-issuance.json)、[PARAM-III](PARAM-III-issuance.json)。三次均为 `setup_attempts=1`、`analysis_gate_root_redraws=0`，每次仅发钥一次；分析本身不消费随机字节，私钥、陷门、私有谱和中心未导出。

| 论文行 | 通过检查数 | 有限发钥至 HNF 参考向量的 TV 上界，含中止 | 该次完整审计耗时 | 该次总随机源读取 |
|---|---:|---:|---:|---:|
| PARAM-I | 12 / 12 | 约 1.9702153622×10⁻⁷ | 46.93 秒 | 2,895,849 B |
| PARAM-II | 12 / 12 | 约 2.9553230779×10⁻⁷ | 57.64 秒 | 4,318,105 B |
| PARAM-III | 12 / 12 | 约 3.9404308165×10⁻⁷ | 94.58 秒 | 5,752,523 B |

表中小数仅供阅读，机器收据保存精确有理上界；耗时包括准备、分析、资源预检与发钥，不是论文 Table 6 的算法性能复现。

12 项检查分别为：CBD1 支持、陷门与公钥关系、分析不耗熵、固定根的 coarse C 门、有限 raw 坐标界、有限 HNF 坐标界、公钥/密钥 wire 界、空 master 缓存、发钥时重建同一计划证书、密钥方程、密钥规范序列化往返以及仅一次发钥。三组固定根均由定向区间 Fourier/LDL 证实 `C ≻ 64 I`；该结论只覆盖这三个根，未证明所有 Setup 输出都通过。

## 参考分布与本批证明边界

分析入口为 [`paper_issuance_bridge.py`](../../../../experiments/research/candidates/srgg/paper_issuance_bridge.py)，真实审计入口为 [`paper_issuance_audit.py`](../../../../experiments/research/candidates/srgg/paper_issuance_audit.py)。令 `N=(2+w)dn`，`Σ` 为原论文 master 两段对角目标 shape，`E_c` 为中心代表下的 gadget 余数盒。参考分布是

```text
centered-HNF#(D_(Z^N,Σ,0) | S_h),
S_h = {u : h - A u mod Q 有代表落在 E_c}。
```

它是近似原像集合上的高斯经过 centered-HNF 的推前分布；在固定 `A,h,Σ` 下，参考定义不依赖私有陷门。这里没有把它认作 exact-preimage 高斯、原文所有 PSF 游戏的 SampleDom 条件分布，或最终签名 law。

总界由四项组成：有限扰动采样误差、有限 gadget 标量采样误差、逐位归一化分母去除的 `x/(2-x)`，以及完成平方后中心归一化的 `ε_C/(1-ε_C)`。gadget 的同一归一化偏差仅计算一次。确定性取 tail 与 centered-HNF 推前不另加 TV 损失，所有采样中止均保留为一个结果，不通过忽略失败缩小上界。

将数学向量界用于当前 `key_extract`，还需同时满足：

1. 公钥、陷门关系有效，根固定且通过本次数值/几何门；身份合法，首次发钥前缓存为空且容量可用。
2. 概率模型中的随机字节独立、均匀，并满足证书声明的 MPFR、区间和精确算术假设；实现中没有外部故障。
3. 实际 finite-output、256 位坐标、对象、规范编码和 wire guards 不会增加未计入的失败。本批对三组实际参数给出公共有限支持及 wire 包络，并通过相应 12 项检查。

在同一 iid 字节、无故障和 guards 前提下，收据同时给出首次发钥成功概率下界 `1-δ`，以及成功后的**向量**分布 TV 上界 `δ`。这是模型内的数学结论；确定性测试种子只核验执行路径，不证明该种子具有 iid 随机字节分布。磁盘/进程故障概率、完整服务历史、所有根的接受概率以及完整 wire 记录分布仍未由本批定理覆盖。

## 当前扰动界与历史证据分开

[current-budget.json](current-budget.json) 通过 [`paper_current_budget.py`](../../../../experiments/research/candidates/srgg/paper_current_budget.py)，认证提交 `38f2459` 的 [precision.json](../2026-10-17-srgg-parameter-closure/precision.json)、原 Manifest、当前四个核心源及辅助源，再核对 shape、维度、目标与噪声。它把严格 theta 界与同一固定根上的公开数值误差包络、包含中止的 scalar batch 误差相加，没有重新生成根或密钥，也没有新抽样。

PARAM-III 的 master160、master192 扰动上界约为 `3.8210238262×10⁻⁷`，signature192 约为 `4.0598378274×10⁻⁷`。**signature160 的数值误差公开包络仍为 1，总界仍为 1**；这表示现有证书没有给出非平凡界，不能解释成实际 TV 等于 1。默认后端继续使用160位数值级数目标，192位结果是同根比较证据。本文件也不把这一局部扰动证书提升为完整 gadget/HNF/最终签名分布证书；三组发钥桥接结果由上一节的独立分析给出。

原区间端点错误相关的历史有限误差收据仍为未验证，不因接上新的 theta 界而恢复有效。本批实际当前根的证书与那些历史算术和式分别保存。

初次三份失败收据 [PARAM-I](PARAM-I-initial-failed.json)、[PARAM-II](PARAM-II-initial-failed.json)、[PARAM-III](PARAM-III-initial-failed.json) 也保留：分析 gate 对 Sage 有理数与 Python `Fraction` 的类型比较不一致，三次在 `certify_same_root` 阶段报 `ValueError`，尚未进行发钥高斯抽样。Setup 已读取根生成所需字节，不能写成整个失败过程耗熵为零。修复只统一分析 guard 的精确表示；最终运行采用相同种子，公钥 context 与相应失败收据逐一相同，是同一固定根的重放，不是更换根以通过分析。

## 资源预检与实际消耗

[resource-preflight.json](resource-preflight.json) 对原三行的两种归一化解释及旧研究候选进行公开零熵预检。`256 MiB` 和标量数量上限是单批预算，不是完整服务生命周期限额。

| 原论文行，标准差解释 | 单次发钥硬字节包络 | 最多64次尝试的单次签名硬字节包络 | 当前 wire/state 包络通过的服务容量 |
|---|---:|---:|---|
| PARAM-I | 6,313,850 B | 16,733,776,128 B | 1、2、3 个身份 |
| PARAM-II | 9,292,104 B | 16,863,646,016 B | 1、2 个身份 |
| PARAM-III | 12,270,393 B | 16,993,515,904 B | 1 个身份 |

两种解释合计的原论文单次签名硬包络约为十进制 **16.7—18.4 GB**。它来自最坏路径、最多64次范数重试和逐标量硬限额的保守相加，**不是实测随机源消耗、RAM、输出文件大小或运行时间**；也不要求预先分配同等内存。上面的三次实际总读取只有约2.9、4.3、5.8 MB，且这些运行是发钥审计，没有运行64次签名。

服务容量来自现有 `2 MiB` wire/state 限额、最大4096字节身份及序列化嵌套的公共包络，并核验了真实服务构造器的接受/拒绝：PARAM-I 的4人、PARAM-II 的3人、PARAM-III 的2人请求被拒绝。它是可保证的类包络，不表示每把实际密钥都会达到上界，也不表示声明的64人缓存容量已具备完整资源准入。三次真实实验各仅使用5字节身份、发出一把密钥。

预检没有给出全 witness 的峰值 RAM、时间上界或服务全局查询/熵配额；原论文 signing-u 的聚合诊断帽也未变成新的运行时总帽。`complete_resource_admission` 保持未闭合。

## 尚未解决的独立 IBS 问题

- **模数来源对应**：Theorem 1 的奇数 `q`、gadget 的 `q=961`、`Q=15,744,063` 和响应关系中的偶数 `2Q` 不能互换。原三行与 `q>2γ` 等条件的对应仍有冲突，本批未改 `w` 或扩大模数。
- **ζ 与最终签名分布**：`ζζ*=2` 产生的 shape factor 2 与原 Algorithm 7 字面 perturbation factor 1 尚未对应；挑战依赖 commitment 的完整签名 law、范数重试和全历史损失仍需推进。
- **r 与来源平滑维度**：作者的标准差/密度解释未定。原 `r=1.16` 在来源 `ε=2^-24`、`m=(2+w)(d+1)n=10240` 下已有严格必要条件失败证据；本批较小局部维度的 theta 或 fixed-root C 门不能替代该来源条件。
- **native strong 与安全归约**：既有 PARAM-II/III 的同消息 `±Q` 替换接受反例继续保留，未由本批发钥分布分析消除。完整 strong 游戏、目标身份签名模拟、ROM/QROM 查询损失和固定服务映射仍未闭合。
- **正式参数与长期资源**：仍需统一困难性与结构/CRT/子域攻击核验、有限误差和全服务中止预算、所有 Setup 根的条件及长期状态/故障模型。Kyber/ML-KEM 与 NIST 标准化只作为比较目标，不作为已达到安全等级的依据。

全批状态保持 `security_claim=none`、`parameters_are_formal=false`、`backend_admitted=false`、`nist_security_category=null`。HIBE 选择、公共组合和组合安全没有进入本批范围。

## 复核与交付记录

在仓库根目录、指定 WSL Sage 环境中运行，`--output` 必须使用新路径以保留原收据：

```text
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_current_budget --output <fresh>/current-budget.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_resource_audit --output <fresh>/resource-preflight.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_issuance_audit --profile PARAM-I --output <fresh>/PARAM-I-issuance.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_issuance_audit --profile PARAM-II --output <fresh>/PARAM-II-issuance.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_issuance_audit --profile PARAM-III --output <fresh>/PARAM-III-issuance.json
```

最终全量回归在指定 WSL Sage 环境完成，命令为：

```text
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg*.py --junitxml=build/outputs/srgg-paper-law-2026-10-18/regression.xml
```

结果为 **1599 passed in 358.10s**，0 失败、0 错误、0 跳过。[stdout](regression.txt)、[JUnit](regression.xml) 及 [原始/公开字节对应](regression-provenance.json) 已封存；JUnit 仅替换一个主机名属性。硬件见 [hardware.json](hardware.json)，三组进程曾并行，耗时不用于公平性能比较。回归通过确认实现和证书检查，不替代上述来源对应、分布或安全义务。

本批新增代码及测试如下；本目录材料的逐文件清单及 SHA-256 见 [MANIFEST.json](MANIFEST.json)，验证记录见 [validation.json](validation.json)。既有算法文件未修改。

| 新增模块，位于 `experiments/research/candidates/srgg/` | 对应新增测试，位于 `tests/` |
|---|---|
| `paper_current_budget.py` | `test_srgg_paper_current_budget.py` |
| `paper_resource_audit.py` | `test_srgg_paper_resource_audit.py` |
| `paper_issuance_bridge.py` | `test_srgg_paper_issuance_bridge.py`、`test_srgg_paper_issuance_binding.py` |
| `paper_issuance_audit.py` | 三组真实固定根审计和完整回归 |

提交信息为 `feat(srgg): advance WIP paper issuance and resource audit`；哈希见本次交付回复及 Git 历史。本批仅本地提交，未推送。原始运行材料位于 `build/outputs/srgg-paper-law-2026-10-18/`；同名公开材料和验证记录在本目录封存。
