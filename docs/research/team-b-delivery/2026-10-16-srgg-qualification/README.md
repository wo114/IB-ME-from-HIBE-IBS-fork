# SRGG 六项联合核验与扩维组件

本批把来源资格、HNF 发钥分布、最终整数采样误差、服务预算、候选参数和实际资源验证放在同一证据链中。基线提交为 `47a0341eca581b6057974b300cb15f2d9aafadfc`，继续更新 PR [#37](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/37)。这批是研究交付，不是六项全部安全闭合或正式参数准入。

## 六项结果与阻塞

| 项目 | 本批可复核成果 | 仍未闭合 |
|---|---|---|
| 1. ζ、归一化、模数和 strong | ζ 陪集推前的 factor2、r 的约定、KLS 条件性 strong 定理前提表、源参数 CUR 精确反例及有明确范数条件的同消息响应变换 | factor2 完整离散卷积及原文定理继承；真实矩阵分布的 CUR/UF-NMA；整个 IBS 的 strong 游戏对应 |
| 2. HNF 后发钥 law | 条件 gadget→raw→tail→HNF→范数门的精确有限 law；PSF image 条件 law；head-wrap 耦合、成功条件化界与严格反例 | 实际 raw law 到 PSF 条件 reference 的 tail-TV、陷门独立性及数学 witness/压缩对象对应 |
| 3. 有限采样误差 | 在明确 MPFR/熵假设下，最终整数输出到指定 sequential ideal sampler 的统一 TV 上界；包括标量中止、Schur 归一化和边缘偏差 | 该 ideal sampler 不自动等于 PSF 发钥或最终 signature Gaussian；完整密码学 reference 尚未识别 |
| 4. 固定服务与查询预算 | 一次发钥、同身份缓存、仅范数拒绝重试的预算公式；两组实际配置的数值账本 | 真实 norm 拒绝上界、基础设施故障模型及完整游戏 oracle 适配；长期查询时当前界成为 1 |
| 5. HIBE 无关候选筛查 | n512、d2/3/4 的条件算术点、整数 smoothing 充分证书、w2..8 搜索及成本模型 | 假定 raw norm cap 的成功率、q/Q 完整对应、强安全与结构攻击估计；全部不是正式安全参数 |
| 6. 实际执行与扩维 | 两组 n8 真实持久生命周期、公开伪造负控、28 项真实采样器资源网格；另交付与稠密版本精确对应的结构化形状组件 | n512 完整采样器、对象及 IBS 生命周期仍未交付；结构 matvec 不等于大维度密码方案可运行 |

这些工作独立于最终 HIBE 选择；本批没有据此决定 HIBE 或改动共享组合协议。教师要求的 Kyber/NIST 对标仍是安全/资源评测目标，KEM 的标准化等级不能直接迁移给 IBS。

新的公开响应检查还给出：若一条原签名本来有效，将首个 `2I` 块的一项 v 向较短方向平移 Q，承诺和原 challenge 均保持不变；若新平方范数 `old_norm²+Q²−2Q|v|≤B`，便得到另一条有效同消息签名。`old_norm²≤B−Q²` 是可观察的充分条件。源参数报告了该 margin，但本批未执行源 n512 诚实签名或估计满足概率，不能写成已完成的无条件源参数攻击。当前 `Q>2γ` 配置门排除这一类范数内签名对；这也不证明其它 strong 攻击不存在。

## 主要数学材料

- [来源与 strong 资格](source-eligibility.md)：冻结论文版本、页码、ζ 的精确陪集分布和 strong 适用条件。
- [HNF 与固定服务](hnf-service.md)：完整 law、失败原子、PSF reference、有限反例及查询/中止公式。
- [最终整数误差推导](sampling-error-review.md)：240 中心核常数、Box–Muller 耦合、1024 数值项、Peikert 连续分支、Schur 与 lower 边缘误差。
- [参数及规模可行性](parameter-feasibility.md)：全部参数、条件、整数门、内存载荷场景及扩维限制。
- [采样器资源实测](resource-probe.md)：实际 28 个公开 SPD 夹具的成功/预检拒绝、熵、时间和 RSS。
- [结构化形状组件](structured-geometry.md)：与当前形状及条件中心的精确对应，实际大维度 matvec 的用途和限制。

## 当前两组可执行研究配置

公共设置：n=8、d=1、p=257、b=31、用户范数平方上限 2^29、身份最多 256 B、消息 0..4096 B、配置身份槽 16、签名最多 16 次范数尝试；本次持久服务各根限定 2 个身份。采用明确的 ζ factor2 和 density shape `exp(-πxᵀΣ⁻¹x)` 约定。

| 配置 | w / Q | r² | master 两个平方宽度 | signature 两个平方宽度 | precision / ticket / scalar mass / scalar tail / gadget tail |
|---|---|---:|---:|---:|---|
| baseline-n8 | 3 / 7,656,287 | 4 | 2^23 | 2^37 | 192 / 128 / 64 / 24 / 16 |
| density-width3-n8 | 4 / 237,344,897 | 9 | 2^23 | 2^38 | 256 / 192 / 96 / 64 / 64 |

两组都保留 8-bit challenge，公开枚举伪造负控均被验签接受。第二组只是用较宽舍入 Gaussian 和更多有限位数检查误差账本；它依然是不安全的研究配置，不是新安全方案或正式性能代表。

向上舍入的精确有理上界见 `sampling-error-default.json` 和 `sampling-error-width3.json`。下表仅为近似显示：

| 比较范围 | baseline | width3 |
|---|---:|---:|
| 一次发钥：到指定 sequential ideal sampler 的 TV，含内部中止 | 1.4561×10^-3 | 2.8612×10^-6 |
| 一次完整签名尝试：同样的 TV | 2.8030×10^-3 | 3.8152×10^-6 |
| 最多 16 次尝试的序列 TV | 4.4848×10^-2 | 6.1043×10^-5 |
| 一次发钥内部采样中止联合界 | 2.3842×10^-6 | 2.8610×10^-6 |
| 一次签名尝试内部采样中止联合界 | 3.3379×10^-6 | 3.8147×10^-6 |

第二组仍受实际 runtime 的 Gaussian abort 默认 24 bits 和 uniform rejection 64 trials 影响，不能把 config 的 scalar tail=64 错当作所有中止项也达到 64 bits。更多票据位数不能消除该项、理想平滑误差或分布桥梁缺口。`query_budgets` 实例化 16 个新身份以及 1、2^20、2^40 次签名查询，后两项 TV 联合界均为 1；这表示当前上界无用，不是实测失败概率为 1。

`full_service_abort_upper` 为 null，未伪造 norm 成功率或文件系统故障概率。共同范数门对包含失败原子的完整 law 是数据处理；只看成功输出必须另除以成功率，不能静默重新归一化。

## 真实生命周期和资源证据

`lifecycle.json` 使用 SecureRandom，每配置 3 套根，各发出 Alice/Bob 两把密钥；全部根和失败均按请求顺序记录，没有按成功结果重选根或重发身份。每个身份在持久服务重启后无熵命中原密钥，并从对象恢复后签署空消息、32 B 和 4096 B 消息，再签署恢复检查消息。结果共 6 套根、12 个身份、48 次诚实签验；逐项结果见原始收据。截断/追加 wire 被拒绝，两次公开小挑战伪造负控被接受。并发、硬退出、pending/failed 阻断和状态损坏路径由既有 service 回归覆盖。

环境为 Intel Core Ultra 7 255HX、Windows 宿主、指定 WSL Sage 10.9/Python 3.13.15。采样器网格使用公开确定性测试熵，17 个配置完成 34 次 draw，11 个配置取熵前预检拒绝，无实际超时或 draw abort。矩阵夹具和 IBS 生命周期分别报告，不能把夹具时间当作正式 IBS 性能。RSS 的进程累计语义及导入基线在各报告中注明；小样本零中止不估计罕见事件概率。

原论文/strong 路线含 hash oracle 模型；ROM/QROM 和 Wang 组合前提仍按各自条件核验。本批的功能测试、失败攻击、精确恒等式和数值上界均不能替代 LWE/MSIS、sEUF 或 IB-ME 安全归约。

## 复现和交付清单

在指定 WSL Sage 环境，以仓库根目录为 cwd：

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_*.py tests/test_primitive_spec_audit.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.sampling_error --profile baseline-n8 --output build/outputs/srgg-admission-2026-10-16/sampling-error-default.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.sampling_error --profile density-width3-n8 --output build/outputs/srgg-admission-2026-10-16/sampling-error-width3.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.qualification_audit --roots 3 --output build/outputs/srgg-admission-2026-10-16/lifecycle.json
```

纯 Python 工具另可运行 `cur_obstruction`、`issuance_analysis` 和 `formal_candidates` 的模块 CLI。各工具只输出与其声明范围相符的公开资料，不输出真实主私钥、用户 tail、秘密形状、随机种子或签名。资源夹具的公开测试种子和输出摘要属于明确的测试材料。

本批新增文件分三组，精确路径及 SHA-256 见 `MANIFEST.json`：

```text
experiments/research/candidates/srgg/{cur_obstruction,formal_candidates,issuance_analysis,sampling_error,qualification_audit,resource_probe,structured_geometry}.py
tests/test_srgg_{cur_obstruction,formal_candidates,issuance_analysis,sampling_error,qualification_audit,resource_probe,structured_geometry}.py
docs/research/team-b-delivery/2026-10-16-srgg-qualification/（本说明、五份数学/工程说明、结构说明、公开收据、测试结果和清单）
```

本次不改生产后端、公共签验规则、已有 wire 版本或采样限制。旧批次的冻结收据不覆盖；本次输出位于新的 `build/outputs/srgg-admission-2026-10-16/`，仓库内本目录保留对应公开副本。最终测试命令、退出状态与检查时间见 `validation.json`。
