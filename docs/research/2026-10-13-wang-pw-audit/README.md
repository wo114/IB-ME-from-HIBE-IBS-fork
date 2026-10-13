# Wang + Pan–Wagner：独立代码修复与验收

更新：2026-10-13。本轮范围是算法单体代码：生成系统密钥、给用户发钥、签名、验签、PW 转换、编码和错误处理。没有改公共框架、CHKP、Luo 或正式参数。

## 先说结论

原交付虽然能签名验签，但有实质实现错误，不能按原 README 验收。现已直接修正：用户密钥只保留自己的委派陷门；发钥使用主陷门；签名使用用户陷门；GPV 采样的中心、宽度和更新公式与原文对应；公钥、身份和消息完整进入哈希；错误输入、随机源短读和非规范编码都明确拒绝。

当前为独立研究参考实现，不是优化过的生产密码库。有限测试能检查下面列出的范围，不能保证所有未知输入都绝无 bug；测试成功也不等于完成安全证明。

## 这次具体改了什么

| 原问题 | 修正 | 对应检查 |
|---|---|---|
| 用户密钥携带完整主陷门，可直接重构主私钥、给别的身份发钥 | 删除用户对象中的主陷门及其访问方法，只保存该身份的 R_x | 对象图检查、独立用户签名、陷门实际调用检查 |
| 发钥路径只从公钥算核基，没有真正消费主陷门 | 使用主 G-陷门构造完整核基，再逐列采样委派原像 | Setup / KeyExt / Sign 实际调用、模方程及核基检查 |
| H1/H2 只绑定参数，没有绑定真实公钥 A | 纳入规范公钥矩阵、参数上下文和长度前缀 | 捕获真实哈希输入，不依赖小输出空间“碰巧不碰撞” |
| GPV 中心符号、更新用的向量、逐坐标宽度有误 | 先以 -t 为中心采样，更新减原基向量，标准差除以 GS 长度，最后加 t | 非正交二维可手算反例、逐步采样调用跟踪 |
| 舍入 Cholesky 整数高斯被误称为 MP12 扰动采样 | 删除这条路径，改为完整基 + GPV 的 SamplePre 实现 | 论文映射、真实生命周期；撤回旧“协方差相同所以分布正确”结论 |
| gadget 诊断只采样整数等式，漏掉模 q 陪集中的合法点 | 显式枚举有限盒内满足模方程的点 | q=7、syndrome=6 时包含 (-1,0,0) |
| LLL 直接丢弃相关向量可能改变整数格 | 先做幺模整数消元，再做精确 LLL | 相关生成组、整数包含、行列式、独立穷举 |
| 完整性判据可能把超格当完整核格 | 同时检查核成员关系和指数 q^rank_q(A) | 真子格、真超格、奇异基、冗余生成组、Sage 双向包含 |
| 窄高斯可能永不接受 | 用最近点权重归一化，所有拒绝采样设置预算 | 半整数中心、窄宽度、恶意随机源、预算耗尽 |
| 超大整数溢出、非整数被隐式截断、非规范编码被接受 | 整数平方范数、严格类型检查、最短编码检查 | 大整数、浮点/布尔/字符串、追加/截断/扩宽 |
| PW 盐短读、可变缓冲复用、memoryview 元素数与字节数混淆 | 读取后冻结为 bytes，再检查实际字节数 | 不完整读取、复用缓冲、typed/released memoryview |

原版独立审计有 20 个细项，3 个通过、17 个失败；它们不是 17 个互不相关的漏洞。历史反例保留在 [independent-audit.json](independent-audit.json)。原来的成功收据重跑留在 [original-receipt-rerun.json](original-receipt-rerun.json)，用来说明“诚实签名能过”不足以发现上述缺陷。

## 与论文的对应

| 来源 | 本实现对应内容 |
|---|---|
| [Wang 等 ePrint 2022/1718](https://eprint.iacr.org/2022/1718)，Figure 4 | Setup / KeyExt / Sign / Ver；H1(mpk,id)、H2(mpk,id,m)；非零、范数和模方程验签 |
| [Pan–Wagner ePrint 2021/970](https://eprint.iacr.org/2021/970)，Figure 5，PDF 第12页 | 独立 KeyExt 新取 r；同一份密钥复用 r；每次 Sign 新取 s；公开验签不需要主密钥 |
| 本地 papers/2011_lattice_trapdoors_micciancio.pdf，MP12 Lemma 5.3，PDF 第23页 | A[R;I]=G 的陷门转完整核基；不是第28页 Algorithm 3 的扰动算法 |
| 本地 papers/2008_gpv_trapdoors_full.pdf，GPV08 §4.2，PDF 第15页 | 随机最近平面采样的中心投影、逐坐标宽度、原基更新 |

完整基构造使用 G 的核基 S 和满足 GW=-Abar 的 W：基向量按 [RS;S] 与 [I+RW;W] 两块排列。先精确核对成员关系与指数，再做保格 LLL；独立线性审查和 Sage 同时检查这一点。

LLL 负责改变基的表示，高斯采样仍由 GPV 执行。此处采用已有方法实现 SamplePre，不称为新密码构造，也不称为 MP12 扰动采样的精确复现。

## 采样与输入约定

- Setup：R_A 每项使用标准差 s0/sqrt(2π)。KeyExt：标准差为 s_del × 主核基最大 GS 长度 × sqrt(m)。这里 s_del 是研究配置中的倍数，不是论文已准入的具体参数。
- Sign：公共参数 s'=verify_width 对应 exp(-π||z||²/s'²)，传给标量采样器的标准差为 s'/sqrt(2π)，再逐坐标除以 GS 长度。非零和范数条件不满足时重试，默认最多64次；耗尽明确中止。
- 标量采样使用 ±(ceil(12σ)+1) 有限窗口、80位 Decimal 权重、128位接受阈值及4096次尝试预算。整数线性代数精确，不代表高斯分布也精确。有限窗口、阈值量化、浮点宽度及截断/重试带来的分布差异未在本轮给出完整统计距离证书。
- 真正的高斯近似质量还依赖 GPV 宽度条件；规范编码和模方程检查不能代替这些条件。本轮没有将其升级为正式参数或安全准入。
- 参数对象限定 n≤8、m_bar≤64、素数 3≤q≤65536、正有限宽度≤10^6，属于纯 Python 参考实现输入域，并非所有域内组合都保证快速完成或满足安全条件。高资源调用可按明确预算失败。
- 盐和内部哈希长度必须整字节。随机源必须一次返回请求的准确字节数。固定测试随机源与默认 SecureRandom 分开。
- 纯函数 key_extract_pw 返回一份新密钥；WangPWScheme 另提供同身份固定密钥缓存。两种生命周期不能混写成同一个论文算法。

## 验证与证据入口

当前源码、测试和驱动的固定哈希统一见 [MANIFEST.json](MANIFEST.json)；执行命令、退出码、测试计数见 [validation-summary.json](validation-summary.json)。

最终版本：**396 项回归通过，0失败、0跳过，36.77秒**；独立边界复核覆盖其中292项。真实生命周期收据15项检查通过、16/16诚实签名成功。独立线性审计覆盖1,909个有限域矩阵、40,607个右端、20,568个行列式、2,109个整数核实例、5,664个完整性候选，以及1,077个陷门转基实例；本次范围内未发现剩余缺陷。这些计数分属不同检查，不能相加声称独立安全样本数。

源码按仓库要求固定为LF换行，SHA256为 `2043096d809993f9a1f3ee7a5d2c0a689c1737dc4351ba380c0267f726ea1e89`。全部最终运行收据绑定此版本，避免Windows换行转换导致下载后哈希不一致。

| 证据 | 用途 |
|---|---|
| [pytest-results.xml](pytest-results.xml) | 单体生命周期、采样、边界、线性代数回归的实际结果 |
| [corrected-receipt.json](corrected-receipt.json) | 修复版真实运行：4个身份 × 4条消息，16次诚实签名；15项检查 |
| [sage-kernel-oracle.json](sage-kernel-oracle.json) | 三类基的 Sage HNF 对照、指数及双向整数包含 |
| [linear-audit.json](linear-audit.json) | 独立有限域、行列式、LLL、完整核基与陷门基检查；含原版/修复版区分 |

主生命周期参数为 n=2、q=7、m_bar=6、s0=3、s_del=s_sig=1、s'=200。s_sig 只用于诊断 gadget，不参与默认签名。补充生命周期还覆盖 n=1、q=3/5/11；输入长度、运行环境、计时范围和重复次数写在各收据中。没有硬件加速。

q=7、n=2 时 H2 只有49种取值，错误消息或身份有可能碰巧满足模方程。这是小参数的固有限制。负例逐项对照实际数学验签条件，并明确记录碰撞；不能把“所有错身份必拒绝”强加到小参数上，也不能把接受的碰撞隐藏为跳过。

复现主要命令（仓库根目录）：

```powershell
$env:PYTHONPATH='src'
python -m pytest tests/test_wang_pw_ibs.py tests/test_wang_pw_boundary_regressions.py tests/test_wang_pw_sampling_regressions.py tests/test_wang_pw_linear_regressions.py -q --tb=short
python experiments/research/wang_pw_receipt.py --out build/outputs/wang-pw-receipt.json
$wangHash = (Get-FileHash src/ibme/ibs/wang_pw.py -Algorithm SHA256).Hash.ToLower()
python experiments/research/wang_pw_linear_audit.py --expected-sha256 $wangHash --output build/outputs/wang-pw-linear.json
```

Sage 对照在既有 WSL conda 环境中运行：切到仓库后执行 `~/miniconda3/envs/sage/bin/python experiments/research/wang_kernel_exact.sage --out build/outputs/wang-pw-sage.json`。这里用该环境的 Python 执行使用 sage.all 的脚本；本机 sage 前端不透传 --out，不能把其参数错误计作通过。

历史原版反例脚本需要显式提供未修改的原交付 wang_pw.py：`python experiments/research/wang_pw_independent_audit.py --subject <原版路径> --out <历史反例结果路径>`。脚本强制检查原版 SHA256 为 `119f1168003b99a39172ce1cb2513658a2ad56ca4925b6c33bcdeb09890c1b8d`；预期退出1表示成功复现被审查实现的缺陷，不是新版回归失败。该私人外部目录没有自动打包进仓库。

## 本次可用结论

可以写“Wang 基本 IBS 与 Pan–Wagner 转换的独立参考代码已实现，并完成所列范围的代码修复、回归与独立代数对照”。不能写“已经证明绝无 bug”“无限离散高斯精确采样”“已证明安全等级”或“已接入完整 IB-ME”。

本轮未改协议和正式参数，保持 `security_claim=none`、`parameters_are_formal=false`、`backend_admitted=false`。后续 DeepSeek 任务是对本次固定版本独立终验；发现新反例直接修复并重跑受影响范围。
