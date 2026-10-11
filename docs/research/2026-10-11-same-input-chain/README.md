# 同组 CHKP 根、父级随机化、终层原像与真实噪声核验

日期：2026-10-11；基点`396eb53a70a46c2f6a44898476b5668238916562`。远端main与本地一致、无开放PR，上一轮CI成功。本轮按用户要求继续首套关键工作，把已交付的真实组件接到同组输入；不继续备用候选或独立性能优化。

**结果：两种奇素数配置、各两个预定测试流，4/4完成GenBasis → 父级RandBasis → 扩展父基终层SampleD → 固定32bit缓存及恢复。128/128原像方程成立，恢复不消耗熵。真实噪声仍有196/384解码错误、256bit容量仍拒绝，故不计完整HIBE或安全实例。**

工具为[主AI链核验](../../../experiments/research/ibme_chain_audit.py)，结果为[chain-results.json](chain-results.json)，交付/测试摘要见[audit.json](audit.json)。没有修改队友chkp_*文件、生产HIBE/协议/CLI、默认采样选项或任何原语硬上限。

## 1. 从单体进展到同组链路

上一轮的183维根采样和连续取整噪声是两个独立组件，不能拼成同组两层成功。本轮每个预定流只生成一次实际AP09根，宽度全部由固定公开GS上界计算；父级扩展后实际调用GPV/RandBasis/ToBasis，再从随机化父级扩展出终层，真实采样32个原像，并调用队友FixedLeafCache。

依据[36页CHKP作者稿](../../../papers/2010_bonsai_trees_cash.pdf)2011-06-14版§5.2/PDF19–20，最大深度可以省去用于再次委派的叶基，解封装原像从扩展父级基采样。因此本路径包含一次父级RandBasis，**不新增第二次叶级RandBasis**。这仍不是ROHIBE：矩阵块和syndrome使用独立测试随机流，未实现§5.3/PDF22的H/G；rcv-test/phi-test仅为8 B缓存标签，不是实际身份映射。

固定缓存装入32个位置。首次抽样后的私有快照仅在内存中序列化/恢复，逐向量验证方程，重取和恢复重取都不能调用熵源；不导出基、原像或私有wire。报告只记录公开配置、标量范数/计数、快照字节数和公共矩阵摘要；不把这些诊断作为生产密钥格式。

## 2. 参数、误差与默认随机带阻塞

所有配置均为教学/诊断参数；`n=1`，没有合法LWE安全等级。AP09参数中r为random_rows、Cprime为hadamard_scale；终层不是另一次随机化。

| q | r / m1 / m2 / Cprime | 根/父/叶维度 | 公开根GS²上界 | s1² | s2² | 噪声alpha |
|---:|---|---|---:|---:|---:|---|
| 17 | 6 / 6 / 22 / 9 | 28 / 56 / 84 | 869 | 135564 | 1214653440 | 1/17 |
| 257 | 10 / 10 / 38 / 10 | 48 / 96 / 144 | 1695 | 271200 | 4269772800 | 1/257 |

每种q的两个预定流为`ibme-same-input-q{q}-0/1`，各子操作有固定角色后缀。不筛选种子；重复运行同流是重放，不增加独立实验数。根公开分布的现有AP09 TV证书在两种配置都达到平凡上界1，不能声称根近均匀已达标。

先保留未经处理的父基默认准入及规约后父基默认准入，再尝试**预定的显式profile**。默认RandBasis需要的最坏随机带为1.515–1.531 GB（q=17）或约3.792 GB（q=257），超过原256 MiB上限，构造器在抽样前拒绝。它不是实际内存峰值，也不是实际熵消耗。

显式选项仅调用现有接口：

```text
epsilon_bits=32, max_vectors=D_parent+32
tail_bits=64, mass_bits=96, precision_bits=160
gaussian_abort_bits=32, max_uniform_trials=48
其它OnlineOptions保持原默认值
```

这是降低有限误差精度目标来换取可执行支持域，**不修改默认profile，也不绕过拒绝**。每一标量Gaussian的尾、量化/区间和ABORT误差仍从原证书逐项计算，父级RandBasis失败上界约为`2.33905e-6`或`5.78953e-6`；它们是给定输入的有限模型上界，不是安全位数。没有随机执行失败后换profile/重抽；失败和异常均有明确outcome。

| 测试流 | 默认父级最坏带/B | 显式父级最坏带/B | 实际父级熵/B | 消耗Gaussian向量 | 32原像最坏带/B | 实际叶熵/B | 缓存快照/B |
|---|---:|---:|---:|---:|---:|---:|---:|
| q17-0 | 1515465600 | 92996640 | 361128 | 56 | 76317696 | 379419 | 19605 |
| q17-1 | 1515500800 | 93015648 | 372012 | 56 | 76317696 | 385845 | 19611 |
| q257-0 | 3792076800 | 232243200 | 1018296 | 96 | 131983488 | 634059 | 33415 |
| q257-1 | 3792076800 | 232215552 | 1032488 | 96 | 131968512 | 645153 | 33423 |

上表默认带是规约后父基；原父基拒绝另保存在JSON。四组显式父/叶最坏带均不超过268435456 B。维度192、scalar width²≤10^12、RandBasis带256 MiB、单批32原像和既有cache/wire限制全部保持；实际熵字节远小于最坏带，不用实际值替代资源准入上界。

## 3. 规约的具体修复与准入边界

未经规约的ToBasis父级结果，扩展到终层时均因过小GS导致坐标Gaussian width²超过10^12而拒绝；4/4失败保留。独立Sage规约后四组叶Sampler获准，使用相同先验s2²，未按测得秘密GS临时调小宽度。

[原根诊断工具](../../../experiments/research/ibme_root_sampler_audit.py)原来以Sage默认eta=0.501运行，却精确检查|mu|≤1/2。预先测试的q257固定根出现`mu=-260/519`，说明两者不一致。直接要求eta=1/2在本机采样父基上触发fplll的`infinite loop in babai`，首次回归为17 passed/5 errors，不能把这样的库错误当作方案不适用。

本轮改成一次预定的Sage LLL(delta=0.999,eta=0.501)，再用精确有理数计算nearest integer并作整数列size reduction，同时更新列变换矩阵。列加法保持每个GS向量和格行列式；相邻mu平方最多下降`0.501²−0.499²=0.002`，delta余量充足。最终仍独立检查：

- 原基乘列变换等于结果、列变换det为±1、完整核格关系和det=q^n。
- 最大GS²不超过原固定公开界，全部|mu|≤1/2，delta=0.99的Lovasz条件。
- 实际GPV所有坐标宽度、中心/残差有理数位数和整次随机带仍由交付构造器检查。

没有规约失败后重试或改用公开核格基冒充秘密GenBasis。本次依然是**独立诊断**：未提供统一运行时间、内存、概率ABORT或侧信道界，不替代队友≤64维有界规约，也不成为获准Setup步骤。q257随机化父级规约后的最小GS²约0.03，不能错误概括成“规约后每个GS²都至少1”；实际最大坐标宽度仍低于原10^12上限。

## 4. 方程、范数、缓存与真实噪声分开验收

128个实际终层原像均满足A_leaf*x=y mod q，所测128个范数都在s2²*D_leaf以内。测得范数不代替所有原像的坏范数概率界。缓存恢复128/128原像保持相同、零新熵；这些是内存快照验收，已有CLI磁盘事务在上一轮单独验证，本轮没有新增跨进程HIBE密钥格式。

按CHKP §5.1/PDF18–19的位相位公式和共享前导，使用上一轮**真实连续Gaussian取整**工具，各流做3次32bit相位诊断，均使用`q*alpha=1`。每次仅抽D+32个噪声；合计1752次噪声调用，其中370个非零，有限噪声证书随结果记录。输出位取交替0/1的诊断输入；没有封装随机32 B种子或形成密文wire。

| 测试流 | 有噪声相位方程 | 无噪声代数控制 | 真实噪声正确bit | 真实噪声错误bit |
|---|---|---|---:|---:|
| q17-0 | 96/96 | 96/96 | 52 | 44 |
| q17-1 | 96/96 | 96/96 | 44 | 52 |
| q257-0 | 96/96 | 96/96 | 47 | 49 |
| q257-1 | 96/96 | 96/96 | 45 | 51 |

这是**预定的负面对照噪声profile**，未满足完整q/宽度/取整正确性条件；实际196/384错误与失效条件一致。无噪声384/384只证实代数方向、符号和模q解码接线，绝不是替换噪声后的成功加解密。相位方程检查精确，奇数q和平局按严格更近0返回0，否则1；不能只按浮点q/4判断。

有限噪声账本仍按同组q/alpha/D/L调用计数附接，但条件正确性不成立时寿命失败上界为null，不能填默认零。JSON的`randbasis_and_leaf_sampling_terms_upper`仅为所选RandBasis/叶采样项之和；坏范数、根分布、规约/资源失败及解码项明确排除，`full_joint_failure_upper=null`。

每流另外向交付leaf入口提交256个目标，并用禁止读熵源确认在抽样前拒绝。完整Hybrid所需32 B种子仍缺256个固定地址/分批/私有wire；不能为同一child换plan或创建新cache来把32的上限藏起来。噪声、256bit、实际H/G和整链参数必须同时闭合。

## 5. 测试、复跑与环境

新增19项Sage检查覆盖真实小型完整链、缓存恢复、容量、数据不导出、奇数q解码、原文噪声相位、精确规约和父级ABORT不重试。旧相关检查复用，批次重叠不能相加。本轮没有XFAIL或把失败标记为成功。

```text
python -B -m pytest -q -p no:cacheprovider tests/test_ibme_noise_budget.py tests/test_ibme_rounded_noise.py tests/test_ibme_joint_parameters.py tests/test_ibme_root_sampler_audit.py tests/test_ibme_chain_audit.py tests/test_ibme_handoff_screen.py tests/test_chkp_paper_preflight.py tests/test_chkp_t2_conditions.py --tb=short --junitxml=test-results/same-input-chain-native.xml
# Windows: 160 passed,6 skipped in 0.45s

PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -B -m pytest -q -p no:cacheprovider tests/test_ibme_noise_budget.py tests/test_ibme_rounded_noise.py tests/test_ibme_joint_parameters.py tests/test_ibme_root_sampler_audit.py tests/test_ibme_chain_audit.py tests/test_ibme_handoff_screen.py tests/test_chkp_paper_preflight.py tests/test_chkp_t2_conditions.py tests/test_chkp_basis.py tests/test_chkp_gpv.py tests/test_chkp_randbasis.py tests/test_chkp_leaf.py tests/test_chkp_leaf_cache.py --tb=short --junitxml=test-results/same-input-chain-sage.xml
# WSL Sage: 409 passed in 56.45s

PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -B -m experiments.research.ibme_chain_audit --output test-results/same-input-chain/results.json
# 4/4链诊断完成，退出码0；不是安全准入退出码
```

WSL先进入仓库，只使用指定`~/miniconda3/envs/sage`；文档不写死用户路径。Windows的6个skip均为明确的Sage边界，已在指定环境执行。环境：Intel Core Ultra9 275HX，Windows Python3.14.6/WSL Python3.13.14、Sage10.9、pytest9.1.1。输入是8 B测试身份标签、每组32个固定目标、3次32bit相位；无应用消息、无IBS或完整IBME性能数据。

单流诊断耗时7.35/6.97/70.69/73.46 s，含GenBasis、精确GS/规约、所有证书/检查及缓存序列化，不是公平性能评测，也未测内存峰值。最坏随机带、实际熵和wall time分别报告。classic ROM只作原文安全模型引用；测试随机流不等价于独立理想RO或生产熵。

首次测试eta=1/2导致的5项error已修复，最终无测试失败；中途一条回归命令的测试文件名错误导致no tests ran，改正后执行上述完整选定批次。最早相位诊断的Sage行数API调用及证书键名错误在收集最终结果前修正；未将这类代码错误解释成密码学反例。最终数据源的15个LF归一化指纹已与当前执行源核对。旧183维根报告保留为当时提交的历史结果，不改写为本轮新样本。

## 6. 修改边界与下一步

本轮13个文件：

| 范围 | 文件 |
|---|---|
| 主AI实际核验和修复 | experiments/research/ibme_chain_audit.py；experiments/research/ibme_root_sampler_audit.py；tests/test_ibme_chain_audit.py |
| CI与入口/冻结条件 | .github/workflows/basic-checks.yml；README.md；IMPLEMENTATION_SPEC.md；docs/PROJECT_RESTART.md |
| 责任和排序 | docs/workplans/2026-10-08/主AI任务-IBS集成与优化.md；docs/workplans/2026-10-08/队友任务-CHKP与格工具.md；docs/workplans/2026-10-10/首套系统关键路径与优先级.md |
| 本轮交付 | 本README.md；chain-results.json；audit.json |

跨范围原因是同组组件的支持域、失败语义和后续接手需要统一；未占用队友原语实现，也未改生产协议或接口语义。CI增加Sage模块的明确跳过说明；本地实际Sage结果单独交付。

下一项不继续相同教学链扩样，应优先解决可覆盖完整q/alpha/宽度/根近均匀和实际LWE条件的实现支持域，以及256地址和真实H/G/KEM。当前35区间门槛空交集仍成立：本轮只让采样链可运行，**没有满足那组q充分条件**。需要有依据的实现支持域/采样或GenBasis路线调整，不能仅继续盲换小参数。队友负责完整CHKP原语和容量，主AI复用本次核验、已有噪声与状态事务，收到合格完整原语后接Wang/BYTEAUTH及攻击验收。

WIP：完整两层匿名HIBE、同组正式选参/攻击估计、统一规约/资源/ABORT界、256个固定地址及wire、真实H/G/bit KEM/字节适配、完整组合攻击验收。旧education公开伪造与冒名两个认证漏洞仍未修复。全部保持`security_claim=none,backend_admitted=false,parameters_are_formal=false`，不宣称QROM、NIST等级、完整匿名性或A+B<C。功能与精确算术检查不能替代安全证明。
