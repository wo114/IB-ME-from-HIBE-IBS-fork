# T5：第三组完整系统基线与统一公开数据

本批在A有界实测结束后，复用相同公共runner完成**LATTE-3/COSAC-FIX＋Luo模格IBS默认research/compact、Hybrid、BYTEAUTH**的三套独立系统随机状态。代码冻结`949bf91562489ca43e82626405a6f6c67c07a6f4`；runner与[ML-DSA](../2026-10-18-full-system-baseline/README.md)、[Falcon](../2026-10-18-full-system-falcon/README.md)两批逐字相同。没有修改Luo、LATTE、协议或基准实现。

每套实际生成一份系统状态和两种用户钥，首次完整加解密、3对warm、另起新进程3次零熵恢复解密。**3次首次解密、9对warm和9次恢复均成功**，无失败后换随机数、外层重抽或后端替换。完整公开原始记录见[收据](evidence/latte-luo-compact.json)。原始身份64/64 B、消息32 B，LATTE内层身份86/86 B、种子32 B；未清空OS缓存或重建引擎。

| 阶段 | 次数 | 中位数 / s | 最小—最大 / s |
|---|---:|---:|---:|
| 共同Setup | 3 | 0.964105 | 0.932728—0.987364 |
| 发送钥 | 3 | 0.318922 | 0.117057—1.068431 |
| 接收钥 | 3 | 0.472760 | 0.413145—0.664676 |
| 首次完整Encrypt（含wire） | 3 | 0.609756 | 0.364951—0.716387 |
| 首次完整Decrypt（含叶提取） | 3 | 0.382824 | 0.376244—0.396839 |
| warm完整Encrypt（含wire） | 9 | 0.364461 | 0.295303—0.937518 |
| warm完整Decrypt | 9 | 0.229220 | 0.215597—0.245983 |
| 新进程对象恢复/绑定 | 3 | 0.779928 | 0.741585—0.800935 |
| 恢复后完整Decrypt | 9 | 0.234768 | 0.228948—0.257552 |

发送钥和签名相关阶段有明显波动，保留全部观察值；本批未额外读取或改变内部拒绝采样计数，不能把波动全部归因于某一个内部步骤。import/build-runtime的6次原始值分属生成/恢复进程，需分别查看；整进程wall含该进程的导入、cold/warm等操作，不是纯加密时间。

12份完整最外层密文（3次cold＋9次warm）为**151876—151955 B**。独立对象：公开钥260819—260851 B、主状态522253—522339 B、接收状态128166—128243 B、发送钥313813 B；主状态有缓存，尺寸不能简单相加称去重总存储。10 ms进程树RSS最大观察493281280 B（约470.43 MiB）；树求和可能重复计算fork共享/COW页，采样可能漏短峰，不能称严格独占物理峰值；self和内核累计高水位亦在收据中。

每套生成进程LATTE Setup/Delegate/Extract各1次；每套恢复均为0，IBS Setup/KeyExtract/Sign被禁止，公共SecureRandom耗熵0 B，公钥、接收状态和既有密文文件不变。恢复解密继续使用已有固定叶。该批是正向生命周期/性能记录，四种匹配、错配/篡改、CLI与安装的完整验收沿用[既有共同框架交付](../team-c-delivery/2026-10-15-c-framework/README.md)，未冒称本次重跑全部负例。

## 三组数据可以怎样使用

三组同机器、同输入长度、相同包装与计时边界的原始数据，已汇成[comparison.json](evidence/comparison.json)，包含各自完整suite、计时观察值、尺寸、环境和公开源文件SHA。它可直接供后续界面/报告读取；生成与核验工具为[evidence/compare.py](evidence/compare.py)，Windows在仓库根执行即可。核验2340个provider记录与原各自Git源码一致、三个runner相同，没有打开任何私有状态。

这三组都是完整IB-ME研究组合，HIBE均为LATTE，IBS分别为Luo模格、BNN-ML-DSA、BNN-Falcon；**不算三个独立HIBE，也尚未自动选定为报告的三个最终代表**。各自安全目标与转换模型未证明等价，因此按`security_group`分组展示，不把耗时直接排成“同安全级别最快”，也没有联合优化收益声明。报告的三个代表仍须兼顾实际用途、困难假设和可执行参数；A小规模功能对照与目标参数投影另列。

## 参数、环境和复跑

LATTE保持作者LATTE-3：N1024、q68718428161、FFT精度768 bit及COSAC-FIX。Luo是当前默认research参数：degree256、k11/l10、q274877844481、eta1、kappa64、gamma1=125440、gamma2=31470387200、gamma3=15270991360、dropped_bits28；提取/签名帽各1024，uniform128，消息上限4096 B，compact签名16063 B。这组不是C64B显式候选，不能混用其条件概率或安全估计。完整参数以收据suite为准。

Core Ultra9 275HX、指定WSL Sage10.9/Python3.13.14、Linux6.18.33.2、OMP4/OPENBLAS1；未与其它密码实测或完整回归同时运行。3套cold/每套3warm只是小样本基线，warm共享各套状态，不推断罕见中止或稳定尾部概率。LATTE引擎复用已有构建，补[独立运行后metadata/二进制SHA查询](evidence/native-provenance.json)及[脚本](evidence/native-provenance.py)，禁止生成和熵读取；这是运行后查询，未冒称worker本身记录二进制SHA。Luo为现有Python实现，provider SHA在各worker内捕获。

```sh
PYTHONPATH=src:. OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=1 \
timeout --signal=TERM --kill-after=10s 300s ~/miniconda3/envs/sage/bin/python \
 -m experiments.research.full_system_benchmark --suite-file ci/c-combinations.json \
 --suite-name latte3-hybrid-luo-module-research-compact-byteauth-v1 \
 --private-directory test-results/full-luo-new --repetitions 3 --warm-repetitions 3 \
 --identity-bytes 64 --message-bytes 32 \
 --security-group latte3-cosac-fix-luo-module-default-compact-research --source-commit <固定代码提交>
```

本批整个调用另加300秒外部上限，实际完成；原runner每worker900秒的内部限额未更改。潜在外部超时保留已有pending/失败状态，不作为算法不可能的判据。真实密钥、随机字节和完整密文内容留在ignored私有目录，公开收据只含统计、尺寸和指纹。

算法安全与HIBE身份匿名沿用用户确定的工作前提，理论以既有论文引用为主；ROM及模型依赖按各原语记载。所有结果仍为`security_claim=none,backend_admitted=false,parameters_are_formal=false`，功能与计时不产生安全等级。剩余四天将优先[演示、报告和冻结复现](../../workplans/2026-10-18-four-day-delivery.md)，不继续扩张A高维采样任务。
