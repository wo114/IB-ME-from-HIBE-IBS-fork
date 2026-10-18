# T5：完整 IB-ME 重复评测首组基线

代码提交 `6b5305a`：`experiments.research.full_system_benchmark`，统一计时/内存边界见[规范](../../specs/full-system-benchmark.md)。本批实际执行 LATTE-3/COSAC-FIX + BNN 认证转换 ML-DSA-44，复用现有公共协议、Hybrid、BYTEAUTH 与默认登记；不修改原语、协议或签名格式。没有选出三个代表，也没有宣布联合优化收益。

## 实际运行

完整参数、逐次观察值、聚合统计、provider指纹、native操作计数与环境在[原始公开收据](evidence/latte-mldsa44.json)。本批固定64 B发送者/接收者身份、32 B消息、3套独立系统随机根/用户钥，每套3轮warm加解密；每套另起进程恢复已有状态，3次零熵解密。**共3次首次解密、9对warm加解密、9次新进程恢复解密，全部匹配。** 每套实际LATTE native Setup/Delegate/Extract各1次；恢复进程三项均为0，普通Keypair/Sign也为0，公共随机源消费0 B，原接收状态字节不变。

| 阶段 | 观察次数 | 中位数 / s | 最小—最大 / s |
|---|---:|---:|---:|
| 共同Setup | 3 | 0.984492 | 0.926150—1.048546 |
| 发送钥 | 3 | 0.273598 | 0.216623—0.288389 |
| 接收钥 | 3 | 0.754343 | 0.688922—0.762147 |
| 首次完整Encrypt（含wire） | 3 | 0.224485 | 0.216995—0.301288 |
| 首次完整Decrypt（含叶提取） | 3 | 0.403997 | 0.393745—0.431785 |
| warm完整Encrypt（含wire） | 9 | 0.211125 | 0.191402—0.278521 |
| warm完整Decrypt | 9 | 0.280116 | 0.250437—0.345583 |
| 新进程对象恢复/绑定 | 3 | 0.665062 | 0.645693—0.699905 |
| 恢复后完整Decrypt | 9 | 0.281654 | 0.245047—0.385978 |

import/build runtime的6次原始记录分别属于生成和恢复进程；原脚本同名汇总保留6次合并统计，跨模式分析应读取各worker原始记录。生成进程wall time为6.989/6.630/6.717 s，包含该套cold生命周期、持久化和3轮warm；恢复进程为4.387/4.292/4.091 s，包含导入、恢复和3次解密。以上不是“纯解释器冷启动”或磁盘缓存清空实验。

12个完整密文（3次cold+9次warm）为 **142051—142146 B**，随机状态下十进制LATTE内层编码的长度略有变化。独立持久对象：公开钥14352—14392 B、主状态177557—177671 B、接收状态128017—128098 B、发送钥8050 B。主状态含固定缓存，不能将主状态与独立接收钥的合计误称去重存储。

10 ms进程树RSS最大观察为 **480243712 B（458.00 MiB）**；该观察发生于第三套warm Encrypt，self为240119808 B（229.00 MiB）。进程树求和可重复计入fork的共享/COW页，其余两套最大观察约253 MiB；这不能解读为第三套独占内存翻倍。收据同时给出self及completed-child内核累计高水位。采样可能漏掉短峰值，本批不作PSS或严格全进程物理峰值声明。

## 环境与口径

Core Ultra 9 275HX，WSL2 Linux6.18.33.2、指定conda Sage10.9/Python3.13.14，`OMP_NUM_THREADS=4`、`OPENBLAS_NUM_THREADS=1`。复用已核源码ABI的LATTE和ML-DSA本机引擎，本批未重编；另补[运行后公开metadata/二进制SHA查询](evidence/native-provenance.json)与[查询脚本](evidence/native-provenance.py)，未生成任何根、密钥或签名。这是独立的运行后查询，不冒称原worker内已记录二进制SHA。每个生成/恢复worker是全新Python进程，操作系统缓存保留；未与A规模测量同时运行。成功后未重抽、替换后端或补零；无worker算法中止/超时。三套cold样本仅建立可重跑基线，warm样本共享各自状态，不用于稳定尾部概率或跨目标排名。

LATTE参数保留作者LATTE-3：N1024、q68718428161、FFT精度768 bit、三层标准差及COSAC修订，详见[已有原语交付](../team-c-delivery/2026-10-14-latte-hibe/README.md)。BNN转换使用已交[ML-DSA-44](../team-c-delivery/2026-10-14-cert-mldsa/README.md)档；完整选参以收据`suite`为准。沿用所选算法安全、HIBE身份匿名的工作前提，ROM条件按各原语记录，测试不产生安全证明；全部仍为none/false/false。显式分组`latte3-cosac-fix-bnn-mldsa44-research`，与A小参数或其它安全目标分开展示，**不做性能排名**。

复跑命令见[规范](../../specs/full-system-benchmark.md#调用)，公开源码指纹核对入口见[A证据脚本](../team-a-delivery/2026-10-18-3m-feasibility/evidence/check-sources.py)。真实密钥、随机字节、原像、完整密文和私有诊断均留在ignored `test-results/`，未放入本交付。共同框架、CLI/安装先前验收继续引用[已有接入记录](../team-c-delivery/2026-10-15-c-framework/README.md)，本批不冒称重新完成全组合负例或仓库外安装。

## 后续仍待

用相同输入、环境、计时/尺寸/内存边界接入其它就绪配对；安全目标不同继续分组。待实际可比较目标参数与多组完整运行数据齐备，再选择三组场景代表、定位瓶颈、做联合优化及完整系统消融。界面、报告、PPT与干净环境发布仍属于统一交付任务。
