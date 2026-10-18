# T5：第二组完整系统重复基线（LATTE＋BNN-Falcon）

本批复用首组的完整IB-ME评测工具，实际完成LATTE-3/COSAC-FIX＋BNN-Falcon padded512、Hybrid、BYTEAUTH的三套独立系统状态。每套有首次加解密、3轮warm加解密及新进程3次零熵恢复解密，**3次首次解密、9对warm、9次恢复全部匹配**。代码冻结`a709e82c01bd30db590452cef6f0401d8e8c3635`；该版本的公共评测入口与[首组ML-DSA基线](../2026-10-18-full-system-baseline/README.md)逐字相同，审计见[A公开核验](../team-a-delivery/2026-10-18-radix-screen/evidence/verification.json)。未修改任何原语或协议。

完整参数、逐次值、环境和源码provider指纹见[公开收据](evidence/latte-falcon512.json)。64 B原始发送者/接收者身份、32 B消息，内层身份86 B、KEM种子32 B；未清空OS缓存，已构建引擎保留。每个生成/恢复worker均为新Python进程，没有外层重抽、失败后替换或计时重跑。

| 阶段 | 观察次数 | 中位数 / s | 最小—最大 / s |
|---|---:|---:|---:|
| 共同Setup | 3 | 0.911282 | 0.847019—0.963223 |
| 发送钥 | 3 | 0.160366 | 0.155577—0.162212 |
| 接收钥 | 3 | 0.511102 | 0.455781—0.620782 |
| 首次完整Encrypt（含wire） | 3 | 0.217907 | 0.187253—0.234456 |
| 首次完整Decrypt（含叶提取） | 3 | 0.368917 | 0.362362—0.387979 |
| warm完整Encrypt（含wire） | 9 | 0.200346 | 0.166940—0.215199 |
| warm完整Decrypt | 9 | 0.249274 | 0.215359—0.291406 |
| 新进程对象恢复/绑定 | 3 | 0.674278 | 0.667017—0.685119 |
| 恢复后完整Decrypt | 9 | 0.247483 | 0.207398—0.300260 |

import/build runtime同名汇总有6次观察，包含生成/恢复两种进程；分别分析须读原始worker，不称纯解释器启动。生成进程wall为6.916/5.666/6.015 s，含该套cold全流程、持久化和3轮warm；恢复进程wall为3.854/3.856/4.144 s，含导入、恢复和3次解密。

12份完整密文（3次cold＋9次warm）为**138150—138207 B**。独立持久对象：公开钥13973—14020 B、主状态172047—172371 B、接收状态128078—128230 B、发送钥4195 B。主状态含缓存，不能把它和独立接收状态相加当作去重尺寸。

10 ms进程树RSS最大观察为480043008 B（约457.80 MiB）；树求和可能重复计入fork共享/COW页，采样也可能漏短峰，不能称严格独占物理峰值。收据另存self和completed-child内核累计高水位。三套cold样本较少，warm共享各套状态；本批不估计罕见中止或稳定尾部概率。

每套生成进程LATTE Setup/Delegate/Extract各1次，Falcon Keypair2次/Sign5次；每套恢复进程这些操作均为0，公共随机源0 B，接收状态字节未变。恢复只复用已缓存叶，不重新生成私钥或签名。该批是正向生命周期/测量验收；四种匹配、负例、CLI及安装继续引用[既有共同框架记录](../team-c-delivery/2026-10-15-c-framework/README.md)，未冒称本次重跑。

环境为Core Ultra9 275HX、WSL2 Linux6.18.33.2、指定Sage10.9/Python3.13.14、OMP4/OPENBLAS1。A公共参数筛选进程已结束后才开始该批密码运算计时。复用已安装本机引擎，运行前/后的独立只读[metadata与二进制SHA查询](evidence/native-provenance-before.json)及[运行后查询](evidence/native-provenance-after.json)完全相同，未重建；查询不生成根、密钥或签名。它们是独立查询，未冒称worker本身记录了二进制SHA。[查询脚本](evidence/native-provenance.py)与公开收据一同保存。

LATTE参数为作者LATTE-3 N1024、q68718428161、FFT精度768 bit及COSAC-FIX；Falcon使用作者v1.2 padded512，BNN身份签名为既有reference格式。实际suite定义在收据中。沿用已确定算法安全/身份匿名的工作前提及各原语ROM口径，不新增安全证明任务；全部仍为`security_claim=none,backend_admitted=false,parameters_are_formal=false`。独立分组`latte3-cosac-fix-bnn-falcon512-research`；与ML-DSA组按同一测量边界展示，但未证明两组同一安全目标，**不作跨组性能排名或优化收益声明**。

复跑在仓库根使用新ignored私有目录：

```sh
PYTHONPATH=src:. OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=1 \
~/miniconda3/envs/sage/bin/python -m experiments.research.full_system_benchmark \
 --suite-file ci/c-combinations.json \
 --suite-name latte3-hybrid-cert-falcon-falcon-padded-512-reference-byteauth-v1 \
 --private-directory test-results/full-system-falcon-new \
 --repetitions 3 --warm-repetitions 3 --identity-bytes 64 --message-bytes 32 \
 --security-group latte3-cosac-fix-bnn-falcon512-research --source-commit <固定代码提交>
```

真实钥、随机字节、原像和完整密文留在ignored实验目录，公开材料只含allowlist统计/尺寸/指纹。其余配对、同目标完整参数、三代表选择、联合优化与消融、作品界面/报告/答辩/发布仍按[当前状态](../../PROJECT_STATUS.md)推进。
