# 多后端准备复用与完整流程消融

本任务按用户确认的“三代表优先，再补Luo／Falcon”推进。实现已提交[PR75](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/75)，当前实验材料仍在补齐。旧作品报告、PPT及PR73的报告正文不在修改范围。

2026-10-20审查衔接：新运行配置沿用用户确认的`secure/true/true`；本目录既有A数据及原wheel／源码清单保留执行时的`none/false/false`和原摘要。只读复核兼容这两个完整快照，算法、预算、格式和原始测量仍精确比较。SRGG运行储备和计划复用已移入独立适配，历史研究源码保持原字节。后续发布版本复现须明确其新源码与清单，不能把已有记录改写为新版本实跑。

## 改动和成本

| 对象 | 实现 | 成本／边界 |
|---|---|---|
| A：LATTE＋BNN/ML-DSA-44 | 成功证书语句的有界LRU；每条消息继续原生验签 | 默认64条、上限256条公开语句；0关闭。命中也重新检查原生引擎与消息签名 |
| B：LATTE＋SRGG论文PARAM-I compact | 同一冻结签名钥的确定性SampleF准备复用 | 默认最多2个秘密相关计划、上限16个；0关闭。不同对象／数值选项重新准备；每次采样使用新熵预算 |
| C：Lai C2＋Sageloli RSIS v3 PARAM-I | 显式进程内接收会话：真实Derive一次，复用已验证叶钥 | 额外保留单接收者／发送者的叶钥；需close，不持久化；原Lai和CLI仍无状态 |
| Luo：LATTE＋Luo模格compact | 固定NTT因子、位反转置换及逆元预计算 | 每个N=256环额外准备510个因子整数、256个置换整数和1个逆元；公开矩阵原有NTT缓存不冒称新增成果 |
| Falcon：LATTE＋BNN/Falcon padded-512 | 与A相同的完整证书正结果复用 | 仍是原Falcon研究转换及其参数；不是新增签名算法或安全等级 |

缓存／会话只复用准备状态，不缓存随机扰动、随机签名或消息验签结果。清空释放Python引用，不承诺物理内存清零。[会话契约](../../specs/prepared-receiver.md)说明绑定、验证和关闭语义。

## 实验口径

实际安装代码为`b4b31d8f76654e108e4443e369e67729b2b6936b`；[安装清单](installation.json)给出wheel摘要，[源码清单](source-manifest.json)包含495个包内Python文件摘要。所有实际导入的`ibme`／研究模块必须位于独立安装目录且匹配清单。运行在指定WSL Sage环境，单独向安装目录安装cryptography 50.0.2，未修改系统Python。原生二进制沿用经ABI／源码检查的原构建。

A/B/C的Suite摘要与[三代表冻结配置](../../deliveries/2026-10-19-report-three-selection/README.md)逐项相同。输入固定64 B发送者／接收者身份、32 B应用消息，使用系统CSPRNG，每次加密使用新IBS随机性和新OTS。每组保留`none/false/false`，不增加安全证明，不跨安全目标排名。

A/B/Luo/Falcon各生成3个独立根；每根两种模式各3轮完整加密和解密，顺序交错。参数、同一根、同一用户钥、既有LATTE叶钥及安装完全相同。计时包含Suite验证、规范wire编码／解析、Hybrid、BYTEAUTH、IBS和原生进程启动。首次生成、准备、预热独立记录；完整流程计时采用相同10 ms RSS观察器。RSS是整棵进程树采样峰值的下界，不能解释为单独缓存的堆大小。多次使用同一根的点不是独立根样本。

C单独作为一根的状态摊销研究：至少2次原无状态解密、一次真实会话准备、至少3次会话解密。先生成并在持久用户目录保留私钥、备份到被忽略的本地目录，再进行长操作；每个计时操作上限1200 s，不因失败重抽根。C的结果不能并入上述三根配对基准或称为原无状态解密成本。

每组还执行截断、追加、重复、字节修改和三种错地址负例。错地址使用本来有效的IBS载荷和新OTS，只改变HIBE地址，避免畸形载荷造成无意义的拒绝。有效外层／无效内层用真实IBS签名覆盖另一消息，并确认完整解密实际到达IBS且返回False。

## 当前已完成的实测

[A原始记录](A.json)：三根均完成诚实往返和全部负例。重复解密的ML-DSA原生verify调用由每次2次降为1次，消息verify保留。三根“各模式根内中位数之比”为0.992、1.086、1.339，中位比1.086。样本较小且第一根略有回退，因此只能确认调用减少及本批有限收益，不能声称稳定翻倍。加密算法未改变，其耗时变化视为对照噪声，不当作证书缓存收益。

B、C及Luo／Falcon的完整数据完成后补入本目录；不能从单元测试推定性能收益。

## 复核与复现

只读一致性复核入口为`python -m experiments.research.verify_backend_optimization --directory docs/research/2026-10-20-multi-backend-optimization`；五份记录齐全后才会返回全量consistent。它检查配置、源码出处、成功／负例状态、次数和统计，**不重新运行密码学实验**。单个组可调用同模块`validate_batch`。

真实重跑入口为`python -m experiments.research.backend_optimization_probe`。从本源码构建wheel并安装到持久的用户目录，安装`ibme[hybrid]`依赖；使用清单确认包内文件与该提交一致。Suite由`expected_suite('A'|'B'|'C'|'Luo'|'Falcon')`生成，传入`--label`、`--suite-file`、`--source-commit`、`--installed-root`、`--manifest`、`--private-directory`、`--backup-directory`、`--public-output`、`--repetitions 3 --operation-timeout 1200`。清空源码PYTHONPATH，切换到仓库外的安装目录，设置原LATTE／ML-DSA／Falcon／Sageloli桥的位置和`OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=1`。私有输出目录必须全新且在用户主目录下，已有状态不可覆盖。

首次安装预检因缺少cryptography而在build-runtime阶段失败，尚未进入Setup或占用任何密码学根。修正安装依赖及驱动失败收据的重复字段错误后，使用上述新提交、新安装继续；原失败诊断保留在本地。它不属于采样失败后的换根重试。
