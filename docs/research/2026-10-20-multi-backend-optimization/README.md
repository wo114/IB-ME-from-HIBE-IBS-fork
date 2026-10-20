# 多后端准备复用与完整流程消融

本任务按用户确认的“三代表优先，再补Luo／Falcon”推进。五组原始数据、准备／状态成本、Luo补充控制试验及表图已齐，提交至[PR75](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/75)。[汇总表](tables.md)、[原始点图及C摊销曲线](optimization.svg)、[PDF图](optimization.pdf)可用于后续报告整合。旧作品报告、PPT及报告正文不在本次修改范围。

2026-10-20审查衔接：当前配置沿用用户确认的`secure/true/true`；本目录整批固定原wheel `b4b31d8`，保留其`none/false/false`和原摘要，后续辅助组也按该归档快照做同源对照，不冒称合并后版本实跑。只读复核兼容这两个完整快照，算法、预算、格式和原始测量仍精确比较。当前SRGG运行储备和计划复用已移入独立适配，历史研究源码保持原字节。发布版本复现须明确其新源码与清单，不能把已有记录改写为新版本实跑。

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

实际安装代码为`b4b31d8f76654e108e4443e369e67729b2b6936b`；[安装清单](installation.json)给出wheel摘要，[源码清单](source-manifest.json)包含495个包内Python文件摘要。所有实际导入的`ibme`／研究模块必须位于独立安装目录且匹配清单。运行在指定WSL Sage 10.7、NumPy 2.4.3环境，单独向安装目录安装cryptography 50.0.2，未修改系统Python。原生二进制沿用经ABI／源码检查的原构建；[运行后环境及文件摘要](native-environment.json)补充复现信息，不冒称新的密码学实验或运行态认证。

A/B/C的数学参数、预算和编码与[三代表冻结配置](../../deliveries/2026-10-19-report-three-selection/README.md)逐项比较；本批记录保留当时的完整Suite摘要，当前`secure/true/true`配置另有新摘要。本批为i9-14900HX、WSL Linux 6.6.87.2、Sage环境Python 3.12.13，不和历史另一台机器的绝对耗时混算。输入固定64 B发送者／接收者身份、32 B应用消息，使用系统CSPRNG，每次加密使用新IBS随机性和新OTS。原数据不回写，不增加安全证明，不跨安全目标排名。

A/B/Luo/Falcon各生成3个独立根；每根两种模式各3轮完整加密和解密，顺序交错。参数、同一根、同一用户钥、既有LATTE叶钥及安装完全相同。计时包含Suite验证、规范wire编码／解析、Hybrid、BYTEAUTH、IBS和原生进程启动。首次生成、准备、预热独立记录；完整流程计时采用相同10 ms RSS观察器。RSS是整棵进程树采样峰值的下界，不能解释为单独缓存的堆大小。多次使用同一根的点不是独立根样本。

C单独作为一根的状态摊销研究：至少2次原无状态解密、一次真实会话准备、至少3次会话解密。先生成并在持久用户目录保留私钥、备份到被忽略的本地目录，再进行长操作；每个计时操作上限1200 s，不因失败重抽根。C的结果不能并入上述三根配对基准或称为原无状态解密成本。

每组还执行截断、追加、重复、字节修改和三种错地址负例。错地址使用本来有效的IBS载荷和新OTS，只改变HIBE地址，避免畸形载荷造成无意义的拒绝。有效外层／无效内层用真实IBS签名覆盖另一消息，并确认完整解密实际到达IBS且返回False。

## 当前已完成的实测

[A原始记录](A.json)：三根均完成诚实往返和全部负例。重复解密的ML-DSA原生verify调用由每次2次降为1次，消息verify保留。三根“各模式根内中位数之比”为0.992、1.086、1.339，中位比1.086。样本较小且第一根略有回退，因此只能确认调用减少及本批有限收益，不能声称稳定翻倍。加密算法未改变，其耗时变化视为对照噪声，不当作证书缓存收益。

[B原始记录](B.json)：三根均完成诚实往返和全部负例，实际缓存每根1条计划、1次miss和4次hit。首次准备为0.178、0.180、0.182 s；重复完整加密的逐根收益比为1.030、1.009、1.921，中位比1.030。小样本下第三根波动较大，不能将其单独挑成总体收益。解密路径未针对该优化改变，其变化视为对照噪声。计时阶段最高进程树采样RSS约489.32 MiB，包含Sage、协议对象、观察器等，不能当作单独缓存大小。

[C原始记录](C.json)：单根的2次原无状态解密和3次会话解密均成功，全部负例通过，含真实到达IBS并返回False的内层负例。原解密中位数526.272 s、会话准备509.548 s、后续解密中位数28.568 s；额外叶钥编码36,414,052 B。后续解密约18.42倍的比值不包括首次准备；第一条的含准备成本为538.115 s，略高于原路径，连续2／3条的每条均摊约283.341／198.417 s。N=10/100只作同根中位数公式外推，不能写为实际执行了这些轮数或多根重复。

[Luo原始记录](Luo.json)：三根诚实流程和全部负例通过，但新随机主批加密的逐根收益比中位数仅0.582，不能宣称稳定吞吐提升。各轮随机消耗约79–512 kB且与重试耗时一起波动。[补充完整流程重放](Luo-replay.json)复用这三根，每根3对，新CSPRNG种子通过TEST-ONLY分域流在两臂重放；9对密文和熵消费完全相同，均诚实解密，原文件未改变。控制重试后的加密逐根收益比为1.024／1.040／1.025，中位1.025，解密中位比1.074。该结果说明固定随机工作下的小幅改善，不能替换主批，也不新增独立根。最后自审另恢复了原`matvec(prepared=..., vector=...)`矩阵关键字兼容，数值路径和归档测量不回写。

[Falcon原始记录](Falcon.json)：三根诚实流程和全部负例通过，原生verify由2次降为1次，消息验签仍执行。解密逐根收益比中位数1.058，范围0.933–1.247；同样不能称为稳定翻倍。加密路径未因证书缓存改变，其变化作为对照保留。

五组只读一致性复核均通过，补充重放单独记账。[verified-summary.json](verified-summary.json)由原始点重新计算。[图像](optimization.png)已目视检查，矢量与PDF使用同一绘图数据。[回归与验证边界](validation.md)列出本线程实际执行的选择及结果。当前代码已接收队友修复；本批整体仍是明确绑定`b4b31d8`的归档安装实跑，最终发布源码／Suite／报告的精确复现仍是后续发布工作，不以本批冒充。

## 复核与复现

只读一致性复核入口为`python -m experiments.research.verify_backend_optimization --directory docs/research/2026-10-20-multi-backend-optimization`。它检查配置、源码出处、成功／负例状态、次数和统计，**不重新运行密码学实验**。单个组可调用同模块`validate_batch`；补充重放使用`validate_replay`，并检查独立驱动源码摘要。

图表重建：安装matplotlib后执行`python -m experiments.research.plot_backend_optimization --directory docs/research/2026-10-20-multi-backend-optimization`。本次绘图工具为matplotlib 3.11.2；绘图环境与密码学运行环境分别记录，不混用耗时。

真实重跑入口为`python -m experiments.research.backend_optimization_probe`。从本源码构建wheel并安装到持久的用户目录，安装`ibme[hybrid]`依赖；使用清单确认包内文件与该提交一致。Suite由`expected_suite('A'|'B'|'C'|'Luo'|'Falcon')`生成，传入`--label`、`--suite-file`、`--source-commit`、`--installed-root`、`--manifest`、`--private-directory`、`--backup-directory`、`--public-output`、`--repetitions 3 --operation-timeout 1200`。清空源码PYTHONPATH，切换到仓库外的安装目录，设置原LATTE／ML-DSA／Falcon／Sageloli桥的位置和`OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=1`。私有输出目录必须全新且在用户主目录下，已有状态不可覆盖。

完全重放本批应从固定`b4b31d8`导出源码再构建；当前分支的新运行会产生新源码清单和当前安全字段，不覆盖此目录。Luo补充入口为独立`luo_ntt_replay_ablation.py`，传入`--private-source`原Luo三根目录、`--installed-root`、`--manifest`及全新`--output`，同时令PYTHONPATH只指向原固定安装。驱动单独记录自身摘要，原输入文件保持不变。

首次安装预检因缺少cryptography而在build-runtime阶段失败，尚未进入Setup或占用任何密码学根。修正安装依赖及驱动失败收据的重复字段错误后，使用上述新提交、新安装继续；原失败诊断保留在本地。它不属于采样失败后的换根重试。

实验私有状态位于持久用户目录，签发后及加密后的备份位于本地被忽略的`test-results/optimization-private-backups/`，不进入Git。补充重放以原三根为输入，不生成或替换根。一次辅助启动的CRLF尾字符导致Falcon参数解析在生成前失败；纠正启动参数后执行原计划的3根，未丢弃任何已生成样本。重放输出文件的尾字符被按原字节复制为正常文件名，没有重跑或改写数值。
