# 首套接收状态：跨进程固定原像、失败保存与重发复用

日期：2026-10-10。承接[队友PR #6审阅与联合门槛](../2026-10-10-chkp-review/README.md)。本轮完成首套接入所需的接收状态工程修复；没有将研究缓存称为完整 CHKP 后端。完整文件、命令、参数、源码/测试记录指纹见[机器审计记录](audit.json)。

## 修复的问题及实际行为

原 CLI 解密读取 ReceiverKey 后直接运行协议，只保存发钥时的主缓存。若 HIBE Derive 更新一级密钥的固定 bit 原像缓存，下一次命令会重新读取旧文件并重采样；BOTTOM、采样失败和中断也会丢失变化。并发命令能读同一旧快照，重新发接收密钥又会覆盖已有叶缓存。数据输出还可以指向私钥或锁文件。

新增20个反例在原实现中全部失败，修复后全部通过；随后增加失败收尾、真实缓存桥接和真实研究密钥复用等检查。

| 场景 | 本轮实现 |
|---|---|
| 新进程重复解密 | 在共用状态锁内读取接收密钥；序列化保存变化，再输出结果 |
| 同/不同发送者并发解密 | 从读取到状态提交、输出持有同一锁，避免重复原像和覆盖另一地址 |
| 成功、BOTTOM、异常或 KeyboardInterrupt | finally 保存更新，包括失败墓碑；保存失败时不返回明文 |
| 进程硬退出或提交不确定 | 采样前已建立 pending 标记；后续解密/接收者发钥明确失败，不自动重抽 |
| 重新签发已有研究接收密钥 | 原语加载验证、身份/公开上下文一致后复用原文件；不再次委派、不覆盖缓存 |
| 外来公钥、坏身份或坏 wire | 明确拒绝已有接收文件，避免用重发覆盖损坏状态 |
| 数据输出指向关键状态 | 在密码操作前拒绝覆盖私钥、公钥、元数据、锁、pending或临时状态等保留路径 |

协议使用不透明 ReceiverKey.to_bytes；私有基和原像只由原语维护。比较的是密钥声明的公开 HIBE 上下文，实际私钥方程校验继续由上轮原语验证能力负责。当前可用 profile 是现有 `luo-module-research`；未来 CHKP profile仍须正式注册和通过契约，不能通过测试驱动选择它。

## pending 与故障边界

`receiver-<digest>.bin.pending` 通过 O_EXCL创建，内容只含固定版本字符串；flush/fsync后才进入协议调用。finally序列化接收密钥，变化通过已有同目录临时文件、flush/fsync和原子替换提交；提交成功或状态未变后移除标记，随后输出结果。

进程硬退出、序列化失败、状态替换失败、标记fsync/删除失败都可能留下标记。此时该接收者被保守阻止；原私有状态及标记保留供审阅。本轮没有自动清除或恢复命令，不能直接删标记、用旧备份回滚、重新委派来称为安全恢复。若最新状态确已提交，仍须由后续恢复流程验证完整性和所有已消费地址；若丢失已抽样但未提交的原像，只凭旧快照不能保证固定地址一致。

这是同一OS本地文件系统内的进程并发/崩溃保护；不保证硬断电后的目录持久化、反回滚、恶意本地文件系统操纵、跨Windows/WSL共同写或分布式锁。当前状态目录共用锁会串行化不同接收者；本轮优先正确性，没有宣称性能改善。首次接收者发钥的主状态固定性和失败语义仍须由真实CHKP主缓存实现并验收。

## 验证与可复跑命令

新文件`tests/test_cli_receiver_state.py`有30项：26项可移植状态驱动检查、3项实际Sage高斯叶缓存桥接、1项真实研究接收密钥复用。可移植驱动为TEST ONLY，真实缓存桥接也不实现H/G或Encaps/Decaps，不计完整HIBE或加密测试。

状态批次另外包含既有本地锁10项、研究快照18项及密钥绑定28项，总计86项。以下最终批次没有失败/XFAIL；Windows的3个skip仅为需Sage的真实缓存桥接，并已在指定Sage环境执行通过。

```text
python -B -m pytest -q -p no:cacheprovider tests/test_cli_receiver_state.py tests/test_cli_state_lock.py tests/test_research_state_integrity.py tests/test_hybrid_key_binding.py --tb=short --junitxml=test-results/receiver-state-native.xml
83 passed, 3 skipped in 20.94s

PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -B -m pytest -q -p no:cacheprovider tests/test_cli_receiver_state.py tests/test_cli_state_lock.py tests/test_research_state_integrity.py tests/test_hybrid_key_binding.py --tb=short --junitxml=test-results/receiver-state-sage.xml
86 passed in 18.99s

python -B -m pytest -q -p no:cacheprovider tests/test_luo_hybrid_ibme.py tests/test_luo_compact_ibme.py -k cli --tb=short --junitxml=test-results/receiver-cli-native.xml
4 passed, 42 deselected in 31.11s

PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -B -m pytest -q -p no:cacheprovider tests/test_luo_hybrid_ibme.py tests/test_luo_compact_ibme.py -k cli --tb=short --junitxml=test-results/receiver-cli-sage.xml
4 passed, 42 deselected in 34.82s

python -B -m pytest -q -p no:cacheprovider tests/test_baseline_ibme.py -k cli --tb=short --junitxml=test-results/receiver-legacy-cli-native.xml
11 passed, 58 deselected in 124.65s

python -B -m pytest -q -p no:cacheprovider tests/test_byteauth.py::test_default_cli_protocol_and_explicit_legacy_flag --tb=short --junitxml=test-results/receiver-legacy-mode-native.xml
1 passed in 0.26s

PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -B -m pytest -q -p no:cacheprovider tests/test_baseline_ibme.py tests/test_byteauth.py -k cli --tb=short --junitxml=test-results/receiver-legacy-cli-sage.xml
12 passed, 81 deselected in 142.15s
```

WSL命令先进入仓库，并使用`PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python`；脚本不写死用户名。该状态/CLI选择的非重叠合计为Windows 99 passed/3 skipped、Sage102 passed；队友审阅及联合预筛是另外批次，不合并为全仓库或独立安全检查总数。基础CI增加联合门槛检查，Hybrid CI增加接收状态检查并明确本地Sage范围。

## 参数、环境与安全声明

密码算法、身份顺序、合法wire、哈希输入、KDF/AAD及当前参数不变；重新发钥现在复用已有接收密钥，不再消费新的委派随机数。

- 现有HIBE仍为教学ABB10：`n=8,m_matrix=168,m_bar=16,q=524288,s0=3,s_enc=s_pre=1`；底层编码身份86 B，种子32 B。
- Luo模格研究IBS：`degree=256,k=11,l=10,q=274877844481,kappa=64,eta=1`；`gamma1=125440,gamma2=31470387200,gamma3=15270991360,dropped_bits=28`，NTT root `153250464611`。
- 外部身份最多64 B，应用消息最多3924 B；reference与compact两个格式分别进行真实CLI回归，默认BYTEAUTH。
- 三项真实Sage缓存桥接：公开教学矩阵`[[1,0]]`、`q=2`、GPV宽度平方512、epsilon_bits16、固定目标`(0),(1)`，容量2、发送者条目上限2；种子为明确的测试固定流。每项首次最多2个实际原像尝试，恢复不再采样；其中1项故意令第二个向量失败，恢复后保留失败墓碑。
- 普通跨进程驱动消息为模式标识，身份Bob/Alice/Carol；其随机token仅用于观察状态丢失，不是高斯、签名或安全参数。

Windows Python3.14.6、WSL Sage10.9/Python3.13.14；pytest9.1.1、cryptography49.0.0；Intel Core Ultra9 275HX。上述是功能/故障回归，每个场景执行一次测试流程，重复次数由各测试规定；没有性能比较或失败概率统计。

统一`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。理论模型保留经典ROM，不宣称QROM、NIST等级、CCA或完整匿名性。测试不能替代安全证明；旧教育IBS公开伪造/冒名两个XFAIL仍未修复。

## 修改边界与后续关键工作

本项14个文件的精确清单见`audit.json`，主要实现为CLI/状态层、新状态测试、CI，以及架构/接口、总进度和双方任务入口。跨范围原因是收到队友缓存后补齐协议磁盘生命周期与统一交接契约；未修改队友`chkp_*`算法、格工具或其测试。

下一项仍是首套：同组参数的真实GenBasis/GS/宽度/资源/alpha/噪声，以及至少256个固定bit地址与完整私有wire容量；随后实际H/G、KEM、字节HIBE契约和Wang组合攻击验收。独立优化、SRGG/Yu深入和自动恢复工具继续后置。现有研究组件和状态修复不能记为已完成安全首套。
