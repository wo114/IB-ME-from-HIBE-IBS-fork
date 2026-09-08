# 给其他 AI 的任务拆分与提示词

## 使用规则

把 `ARCHITECTURE.md` 和 `IMPLEMENTATION_SPEC.md` 放在每个任务的上下文中。一个 AI 只负责一个边界，不允许为了方便直接重写其他模块。每个任务结束时必须提交测试、修改文件列表和限制说明。

建议合并顺序：Core → Lattice → HIBE → IBS → Baseline → Tests/Benchmark → Enhanced。

## 任务 A：基础设施

```text
你负责 IB-ME 项目的 core 模块。
先阅读 ARCHITECTURE.md 和 IMPLEMENTATION_SPEC.md。
只修改 src/ibme/core/、tests/test_encoding.py，以及必要的类型导出文件。

实现：规范字节编码、域分隔 SHAKE-256、系统 CSPRNG、可控测试 RNG、项目异常类型和基础数据类。
要求：长度前缀使用 uint32 big-endian；所有编码可往返解析；拒绝截断、溢出和尾随垃圾；生产 RNG 与测试 RNG 分离。
不要实现 HIBE、IBS 或协议逻辑，不要改变公开接口。

完成后运行相关测试，并返回修改文件、测试命令、结果和剩余风险。
```

## 任务 B：格工具

```text
你负责 lattice 模块。
只修改 src/ibme/lattice/、tests/test_lattice_core.py 和参数样例。

实现 ModMatrix、gadget 矩阵、模 q 向量运算、离散高斯采样、TrapGen/DelTrap/SamplePre 的适配层。
矩阵和向量必须有严格维度检查；所有模 q 表示统一；采样器必须是真正的离散高斯或明确标注为尚未完成，不能用均匀随机数冒充。
先提供最小可验证版本和统计测试，再接入 HIBE/IBS。
不要修改协议层和编码规则。
```

## 任务 C：两层 HIBE

```text
你负责 HIBEBackend。
先阅读论文中 Agrawal–Boneh–Boyen 两层 HIBE 的算法，再阅读 ARCHITECTURE.md 的接口。
只修改 src/ibme/hibe/、tests/test_hibe_contract.py 和 HIBE 相关参数说明。

必须实现 setup、extract、derive、encrypt、decrypt，并保持身份顺序为 parent_id=rcv、child_id=phi。
先让 mock HIBE 通过 contract tests，再接入格基实现。密文不得明文携带身份。
不要实现 IBS 或 IB-ME 组合，不要宣称未经参数估计的安全级别。
```

## 任务 D：SIS-IBS

```text
你负责改进版 SIS-IBS。
只修改 src/ibme/ibs/、tests/test_ibs_contract.py 和 IBS 参数说明。

按指导论文构造 3.4.1 实现 KeyExt、Sign、Verify。必须保持
F_id=[A | H1(mpk,id)]，H1=A R_id + G，F_id*z=H2(mpk,id,message) mod q，
并检查 z 非零和论文规定的范数界。
签名密钥要绑定身份摘要；哈希使用 core 的域分隔接口；采样使用 lattice 的采样器。
先通过 mock/contract tests，再运行真实格实现的正确性测试。
不要修改 HIBE 或协议层。
```

## 任务 E：基线协议组合

```text
你负责 IB-ME baseline 协议层。
只修改 src/ibme/protocol/baseline.py、协议数据结构、tests/test_baseline_ibme.py 和 CLI 的最小接线。

严格实现：IBS 对 encode(receiver_id)||message 签名；HIBE 在 (receiver_id, sender_id) 下加密 signature||message；解密先 Derive，再 HIBE.Decrypt，再 IBS.Verify。
四种匹配组合、密文篡改、签名篡改和格式错误都必须有测试。
协议层不得访问 HIBE/IBS 内部矩阵，也不得把身份明文放入密文。
```

## 任务 F：增强隐私版

```text
只有 baseline 通过后才执行此任务。
实现 Boyen–Li 风格的 Ext/ReExt 掩码层，放在 src/ibme/protocol/enhanced.py。
明确标注 ROM 工程实例，使用 SHAKE-256 域分隔，不得声称标准模型安全。
固定长度序列化后才能进行 XOR；如果底层密文变长，改用明确的 KEM/DEM 包装并说明与论文接口的差异。
增加匹配、不匹配和身份猜测场景测试，记录身份熵条件。
```

## 任务 G：审计与基准

```text
你不负责改密码算法，只负责审计和实验。
阅读所有模块接口，运行完整测试，检查身份顺序、编码、异常处理、随机性、参数声明和安全措辞。
生成 experiments/ 下的尺寸与耗时报告，指出任何无法由论文支持的安全声明。
除非发现明确 bug，不要重构算法代码。
```

## 给最终审查 AI 的提示词

```text
请以密码学实现审查员身份检查本项目。
重点检查：
1. 第三章基线构造是否被准确实现；
2. HIBE 身份顺序是否始终为 rcv|phi；
3. IBS 签名和验证消息是否完全一致；
4. 序列化是否无歧义且拒绝畸形输入；
5. 离散高斯采样是否被错误替换；
6. 测试是否覆盖四种匹配组合和篡改；
7. 报告是否把 baseline 的原始隐私误写成 Boyen–Li 增强隐私；
8. 参数是否有明确的“调试参数/安全参数”标注。

请只提交审查报告和必要的最小修复，不要引入新的密码构造。
```
