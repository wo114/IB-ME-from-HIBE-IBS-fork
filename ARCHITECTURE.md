# IB-ME 统一框架与独立原语

更新：2026-10-12。接口和验收细节以 [IMPLEMENTATION_SPEC.md](IMPLEMENTATION_SPEC.md) 为准；实际完成情况、外部交付和当前任务统一查 [PROJECT_STATUS.md](docs/PROJECT_STATUS.md)。本文件描述模块职责，不累计逐轮进度。

## 1. 项目目标

采用指导论文第三章、Wang 等论文 §4 的两层匿名 HIBE + IBS 通用构造。共享一套协议、编码、状态管理和验收工具；HIBE 与 IBS 分别实现，再选择兼容组件组成实例。每个模块只实现一次，供多个组合复用。最终按场景选择三组有实际优势的完整组合，其余保留为比较对象。

有 h 个 HIBE 和 i 个 IBS 时，主要实施 h+i 个原语，共用协议接入后对 h×i 的候选配对逐一预检。准备公开支持的可行配对必须实际执行完整组合验收；全部结果进入平台和比较材料，最后三个代表用于报告重点。三人的多个原语和公共协调任务见[交付计划](docs/workplans/三人方案分工与统一框架交付.md)。

分别统计困难假设、原语算法、参数配置和完整组合。两个原语可以属于不同格家族；第三套 HIBE 不再强制覆盖 Module-LWE。候选组合仍须经过各自验证，不能把参数调整计为新算法，也不能把配置接线计为已完成安全实例。

解密匹配条件固定为 `rho == rcv and phi == snd`：`rho` 为接收密钥身份，`phi` 为真实发送者，`rcv` 为加密指定的接收者，`snd` 为解密尝试的发送者。HIBE 身份顺序始终是 `(parent_id, child_id) = (rcv, phi)`。

目标包括普通隐私、加强认证、自我伪造防护和所选包装层的篡改拒绝。不实现 Boyen–Li 增强隐私或 Ext/ReExt；普通隐私不自动保护持有目标接收密钥的恶意用户。

## 2. 模块分层

```text
CLI / 应用 / 统一评测
        │
组合配置与装配：选择 HIBE、IBS、各自参数、包装及编解码器
        │
共享 IB-ME 协议：BaselineIBME / ByteAuthenticatedIBME
        ├── HIBEBackend ← 可选 HybridHIBE 容量适配
        │       └── 独立 HIBE 算法实现
        └── IBSBackend
                └── 独立 IBS 算法实现
基础设施：编码、域分隔、随机源、错误、状态存储
算法工具：各后端所需的矩阵 / 环 / 模 / 陷门 / 采样器
```

格工具可以按算法需要复用，不强制所有算法采用同一种陷门、采样分布或签名方程。协议层通过公开接口传递不透明对象；不得跨模块读取秘密矩阵或私有字段来弥补接口缺口。

## 3. 现有装配机制

| 层次 | 代码入口与职责 | 本次整理时的状态 |
|---|---|---|
| 原语接口 | [HIBE](src/ibme/hibe/api.py)、[IBS](src/ibme/ibs/api.py) | 已有独立接口 |
| 共享协议 | [baseline.py](src/ibme/protocol/baseline.py) | 构造函数接收两个后端；Setup 可分别传入 HIBE/IBS 参数 |
| 容量适配 | [hybrid_hibe.py](src/ibme/protocol/hybrid_hibe.py) | 用内层 HIBE 封装种子，外层 HKDF/AES-GCM 处理载荷 |
| 字节认证 | [byteauth.py](src/ibme/protocol/byteauth.py) | 在基线外增加密文字节认证及加密内容绑定 |
| 当前研究配置 | [luo_hybrid.py](src/ibme/protocol/luo_hybrid.py) | 教学 ABB10 + Luo 模格 IBS + Hybrid + BYTEAUTH 的专用配置 |
| 可选 HIBE 研究配置 | [mp12_chkp](src/ibme/hibe/mp12_chkp/__init__.py)、[公共格工具](src/ibme/lattice/research/__init__.py) | MP12 计算型根/DelTrap + CHKP H/G，真实六方法/固定叶/对象恢复；安装包保持单一 provider，Sage 下默认可选，缺 Sage 明确 unavailable；原 CHKP/正式安全准入保持分开 |
| 用户入口 | [cli.py](src/ibme/cli.py) | 独立 `--hibe` / `--ibs`、两边选参；旧预设保留 |
| 统一选择与装配 | [assembly](src/ibme/assembly/__init__.py)、[registry](src/ibme/assembly/registry.py) | 显式后端登记、严格配置快照、无随机性的能力/容量预检、公开对象恢复 |
| 组合验收 | [run_combination_matrix.py](experiments/run_combination_matrix.py) | 同一驱动执行各已实现组合；静态兼容与真实执行分开记录 |

装配机制复用现有构造函数。`SuiteConfig` 保存后端标识与版本、各自完整参数、包装/格式/限额和声明；读取器与工厂由代码注册，JSON 不能指定任意导入。`validate_suite` 在发钥或状态写入前报告不兼容项；`build_runtime` 构造共同协议及对应解码器。命令与 Python 示例见 [使用指南](docs/FRAMEWORK_USAGE.md)。接口、容量通过不代表论文安全前提已核准。

## 4. 原语接口

### 4.1 HIBE：六个方法

以下是 [HIBEBackend](src/ibme/hibe/api.py) 的调用形状；对象详细约束见实现规范。

```python
setup(params, *, rng=None) -> (public_key, master_secret)
extract(master_secret, parent_id: bytes, *, rng=None) -> level1_key
derive(level1_key, child_id: bytes, *, rng=None) -> level2_key
encrypt(public_key, parent_id: bytes, child_id: bytes,
        payload: bytes, *, rng=None) -> ciphertext
decrypt(level2_key, ciphertext, *, rng=None) -> bytes | None
load_ciphertext(data: bytes) -> ciphertext
```

`rng` 遵守 `read(n) -> bytes`，默认采用安全随机源；固定随机源只用于复现。密钥和密文提供规范序列化；协议经 `load_ciphertext` 恢复密文，不猜测具体类。公钥、主密钥、一级密钥、二级密钥、密文的编解码由后端负责。

一级密钥公开 `identity`，二级密钥公开 `parent_identity` / `child_identity`。匿名 HIBE 密文不得直接暴露身份或可公开枚举验证的身份标签。解密失败返回 `None`，成功返回完整载荷；数学参考核产生比特并不等于已满足这一适配契约。

`HIBEKeyBindingValidator.validate_key_binding(public_key, secret_key) -> bool` 是**独立能力**，不计入六个基本方法。Hybrid 要求后端提供该能力或显式注入验证器；验证在后端内部检查公钥归属、身份路径和可检查的秘密关系。仅字面值 `True` 放行，检查不消耗随机数，也不证明采样来源或安全等级。

### 4.2 IBS：五个方法

```python
setup(params) -> (public_key, master_secret)
key_extract(master_secret, identity: bytes) -> signing_key
sign(signing_key, message: bytes) -> signature
verify(public_key, identity: bytes, message: bytes, signature) -> bool
load_signature(public_key, data: bytes) -> signature
```

随机源经 IBS 后端构造函数注入，不给这五个方法额外增加 `rng` 参数。签名密钥绑定身份，`sign` 不重复接受身份。协议经 `load_signature` 解析签名；公钥提供算法需要的解析上下文。

验证失败返回 `False`；严格反序列化失败抛 `SerializationError`；Setup/提取/签名的非法参数、编程错误和采样中止按专属契约明确报告。不能把采样中止伪装成有效签名。

### 4.3 参数和公共基础

`BaselineIBME.setup(hibe_params, ibs_params=ibs_params, rng=...)` 的第一个参数在当前代码中名为 `params`。两个原语允许不同参数类、模数、维度、环和分布；共享的是协议语义与编码边界。不得为了“统一”而强制相同 `q` 或复用一个算法的参数不等式。

协议编码使用 core 中的长度前缀和域分隔规则。后端内部哈希、随机分布和范数判据按选定算法规定实现；公共框架不能把所有构造改成一种哈希或采样器。

### 4.4 已实现的接收状态职责

CLI 解密与发钥共用状态锁，研究 profile 在协议调用前建立 pending 标记，在输出之前保存不透明接收密钥状态；硬退出或不确定提交保留标记并阻止自动重试。已有接收密钥经验证复用。详细格式、故障边界及实现证据见 [状态契约](docs/specs/transport-and-state.md#21-固定接收状态的磁盘事务)。实际固定原像的生成与缓存仍由 HIBE 负责。

## 5. 组合与兼容性

基线加密按现有规范执行：

```text
signed_message = encode_message(receiver_id, message)
signature = IBS.sign(sender_key, signed_message)
payload = encode_signature(signature) || encode_bytes(message)
ciphertext = HIBE.encrypt(hpk, receiver_id, sender_id, payload)
```

解密先由接收密钥和尝试的发送者身份派生二级 HIBE 密钥，再解密、严格解析、加载 IBS 签名并验证 `encode_message(receiver_key.identity, message)`。BYTEAUTH 在其外层验证认证及绑定；Hybrid 在 HIBE 接口内处理种子与大载荷。具体层次和拒绝责任见 [实现规范](IMPLEMENTATION_SPEC.md)。

每个组合须分别检查：

| 检查 | 需要确认的内容 |
|---|---|
| 接口 | 两层委派、对象编解码、失败语义和随机源满足共同契约 |
| 容量 | 应用消息、签名/认证开销、内层种子、两级身份编码均适配 |
| 状态 | 公钥/参数/后端版本绑定；所用缓存和持久化能力满足该配置的要求 |
| 正确性 | 原语条件与组合后的解密/验证条件同时成立，失败来源可区分 |
| 安全前提 | 匿名 HIBE、IBS 安全模型、通用构造定理与包装假设逐项对应 |

因此，可配置组合表示工程复用；每一套安全声明仍需独立核对前提。原始 CPA 数学解码可能在小幅篡改后恢复原值，不能把全字节篡改拒绝硬塞入其数学算法。

## 6. 并行实施与验收

框架、HIBE、IBS、工具和测试可以按文件所有权并行推进。使用 mock 的框架测试、原语真实研究运行、完整研究组合、正式安全准入分别记录；一个原语受阻只阻塞依赖它的组合。具体门槛与交接见 [AI_WORKFLOW.md](AI_WORKFLOW.md)。

当前可运行配置和最新 CHKP/Luo 结果仅在 [项目状态](docs/PROJECT_STATUS.md) 更新。功能成功、性能结果、正确性论证、参数估计和安全归约分别报告；任何包装都不自动补齐原语安全性，也不自动得到 CCA、QROM、标准模型或 NIST 等级声明。
