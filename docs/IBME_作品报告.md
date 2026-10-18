# 基于多类格困难假设的抗量子身份基匹配加密通用设计和优化实现

> 材料事实版本：`IBME-SAME-VERSION-MATERIALS/1`<br>
> 数据基点：`2fccb0871d9b68c11c1e80828fabf154496de6df`<br>
> 参数卡：`IBME-SHOWCASE-CARDS/1`，SHA-256 `970c5303f5d8a7e73cbbfaee8dd50a3c3186f83b5c40062a32a68c4d682edcd6`<br>
> 当前主演示：`latte3-bnn-mldsa44-hybrid-byteauth`<br>
> Suite digest：`10a23d28bfdf9b2e18b140149561c43d62f2649feb78b72510d350b419233346`

本文是与当前代码、参数卡和公开收据同步的作品报告初稿，不是已经排版完成的竞赛终稿。当前建议用 **LATTE-3 + BNN/ML-DSA-44 + Hybrid + BYTEAUTH** 作为主演示底座；图形界面尚未交付，最终三组代表尚未锁定。

## 摘要

身份基匹配加密（Identity-Based Matchmaking Encryption，IB-ME）要求接收者身份和发送者身份同时匹配，接收方才获得消息。作品沿用 Wang 两层匿名 HIBE 与 IBS 的通用构造，把 HIBE、IBS、传输包装和完整字节认证拆成可独立选择的模块，并通过严格 Suite 配置、规范编码、容量预检和持久状态事务形成统一实现。身份顺序固定为 `(parent_id, child_id)=(rcv, phi)`；协议层只调用原语公共接口，不读取矩阵、陷门或私钥内部字段。

当前主演示实例采用 LATTE-3/COSAC-FIX 两层 HIBE、BNN 认证构造实例化的 ML-DSA-44 IBS、HYBRID-HIBE/1 和 BYTEAUTH/1。已归档实验在 64 B 接收者身份、64 B 发送者身份和 32 B 应用消息下，使用 3 套独立系统状态，每套执行 3 对 warm 加解密；9 次 warm 加密和解密的中位数分别为 0.211125 s 和 0.280116 s，12 份完整外层密文为 142051—142146 B。另有 3 个恢复进程、9 次恢复后解密，恢复过程读取 0 B 公共随机源且公开钥、接收状态和密文保持不变。

同边界下还归档了 BNN/Falcon-padded-512 和 Luo 模格 compact 两个 IBS 对照实例，用于展示认证转换、紧凑 NTRU 签名和原生 MLWE/MSIS IBS 的不同工程取舍。三组共享同一个 LATTE HIBE，且尚未建立相同具体安全目标，因此不把它们写成三种 HIBE，也不作“同安全等级最快”的排名。

当前研究配置统一保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。本文中的功能、拒绝、恢复和性能数据是实现证据，不是 NTRU、RLWE、MLWE、MSIS、HIBE、IBS 或完整 IB-ME 的安全证明，也不对应已授予的 NIST 安全等级。

**关键词：** 身份基匹配加密；层次身份基加密；身份基签名；格密码；混合加密；规范编码；持久状态

## 1. 问题、目标与范围

普通公钥加密解决“只有指定接收者能够解密”，普通签名解决“消息来自谁”。IB-ME 把两者放入同一身份语义：发送者指定接收者，接收者解密时同时声明期望发送者；只有两个方向都匹配才返回明文。

| 实际密文 | 解密使用的接收者密钥 | 声明发送者 | 结果 |
|---|---|---|---|
| Alice 发给 Bob | Bob | Alice | 返回原消息 |
| Alice 发给 Bob | Carol | Alice | `BOTTOM` |
| Alice 发给 Bob | Bob | Carol | `BOTTOM` |
| Alice 发给 Bob | Carol | Carol | `BOTTOM` |

作品的共同目标是普通隐私、加强认证、自我伪造防护和完整密文字节篡改拒绝。当前工程实现覆盖双身份匹配、来源验证、严格 wire、错误身份与非法数据拒绝、跨进程状态恢复；安全结论仍须以所选 HIBE、IBS 和包装的确切前提为条件。

以下内容不在当前范围：

- Boyen–Li 增强隐私所需的 `Ext`、`ReExt` 及相应身份熵条件；
- 把测试成功改写为困难假设或不可伪造性证明；
- 未完成的 QROM、完整组合归约、统一具体安全等级和 NIST 等级声明；
- 把参数变化、压缩格式或采样实现重复计算为新算法；
- 把仍在开发的图形界面、目标规模运行或最终三代表写成已完成成果。

## 2. 通用构造

### 2.1 基线协议

系统分别初始化 HIBE 和 IBS。发送密钥是发送者身份的 IBS 签名密钥；接收密钥是接收者身份的 HIBE 一级密钥。核心流程为：

```text
Setup:
  (hpk, hmsk) <- HIBE.Setup()
  (ipk, imsk) <- IBS.Setup()

SKGen(phi):
  ek_phi <- IBS.KeyExtract(imsk, phi)

RKGen(rcv):
  dk_rcv <- HIBE.Extract(hmsk, rcv)

Encrypt(ek_phi, rcv, message):
  sigma <- IBS.Sign(ek_phi, EncodeMessage(rcv, message))
  payload <- EncodeSignature(sigma) || EncodeBytes(message)
  ct <- HIBE.Encrypt(hpk, rcv, phi, payload)

Decrypt(dk_rcv, claimed_phi, ct):
  leaf <- HIBE.Derive(dk_rcv, claimed_phi)
  payload <- HIBE.Decrypt(leaf, ct)
  strict-parse(payload)
  verify ipk, claimed_phi, EncodeMessage(rcv, message), sigma
  全部通过则返回 message，否则返回 BOTTOM
```

HIBE 的两层身份顺序固定为接收者在前、发送者在后。签名再次绑定接收者和消息，因此协议不会只依赖密文中一个未认证的身份字段。身份、消息、签名及全部顶层对象使用域分隔和长度前缀编码，解析拒绝未知版本、截断、追加、重复字段、超预算长度和非规范重编码。

### 2.2 Hybrid 大载荷适配

LATTE 实例只承担 32 B 会话种子的两层身份加密。每次加密新取 32 B seed 和 12 B nonce，经 HKDF-SHA256 派生 AES-256-GCM 密钥，再加密完整协议载荷。AAD 绑定 suite、公钥上下文、完整 HIBE capsule、nonce 和载荷长度。

外部身份最大 64 B；进入 LATTE 前按角色、长度和零填充规范编码为固定 86 B，仍保持 `(rcv, phi)` 顺序。该设计降低大签名直接进入 HIBE 的容量压力，也避免旧胶囊直接暴露身份长度；它不自动把底层 CPA HIBE 提升为 CCA 安全。

### 2.3 BYTEAUTH 完整字节认证

BYTEAUTH 为每个外层密文生成一次性 Lamport 型认证密钥，对完整基线密文字节签名；其公钥承诺又被内部 IBS 签入。旧认证公钥下修改密文需要突破一次性签名，新建认证公钥并重签则需要改变 IBS 已签入的承诺。

这是条件式的完整字节认证论证。它依赖哈希和一次性签名条件，也依赖底层 IBS 的不可伪造性；不能据此宣称完整系统已经获得 CCA、QROM 或正式安全准入。

## 3. 系统结构与多算法实例化

```text
CLI / 应用 / 评测
        |
SuiteConfig + registry + 静态容量/依赖预检
        |
BYTEAUTH/1
        |
Wang BaselineIBME
      /   \
HybridHIBE  IBSBackend
      |        |
HIBEBackend  独立 IBS 实现
```

HIBE 与 IBS 分别拥有参数类型、模数、环、随机分布、对象格式和解码器。共同框架只约束接口、身份语义、配置绑定、容量和失败行为，不要求两类原语共享矩阵或模数。

当前候选盘点为 3/8 条 HIBE 和 10/11 条 IBS 已有独立研究实现，合计 13/19 条原语路线。这个数字不是 13 套完整 IB-ME，也不是正式安全准入数量。每一具体配对还须独立经过依赖预检、完整生命周期、拒绝、恢复和安全前提核对。

当前三张完整系统参数卡如下。它们都使用 `allow_mock=false`、LATTE-3、Hybrid 和 BYTEAUTH：

| 展示角色 | 完整组合 | IBS 困难假设/来源侧重点 | 当前结论 |
|---|---|---|---|
| 主演示候选 | LATTE-3 + BNN/ML-DSA-44 | ML-DSA 使用的模格假设；标准化基础原语的解释与复现路径最清楚 | 当前主线，不等于完整 IBS/IB-ME 获得 FIPS 认证 |
| 紧凑性工程对照 | LATTE-3 + BNN/Falcon-padded-512 | Falcon v1.2 的 NTRU 格签名假设 | 实测密文和签名更小；不是 FN-DSA/FIPS 206，也未建立同安全目标 |
| 原生 IBS 设计对照 | LATTE-3 + Luo module compact | 密钥恢复分支 MLWE、伪造分支 MSIS | 展示原生模格 IBS；当前默认 research 档不是 C64B，也不继承论文 200-bit 标签 |

## 4. 主展示组合的实际参数

### 4.1 LATTE-3/COSAC-FIX HIBE

| 项目 | 实际配置 |
|---|---|
| 论文与算法 | Zhao 等《Quantum-safe HIBE: does it cost a LATTE?》，Algorithms 1—5 |
| 固定上游源码 | `18cfbf9a671fca34785583b58ab9f28e3be21a3c` |
| 实现/wire 版本 | `latte3-cosac-fix-v1` / `IBME/LATTE3/COSAC-FIX/1` |
| 假设族 | NTRU、RLWE；论文报告经典随机预言机模型 |
| 环参数 | `N=1024`，`q=68718428161`，最大深度 2 |
| Gaussian 标准差 | `6777.5879662983919609175926`；`351968.36683734171059914430`；`22559988.027951553365675150` |
| 数值精度 | FFT 768 bit；reduce-k 256—768 bit |
| 加密噪声 | 8 对 Bernoulli 之差，中心二项分布标准差 2；不是离散 Gaussian |
| 实际容量限制 | 2 个接收者、每接收者 2 个子身份；native 超时 60 s |

KeyGen 和 Delegate 保留真实 Gaussian/FACCT 路径，Extract 保留作者方案按目标 seed 确定化的机制。构建时的 COSAC 修订使其读取新生成的 24 B Box–Muller 缓冲、限制 AES 计数器，并使用已对照向量的 OpenSSL SHAKE-256 兼容入口。

论文给出的 LATTE-3 目标表和解密失败数据是参数来源背景。本项目改变了身份域、seed 输入并包含构建修订，尚未闭合有限精度、总体失败和组合匿名映射，所以不继承论文表格为本组合的安全位数。按当前项目决策，HIBE 身份匿名性是工程推进的工作假设；论文的 ID-IND-CCA 结果不在本文中冒充已经完成的接收者匿名性映射。

### 4.2 BNN/ML-DSA-44 IBS

| 项目 | 实际配置 |
|---|---|
| IBS/wire | `cert-ml-dsa` / `IBME/CERTIBS/1`，reference 格式 |
| 构造 | Bellare–Namprempre–Neven 认证构造，按 Galindo–Herranz–Kiltz 2006 §3 / Theorem 1 |
| 普通签名 | pure external ML-DSA-44；未实现 HashML-DSA、external-mu |
| 固定源码 | `pq-crystals/dilithium` 提交 `d35ba3fe5449bee3e6d43e1f296c3ca818bd36be` |
| 容量 | 身份 64 B、消息 65536 B、最多 16 个固定身份、超时 30 s |
| 基础尺寸 | 公钥 1312 B、普通签名 2420 B |
| 完整 BNN IBS 签名 | 6237 B |
| 原语核验 | 原语交付执行 210 个固定 FIPS 204 向量 |

机构签名认证 `identity || user public key`，用户再以独立普通签名钥签消息；实现另以规范编码绑定主公钥上下文、身份、用户公钥、证书和消息。BNN 转换和 ML-DSA 均按原来源引用，不宣称为本项目新发明的密码算法。完整认证转换、量子模型和 Wang 组合所需安全前提尚未完成正式准入。

## 5. 工程实现要点

### 5.1 配置和依赖拒绝

`IBME/SUITE/1` 冻结 HIBE、IBS、两边参数、wire 版本、签名格式、transport、protocol、容量和状态策略。`check` 在创建密钥或消耗熵前验证实现、原生依赖、两层派生能力、对象解码器、身份宽度及消息/签名/capsule 预算。缺少原生引擎时明确失败，不回退到 ABB10、SIS 或 mock。

主组合固定为：

```text
hibe=latte                  hibe_params=seed32
ibs=cert-ml-dsa             ibs_params=ml-dsa-44
transport=hybrid            protocol=byteauth-v1
signature_format=reference  allow_mock=false
suite_digest=10a23d28bfdf9b2e18b140149561c43d62f2649feb78b72510d350b419233346
```

### 5.2 规范编码与分层失败

身份、消息和签名均使用域分隔及 `uint32_be(length) || bytes` 编码。数据层失败统一返回 `BOTTOM`；参数、I/O 或状态错误使用不同退出码。原始 CPA 数学解码、Hybrid AEAD、IBS 验证、BYTEAUTH、wire 解析和状态恢复分别验收，避免把某一层的容错或拒绝特性误写成另一层性质。

### 5.3 可恢复状态

CLI v2 状态保存完整 suite digest、公钥 digest 和带对象类型的封装。发钥采用本地单写者锁、pending 标记以及“先提交主状态，再发布密钥”；解密在输出明文前保存接收状态。已有接收密钥经公开上下文验证后复用，避免再次委派丢失固定叶状态。

该机制处理同一 OS 本地进程的并发和不确定提交，不是分布式事务、外部存储认证、防恶意回滚或硬断电证明。

## 6. 实验与结果

### 6.1 条件和重复次数

公开收据环境为 Intel Core Ultra 9 275HX、WSL2 Linux 6.18.33.2、Python 3.13.14、Sage 10.9、OMP 4、OpenBLAS 1。每个 worker 是新 Python 进程，但保留 OS 页缓存和已构建 native engine。该环境是原收据的一部分，不表示当前电脑使用同一解释器路径。

三组均使用 64 B 接收者身份、64 B 发送者身份、32 B 应用消息，内层身份各 86 B，HIBE 种子 32 B。每组包含 3 套独立系统状态，每套 3 对 warm 加解密；合计 3 次首次解密、9 次 warm 加密、9 次 warm 解密，以及 3 个恢复进程中的 9 次恢复后解密。观察到的操作全部成功；小样本不能支持罕见中止或尾部概率结论。

### 6.2 完整系统时间

下表是公开原始观察值的中位数，单位为秒；不同 security group 不作同等级排名。

| 阶段 | BNN/ML-DSA-44 | BNN/Falcon-512 | Luo module compact |
|---|---:|---:|---:|
| Setup（3） | 0.984492 | 0.911282 | 0.964105 |
| 发送钥（3） | 0.273598 | 0.160366 | 0.318922 |
| 接收钥（3） | 0.754343 | 0.511102 | 0.472760 |
| cold Encrypt（3） | 0.224485 | 0.217907 | 0.609756 |
| 首次 Decrypt，含叶提取（3） | 0.403997 | 0.368917 | 0.382824 |
| warm Encrypt（9） | 0.211125 | 0.200346 | 0.364461 |
| warm Decrypt（9） | 0.280116 | 0.249274 | 0.229220 |
| 新进程对象恢复/绑定（3） | 0.665062 | 0.674278 | 0.779928 |
| 恢复后 Decrypt（9） | 0.281654 | 0.247483 | 0.234768 |

### 6.3 完整系统尺寸

| 公开观察 | BNN/ML-DSA-44 | BNN/Falcon-512 | Luo module compact |
|---|---:|---:|---:|
| 完整外层密文（12 份） | 142051—142146 B | 138150—138207 B | 151876—151955 B |
| 公开状态 | 14352—14392 B | 13973—14020 B | 260819—260851 B |
| 主状态 | 177557—177671 B | 172047—172371 B | 522253—522339 B |
| 接收状态 | 128017—128098 B | 128078—128230 B | 128166—128243 B |
| 发送状态 | 8050 B | 4195 B | 313813 B |
| 10 ms 进程树 RSS 最大观察 | 480243712 B | 480043008 B | 493281280 B |

主状态包含缓存，不能与独立接收状态简单相加后称为去重总存储。进程树 RSS 求和可能重复计算 fork 共享/COW 页，10 ms 采样也可能漏掉短峰，因此这里只报告观察统计。

### 6.4 成功、拒绝和恢复证据

共同组合验收覆盖：匹配成功、仅接收者错、仅发送者错、两者都错；完整密文和签名篡改；截断、追加、重复字段与未知版本；随机伪造签名；对象序列化和新进程恢复。参数卡本批复用既有负例测试和三份正向生命周期收据，没有把历史结果改写成新一轮重复实验。

当前电脑的同一主组合静态预检返回 suite digest 与上文一致，但因为 LATTE bridge 和 ML-DSA native engine 未构建而以退出码 2 拒绝，`execution=not_executed`。这说明当前机器依赖未就绪，不是算法运行失败；现场不得启用回退后端冒充该组合。真实运行数据来自固定源码、固定 suite 的公开归档收据。

## 7. 作品贡献与原创性边界

1. **一个协议、多原语独立实例化。** 将 HIBE、IBS、参数、解码器和能力检查分离，在同一 Wang 构造下严格组合，并把“已实现”“可装配”“已真实运行”“已安全准入”分开记录。
2. **跨层的规范绑定与拒绝语义。** 固定 `(rcv, phi)`、域分隔、长度前缀、Hybrid capsule AAD、IBS 身份/消息绑定和 BYTEAUTH 全字节认证，统一处理错配和恶意 wire。
3. **可审计的持久状态与真实组合验收。** Suite digest、对象上下文、单写者事务、固定接收状态、新进程零公共熵恢复，以及按完整系统而非裸原语记录时间、通信、状态和 RSS。
4. **多类格路线的可复现取舍展示。** 在相同 HIBE 和输入边界下，以 ML-DSA、Falcon 和 Luo IBS 展示模格标准化基元、NTRU 紧凑签名与原生 MLWE/MSIS 设计的实际尺寸和时间，不把不同目标强行合成单一排名。

Wang 通用构造、LATTE、BNN 转换、ML-DSA、Falcon、Luo 算法、HKDF 和 AES-GCM 均为已有成果或标准组件，分别引用来源；作品贡献集中在通用实现、跨层绑定、状态工程、组合验收、来源固定和可复现测量。

## 8. 安全声明与已知限制

所有展示卡固定：

```text
security_claim=none
backend_admitted=false
parameters_are_formal=false
security_proofs_produced=0
```

可以陈述三组是在真实非 mock 后端上的完整研究运行，配置、固定源码、输入、重复次数、恢复和公开测量可追溯；可以陈述 BYTEAUTH 在既有组合测试覆盖的受保护区域拒绝字节篡改。

不能陈述三组已经正式安全准入、具有相同具体安全目标、获得 NIST 等级、完成 QROM 或完整 Wang 组合归约，也不能说功能/性能测试证明格困难假设。LATTE 身份匿名性是当前工作假设；BNN 构造条件、普通签名安全、Luo ROM 条件和包装假设须分别保留。

## 9. 复现与公开证据

- [三组完整系统参数卡](deliveries/2026-10-18-main-showcase-cards/README.md)与[机器可读 cards.json](deliveries/2026-10-18-main-showcase-cards/evidence/cards.json)；
- [ML-DSA 完整系统收据](research/2026-10-18-full-system-baseline/evidence/latte-mldsa44.json)；
- [Falcon 完整系统收据](research/2026-10-18-full-system-falcon/evidence/latte-falcon512.json)；
- [Luo 完整系统收据](research/2026-10-18-full-system-luo/evidence/latte-luo-compact.json)与[统一 comparison.json](research/2026-10-18-full-system-luo/evidence/comparison.json)；
- [现行 CLI 使用说明](FRAMEWORK_USAGE.md)、[共同实现规范](../IMPLEMENTATION_SPEC.md)和[传输/状态契约](specs/transport-and-state.md)；
- [同版本演示与答辩脚本](COMPETITION_DEMO_AND_DEFENSE.md)及[材料一致性证据](deliveries/2026-10-18-same-version-materials/README.md)。

选择当前机器上实际可用的 Python 3 解释器后，可按顺序生成比较数据并核验证据。第一条命令会写回 `comparison.json`；后两条命令为只读一致性核验：

```sh
<python> docs/research/2026-10-18-full-system-luo/evidence/compare.py
<python> docs/deliveries/2026-10-18-main-showcase-cards/evidence/verify.py
<python> docs/deliveries/2026-10-18-same-version-materials/evidence/verify.py
```

上述工具不需要 Sage，不生成密钥、不读取私有状态。真实新建主组合必须先用当前机器实际安装的 Sage/Python 和两个 native engine 通过预检；不得复制另一台电脑的旧 Sage 绝对路径。

## 10. 结论与待完成工作

作品已经形成可替换 HIBE/IBS 的公共 IB-ME 框架、真实 LATTE 主线、三种 IBS 完整运行对照、规范 wire、Hybrid/BYTEAUTH 包装、CLI 和可恢复状态。当前数据足以形成诚实的主组合演示和报告基线。

仍待完成的竞赛交付包括：接收并核对两种在途 HIBE，依据实际参数和完整配对选择最终三组代表；完成图形界面、最终截图、赛方模板排版和冻结复现；补齐目标参数与统一安全声明所需的核验。上述欠项不会因本报告同步而自动完成。

## 参考资料

1. Wang 等，身份基匹配加密通用构造，仓库论文 [2022_identity_matchmaking_wang.pdf](../papers/2022_identity_matchmaking_wang.pdf)。
2. Zhao 等，*Quantum-safe HIBE: does it cost a LATTE?*，[2024_quantum_safe_hibe_zhao.pdf](../papers/2024_quantum_safe_hibe_zhao.pdf)。
3. Galindo、Herranz、Kiltz，认证式通用 IBS 构造，[2006_generic_ibs_galindo.pdf](../papers/2006_generic_ibs_galindo.pdf)。
4. Luo、Chen、Susilo、Huang，*Identity-Based Signature from Lattices without Trapdoors*，[2024_ibs_without_trapdoors_luo.pdf](../papers/2024_ibs_without_trapdoors_luo.pdf)。
5. 项目的固定上游源码、许可证和构建信息以各原语交付及[算法目录](ALGORITHM_CATALOG.md)为准。
