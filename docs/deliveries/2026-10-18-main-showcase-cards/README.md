# 三组完整系统主展示参数卡

> 当前状态更新（2026-10-19）：本交付中的原始卡片JSON保留生成时的 `none/false/false` 与证据哈希；用户随后已对三组完成展示 profile 授予项目准入，当前 Suite 输出 `project-admitted/true/true`。准入清单见[最新项目准入交付](../2026-10-19-project-admission/README.md)。

本交付把已经实际跑通的三组 LATTE-3 完整系统整理为可直接用于界面、作品报告和答辩的参数卡。当前建议把 **LATTE-3 + BNN/ML-DSA-44 + Hybrid + BYTEAUTH** 作为主演示底座；Falcon-padded-512 用于紧凑性工程对照，Luo 模格默认 compact 用于展示原生格 IBS 路线。

这只是当前展示决策，不是最终三组代表的锁定。三组共用同一个 LATTE HIBE，不能写成三种 HIBE；各组具体安全目标尚未证明等价，因此不能把本页数据排序成“同安全等级最快”。机器可读卡片见 [cards.json](evidence/cards.json)，只读一致性核验见 [verify.py](evidence/verify.py)。

## 1. 共同系统边界

三组均使用以下完整链路：

```text
(rcv, phi) --规范编码--> LATTE-3 两层身份
32 B 会话种子 --LATTE-3/Hybrid--> 对称载荷
发送者身份与完整上下文 --IBS--> 发送者认证
完整外层字节 --BYTEAUTH--> 篡改拒绝
```

共同 suite 为 `IBME/SUITE/1`：HIBE=`latte`、版本=`latte3-cosac-fix-v1`，transport=`hybrid`，protocol=`byteauth-v1`，状态策略=`single-writer-commit-before-publish-v1`，`allow_mock=false`。Hybrid 接收最多 64 B 的外部身份、65536 B 应用载荷和 4194304 B capsule；LATTE 内层两级身份固定按 `(parent_id, child_id)=(rcv, phi)`，每级 86 B，消息模式为 `seed32`。

三批输入和边界完全一致：接收者身份 64 B、发送者身份 64 B、应用消息 32 B；每组 3 套独立系统随机 cold 状态，每套 3 对 warm 加解密，另起 3 个恢复进程、每个恢复后解密 3 次。合计每组 3 次首次解密、9 次 warm 加密、9 次 warm 解密和 9 次恢复后解密，观察到的操作全部成功。恢复进程公共随机源读取 0 B，已有公开钥、接收状态和密文保持不变。

原始收据中的执行环境是 Intel Core Ultra 9 275HX、WSL2 Linux 6.18.33.2、Python 3.13.14、Sage 10.9、OMP 4、OpenBLAS 1。每个 worker 是新 Python 进程，但保留 OS 页缓存和已构建 native engine。这里记录的是原实验环境，不推断当前电脑具有相同路径或配置。

## 2. 共同 HIBE 参数卡：LATTE-3/COSAC-FIX

| 项目 | 实际值 |
|---|---|
| 论文与算法 | Zhao 等《Quantum-safe HIBE: does it cost a LATTE?》，Algorithms 1—5 |
| 固定作者源码 | `18cfbf9a671fca34785583b58ab9f28e3be21a3c` |
| wire / 后端版本 | `IBME/LATTE3/COSAC-FIX/1` / `latte3-cosac-fix-v1` |
| 困难假设族 | NTRU、RLWE；原文证明使用经典随机预言机模型 |
| 环参数 | `N=1024`，`q=68718428161`，最大深度 2 |
| 三层 Gaussian 标准差 | `6777.5879662983919609175926`；`351968.36683734171059914430`；`22559988.027951553365675150` |
| 数值精度 | FFT 768 bit；reduce-k 256—768 bit |
| 加密噪声 | 8 对 Bernoulli 之差的中心二项分布，标准差 2；不是离散 Gaussian |
| 资源限制 | 2 个接收者、每接收者 2 个子身份、单次 native 超时 60 s |

KeyGen、Delegate 使用真实 Gaussian/FACCT 路径；Extract 保留作者方案按目标 seed 确定化的机制。本实现构建时修正 COSAC 两处缓冲指针，使其读取新生成的 24 B Box–Muller 缓冲，同时限制 AES 计数器并使用已对照向量的 OpenSSL SHAKE-256 兼容入口。

原文把 LATTE-3 放入其 80-bit 目标表并给出相应解密失败数据，但本项目改变了身份域、seed 输入和构建细节，且尚未闭合 COSAC 修订、有限精度、总体失败及组合身份匿名映射。因此这些论文表格只作来源背景，不能转写为本组合的 NIST 等级或已准入安全位数。按用户决策，HIBE 身份匿名性作为工程推进的工作假设；原文 `ID-IND-CCA` 结果不在此冒充已完成的接收者匿名性映射。

## 3. 参数卡 A：BNN/ML-DSA-44（当前主演示候选）

| 项目 | 实际值 |
|---|---|
| IBS | `cert-ml-dsa`，`IBME/CERTIBS/1`，reference wire |
| 构造 | Bellare–Namprempre–Neven 认证构造，由 Galindo–Herranz–Kiltz 2006 §3 / Theorem 1 重述 |
| 普通签名 | pure external ML-DSA-44；未实现 HashML-DSA、external-mu |
| 固定源码 | `pq-crystals/dilithium` 提交 `d35ba3fe5449bee3e6d43e1f296c3ca818bd36be` |
| 容量 | 身份 64 B、消息 65536 B、最多 16 个固定身份、超时 30 s |
| 基元尺寸 | 公钥 1312 B、普通签名 2420 B |
| 完整 BNN IBS 签名 | 6237 B |
| 基元核验 | 210 个固定 FIPS 204 向量已在原语交付执行 |
| 原始完整系统收据 | [latte-mldsa44.json](../../research/2026-10-18-full-system-baseline/evidence/latte-mldsa44.json)，SHA-256 `dc8e5cef04534df6cd643a6c4aa908cb7b74e5e27c27e6730becadbe038ef8ab` |

BNN 构造中，机构普通签名认证 `identity || user public key`，用户再以独立普通签名钥签消息；本实现额外使用规范长度前缀和域分隔绑定主公钥上下文、身份、用户公钥、证书及消息。这是对已有通用构造的工程实现，不宣称转换本身为项目原创。

选择它作为当前主演示，是因为 ML-DSA-44 的基础规范、固定向量和解释路径最清楚，现有复现风险最低。这不表示完整 BNN IBS 或 IB-ME 获得 FIPS/NIST 认证，也不等于其强不可伪造、QROM、多用户腐化和 Wang 组合归约已经闭合。

## 4. 参数卡 B：BNN/Falcon-padded-512（紧凑性对照）

| 项目 | 实际值 |
|---|---|
| IBS | `cert-falcon`，`IBME/CERTIBS/1`，reference wire |
| 构造 | 与卡 A 相同的 BNN 认证构造 |
| 普通签名 | Falcon v1.2 padded-512，`n=512`、`q=12289` |
| 固定源码 | 作者 2021-11-01 包，SHA-256 `d9f982bd825b9903b57b686d6d26018dac173a1dff09f224cc39302f9d85a595` |
| 容量 | 身份 64 B、消息 65536 B、最多 16 个固定身份、超时 30 s |
| 基元尺寸 | 公钥 897 B、私钥 1281 B、padded 普通签名 666 B |
| 完整 BNN IBS 签名 | 2322 B |
| 采样 | 作者参考 ffSampling/SamplerZ Gaussian 路径；未用均匀采样替代 |
| 原始完整系统收据 | [latte-falcon512.json](../../research/2026-10-18-full-system-falcon/evidence/latte-falcon512.json)，SHA-256 `1937d36253490a6c4cf4447a57f2399dbaaf09805a403444d0d0bfa453c4b511` |

Falcon 卡的完整签名、发送状态和完整密文均比当前 ML-DSA 卡小，适合展示“更紧凑的工程选项”。但该实现固定的是 Falcon v1.2，不是 FN-DSA/FIPS 206；两张卡也没有建立相同具体安全目标，所以只能陈述实测尺寸和时间，不能写成“同等安全下更快/更小”。

## 5. 参数卡 C：Luo 模格 IBS 默认 research/compact（原生 IBS 对照）

| 项目 | 实际值 |
|---|---|
| IBS | `luo-module`，`luo-module-ref1`，`MODULE-COMPACT/1` |
| 论文与算法 | Luo–Chen–Susilo–Huang《Identity-Based Signature from Lattices without Trapdoors》，Algorithms 13—16 |
| 困难假设族 | MLWE 用于密钥恢复分支，MSIS 用于密钥/消息伪造分支；原文为经典 ROM |
| 环与模维度 | degree 256，`(k,l)=(11,10)`，`q=274877844481`，root `153250464611` |
| 分布/舍入 | `eta=1`，`kappa=64`，`gamma1=125440`，`gamma2=31470387200`，`gamma3=15270991360`，dropped bits 28 |
| 预算 | Extract 1024、Sign 1024、uniform 128、缓存身份 64 |
| 容量 | 身份 64 B，消息 4096 B |
| compact 签名 | 16063 B |
| 原始完整系统收据 | [latte-luo-compact.json](../../research/2026-10-18-full-system-luo/evidence/latte-luo-compact.json)，SHA-256 `311ff021ec88f4084a789027803d4b548725b9fa0e9c243129e9cd8a5b2b9395` |

本实现保留均匀掩码、拒绝采样和 Hint，不使用离散 Gaussian；`H1/H2` 角色分离，以显式均匀矩阵 `A` 代替论文中的 SHAKE-128 seed 压缩。当前卡是默认 research 配置，不是另一个显式 C64B 候选。

尤其要避免把它写成论文的“200-bit 参数”：论文表中相邻配置虽同样使用 degree 256、`(k,l)=(11,10)` 和主要 gamma 数值，但 `kappa=49`、论文签名 14680 B；当前代码是 `kappa=64`、compact 签名 16063 B，并具有显式 `q/root` 和不同 wire。因此本卡不继承论文该行的 200-bit 标签。

## 6. 同边界实测摘要

以下均为原始观察值的中位数，单位秒；括号内是观察次数。3 个 cold 状态是小样本，warm 值共享各自状态，不用于推断罕见中止或稳定尾部概率。

| 阶段 | BNN/ML-DSA-44 | BNN/Falcon-512 | Luo module compact |
|---|---:|---:|---:|
| Setup | 0.984492 (3) | 0.911282 (3) | 0.964105 (3) |
| 发送钥 | 0.273598 (3) | 0.160366 (3) | 0.318922 (3) |
| 接收钥 | 0.754343 (3) | 0.511102 (3) | 0.472760 (3) |
| cold Encrypt | 0.224485 (3) | 0.217907 (3) | 0.609756 (3) |
| 首次 Decrypt（含叶提取） | 0.403997 (3) | 0.368917 (3) | 0.382824 (3) |
| warm Encrypt | 0.211125 (9) | 0.200346 (9) | 0.364461 (9) |
| warm Decrypt | 0.280116 (9) | 0.249274 (9) | 0.229220 (9) |
| 新进程对象恢复/绑定 | 0.665062 (3) | 0.674278 (3) | 0.779928 (3) |
| 恢复后 Decrypt | 0.281654 (9) | 0.247483 (9) | 0.234768 (9) |

| 公开尺寸 | BNN/ML-DSA-44 | BNN/Falcon-512 | Luo module compact |
|---|---:|---:|---:|
| 完整外层密文（12 份） | 142051—142146 B | 138150—138207 B | 151876—151955 B |
| 公开状态 | 14352—14392 B | 13973—14020 B | 260819—260851 B |
| 主状态 | 177557—177671 B | 172047—172371 B | 522253—522339 B |
| 接收状态 | 128017—128098 B | 128078—128230 B | 128166—128243 B |
| 发送状态 | 8050 B | 4195 B | 313813 B |
| 10 ms 进程树 RSS 最大观察 | 480243712 B | 480043008 B | 493281280 B |

主状态包含缓存，不能与独立接收状态简单相加后声称为去重总存储。进程树 RSS 求和可能重复计算 fork 共享/COW 页，10 ms 采样也可能漏过短峰；这里不称其为严格独占物理峰值。

## 7. 可宣称与不可宣称

可以陈述：三组是真实非 mock 后端上的完整 IB-ME 研究运行；身份/消息长度、suite、源码版本、收据哈希、恢复零公共熵和公开测量均可追溯；BYTEAUTH 与规范 framing 在既有组合测试中提供了逐字节篡改拒绝；三种 IBS 路线呈现了标准化基元转换、紧凑 NTRU 签名转换和原生 MLWE/MSIS IBS 三种工程取舍。

不能陈述：三组已经正式安全准入；获得 NIST 安全等级；已完成 QROM 或完整组合归约；功能测试证明 NTRU/RLWE/MLWE/MSIS 困难；三组具有等价具体安全目标；或三张卡代表三种 HIBE。所有卡固定：

```text
security_claim = none
backend_admitted = false
parameters_are_formal = false
security_proofs_produced = 0
```

本次参数卡复用现有正向生命周期收据，没有重新生成密钥或重跑耗时实验。接收者/发送者错配、密文与签名篡改、截断/追加/重复字段及随机伪造等攻击验收由既有共同框架测试提供，本批不把它们冒充为新一轮重复实验。功能与有限攻击测试均不能替代安全证明。

作品原创性应放在统一可选框架、跨原语规范绑定、状态事务、wire/字节认证、真实组合验收、来源指纹、可复现实测和明确安全分层；LATTE、BNN 转换、ML-DSA、Falcon、Luo 算法及复用库分别按原来源引用，不直接宣称为原创密码算法。

## 8. 证据核验

先按当前机器实际环境选择一个 Python 3 解释器，再执行：

```sh
<python> docs/research/2026-10-18-full-system-luo/evidence/compare.py
<python> docs/deliveries/2026-10-18-main-showcase-cards/evidence/verify.py
```

两个脚本都不需要 Sage，不应复制仓库历史记录里的旧 Sage 绝对路径。`verify.py` 只读取公开 JSON、固定源码常量、upstream 清单和本地论文文件；不打开私有状态、不导入密码后端、不生成密钥、不消费随机数。它核对三份收据 SHA-256、完整 suite、输入/重复次数、恢复不变性、计时中位数、尺寸、RSS、共同安全标志及固定源码元数据。

完整逐次观察值继续以三份原始收据和统一 [comparison.json](../../research/2026-10-18-full-system-luo/evidence/comparison.json) 为准；本页的六位小数只用于展示。
