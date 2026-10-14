# BNN 认证转换 IBS 独立契约

版本 `IBME/CERTIBS/1`；`cert-ml-dsa` 与 `cert-falcon` 共用一份转换核心，各自有显式算法ID、普通密钥格式、验证器和可选BackendSpec。不另写 IBME。

## 1. 原文和实现选择

Galindo–Herranz–Kiltz, ASIACRYPT 2006 §3 / Theorem 1（本地 PDF 第5页）复述 BNN 通用构造：机构普通签名密钥；每身份独立用户密钥；机构认证身份和用户公钥；完整 IBS 签名包含证书、用户公钥、用户消息签名。验证同时检查机构证书和用户消息签名。没有省略证书的普通签名接口。

普通签名固定 `pq-crystals/dilithium` 提交 `d35ba3fe5449bee3e6d43e1f296c3ca818bd36be`（2026-06-03 严格范数检查修订），原始源码及许可证逐字保留。源内符号仍用 Dilithium 命名；只有通过 NIST FIPS204 向量核验的 ML-DSA-44/65/87 字节格式用于此接口。只支持 pure external ML-DSA，未实现 HashML-DSA 或 external-mu 接口。

## 2. 算法和编码

- `setup`：所选普通签名的机构密钥对，系统熵32 B。
- `key_extract`：在主密钥锁内先写 pending，生成独立用户密钥对（32 B），机构签发证书（新32 B签名随机种子），校验后保存；已发身份复用同一密钥和证书。
- `sign`：对已绑定身份的密钥签名，每消息使用新32 B随机量；ML-DSA为hedged rnd，Falcon为SHAKE PRNG种子。没有身份形参。
- `verify`：只用公共对象/身份/消息/完整签名校验证书和用户签名；错误类型、身份、消息、签名返回 False，缺少或损坏本机引擎单独报告运行错误。
- `load_signature`：规范解析完整签名；不按公钥推测其它算法或格式。

主公钥规范字节的32 B SHAKE256域分隔摘要绑定完整参数和机构公钥。证书消息是独立域下的公钥上下文、身份、用户公钥的长度前缀编码；用户消息另以域分隔绑定相同上下文、身份、用户公钥、证书字节和应用消息。ML-DSA native context 固定 `IBME/CERTIBS/DIGSIG/1`。这些是对原文串连接口的显式、单射组帧；其量子/定量归约没有由功能测试自动获得。

PK/MSK/SK/SIG 各有独立 magic/version；字段采用固定递增1字节tag、4字节大端长度、数据。重复/乱序/未知tag、截断/追加、非规范参数JSON、错误类型/尺寸均拒绝。SIG 保存算法ID、公共上下文、用户公钥、机构证书、用户签名；不含用户秘密钥。SK 另含完整公共上下文、身份和用户秘密钥，公开 `identity` / `identity_digest`。私有恢复检查 ML-DSA 短秘密范围、规范重编码、公钥重建、tr/t0及证书绑定；它不认证文件、不证明生成分布。

## 3. 固定状态和失败

主状态保存完整机构秘密钥、身份缓存及失败/pending tombstone；有界容量，身份排序唯一。重复发钥和同一快照恢复不重新取熵。可选 `persist_callback(master)` 在 pending 和完成时调用；RLock允许回调序列化整份状态。回调或采样/原生异常不返回密钥，当前进程将该地址保留为 pending，禁止自动重发；回滚、跨快照多写者和“落盘后抛异常”的不确定发布由现有CLI事务/pending标记管理。本模块不声称外部认证或防回滚。

## 4. 原生边界和准入

每次原生操作独立进程、严格长度和EOF、公开资源/超时限制。生产熵由Python安全随机源输入；C桥只读取显式32 B tape，不调用原vendor的操作系统随机源。原vendor保持不变；链接包装限制 ExpandMask 的16位nonce使用范围，界外直接中止，不换种子重试。成功路径与上游一致，有限中止事件及整体查询损失仍需映射。

ML-DSA基元参数为 FIPS204 标准参数，完整认证 IBS/IBME 的正式准入继续 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。原文 Theorem 1 为经典标准签名到 IBS 的条件性依据；不据此宣称完整量子安全、NIST等级、强不可伪造或 Wang 组合已准入。参数集、格式或库复用不新增密码算法或原创性。

## 5. Falcon v1.2 第二适配

固定[作者参考源码包20211101](https://falcon-sign.info/Falcon-impl-20211101.zip)，SHA-256 `d9f982bd825b9903b57b686d6d26018dac173a1dff09f224cc39302f9d85a595`。18份MIT原文件逐字保留，包含seed初始化缺失flip的作者修订。规范为本地Falcon v1.2（2020-10-01），不等同FN-DSA/FIPS206。

只接受 `falcon-padded-512` / `falcon-padded-1024`，n512/1024、q12289，固定PK897/1793 B、SK1281/2305 B、普通签名666/1280 B。压缩可变长和CT编码不自动解释为所选格式。签名的nonce40 B由调用者新32 B种子的SHAKE流导出；后续参考ffSampling/SamplerZ使用同一已初始化PRNG的后续流，不把均匀采样冒充高斯。两个参数不计两种算法。

普通签名输入为 `IBME/CERTIBS/FALCON-DIGSIG/1` 后一个NUL、context的4 B小端长度/context、消息4 B小端长度/消息。默认context同ML-DSA；转换层的身份/机构/证书域分隔保持不变。普通API的上下文不宣称是Falcon规范原生功能。官方KAT使用独立vector-driver对原始消息签名，生产driver拒绝KAT操作，metadata也区分两者。

公共对象与用户公钥检查头、尺寸和每个模q系数范围。恢复秘密时，检查f/g/F规范重编码，重建G并逐项核验整数负循环环上的 `fG-gF=q`，检查f/g奇校验与范数和参考Gram–Schmidt边界，再重建h并检查机构/用户证书链。不调用keygen/sign、不取熵，不证明原始生成分布或外部文件真实性。

所有C源码不改；编译固定FPEMU整数模拟IEEE-754，关闭AVX/FMA/ChaCha-keygen及OS熵源。GNU链接包装限制每操作跨单元SHAKE输出16MiB、PRNG refill65536次；超时1..300 s为完整进程后备上限。相同编译单元内部调用可能不经过链接包装，不能把计数解释为所有内部调用次数；完整进程超时仍强制有界。有限中止直接失败，发钥保留pending，不换种子重试。尚未从实验推导整体TV/RD、数值/中止概率或侧信道保证。

完整IBS签名还包括第二份Falcon签名、用户公钥和转换编码；应使用可选descriptor的完整尺寸。两种descriptor的配置检查拒绝跨家族参数。默认registry、真实HIBE组合、强不可伪造/量子游戏及安全准入须分别完成，不因底层KAT成功放行。
