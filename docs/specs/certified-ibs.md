# BNN 认证转换 IBS 独立契约

版本 `IBME/CERTIBS/1`；本批先实现 `cert-ml-dsa`，同一转换核心供后续 Falcon 复用。不另写 IBME。

## 1. 原文和实现选择

Galindo–Herranz–Kiltz, ASIACRYPT 2006 §3 / Theorem 1（本地 PDF 第5页）复述 BNN 通用构造：机构普通签名密钥；每身份独立用户密钥；机构认证身份和用户公钥；完整 IBS 签名包含证书、用户公钥、用户消息签名。验证同时检查机构证书和用户消息签名。没有省略证书的普通签名接口。

普通签名固定 `pq-crystals/dilithium` 提交 `d35ba3fe5449bee3e6d43e1f296c3ca818bd36be`（2026-06-03 严格范数检查修订），原始源码及许可证逐字保留。源内符号仍用 Dilithium 命名；只有通过 NIST FIPS204 向量核验的 ML-DSA-44/65/87 字节格式用于此接口。只支持 pure external ML-DSA，未实现 HashML-DSA 或 external-mu 接口。

## 2. 算法和编码

- `setup`：机构 ML-DSA 密钥对，系统熵32 B。
- `key_extract`：在主密钥锁内先写 pending，生成独立用户密钥对（32 B），机构签发证书（hedged rnd 32 B），校验后保存；已发身份复用同一密钥和证书。
- `sign`：对已绑定身份的密钥签名，每消息 hedged rnd 32 B；没有身份形参。
- `verify`：只用公共对象/身份/消息/完整签名校验证书和用户签名；错误类型、身份、消息、签名返回 False，缺少或损坏本机引擎单独报告运行错误。
- `load_signature`：规范解析完整签名；不按公钥推测其它算法或格式。

主公钥规范字节的32 B SHAKE256域分隔摘要绑定完整参数和机构公钥。证书消息是独立域下的公钥上下文、身份、用户公钥的长度前缀编码；用户消息另以域分隔绑定相同上下文、身份、用户公钥、证书字节和应用消息。ML-DSA native context 固定 `IBME/CERTIBS/DIGSIG/1`。这些是对原文串连接口的显式、单射组帧；其量子/定量归约没有由功能测试自动获得。

PK/MSK/SK/SIG 各有独立 magic/version；字段采用固定递增1字节tag、4字节大端长度、数据。重复/乱序/未知tag、截断/追加、非规范参数JSON、错误类型/尺寸均拒绝。SIG 保存算法ID、公共上下文、用户公钥、机构证书、用户签名；不含用户秘密钥。SK 另含完整公共上下文、身份和用户秘密钥，公开 `identity` / `identity_digest`。私有恢复检查 ML-DSA 短秘密范围、规范重编码、公钥重建、tr/t0及证书绑定；它不认证文件、不证明生成分布。

## 3. 固定状态和失败

主状态保存完整机构秘密钥、身份缓存及失败/pending tombstone；有界容量，身份排序唯一。重复发钥和同一快照恢复不重新取熵。可选 `persist_callback(master)` 在 pending 和完成时调用；RLock允许回调序列化整份状态。回调或采样/原生异常不返回密钥，当前进程将该地址保留为 pending，禁止自动重发；回滚、跨快照多写者和“落盘后抛异常”的不确定发布由现有CLI事务/pending标记管理。本模块不声称外部认证或防回滚。

## 4. 原生边界和准入

每次原生操作独立进程、严格长度和EOF、公开资源/超时限制。生产熵由Python安全随机源输入；C桥只读取显式32 B tape，不调用原vendor的操作系统随机源。原vendor保持不变；链接包装限制 ExpandMask 的16位nonce使用范围，界外直接中止，不换种子重试。成功路径与上游一致，有限中止事件及整体查询损失仍需映射。

基元参数为 FIPS204 标准参数，完整认证 IBS/IBME 的正式准入继续 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。原文 Theorem 1 为经典标准签名到 IBS 的条件性依据；不据此宣称完整量子安全、NIST等级、强不可伪造或 Wang 组合已准入。参数集、格式或库复用不新增密码算法或原创性。
