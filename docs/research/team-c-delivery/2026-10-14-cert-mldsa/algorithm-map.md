# BNN + ML-DSA 算法、参数和证明对应

范围为单独 IBS；[契约](../../../specs/certified-ibs.md)。普通签名的三个参数集算一个算法族，认证转换算同一份共享核心；没有增加三套 IBS 或完整 IBME 数量。

| 原文/条件 | 本实现 | 已核边界 |
|---|---|---|
| Galindo–Herranz–Kiltz 2006 §3，PDF第5页，复述 Bellare–Namprempre–Neven 2004 的认证构造；Theorem1 | `CertifiedIBS.setup/key_extract/sign/verify`；机构证书、用户公钥、用户消息签名三部分均保留 | 两个普通签名实例使用相同 ML-DSA 参数，机构与每个用户密钥独立生成；没有共用秘密钥 |
| `S.KG` 产生机构密钥；`S'.KG` 产生每身份密钥；证书签 `id||pk_user` | pure external ML-DSA；证书用独立域和长度前缀绑定完整主公钥上下文、身份、用户公钥 | 非原文未加分隔的裸串；上下文为完整PK编码的域分隔SHAKE256摘要，哈希碰撞及模型成本仍需计入归约 |
| IBS签名携带证书、公钥和 `S'.Sign(sk_user,m)`，验两条签名 | 用户消息另绑定上下文、身份、用户公钥、机构证书及消息；ML-DSA context固定 | 增强组帧避免组件混接；不是新转换创新，也不声称原定理逐字覆盖修改后接口的全部目标 |
| FIPS204参数/编码，Tables1/2及pure external接口 | `ml-dsa-44/65/87`：PK 1312/1952/2592 B、SK 2560/4032/4896 B、普通签名2420/3309/4627 B | 不使用旧Dilithium的密钥尺寸；未实现HashML-DSA、internal/external-mu接口 |
| 参考代码版本、范数与hint编码 | 固定[官方源码提交](https://github.com/pq-crystals/dilithium/tree/d35ba3fe5449bee3e6d43e1f296c3ca818bd36be)；保留原始26文件及CC0许可，逐文件SHA256/Git blob | 包含2026-06-03严格无穷范数修订。自己的C桥和链接包装单列，没有修改vendor字节 |
| FIPS204 finite-loop实现与当前勘误 | nonce为16位，禁止 `L*nonce+i` 越界/重复；44/65/87上限16384/13107/9362，越界报错，不换种子重试 | 已检查[2026-07-31潜在修订表](https://csrc.nist.gov/pubs/fips/204/final)：最低上限由814修订为821，平均迭代改为4.36/5.14/3.91。本实现上限均超过821；未由实验推导总中止概率 |
| 单体确定向量和公开输入 | 固定[NIST ACVP数据提交](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files)，75 keyGen、90 pure external sigGen、45 pure external sigVer | 全210例逐一执行；大量输出存SHA256，签名向量包含官方公布的TEST私钥。不是NIST认证，不含项目实物私钥 |
| 固定身份服务 | 主状态内有界缓存/RLock；先pending，再新用户密钥和证书，完成后发布；复用/恢复零熵 | 回调异常保留当前进程pending，已存pending恢复仍禁止重发。若完成快照已落盘后回调抛错，恢复复用同一把已存密钥；跨快照/多写者/回滚不由此模块解决 |
| 私钥恢复对应合法公钥和证书 | 解包、短秘密范围、规范重编码、NTT公开方程重建、t0/tr；SK额外验机构证书，MSK验缓存身份/上下文/排序 | 无新keygen、无挑战签名、无熵。不能认证文件或验证秘密的生成分布；SK内独立PRF key不由公钥方程唯一确定 |
| Theorem1经典EUF-CMA/适应身份结论 | 作为认证构造的已有条件性依据 | BNN原始具体归约、固定状态/腐化的完整映射、量子/QROM与查询损失未闭合；普通EUF不自动变成强不可伪造 |
| Wang组合的匿名HIBE和签名条件 | 本批只交独立IBS和可选BackendSpec | 无真实HIBE配对或完整IBME攻击验收；尤其不能由此授予自我伪造防护、完整QROM或NIST等级 |

生产随机源为系统CSPRNG；固定向量/pytest使用明确标识的测试随机源。普通ML-DSA的均匀有界/拒绝分布沿用参考算法，不宣称离散Gaussian。每个签名的hedged随机量为32 B，每个keygen种子32 B。机构证书每身份只签发一次，用户消息签名每次使用新随机量。

完整IBS对象绑定参数、算法、身份与公钥；ML-DSA的标准基础参数本身不是教学参数。完整转换及未来IBME仍 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。Python不可变字节和参考C不是经过侧信道/秘密擦除审计的生产密码模块；功能测试不能替代证明与准入。
