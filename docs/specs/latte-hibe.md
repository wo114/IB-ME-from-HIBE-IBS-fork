# LATTE-3 独立研究 HIBE 契约

本契约限定 `ibme.hibe.latte` 的 `latte3-research`、`IBME/LATTE3/COSAC-FIX/1`。接口沿用[公共规范](../../IMPLEMENTATION_SPEC.md)，原文为[Zhao 等 TIFS 2024 作者稿](../../papers/2024_quantum_safe_hibe_zhao.pdf) Algorithms 1–5，源代码固定 MIT 版本 `18cfbf9a671fca34785583b58ab9f28e3be21a3c`。逐批实测见[交付材料](../research/team-c-delivery/2026-10-14-latte-hibe/README.md)。

## 执行与参数

- 固定作者 LATTE-3：`N=1024`、`q=68718428161`、最大身份深度2；不是任意环维度/深度/模数的参数工厂。
- `sigma_l` 是标准差，原数值和高精度设置从固定 `param.h` 保留。加密噪声为8对 Bernoulli 差的中心二项分布，标准差2，不宣称为 Gaussian。
- 需要 WSL 的 `~/miniconda3/envs/sage`、按随包源码构建的 Linux x86-64 原生桥及本机 CPU 指令。用原生子进程隔离作者代码的静态状态；无依赖明确失败。
- 公共 `LATTEParams` 完整绑定模式、身份容量、发钥容量和原生操作超时；固定数学常量、来源版本及安全标记也进入对象快照。默认每层身份至多86 B、2个接收者/每接收者2个子身份，可显式选择上限内其它容量。
- `seed32` 严格处理32 B，供既有 Hybrid 包装使用；`framed32` 使用4 B长度、最多28 B消息和规范零填充，支持空消息。无自动换模式或降参数。

## 六方法与算法对应

| 方法 | 实际执行 |
|---|---|
| setup | 原生 KeyGen / Algorithm1：真实 Gaussian/FACCT NTRU 根与公开 h |
| extract(master, rcv) | 原生 Delegate / Algorithm2，`l=1`：从根的2×2环基生成接收者3×3环基 |
| derive(parent, phi) | 原生 Extract / Algorithm3，`l=2`：从该接收者基提取两个解密多项式 |
| encrypt | 原生 Algorithm4：新32 B种子、KDF、真实中心二项噪声和Encode |
| decrypt | 原生 Algorithm5：Decode后完整重加密比较，失败返回None |
| load_ciphertext | 严格规范对象解码，未知/重复字段、非整数/范围错误、截断/追加拒绝 |

身份顺序为 `(rcv, phi)`。两层公开环哈希使用不同域、完整公钥/参数上下文及长度前缀，以有界XOF拒绝流生成均匀模系数。公开/密文wire采用系数域；桥内与作者NTT表示往返，不把平台原生结构体作为wire。

Setup、接收者委派、Encrypt的新熵经 `rng.read(32)` 注入，默认为系统CSPRNG。作者代码的终层Extract以 `SHAKE256(target_NTT_bytes || 'G')` 播种AES采样器，确定性地产生同址密钥；本实现明确保留该机制，`derive` 的rng参数不用于替换它。它不构成“每次新抽独立原像”的承诺。

## 对象、绑定和状态

五类对象为公钥、主密钥、一级密钥、二级密钥和密文。公钥/密文只含公开数学数据和参数；密文无身份或身份摘要字段。**没有明文标签不等于已经证明匿名性。**

私钥导入用Sage精确系数环检查：根/父基的核关系及环行列式±q，证明所导入基的系数格指数为q^N；不是只检查若干短核向量。终层检查由公钥及完整路径确定的短原像关系，使用预声明的`4·3N·sigma_2²`平方范数资源/导入门。上述检查不认证采样来源或Gaussian分布。

同一地址成功后固定复用；失败或不确定地址保留None占位，禁止重发。新操作前可通过 `persist_pending(owner)` 保存不透明状态。主密钥树的节点共用可重入锁，支持在父级回调中保存整棵树；成功缓存随主/父对象一起恢复，无需重跑KeyGen、Delegate或Extract。原生过程有单次超时，AES每个种子最多2^27块，耗尽直接中止；不在外层自动重试。

磁盘原子写、跨进程锁和保存后输出由调用应用负责。快照没有外部MAC、防回滚或分布式唯一性；复制旧快照不能视为全局唯一发钥。

## 实现差异和准入

原版源码与MIT声明逐字保留，只在构建临时目录应用明确差异：COSAC改读实际新生成的24 B Box–Muller缓冲；限制AES计数器块数；用经过SHAKE256向量对照的OpenSSL EVP替代XKCP链接接口。编译使用`-fwrapv`，每次真实输出仍经独立精确环验证；不把有符号溢出的环绕行为当数学正确性依据。

公共后端版本另外冻结了身份域分隔、参数/公钥绑定、有限容量与超时、消息组帧和系数域规范编码。保留作者实际Extract种子输入与论文`G(ID)`字面写法的区别，不静默宣称两者已获得同一分布/模型结论。

`backend_spec()` 可交给显式注册器；默认registry的`latte`占位尚未替换，CLI和真实IBS配对属于后续公共接入。已有单独Hybrid适配测试不计完整IBME。

本版本始终 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。接收者匿名/具体身份模型、修订后整体TV/RD、数值FFT/采样和范数/资源失败预算、完整攻击成本与Wang组合前提尚未准入。作者参数和定理引用、诚实解密及有限负例均不能替代这些条件。
