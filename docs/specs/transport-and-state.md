# 传输、完整性包装与状态契约

本文件补充 [统一实现规范](../../IMPLEMENTATION_SPEC.md)，约束已实现的共享包装。代码入口：[HybridHIBE](../../src/ibme/protocol/hybrid_hibe.py)、[BYTEAUTH](../../src/ibme/protocol/byteauth.py)、[固定研究 profile](../../src/ibme/protocol/luo_hybrid.py)。进度见 [项目状态](../PROJECT_STATUS.md)。

## 1. HIBE 大载荷适配（HYBRID-HIBE/1）

HIBE 接口后的载荷适配采用以下已实现顺序：Wang 的 IBS 输入、signature||message 载荷、(rcv,phi) 顺序与 BYTEAUTH 内层 OTS 绑定都不改。适配器放在 `src/ibme/protocol/hybrid_hibe.py`，只调用底层 HIBE 的公开接口。

Encrypt：新抽取 32 B 均匀种子和 12 B nonce；底层 HIBE 在 (rcv,phi) 的规范固定宽度编码下仅加密种子；HKDF-SHA256 从种子、公钥上下文和固定 suite 域导出 32 B AES 密钥；AES-256-GCM 加密完整载荷。AAD 规范绑定 suite、64 B 公钥上下文、**完整底层胶囊字节**、nonce 和载荷长度。身份及其可公开枚举摘要不放入新头部/AAD。每次加密重新抽取种子，不持久化种子/DEM 密钥/RNG。Decrypt：上下文/预算与规范解析 → 底层解出恰好 32 B 种子 → KDF → GCM 验证，全部通过才返回完整载荷；数据错误返回 None。

采用固定宽度身份编码以处理旧胶囊的长度泄漏：`IBME:HYBRID-ID:v1 || role(P/C) || LP(raw_identity) || zero_padding`，padding 将原身份槽补至公开 identity_max_bytes。编码定长且单射；不哈希身份，不增加碰撞假设。包装密钥持有原身份并在加载时检查底层冻结身份属性等于相应编码；协议/IBS/CLI 继续使用原身份。默认原身份上限 64 B，对应底层身份宽度及上限 86 B；加密和派生保持接收者先、发送者后。suite 明确包含 IDPAD，固定底层身份宽度及种子宽度，仍不据长度测试声称完整匿名证明。

公钥、主状态、两级密钥及密文使用独立 kind 和 suite 的长度前缀格式。包装密钥携带同一完整包装公钥、底层对象和相应原身份字段，冻结身份属性返回原身份，并核对其底层编码绑定；公钥上下文由其规范字节导出，底层对象通过调用方明确绑定的解码器加载，拒绝非规范往返与后端错配。默认资源为身份≤64 B、载荷≤65536 B、胶囊≤4 MiB；硬上限分别 256 B、16 MiB、4 MiB，底层对象≤16 MiB，包装对象≤32 MiB+1 KiB；解析先检查总长再调用底层加载器。旧组件类形式之外允许显式绑定的 `from_bytes` 解码器，协议方法形状不变。

显式研究配置 `luo-module-research`：底层 ABB10 教学参数的载荷上限缩为 32 B、编码身份上限 86 B，外部原身份上限仍为 64 B；IBS 为 M2-B2 的精确模格输入，完整消息仍经 BYTEAUTH。应用消息统一上限 3924 B，包含 IBS 输入所需接收身份和 89 B envelope；越限在随机数/签名操作前拒绝。跨命令发钥须写回 Luo 身份缓存；新进程按 state 的明确版本/研究配置选择解码器，不能退回旧教育后端。研究配置禁止 --mock 和 --legacy-baseline，不自动成为安全 preset；当前默认 education 及其旧攻击对照保持可复现。

## 2. 固定密钥状态与参数快照

LuoModuleMasterSecret的同一对象以不进入wire的重入锁串行化key_extract与缓存快照；from_bytes重建新的锁。同一身份的缓存检查、随机发钥和插入构成一个临界区，序列化的count与条目来自同一快照；数学算法、H1/H2、参数、同一串行操作序列的协议随机消费和MODULE-REF/COMPACT格式保持。

CLI所有Setup/发钥写操作在读取主状态前取得本地状态锁，并保持至缓存提交和完整密钥文件发布。研究接收者发钥也写回主状态，以承接后续有状态HIBE。主状态先提交，密钥文件随后通过同目录临时文件、flush/fsync和原子替换发布；主状态发布失败不暴露新密钥，密钥文件发布失败可以从已提交缓存重试同一密钥。研究状态不允许通过改选education/mock等配置来覆盖。参数/格式预检在创建状态目录和锁文件之前执行。

状态锁文件为永久的`.ibme-issue.lock`，只保存一个零字节，不保存身份/私钥/种子。Windows使用msvcrt字节锁，POSIX使用flock；默认最多等待30秒，忙或文件系统错误明确失败，不降级为无锁读写。进程退出释放OS锁；禁止删除锁文件来“解锁”，避免产生第二个锁inode。这是同一OS本地文件系统范围，不是分布式锁或硬断电下的多文件事务。未验证Windows与WSL混合进程共同写同一状态目录的互操作性。

固定研究profile的HIBE解码器同时核对外层限额，以及公钥与各级秘密对象中公开参数快照的n、m_bar、q、身份/载荷上限、s0/s_enc/s_pre，必须等于RESEARCH_INNER_PARAMS推导的完整快照。只比较参数，不读取陷门矩阵；合法通用HIBE对象也不能绕过该profile的固定选参。协议接口、有效旧wire和安全声明保持none/false。

安全依据按普通混合加密、RFC 5869 与 AES-GCM 的条件分项引用，对应历史实施记录见 [M2 交接](../research/2026-10-09-m2/README.md)；未宣称 HPKE 兼容或由 CPA HIBE 获得 CCA/QROM。AEAD 不能防持钥接收者重签，IBS 与 BYTEAUTH 继续承担发送者认证和完整字节绑定。本地上述研究后端/组合声明保持 none/false，底层教学 HIBE、模格 IBS 的安全参数和引用条件仍需准入。

### 2.1 固定接收状态的磁盘事务

CLI解密与Setup/发钥共用本地状态锁，从读取接收密钥前保持至明文输出；研究profile解密前核对接收身份及其声明的公开HIBE上下文。协议只调用不透明ReceiverKey.to_bytes，不读取私有基/原像矩阵。底层序列化须包含固定地址和失败墓碑。

研究解密进入可能采样的协议调用前，以O_EXCL建立receiver-<digest>.bin.pending，写固定版本字节并flush/fsync；该文件不存身份/私钥/原像。finally序列化当前接收状态，有变化时通过同目录临时文件和原子替换提交，再移除标记。成功、BOTTOM和异常/KeyboardInterrupt均走相同保存路径；完成保存后才返回明文或BOTTOM。无变化则保持原密钥字节，不增加重写。

进程硬退出、序列化/提交/解除标记失败时，标记保留，后续解密和接收者重新发钥明确失败，不自动重抽或删除标记。它是同OS本地进程崩溃下的保守阻止机制，不是硬断电、目录持久化、反回滚或跨OS分布式事务；本轮不增加自动修复命令。

研究profile已有接收密钥时，重新发钥经原语加载校验、身份和公开上下文检查后复用完整文件，不再次委派、不覆盖缓存；坏文件明确拒绝。首次发钥仍按主缓存先提交再发布密钥的契约，具体HIBE主状态须实现固定发钥及失败状态。数据输出拒绝覆盖密钥、元数据、锁、pending和临时状态等保留路径；现有别名按resolve检查，不声称抵抗恶意本地文件系统操纵。有效wire、密码算法、KDF/AAD和安全声明保持。

实现与故障证据见 [接收状态事务记录](../research/2026-10-10-receiver-persistence/README.md)；本次文档合并未重新执行该实验。

### 2.2 v2 可选组合的状态

独立选择 CLI 使用版本 2 的 `state.json`，存储完整 `IBME/SUITE/1` 配置、配置 digest、容量和公钥 digest。磁盘上的公钥/主密钥/发送者/接收者对象再封装对象 kind、suite digest、公钥 digest 与规范原语字节；底层密码对象的既有 wire 不改。恢复严格按固定配置装配，无自动后端/格式降级。摘要用于一致性检查，不提供外部存储认证或防回滚。

v2 发钥和解密采用上节相同锁/pending/先保存后输出规则，接收状态保存包含完整 v2 封装；已有接收密钥校验后复用。数据输出拒绝本状态保留文件及现有路径别名/硬链接。旧 `education`、`luo-module-research` 入口保持各自版本，不能与 v2 选择混用。旧 ABB10/SIS 裸对象未编码的字段由配置封装额外绑定；直接使用 Python 原语加载器不能据此声称能追溯这些生成字段。使用入口见 [FRAMEWORK_USAGE](../FRAMEWORK_USAGE.md)。

### 2.3 首次发钥的主状态事务

v2 选择入口及 `luo-module-research` 的发送者发钥和首次接收者发钥，在持有同一状态锁后、进入原语前，独占创建并 fsync `msk.bin.pending`。顺序为：读取主状态 → pending → 原语操作及校验 → 保存变化后的主状态 → 发布密钥 → 删除 pending。采样或校验异常时仍尝试保存当前主状态，以保留失败墓碑，且 pending 保留；提交、密钥发布、解除标记或进程硬退出失败，也保留标记。

只要标记存在，整个发行者的新发钥及重发均拒绝，不自动删标记、恢复旧快照或重抽。已有密钥的加解密按各自接收状态规则处理；这不承诺防止恶意操作者回滚磁盘。旧成功对象格式不变。数据输出禁止覆盖主 pending（含现有硬链接），同线程重复获取发行锁立即报错，避免回调自锁等待。

本规则补足首次 HIBE 委派失败时主状态丢失的问题，不能把后续接收状态的 finally 保存机制误作首次发钥已有保护。故障测试入口：`tests/test_cli_master_state.py`。

## 3. HIBE 密钥与公钥的语义绑定

独立的`HIBEKeyBindingValidator.validate_key_binding(public_key, secret_key) -> bool`能力。HIBE 六个基础方法签名保持；HYBRID-HIBE适配器构造时必须取得该验证器，可由原语方法提供，或以`key_binding_validator`显式注入。缺失/不可调用即拒绝，不能只比较类型或参数后放行。

协议层传入不透明的底层公钥/秘密对象，由原语内部核对公钥来源、身份路径及可验证的私钥方程。调用不消费随机性；只有Python字面True接受，None/0/1/字符串及异常都明确失败。加载错误映射SerializationError，运行时错误映射InvalidParameterError。Setup/Extract/Derive产生的秘密对象和Decode/Decrypt使用的秘密对象均经过相同检查，坏密钥在新随机采样或胶囊解析前拒绝。

ABB10教学实现：主密钥重建公开A并核对元数据/u；一级、二级密钥核对同一根A/u/元数据，再复用既有公开代数验证函数核对A·R1+G=H(parent)、[A|H(parent)]·R2+G=H(parent,child)。私有矩阵只在原语层读取。校验不证明Gaussian采样来源、范数分布、不可伪造或匿名性，不提高安全声明。

Mock仅供契约测试：核对可验证的公开种子/限额与二级公开派生值，一级秘密链不能从公钥核验，仍无任何密码安全性。不得以mock结果放行CHKP；CHKP 公开适配器须交真实验证器并覆盖同参数不同公钥/坏方程/身份路径及恢复案例。

合法既有 wire、算法、身份顺序及随机输入保持；先前可解析但语义不绑定的密钥必须拒绝。新后端应实现自己的验证器，协议不得读取其陷门。

## 4. 完整密文字节认证（BYTEAUTH/1）

这是统一规范 §4 Wang 基线外的独立工程包装，不改变 HIBE 身份顺序。底层基线的消息改为规范 envelope：`IBME:BOUND-MSG:v1 || LP(ots_vk_commitment) || LP(application_message)`；因此原有 IBS 同时签入接收者、应用消息和临时 OTS 公钥承诺。每次 Encrypt 新生成一把 Lamport 型一次性哈希签名密钥；先完成基线加密，再对外层版本域、公钥上下文承诺、完整 OTS 公钥及完整基线密文字节签名。签名置于外层末尾，无签名/被签密文循环。

OTS 固定 512 个消息摘要 bit，每个 bit 两个 64 B 随机原像；公钥 1024 个 64 B 哈希像，签名 512 个 64 B 原像。元素像、消息摘要、OTS 公钥承诺和协议公钥上下文使用各自新域的 SHAKE-256，不改变旧六个域常量。生产随机数使用系统 CSPRNG，测试流构造注入；单个私钥对象签一次即耗尽，不序列化进主密钥/状态。

外层 wire：`IBME:BYTEAUTH-CT:v1 || LP(public_context_digest) || LP(ots_public_key) || LP(baseline_ciphertext) || LP(ots_signature)`。承诺均 64 B；内部密文≤64 MiB，公钥/签名长度固定，严格拒绝重复、截断、追加和未知版本。Decrypt 先核对公钥上下文和完整 OTS，再走原基线 Decrypt，最后核对 envelope 中的 OTS 公钥承诺，全部数据失败返回 BOTTOM。公钥及双方长期密钥编码不变。

攻击者可持接收者密钥和原合法签名。若修改原认证公钥下的密文/外层签名却通过，形成强一次性签名伪造；若换新认证公钥并重签，则内部 IBS 签入的承诺必须改变，除承诺碰撞外需要 IBS 伪造。相同字节密文重放不是篡改。临时签名密钥不交给接收者，公开 checksum 或接收者已知密钥的 MAC 不作为替代。

依据为 Lamport 一次性哈希签名的单次签名与单向/第二原像条件；工程实例化另假设 SHAKE 域的原像/碰撞安全。CHK 的强 OTS 包装仅作参考：本版本不把 vk 改成 HIBE 身份，**不引用其定理宣称 CCA**。上述是条件式字节认证论证；旧教学 SIS-IBS 的已知伪造仍使该组合的新公钥分支可被攻击，必须保留负面对照。Luo 研究组合尚未安全准入，不能据包装测试宣称完整加强认证或后量子安全级别。

CLI 默认产生并只接受 BYTEAUTH/1；旧未认证密文仅经显式 `--legacy-baseline` 研究开关访问，不自动降级。原 BaselineIBME 保留数学参考和负面对照；新版本与旧版本的测试分别记录，不能靠关闭验签使安全目标通过。

## 5. 组合容量与验收边界

| 层 | 当前固定研究 profile 的约束 | 含义 |
|---|---|---|
| 应用消息 | ≤3924 B | 由 IBS 的 4096 B 输入预算扣除接收身份与 89 B envelope 等规范开销 |
| Hybrid 载荷 | ≤65536 B | 接收完整 signature/message 载荷，与 inner seed 容量不同 |
| inner HIBE 载荷 | 恰好 32 B | 本地实际接线是教学 ABB10；CHKP 必须独立实测其 256 bit 路线 |
| 原始身份 | ≤64 B | 协议和 IBS 使用的身份 |
| inner parent / child | 各 86 B | 原始身份定长编码后分别进入两层 HIBE |
| 胶囊 | ≤4 MiB | 完整胶囊字节进入 GCM AAD |

32/86/86 是当前 wrapper 的输入合同，不是已证明的 CHKP 容量。教学 ABB10 的内部组帧长度不进入 CHKP/Hybrid 容量定义。HIBE 解密原始数学层可能在低位扰动后恢复同一 seed；Hybrid 必须在完整胶囊 AAD 验证处拒绝这种修改。完整组合仍必须经 IBS 和 BYTEAUTH 的认证路径验收。

测试入口：`tests/test_hybrid_hibe.py`、`tests/test_hybrid_key_binding.py`、`tests/test_byteauth.py`、`tests/test_luo_hybrid_ibme.py`、`tests/test_luo_compact_ibme.py`、`tests/test_cli_state_lock.py`、`tests/test_cli_receiver_state.py`、`tests/test_research_state_integrity.py`。报告应分别标记 raw math、wire、state、Hybrid 和完整协议的执行结果，保留预计失败的历史负面对照。
