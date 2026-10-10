# IB-ME from HIBE + IBS：实现规范与验收标准

本文档是代码实现的唯一接口规范。其他 AI 只应根据本文件和 `ARCHITECTURE.md` 修改代码；论文中的记号与代码命名不一致时，以本文件的接口为准，并在适配层转换。

2026-10-03 重建范围已固定为王老师的两层匿名 HIBE + IBS 通用构造，不实施 Boyen–Li 增强隐私。当前接口暂保持兼容；第 3 节的二进制 gadget 和 SIS 关系描述现有参考后端，不是所有未来后端必须采用的算法。具体原语选定后，再版本化补充参数与算法规范。研究记录不能自行改写代码接口，进度见 `docs/PROJECT_RESTART.md`。

原语准入条件为满足 Wang 的 HIBE 自适应匿名安全定义和 IBS 自适应不可伪造定义；mock、非自适应 IBS 基本形式或教学采样不能作为安全完整实例交付。错误身份拒绝与密文字节篡改拒绝仍须实现，取消增强隐私不降低本文件验收要求。

2026-10-08 用户转述老师要求安全性证明以引用为主。对于忠实复现的已发表算法，交付算法/定理/参数和实现对应表即可组织理论依据，不要求重做基础定理或完整 Lean 形式化。仍须检查引用结论覆盖两层匿名、自适应与实际密钥复用模型，完成合法选参和实现验收；已知反例、未覆盖的算法改变与完整性包装不能靠引用消除。具体工作顺序见 [文献复核与实施计划](docs/research/2026-10-08-selection/文献复核与后续实施计划.md)。此说明不改变接口与安全声明门槛。

2026-10-06 多实例验收口径（老师确认后的补充）：同时要求不同格困难假设和不同具体算法的实例化。按 HIBE/IBS 真实依赖记录假设类别，按完整具体方案记录算法实例；同一假设下的不同算法可计为算法实例，参数或采样器调整仍属于参数扫描/实现优化。每套实例须提供假设、具体原语、安全模型、证明映射、参数与攻击估计，再通过完整协议验收。完整组合数与底层算法数分别报告，不靠接口配置组合凑数量。详见 [专项说明](docs/research/2026-10-06/多困难假设实例化口径与验收.md)。此修订不改变现有代码接口或 `Params` 类型。

## 1. 身份与编码

身份类型为非空字节串 `Identity`。CLI 可以接受 UTF-8 字符串，但进入密码算法前必须转成字节串。

规范编码：

```text
encode_bytes(x) = uint32_be(len(x)) || x
encode_identity(id) = DOMAIN_ID || encode_bytes(id)
encode_pair(a, b) = DOMAIN_PAIR || encode_bytes(a) || encode_bytes(b)
encode_message(id, message) = DOMAIN_MSG || encode_bytes(id) || encode_bytes(message)
```

禁止使用无长度的字符串拼接。身份比较使用原始规范化字节串的常数时间比较。

2026-10-08 增加兼容的 Core 辅助接口 `PreparedShake256(domain, prefix).digest(suffix, out_len)`，结果逐字节等于 `shake256(domain, prefix + suffix, out_len)`。前缀在构造时吸收，后续每次复制状态再添加后缀；调用者仍负责原有规范字段编码。六个域常量、原 `shake256` 输入布局与生产协议保持不变。此接口用于已编码联合上下文的重复吸收优化，不替换熵源、不缩短上下文、不复用扰动/噪声/签名输出。研究适配器显式注入，详见优化报告。

## 2. 参数对象

```python
@dataclass(frozen=True)
class Params:
    name: str
    security_parameter: int
    n: int
    m_matrix: int
    q: int
    s0: float
    s: float
    s_prime: float
    identity_bytes: int
    max_message_bytes: int
```

代码中不要用 `m` 同时表示消息和矩阵列数；矩阵列数统一叫 `m_matrix`，消息统一叫 `message`。

`identity_bytes` 的语义（主 AI 冻结，2026-09 M3 审查后）：**身份的最大字节长度**（上限，不是固定长度）。HIBE 后端的所有身份入口（extract/derive/encrypt/decrypt 中的身份参数）必须以 `validate_identity(..., max_bytes=params.identity_bytes)` 强制执行；协议组合中每个身份都会流经 HIBE 层，因此该上限覆盖整个 IB-ME 路径。IBS 原语单独调用时依赖调用方先经过 HIBE 层规范化（在 IBS 模块文档中注明）。

参数文件必须记录：来源论文、是否仅用于调试、预期安全级别、已知限制。没有完成安全估计的参数必须标注 `security_claim: none`。

R1 研究扩展决定（2026-10-08）：旧 `Params` 及旧 uint32 格式保持兼容；CHKP、Luo/SRGG 的独立数学参考使用各自显式研究配置，记录层级宽度、挑战和编码条件等旧类型无法表达的字段。大模数不得截断为 uint32。`BaselineIBME.setup` 已分别转发 HIBE/IBS 参数，方法形状不需改变；进入 `src/ibme/` 的新版本参数类型与 wire 必须在对应后端任务中单独补充规范和 contract tests，研究配置不自动成为生产后端。当前规格见 [R1](docs/research/2026-10-08-r1/README.md)。

M2-A Luo 研究适配（2026-10-09）：`src/ibme/ibs/luo.py` 实现冻结的 IBS 方法与对象基类，显式使用独立 `LuoMatrixParams`；旧 Params 不自动映射。配置为 `IBME/LUO2024/MATRIX-CONFIG/1`，完整字段且安全声明固定 none/false，JSON 解析拒绝重复/未知字段和错误版本。对象继续兼容 M1 的 `MATRIX-REF/1` 研究格式，主状态保存固定身份密钥而不保存 RNG，验签只依赖公开输入。程序对象类型错误为 TypeError，身份/消息错误为 EncodingError，配置错误为 InvalidParameterError，反序列化错误为 SerializationError；熵源错误为 RandomnessError，预算耗尽为明确的 LuoSamplingAbort。当前 n≤16,m≤128,k≤32、uint32 q、有符号 int64 整数及 8 MiB 上限是研究资源限制；分析报告里的大参数不能交给这个版本执行。方法形状、旧后端和 CLI 选择不变，未准入安全后端。算法对应、测试、完整格式及 CHKP 载荷交接见 [M2-A](docs/research/2026-10-09-m2/README.md)。

## 3. 格基基础模块

2026-10-09 Luo 模格研究后端冻结补充（M2-B2）：独立 `LuoModuleParams` 和 `MODULE-REF/1` 格式，不转换旧 Params。默认研究输入 degree=256、(k,l)=(11,10)、q=274877844481、NTT 512 阶根 153250464611、η=1、κ=64、γ₁=125440、γ₂=31470387200、γ₃=15270991360、d=28。实现论文 §4 Algorithms 7–16；Algorithm 15 第 9 行的 zid 按该节正文及 Algorithm 16 解释为签名 z。不增加 z 非零条件。H1/H2 用独立 SHAKE-256 角色域、规范输入和本 IBS 公钥上下文；本轮 A 为真实均匀显式矩阵，未实施原文 SHAKE-128 种子压缩。

多项式为 Z[X]/(X^N+1) 与 Z_q[X]/(X^N+1)：掩码、私有响应和 z 保留有符号整数；A、t、w 为 [0,q) 系数。负循环 NTT 用 twist/untwist 和 2N 阶根，整数运算不得溢出或截断 q。Power2Round 保留最高端进位（默认 w1 可为 1024）；Decompose 的 q−1 特例、MakeHint/UseHint 严格依原文，h 为逐系数 bit，不发明 hint 重量上限。

对象公钥/主状态/固定身份密钥/签名分别版本化、类型化、长度前缀编码；参数和模系数为 uint64，z/私有系数为 int64，c 为 signed int8，h 为 bit 字节，w1 宽度由参数决定。解析拒绝未知版本、重复/截断/追加、维度/范围错误、错误公钥上下文；主状态恢复校验 t=As1+s2，身份密钥恢复校验 Az1+z2=w+tH1(w1,id)。同一身份缓存同一份密钥，RNG 不进入快照，私有 repr 隐去秘密。

公开资源限制：N 为 2–256 的二次幂，k/l≤16，消息≤65536 B、身份≤256 B、缓存≤64 身份、wire≤16 MiB；均匀抽样/Extract/Sign 均有显式预算，超限抛 IBMEError 的采样中止而不返回默认值。大素数仅接收本轮已有 Sage 核验的模数，小素数独立核验；不把资源/方程通过当作 MLWE/MSIS 或完整 QROM 安全。`security_claim: none`、`backend_admitted: false`，不注册为 CLI 安全后端，签名载荷与完整攻击验收仍是后续切换门槛。

2026-10-09 模格 MSIS/Hint 核验口径：论文 §4.4 式 (4.1) 引入 u′ 的系数无穷范数界 `κ*2^(d−1)+2γ₃+1`，当前为 39131917313，不能仅用 z 的界代替。已签身份条件分支的矩阵为 [A|I_k]；新身份分支在 MLWE 将 t 换为均匀后采用 [A|I_k|t]，对应系数维度分别 (2816,5376)/(2816,5632)，后一分支的小挑战乘积块单独限制为 128。筛查的共同放松界为 78279890946，采用固定版本工具的无穷范数模型，记录块界/放松方向、模型与局限。HighBits→完整 w 的升举在最高 w1=1024 时必须保留低部 −62464，H1 仍作用于 Power2Round(w) 的原高位编码。

非零条件须分支记录：整数二次幂分圆环是整环，小挑战乘积的系数界小于 q，足以排除新身份分支的零模产品，无需错误假设所有挑战在 Rq 可逆；已签身份分支不能只由 c≠c′ 推出非零，需要原文公开模拟/固定缓存条件下的平均猜测界。此条件论证、启发式成本筛查及真实实现分别验收，尚无完整 QROM/侧信道/安全默认实例；研究代码与生产参数不得据此被无条件放行。

2026-10-09 `MODULE-COMPACT/1` 传输格式：只压缩签名字节，不改变参数、公钥/密钥格式、数学签名或 H1/H2 的既有输入编码。z 以偏移 `z+Zmax` 打包，`Zmax=γ₂−β₂−1`，宽度 `max(1,bit_length(2*Zmax))`；w₁ 宽度为 `max(1,bit_length(max_w1))`；默认分别36/11位。挑战使用N位存在位图和κ个符号位（按系数下标递增，1表示−1）；h 按全体 kN 个 bit 打包，不增加 Hint 重量限制。全部系数按多项式行序、最高位优先打包；末尾不足字节的低位必须零，不能接受非规范填充或未使用范围编码。

压缩 wire：`L24C1 || LP(IBME/LUO2024/MODULE-COMPACT/1) || LP(SIGNATURE) || LP(params) || LP(context) || LP(z) || LP(c_presence) || LP(c_signs) || LP(w1) || LP(h)`；params/context仍是136/64B，字段长度由已验证公钥参数推导，先核对参数/上下文，再解码固定大小字段。总长≤1MiB，拒绝截断、追加、重复、版本/上下文错误、维度/范围/权重和填充异常。编码/解码在合法数学签名空间与规范字节空间上互逆；BITPACK不是新的密码算法。

显式 `LuoModuleCompactIBSBackend` 复用原四算法与密钥缓存，只包装 Sign 返回值及选定格式的加载；规范转换函数可用于参考/压缩差分。`luo-module-research` setup 支持 `--signature-format reference|compact`，缺省 reference；研究 state明确保存选择，既有缺少该字段的v1状态按已知 reference 格式读取。Encrypt/Decrypt 按state选择，不能用这个选项临时改解码器；compact加载器仅接收compact，reference仅接收reference。教育/mock配置不支持compact选项，既有哈希域及Wang/BYTEAUTH的输入和绑定均不改。安全声明和原语实例计数不因压缩改变。

### 模矩阵

`ModMatrix` 至少支持：

- 创建和维度检查；
- 模 $q$ 加、减、乘；
- 矩阵拼接；
- 固定长度序列化；
- 从规范字节串反序列化；
- 与整数向量相乘。

所有操作都必须检查模数和维度一致性，失败时抛出项目自定义异常。

### gadget 矩阵

对 $q$ 使用统一的二进制 gadget 矩阵：

$$
G\in\mathbb{Z}_q^{n\times n\lceil\log_2q\rceil}.
$$

### SIS-IBS 关键关系

$$
H_1(mpk,id)=A\widehat R_{id}+G,
\qquad
F_{id}=[A\mid H_1(mpk,id)] .
$$

签名必须满足：

$$
F_{id}z=H_2(mpk,id,message)\pmod q.
$$

验证还要检查 $z\neq 0$ 和论文规定的范数界。

### 随机性

离散高斯采样器必须提供：

```python
sample_integer_gaussian(sigma, center=0) -> int
sample_vector_gaussian(length, sigma) -> list[int]
```

实现者必须提供采样统计测试，报告均值、方差和尾部计数。不能把均匀随机数伪装成离散高斯。

## 4. 基线 IB-ME 算法

```python
def setup(params):
    hpk, hmsk = hibe.setup(params)
    ipk, imsk = ibs.setup(params)
    return PublicKey(hpk=hpk, ipk=ipk), MasterSecret(hmsk=hmsk, imsk=imsk)

def skgen(msk, sender_id):
    return SenderKey(ibs.key_extract(msk.imsk, sender_id))

def rkgen(msk, receiver_id):
    return ReceiverKey(hibe.extract(msk.hmsk, receiver_id))

def encrypt(public, ek_sender, receiver_id, message):
    signed_message = encode_message(receiver_id, message)
    signature = ibs.sign(ek_sender.signing_key, signed_message)
    payload = encode_signature(signature) + encode_bytes(message)
    return hibe.encrypt(public.hpk, receiver_id,
                        ek_sender.identity, payload)

def decrypt(public, dk_receiver, sender_id, ciphertext):
    child_key = hibe.derive(dk_receiver.level1_key, sender_id)
    payload = hibe.decrypt(child_key, ciphertext)
    if payload is None:
        return None
    signature, message = parse_payload(payload)
    verify_message = encode_message(dk_receiver.identity, message)
    if not ibs.verify(public.ipk, sender_id, verify_message, signature):
        return None
    return message
```

实现时将 `None` 映射为对外 API 的 `BOTTOM`，不要返回部分解密结果。

## 5. 混合加密包装

当消息超过 HIBE 明文容量时：

1. 生成随机对称密钥；
2. 用 AEAD 加密文件；
3. IB-ME 只加密对称密钥和必要的绑定信息；
4. IBS 绑定规范化后的 `receiver_id || nonce || aead_ciphertext` 的哈希。

这是工程包装，报告中必须说明它与论文中直接加密消息的接口差异。

上述步骤只描述待论证的包装方向，尚不是完整性或 CCA 定理。认证必须覆盖完整头部、格胶囊和消息体；只绑定 nonce 与 AEAD 消息体不能排除胶囊修改后恢复同一短密钥的情况。新包装先写计算顺序、攻击者权限和安全论证，再实现，不形成签名与被签密文相互依赖的循环。

### 2026-10-09 HIBE 大载荷适配（HYBRID-HIBE/1）

主 AI 决定本轮先在 HIBE 接口后实现载荷适配，和上面的待研究应用文件包装分开：Wang 的 IBS 输入、signature||message 载荷、(rcv,phi) 顺序与 BYTEAUTH 内层 OTS 绑定都不改。适配器放在 `src/ibme/protocol/hybrid_hibe.py`，只调用底层 HIBE 的公开接口，不占队友原语文件。

Encrypt：新抽取 32 B 均匀种子和 12 B nonce；底层 HIBE 在 (rcv,phi) 的规范固定宽度编码下仅加密种子；HKDF-SHA256 从种子、公钥上下文和固定 suite 域导出 32 B AES 密钥；AES-256-GCM 加密完整载荷。AAD 规范绑定 suite、64 B 公钥上下文、**完整底层胶囊字节**、nonce 和载荷长度。身份及其可公开枚举摘要不放入新头部/AAD。每次加密重新抽取种子，不持久化种子/DEM 密钥/RNG。Decrypt：上下文/预算与规范解析 → 底层解出恰好 32 B 种子 → KDF → GCM 验证，全部通过才返回完整载荷；数据错误返回 None。

身份编码修复本轮发现的旧胶囊长度泄漏：`IBME:HYBRID-ID:v1 || role(P/C) || LP(raw_identity) || zero_padding`，padding 将原身份槽补至公开 identity_max_bytes。编码定长且单射；不哈希身份，不增加碰撞假设。包装密钥持有原身份并在加载时检查底层冻结身份属性等于相应编码；协议/IBS/CLI 继续使用原身份。默认原身份上限 64 B，对应底层身份宽度及上限 86 B；加密和派生保持接收者先、发送者后。新 suite 明确包含 IDPAD，固定底层身份宽度及种子宽度，仍不据长度测试声称完整匿名证明。

公钥、主状态、两级密钥及密文使用独立 kind 和 suite 的长度前缀格式。包装密钥携带同一完整包装公钥、底层对象和相应原身份字段，冻结身份属性返回原身份，并核对其底层编码绑定；公钥上下文由其规范字节导出，底层对象通过调用方明确绑定的解码器加载，拒绝非规范往返与后端错配。默认资源为身份≤64 B、载荷≤65536 B、胶囊≤4 MiB；硬上限分别 256 B、16 MiB、4 MiB，底层对象≤16 MiB，包装对象≤32 MiB+1 KiB；解析先检查总长再调用底层加载器。旧组件类形式之外允许显式绑定的 `from_bytes` 解码器，协议方法形状不变。

新增显式研究配置 `luo-module-research`：底层 ABB10 教学参数的载荷上限缩为 32 B、编码身份上限 86 B，外部原身份上限仍为 64 B；IBS 为 M2-B2 的精确模格输入，完整消息仍经 BYTEAUTH。应用消息统一上限 3924 B，包含 IBS 输入所需接收身份和 89 B envelope；越限在随机数/签名操作前拒绝。跨命令发钥须写回 Luo 身份缓存；新进程按 state 的明确版本/研究配置选择解码器，不能退回旧教育后端。研究配置禁止 --mock 和 --legacy-baseline，不自动成为安全 preset；当前默认 education 及其旧攻击对照保持可复现。

### 2026-10-10 首套固定密钥状态与参数快照

LuoModuleMasterSecret的同一对象以不进入wire的重入锁串行化key_extract与缓存快照；from_bytes重建新的锁。同一身份的缓存检查、随机发钥和插入构成一个临界区，序列化的count与条目来自同一快照；数学算法、H1/H2、参数、同一串行操作序列的协议随机消费和MODULE-REF/COMPACT格式保持。

CLI所有Setup/发钥写操作在读取主状态前取得本地状态锁，并保持至缓存提交和完整密钥文件发布。研究接收者发钥也写回主状态，以承接后续有状态HIBE。主状态先提交，密钥文件随后通过同目录临时文件、flush/fsync和原子替换发布；主状态发布失败不暴露新密钥，密钥文件发布失败可以从已提交缓存重试同一密钥。研究状态不允许通过改选education/mock等配置来覆盖。参数/格式预检在创建状态目录和锁文件之前执行。

状态锁文件为永久的`.ibme-issue.lock`，只保存一个零字节，不保存身份/私钥/种子。Windows使用msvcrt字节锁，POSIX使用flock；默认最多等待30秒，忙或文件系统错误明确失败，不降级为无锁读写。进程退出释放OS锁；禁止删除锁文件来“解锁”，避免产生第二个锁inode。这是同一OS本地文件系统范围，不是分布式锁或硬断电下的多文件事务。未验证Windows与WSL混合进程共同写同一状态目录的互操作性。

固定研究profile的HIBE解码器同时核对外层限额，以及公钥与各级秘密对象中公开参数快照的n、m_bar、q、身份/载荷上限、s0/s_enc/s_pre，必须等于RESEARCH_INNER_PARAMS推导的完整快照。只比较参数，不读取陷门矩阵；合法通用HIBE对象也不能绕过该profile的固定选参。协议接口、有效旧wire和安全声明保持none/false。

安全依据按普通混合加密、RFC 5869 与 AES-GCM 的条件分项引用，见本轮报告；未宣称 HPKE 兼容或由 CPA HIBE 获得 CCA/QROM。AEAD 不能防持钥接收者重签，IBS 与 BYTEAUTH 继续承担发送者认证和完整字节绑定。所有后端/组合声明固定 none/false，底层教学 HIBE、模格 IBS 的安全参数和引用条件仍需准入。

### 2026-10-10 HIBE密钥与公钥的语义绑定

新增独立的`HIBEKeyBindingValidator.validate_key_binding(public_key, secret_key) -> bool`能力。既有HIBE七个方法签名保持；HYBRID-HIBE适配器构造时必须取得该验证器，可由原语方法提供，或以`key_binding_validator`显式注入。缺失/不可调用即拒绝，不能只比较类型或参数后放行。

协议层传入不透明的底层公钥/秘密对象，由原语内部核对公钥来源、身份路径及可验证的私钥方程。调用不消费随机性；只有Python字面True接受，None/0/1/字符串及异常都明确失败。加载错误映射SerializationError，运行时错误映射InvalidParameterError。Setup/Extract/Derive产生的秘密对象和Decode/Decrypt使用的秘密对象均经过相同检查，坏密钥在新随机采样或胶囊解析前拒绝。

ABB10教学实现：主密钥重建公开A并核对元数据/u；一级、二级密钥核对同一根A/u/元数据，再复用既有公开代数验证函数核对A·R1+G=H(parent)、[A|H(parent)]·R2+G=H(parent,child)。私有矩阵只在原语层读取。校验不证明Gaussian采样来源、范数分布、不可伪造或匿名性，不提高安全声明。

Mock仅供契约测试：核对可验证的公开种子/限额与二级公开派生值，一级秘密链不能从公钥核验，仍无任何密码安全性。不得以mock结果放行CHKP；队友T4须交真实验证器并覆盖同参数不同公钥/坏方程/身份路径及恢复案例。

合法既有wire、HIBE/IBS算法、身份顺序及随机输入保持；不引入新的密文字段或公开身份。先前可解析但语义不绑定的密钥现在拒绝。CHKP文件和格工具未被修改。

## 6. 测试验收

### 2026-10-09 完整密文字节认证版本（BYTEAUTH/1）

这是 §4 Wang 基线外的独立工程包装，不改变 HIBE 身份顺序。底层基线的消息改为规范 envelope：`IBME:BOUND-MSG:v1 || LP(ots_vk_commitment) || LP(application_message)`；因此原有 IBS 同时签入接收者、应用消息和临时 OTS 公钥承诺。每次 Encrypt 新生成一把 Lamport 型一次性哈希签名密钥；先完成基线加密，再对外层版本域、公钥上下文承诺、完整 OTS 公钥及完整基线密文字节签名。签名置于外层末尾，无签名/被签密文循环。

OTS 固定 512 个消息摘要 bit，每个 bit 两个 64 B 随机原像；公钥 1024 个 64 B 哈希像，签名 512 个 64 B 原像。元素像、消息摘要、OTS 公钥承诺和协议公钥上下文使用各自新域的 SHAKE-256，不改变旧六个域常量。生产随机数使用系统 CSPRNG，测试流构造注入；单个私钥对象签一次即耗尽，不序列化进主密钥/状态。

外层 wire：`IBME:BYTEAUTH-CT:v1 || LP(public_context_digest) || LP(ots_public_key) || LP(baseline_ciphertext) || LP(ots_signature)`。承诺均 64 B；内部密文≤64 MiB，公钥/签名长度固定，严格拒绝重复、截断、追加和未知版本。Decrypt 先核对公钥上下文和完整 OTS，再走原基线 Decrypt，最后核对 envelope 中的 OTS 公钥承诺，全部数据失败返回 BOTTOM。公钥及双方长期密钥编码不变。

攻击者可持接收者密钥和原合法签名。若修改原认证公钥下的密文/外层签名却通过，形成强一次性签名伪造；若换新认证公钥并重签，则内部 IBS 签入的承诺必须改变，除承诺碰撞外需要 IBS 伪造。相同字节密文重放不是篡改。临时签名密钥不交给接收者，公开 checksum 或接收者已知密钥的 MAC 不作为替代。

依据为 Lamport 一次性哈希签名的单次签名与单向/第二原像条件；工程实例化另假设 SHAKE 域的原像/碰撞安全。CHK 的强 OTS 包装仅作参考：本版本不把 vk 改成 HIBE 身份，**不引用其定理宣称 CCA**。上述是条件式字节认证论证；当前不安全 IBS 仍使新公钥分支可被伪造，完整加强认证/后量子安全级别仍不得宣称。本轮必须保留该反例。

CLI 默认产生并只接受 BYTEAUTH/1；旧未认证密文仅经显式 `--legacy-baseline` 研究开关访问，不自动降级。原 BaselineIBME 保留数学参考和负面对照；新版本与旧版本的测试分别记录，不能靠关闭验签使安全目标通过。

### 原语测试

- 矩阵维度和模数检查；
- `F_id * z = h2 mod q`；
- 陷门委派前后接口兼容；
- 离散高斯统计；
- 序列化往返一致性。

### 协议测试

| 情况 | 结果 |
|---|---|
| `receiver = rcv` 且 `sender = snd` | 返回原消息 |
| 仅接收者不匹配 | `BOTTOM` |
| 仅发送者不匹配 | `BOTTOM` |
| 两者都不匹配 | `BOTTOM` |
| 修改密文一个字节 | `BOTTOM` |
| 修改签名一个系数 | `BOTTOM` |
| 截断、追加或重复字段 | `BOTTOM` |
| 随机伪造签名 | 验证失败 |

### 性能测试

记录 `Setup`、`KeyExt`、`Extract`、`Derive`、`Sign`、`Verify`、`Encrypt`、`Decrypt` 的中位数、四分位数、参数和消息长度。尺寸记录 `mpk`、`ek`、`dk`、`ct` 的序列化字节数。

## 7. CLI 验收场景

```text
setup --params education
issue-sender-key Alice
issue-receiver-key Bob
encrypt --sender Alice --receiver Bob --in message.bin
decrypt --receiver Bob --sender Alice --in ciphertext.bin   # 成功
decrypt --receiver Bob --sender Carol --in ciphertext.bin   # BOTTOM
decrypt --receiver Carol --sender Alice --in ciphertext.bin  # BOTTOM
tamper ciphertext.bin
decrypt --receiver Bob --sender Alice --in tampered.bin     # BOTTOM
```

## 8. 交付格式

每个实现任务必须返回：

1. 修改的文件列表；
2. 运行过的命令；
3. 测试结果；
4. 使用的参数及其安全声明；
5. 未实现内容和已知风险；
6. 对接口或论文解释有疑问的地方。
