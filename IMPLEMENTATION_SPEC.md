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

## 3. 格基基础模块

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

## 6. 测试验收

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
