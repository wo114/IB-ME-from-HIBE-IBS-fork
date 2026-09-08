# IB-ME from HIBE + IBS：实现规范与验收标准

本文档是代码实现的唯一接口规范。其他 AI 只应根据本文件和 `ARCHITECTURE.md` 修改代码；论文中的记号与代码命名不一致时，以本文件的接口为准，并在适配层转换。

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

参数文件必须记录：来源论文、是否仅用于调试、预期安全级别、已知限制。没有完成安全估计的参数必须标注 `security_claim: none`。

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
