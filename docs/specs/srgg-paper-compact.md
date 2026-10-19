# SRGG 原论文对象的可选紧凑编码 v1

本格式只改变传输与快照的表示，不改变 Jia 等 *Constructing Efficient
Identity-Based Signatures on Lattices* 的算法或 Table 4 参数。来源绑定为
`papers/2025_efficient_ibs_jia.pdf`，SHA-256
`258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。

实现：`experiments/research/candidates/srgg/paper_compact.py` 与
`paper_compact_bits.py`。全部 load 返回现有 `paper_objects` 类。现有 JSON
`to_bytes/from_bytes`、默认服务磁盘格式、采样、范数门和哈希输入保持不变。
尤其 `pk.context` 仍为原规范 JSON 公钥的 SHA-256；不会改成二进制公钥的哈希。
这是可选无损编码，不是论文作者的 ANS 或 C 编码复现，也不提供加密、完整性
认证或 constant-time 保证。

## API

```python
dump_public(pk) -> bytes
load_public(data) -> PublicKey
dump_key(sk) -> bytes
load_key(data, expected_public=None) -> SigningKey
dump_master(msk) -> bytes
load_master(data, expected_public=None) -> MasterSecret
dump_signature(pk, sig) -> bytes
load_signature(pk, data) -> Signature
```

主密钥和用户密钥包含秘密材料；调用者负责与原私钥相同的保密存储、锁、原子
落盘和故障恢复。此模块不替换 `FixedIssuer`，不更改其容量或恢复策略。

## 通用编码

所有整数都用无符号 big-endian；位域按 MSB-first 顺序打包，最后不足一字节时
仅允许低位补零。矩阵逐行、向量逐多项式，多项式按升幂系数顺序。没有隐式模约减、
截断、有损压缩或浮点转换。整包上限为 2 MiB。

固定 24-bit public 编码不保证对任意稀疏对象都小于 JSON；例如测试中的大量零系数
可以用 JSON 的 `0,` 表示，仅约 2 B/系数。真实随机公钥和采样密钥的尺寸收益必须
逐对象实测，不能从稀疏测试夹具或位宽公式推定所有对象都会缩小。

每个对象包含固定头：

| 字段 | 字节 | 取值 |
|---|---:|---|
| magic | 18 | ASCII `IBME/SRGG-COMPACT` 后跟 `00` |
| version | 1 | `01` |
| kind | 1 | public=1、key=2、master=3、signature=4 |
| profile | 1 | PARAM-I=1、PARAM-II=2、PARAM-III=3 |
| interpretation | 1 | table-standard-deviation=1、literal-density-width=2 |
| source hash | 32 | 上述论文 SHA-256 原始字节 |

profile 固定 `n=512, p=16383, b=31, w=2, Q=15744063`，模块秩依次 2/3/4；
其余原文宽度与约定由现有 `PaperParams` 的精确记录重建。没有自由参数区。

## 四种对象

**Public**：头、32 B 公共种子、`d × (dw) × n` 个 24-bit `b` 系数。每个系数
必须在 `[0,Q)`；`a_hat` 由原参数记录和种子按原算法重建，不重复存储。

**Key**：头、一份完整 compact public、`u16` 身份长度、1–4096 B 身份、tail。
tail 长度固定 `(1+w)d` 个 `n` 次系数数组。既有 SigningKey 构造器从 tail 与身份
重建完整 HNF key；不保存或更改其 head。

**Master**：头、一份完整 compact public、`2d × dw × n` 个 2-bit witness 系数、
`u8` 用户数，再按身份原始字节严格升序排列缓存项。CBD1 系数 -1/0/1 分别编码
0/1/2，3 非法。每项为 `u16` 身份长度、身份、`u8` 状态（pending=0、failed=1、
issued=2）；仅 issued 再跟 tail，不重复嵌公钥。最多 64 项；pending/failed 保留，
不得恢复为可重抽状态。现有 MasterSecret 构造器继续检查 witness 支持、陷门等式
和 issued key 的身份/公钥绑定。紧凑容器上限不代表旧 JSON 快照或默认服务支持同样
多的最大宽度密钥；旧服务限制完全保留。

**Signature**：头、32 B 原 JSON 公钥 context、response、`n` 个 1-bit challenge。
response 固定 `(2+w)d+1` 个多项式。context 必须匹配传入公钥，profile 和 interpretation
也必须匹配。这里只执行既有 Signature 的对象域检查和公钥/维度绑定；原 gamma
范数门及签名方程仍由原 backend 验证，codec 不引入新的范数门，也不把“能解码”
当作“签名有效”。

tail 和 response 的每个完整 module vector 采用一个最小统一宽度：
`z(x)=2x`（x≥0），否则 `z(x)=-2x-1`；先写 `u16 width`，随后逐系数写 width-bit
zigzag 值。width 为所有 zigzag 值 bit_length 的最大值，范围 0–257；全零向量必须
width=0，且没有系数字节。现有对象允许的系数是 `abs(x).bit_length()≤256`；解码
会另行拒绝 zigzag 的 `2^257-1`，因为它对应超域的 `-2^256`。不按模数压缩 tail/
response，负数和所有允许的精确整数完全保留。

## 严格解析和验收

先检查整包上限和固定头；profile 固定所有系数数量。在分配系数数组前检查对应
位域完整长度。拒绝错误 magic/version/kind/source、未知 profile/interpretation、
截断/追加、超界 public residue、非法 CBD1、重复或乱序身份、未知状态、非最小位宽、
非零 padding、超域整数、公钥/context/维度不符。对象构造验证后重新编码，要求与输入
逐字节相同。签名和私钥内容不会出现在错误消息中。

`tests/test_srgg_paper_compact.py` 使用带真实环代数关系的公开固定 fixture，覆盖六种
profile/interpretation、四对象精确往返和解析负例；它不声称该 fixture 是真实采样密钥。
原 Table 4 参数、SecureRandom、真实 Setup/Extract/Sign/Verify、恢复后再签名的性能
与 RSS 证据由独立 runtime benchmark 生成，并单独记录重复次数及环境。

安全元数据保持 `security_claim=none`、`backend_admitted=false`、
`parameters_are_formal=false`、`nist_security_category=null`。编码一致性和计时测试不替代
论文安全结论、参数安全估计或实现安全审计。
