# 结构化 SRGG 独立后端与持久发钥契约

本契约对应 `ibme.ibs.srgg.structured`，与旧 `srgg2025` 小维后端及其快照版本独立。算术、H1/H2 和参数序列化复用 `structured_execution.py` 的固定研究命名空间；真实采样只选 `query-bounded-deep` 数值 profile。不改变旧默认登记、共享 CLI 或任何 HIBE 配对。

## 公共五方法与对象

```python
from ibme.ibs.srgg.structured import (
    Backend, Parameters, PublicKey, MasterSecret, SigningKey, Signature,
    FixedIssuer, backend_spec,
)

# params 为完整 Parameters 快照，由调用方明确选择研究点。
backend = Backend()
public, master = backend.setup(params)
key = backend.key_extract(master, b"alice")
signature = backend.sign(key, b"message")
assert backend.verify(public, b"alice", b"message", signature)
restored_signature = backend.load_signature(public, signature.to_bytes())
```

`setup / key_extract / sign / verify / load_signature` 满足冻结 IBS 五方法。公钥、主密钥、签名密钥和签名分别继承公共对象基类。签名密钥的 `identity` 是规范字节身份，`identity_digest=hash_identity(identity,32)`；签名从密钥取得身份，调用者不能替换。

四对象都支持严格 `to_bytes / from_bytes`。签名的独立 `from_bytes` 只验证有界结构；公钥相关的上下文、维度和范数由 `load_signature` 验证。`verify` 还重构真实承诺并比较消息挑战，错误输入返回 False；不构造 Gaussian 采样器，不读取熵。

完整参数通过公钥规范字节和上下文摘要绑定，私有对象包含同一公钥。公钥保持底层 `IBME/SRGG-STRUCTURED-EXECUTION/1` 格式；主密钥、用户密钥、签名和服务状态采用 `IBME/SRGG-STRUCTURED-OBJECT/1`，固定 `profile=query-bounded-deep`。未知、缺失、重复字段，非规范 JSON/hex，布尔数值、错误维度和超范围系数均拒绝。不能将不同版本或参数快照拼接恢复。

身份 1–4096 B；消息 0–65536 B；单个对象和服务快照最多 2 MiB。JSON 只接受唯一的 ASCII 规范表示。签名密钥恢复重新检查真实 HNF 重构与公钥范数条件；主密钥恢复重新检查 CBD1 支持和陷门方程。该验证不把不可信快照变为经认证存储。

## 固定内存服务

一个 `MasterSecret` 为同一身份缓存唯一的已发密钥。首次发钥先标记 pending；采样或校验失败后标记 failed，此后明确中止，不重抽。已发缓存不消费熵，主密钥序列化保留 issued/pending/failed。最多64个身份，还受整个对象的 wire 容量限制。

内存主状态不能用于多个进程之间直接共享；持久服务负责合作进程之间的互斥和事务。

## 持久服务

```python
issuer = FixedIssuer(path, expected_params=params)
public = issuer.initialize(params, max_users=2)
key = issuer.key_extract(b"alice")

reopened = FixedIssuer(path, expected_public=public, expected_params=params)
assert reopened.public_key() == public
assert reopened.key_extract(b"alice") == key
```

`expected_public` 用于重开已有状态，不用于新建根。错误公钥或完整参数拒绝重开。新建只接受专用空目录，既有无关文件不会被覆盖。`max_users` 为1–64，默认2；调用前计算覆盖最长身份、最大公钥系数、CBD1 陷门、最坏用户系数长度和所有嵌套 hex 的保守字节包络。超过快照容量，在取熵和创建目录前拒绝；不自动缩减用户容量。包络是编码上界，不是有效密钥或采样样本。

服务复用旧 SRGG 固定发钥的本地文件锁、pending 标记、临时文件、fsync 和原子替换机制。每次在锁内重载；首次请求先持久化 pending，再执行一次真实发钥；成功落盘并结束事务后才返回。已发身份在重启和并发请求后复用原密钥，不重新采样、不重写快照。

采样失败、pending 保存失败、最终写入失败、结束事务失败或事务中进程退出，都会保留全服务阻断状态。后续读取和发钥拒绝自动恢复；没有自动重新取样、清除 tombstone、选择成功根或重新发钥的路径。底层数值/熵中止直接传播；签名只保留原算法至多16轮的公开范数重试，不因数值失败重试整组。

这是可信本地明文快照、合作写者模型。文件必须是普通单链接文件，拒绝符号链接、硬链接及 Windows reparse point。没有恶意回滚防护、快照认证、管理员攻击或跨 Windows/WSL 混合写入保证；也不将文件系统 fsync 测试扩大为硬断电保证。

## 给统筹的独立描述符

`backend_spec()` 返回调用方可登记的完整描述符，id 为 `srgg2025-structured`，公开对象解码器、完整参数类型、签名格式、保守尺寸函数及无熵参数检查。提供 `research-small` 和 `research-n512` 两个研究点；调用者必须显式选择，不存在默认安全配置。描述符构造不生成密钥，也不修改全局 registry。

Sage 依赖显式检查，真实采样使用 WSL `~/miniconda3/envs/sage`。没有缺失依赖时的 mock/均匀采样回退。统筹负责把描述符接到共享框架、CLI 及具体 HIBE；这不妨碍独立五方法和固定服务验收。

## 安全和参数边界

小点 `n8,d1,w3` 仅用于工程行为验收，存在真实公开伪造及错误身份接受反例；测试保留这些结果，不增加白名单或私有密钥检查改变验签。`n512,d2,w8` 已有完整研究运行材料，但当前困难性对照不足以支持 Kyber/ML-KEM、NIST 目标强度。描述符中的研究点不构成正式参数。

连续 SampleF 误差、有限输出 TV/abort、HNF 发钥分布、原生 strong 归约及量子预言机条件分别核验。服务锁和恢复通过只证明指定工程行为；攻击测试失败不构成不可伪造性证明。当前统一保留：

```text
security_claim=none
backend_admitted=false
parameters_are_formal=false
nist_security_category=null
```
