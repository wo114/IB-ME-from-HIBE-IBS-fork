# SRGG 固定发钥服务契约

`src/ibme/ibs/srgg_service.py` 为现有 SRGG 研究后端增加显式的本地固定发钥服务。原始 `experiments/research/candidates/srgg/backend.py` 的五个 IBS 方法和内存缓存语义不改；共享 registry、CLI 和默认组合也不由本批自动改接。

## 接口

```python
from ibme.ibs.srgg_service import FixedIssuer

issuer = FixedIssuer(path, backend=Backend())
issuer.initialize(Config(), max_users=16)
public = issuer.public_key()
signing_key = issuer.key_extract(identity)
```

`initialize` 只接受完整 `Config`，会在读取熵或改动目录前检查整体快照容量。可复用已有空目录，但不会覆盖已有状态或无关文件。`max_users` 不能超过 SRGG `Config.max_users`，并且受服务最大账本和 2 MiB canonical wire 限制。

## 持久化和失败语义

- 状态保存在专用本地目录的 `master.bin`，使用 SRGG canonical wire；快照含公开上下文、主状态和已发用户条目。
- 同身份已发密钥在进程重启后直接复用，不消费新的发钥熵。
- 新身份先写入 `pending` 账本并持久化，再由工作副本执行一次原始 `Backend.key_extract`；成功后才写入 `issued` 并删除 pending 标记。
- 采样、最终保存、删除标记或进程在事务中途失败时保留阻断状态；后续读取和发钥都要求人工检查，不自动重抽。
- 本地合作进程使用 `key_issuance_lock` 串行化状态读取和发钥；快照采用临时文件、`fsync` 和原子替换。

这是可信本地明文状态模型。它不提供恶意回滚、管理员篡改、NFS、混合 Windows/WSL 写入或硬断电后的密码学保证，也不建立固定服务的安全归约。
