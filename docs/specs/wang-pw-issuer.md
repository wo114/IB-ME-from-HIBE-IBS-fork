# Wang–PW 持久固定发钥契约

本契约对应 [独立发钥模块](../../src/ibme/ibs/wang_pw_service.py)，服务于现有 [Wang–PW 研究后端](../../experiments/research/candidates/wang_pw/)。本轮基线为上游 `a30276655d2db2646a75bf59956900a29ca853bf`。共享 IBS 五方法及签名算法不变；这是显式使用的独立发钥入口，现有 registry/CLI 不会自动改为调用它。

## 1. 为什么需要它

原始 `Backend.key_extract(master, identity)` 对应一次 PW KeyExt，重复调用可以得到新的身份盐和密钥。保存某一把用户密钥后，已有 Sign、Verify 和密钥加载能继续使用它；这与“一个重启后仍记得曾给哪些身份发过钥的服务”不同。

`FixedIssuer` 在原算法外维护固定发钥账本。第一次成功发钥后，同身份始终返回账本中原来的完整 SigningKey，包括原身份盐。签名继续由原后端执行，每次使用新消息盐和新采样随机性。服务不增加验签白名单，不用缓存阻止公开密码学攻击。

## 2. 公开使用方式

```python
from ibme.ibs.wang_pw_service import FixedIssuer
from experiments.research.candidates.wang_pw import Backend, Params

# 私有、本机、独立目录；父目录须存在，最终目录可由 initialize 创建。
issuer = FixedIssuer("/private/local/path/wang-issuer")
public = issuer.initialize(Params(), max_users=16)  # 仅第一次执行
key = issuer.key_extract(b"Alice")
signature = issuer.backend.sign(key, b"hello")
assert issuer.backend.verify(public, b"Alice", b"hello", signature)

# 新进程重新打开同一目录，不再次 initialize。
restored = FixedIssuer("/private/local/path/wang-issuer", Backend())
same_key = restored.key_extract(b"Alice")
```

入口为 `initialize(params, *, max_users=16)`、`public_key()`、`key_extract(identity)`。初始化参数必须为原生 `Params`，身份为非空字节串；支持规范化 bytes-like 输入，最终身份长度受参数限制。服务容量为 1—64 个身份，默认 16；初始化时还须通过整个最大容量的 1 MiB 序列化预算，不能把单把密钥的上限冒充整个账本上限。较大配置可能因此被明确拒绝。

公开错误：`IssuerStateError` 表示状态或路径异常，`IssuerPendingError` 表示未确认事务，`IssuerCapacityError` 表示容量不足。原始参数、熵源、采样异常继续传播；不替换为默认密钥、不自动重试。

## 3. 状态与事务

| 文件／内容 | 约定 |
|---|---|
| `.ibme-issue.lock` | 复用已有同一 OS 本地进程锁；永久保留，不删除“解锁” |
| `master.bin` | `ISSUER` 版本封装：整体 ready/failed 状态、原始主秘密、完整公开上下文、容量、按身份排序的发钥账本 |
| `master.bin.pending` | 私有操作前落盘的固定版本标记，不含身份或秘密 |
| 账本条目 | `pending`、`issued` 或 `failed`；只有 issued 含完整用户密钥 |

所有公开操作持同一 OS 锁，并在锁内重新加载磁盘状态。缓存命中既不读取熵，也不重写状态。新身份先保存 pending 标记及 pending 账本，再调用真实 KeyExt；检查返回密钥的完整公钥、参数、身份及既有陷门关系，原子保存 issued 状态，完成提交后才返回用户密钥。

采样中止、存储失败或进程硬退出保留全局阻断。磁盘仍可写时，失败身份及整体状态进一步记为 failed；即使标记意外消失，整体 failed 或 pending/failed 条目也会阻断整个服务。补建标记和保存失败账本分别尝试，一条通道失败不会跳过另一条。初始化的结束阶段失败也会重新阻断。失败身份不能通过再次请求、重新初始化或换一个服务实例自动重抽。已有目录或无关文件不会被初始化覆盖。

写盘使用私有临时文件、文件 fsync、原子替换，以及 POSIX 目录 fsync。只清理自己创建的临时路径。没有自动删除 pending、人工恢复、密钥轮换、备份合并或防回滚入口。

## 4. 加载与资源限制

磁盘读取前先检查普通单链接文件和 1 MiB 大小上限，再进行有限读取。封装及嵌套原语对象都要求规范编码；拒绝重复／未知字段、截断追加、非规范 hex、错版本、非法状态、重复／未排序身份、容量超限、错误身份／公钥／参数和不满足原始陷门关系的对象。未完成状态、上下文、容量及各条目的公钥／身份绑定先做便宜的结构检查，再恢复主秘密和用户陷门对象。未完成条目不能携带一把看似已发的密钥。

容量预算计入 PK 在 MSK/SK 中的 hex 嵌套、每把密钥的最大身份长度和陷门系数长度，以及整个账本。参数的范数上限给出系数绝对值上界；预算只计算长度，不预先分配虚构的大矩阵。

## 5. 研究与安全边界

- 沿用原研究档：`n=1, q=17, m_bar=5, m=10, w=5`，签名向量维度 15。仍为 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。
- Wang 基本 IBS、PW 转换和实际固定服务的安全模型须分别对应。[既有固定服务审查](../research/2026-10-04-round3/Wang与PanWagner固定密钥接入审查.md)保留 PW 查询模型与持久单密钥服务的差异；工程缓存不补出新的归约，也不继承未核准的紧性。
- 高斯采样、委派和签名方程沿用已有实现。本批不把原文、参数估计或功能测试互相替代。根近均匀、统一有限采样误差／中止界、正式参数和安全引用条件仍须另行核验。
- 状态是可信本地明文，必须放在 Git、公共证据及同步共享目录之外。POSIX 权限尽力限制，Windows ACL 由运行者配置。没有恶意管理员修改、防回滚、NFS、混合 Windows/WSL 写入或跨平台硬断电保证；文件系统无法写入时也不能保证阻断标记一定可持久化。
- 本批没有自动接入 CLI 或重跑全部 HIBE 配对。已存在组合的历史结果不因此变成本服务的组合验收。

本轮执行结果和脱敏材料见 [交付 README](../research/team-b-delivery/2026-10-15-wang-pw-service/README.md)。
