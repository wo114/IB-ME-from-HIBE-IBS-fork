# Foo–Li 独立研究 IBS 契约

版本：`FooLi-IBS/1`，2026-10-15。责任 B；公共接口遵守 `IMPLEMENTATION_SPEC.md`。此文件定义原语交付，统筹负责默认登记、CLI 和各真实 HIBE 配对。

来源为 Ernest Foo、Qinyi Li，*Tightly Secure Lattice Identity-Based Signature in the Quantum Random Oracle Model*，ACISP 2023 接受稿，§3 Figure 2（PDF 13／印刷12页），DOI `10.1007/978-3-031-35486-1_17`。本轮重新核对 Figure 2，复用仓库已有有限 MP12 实现、条件式正确性材料及公钥验签；没有重做全文安全归约。

## 算法和代码

| 原文步骤 | 原语实现 | 语义 |
|---|---|---|
| Setup：TrapGen 与 k1/k2 | `FooLiIBS.setup` → `ResearchSession.setup` | 原真实有限高斯生成，一次失败即报告；生产默认系统熵，测试显式注入 |
| Ext：固定分支与委派随机带 | `key_extract` → `ResearchSession.extract` | 按主种子、身份、完整公开上下文重现；同一身份固定私钥和用户种子 |
| Sig：kid 决定随机带的 SampleD | `sign` → 原 `sample_from_tape` | 用户私钥可独立签名，不携带主秘密；同身份同消息不取新熵、不重抽 |
| Ver：模方程和整数范数 | `verify` → `PublicVerifier` | 只使用公开输入，保留原始数学判据 |
| 公共第五方法 | `load_signature(pk, data)` | 严格格式、上下文、维数和范数检查，未知格式抛 SerializationError |

`src/ibme/ibs/foo_li/` 只适配原算法与对象；数学源仍在 `experiments/research/foo_li_runtime_reference.py`、`foo_li_public_verifier.py`、`online_mp12_reference.py` 等已可安装模块中。原代码的陷门正负号、五个独立域、长度前缀和完整配置/epoch/公开矩阵上下文保持一致。规范签名是公开上下文摘要、分支 bit 和完整有符号向量；没有添加会改变原签名数学的身份标签。

## 参数、对象与失败

`FooLiParams` 使用平坦完整字段，包含 q/n/m_bar、两级陷门质量、生成与采样宽度、epsilon0、身份/消息/用户限额和有限采样预算。转换成原 `ResearchConfig` 时保持全部字段。默认仅研究回归：q=3,n=1,m_bar=1,w=2,m=3，签名维数5；s²=567，t²=214389，完整签名104字节；身份最多256字节，消息最多4096字节，最多16个已发/失败/待定身份。数学工具维数上限128、单随机带上限256 MiB、对象上限16 MiB均保留。

公钥、主秘密、用户私钥和签名分别实现 IBS 公共基类。wire 使用独立版本 magic、严格顺序标签和长度前缀。完整参数快照采用规范 JSON，矩阵维度由参数确定；模系数是规范 uint32，秘密和签名向量是有符号 int64。解码先查大小和剩余长度，拒绝重复/未知/错序字段、尾随数据、非规范数字/参数和方程不符。完整参数及公钥上下文不可静默换成默认值。

主秘密恢复核对公开矩阵、主陷门、固定分支、用户陷门关系和发钥状态；独立签名密钥恢复核对身份、分支、质量及对应公钥/身份矩阵的陷门方程。种子或代数合法私钥被有权修改状态者替换，不一定能靠这些检查识别；规范编码不是存储认证。

| 情况 | 行为 |
|---|---|
| 错误对象/API类型、无效参数、身份/消息超长 | 明确 TypeError／ValueError／EncodingError，不进入采样 |
| 熵源返回非法字节长度或缓冲区 | RandomnessError；已开始的发钥保留阻断记录 |
| Setup/Ext/Sign 有限采样中止、质量失败 | FooLiSamplingAbort，无自动重抽 |
| Sign 原始样本超过 Ver 范数 | 一次 `signature_norm_rejected` 中止；原 `sign_raw` 仍可用于研究原始分布 |
| Sign 输出违反公开方程 | IBSError，按实现不变量错误处理 |
| 非法或不能验证的公开签名 | verify 返回 False；严格加载抛 SerializationError |
| 同身份已发钥 | 返回相同持久私钥，不重新读取用户种子 |
| 身份 pending/failed | IssuancePending，不自动重发 |

零向量没有单独拒绝规则；当原方程成立时仍按论文接受。小模数下错误身份、错误消息及公开伪造可能被接受，测试保留这些反例，不增设旁路标签掩盖它们。

## 固定服务与恢复

内存 `MasterSecret` 用锁串行发钥；可配置 `persist_callback(master)`，提取私有随机性之前保存 pending，完成后保存 issued，保存完成才返回用户密钥。失败/中断留 pending 或 failed；单独 to_bytes/from_bytes 只是明文快照，使用方负责持久化和独占写入。

`FixedIssuer` 提供专用本地目录服务：复用公共 OS 独占锁，每次先锁定再重新读取主状态；目录 pending 标记先落盘，随后原子保存主状态，再清除标记并返回。任一不确定操作阻断整个发钥服务；无自动删标记或重抽。新进程可直接恢复已完成实例，重复发钥与签名重放无需新随机性。初始化不会覆盖已有实例或无关目录内容。

服务只保证约定本地同 OS 文件系统和同一服务路径的协作写入。状态文件未加密，依赖目录访问控制；不承诺防恶意回滚、管理员改写、并发改路径、NFS 或 Windows/WSL 混合写入。没有跨 OS 硬断电恢复证明。若必须人工处理 pending，应先审查私有状态，不直接删除标记继续运行。

## 交给统筹的材料

`registration.backend_spec()` 提供独立 BackendSpec：id=`foo-li`，preset=`debug-q3`，factory、完整参数类型、ipk/imsk/sk 解码器、master_public_key、signature_size、固定身份缓存及配置预检。只支持 reference 格式。默认 registry、公共协议和 CLI 未在此批改写；统筹应按安装证据加载该描述符，并分别执行选定真实配对。现有 CI 的 `tests/test_foo_li_*.py` 自动覆盖新原语和服务测试。

保留 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。本参数存在公开伪造，不能声明原论文安全强度。正式参数、公开主矩阵分布、有限采样总误差、固定种子/查询模型与所引用安全定理及 Wang 前提仍需分别核验；实际 SHAKE 不是已经证明的理想随机预言机。
