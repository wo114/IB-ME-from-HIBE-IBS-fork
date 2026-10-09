# M1：Luo 2024 矩阵 IBS 真实研究参考

日期：2026-10-08。基点 `faa004e`。本轮完成用户认可分工中的主 AI M1：按 Luo–Chen–Susilo–Huang，ICICS 2024，§3 Algorithms 1–4 实现真实矩阵签名、持久身份密钥和规范保存恢复。主线仍是 Wang HIBE + IBS；本轮没有接 HIBE，也没有注册生产 IBSBackend。

2026-10-09 导航：本页与 JSON 固定的是提交 `86f1895` 的 M1 结果/源码指纹。当前唯一引擎已移入安装包，旧实验路径为兼容入口；新的适配与参数成本见 [M2-A](../2026-10-09-m2/README.md)。本页历史统计不改为新批次，M1 公共数据已重新核验保持同字节。

## 1. 已实现什么

| 论文/规格操作 | 代码入口 | 实际行为 |
|---|---|---|
| Algorithm 1 | `setup` | 均匀公开 $A$，有界整数秘密 $S$，$T=AS\bmod q$ |
| Algorithm 2 | `key_extract` | 新均匀掩码 $Y$，$W=AY$，$Z=SH_1(W,id)+Y$；范数超过范围就拒绝重抽；同身份返回缓存的同一密钥 |
| Algorithm 3 | `sign` | 保留用户 $Z,W$，每次采样新 $y$；输出整数 $z=Zc+y$、稀疏挑战 $c$ 与 $W$ |
| Algorithm 4 | `verify` | 只用公开参数、身份、消息和签名重构承诺；不读取主私钥或发钥目录 |
| 研究 oracle | `sign_for_identity` | 签名内部发钥与显式取钥使用同一张身份缓存 |
| 保存/恢复 | `to_bytes` / `from_bytes` | 公开参数、用户密钥、主状态缓存及签名的版本化严格编码；重启保持身份密钥 |

代码见 [reference](../../../experiments/research/luo_matrix_reference.py)、[审计](../../../experiments/research/luo_matrix_audit.py)、[测试](../../../tests/test_luo_matrix_reference.py)。模运算使用现有 ModMatrix/ModVector 接口；秘密 $S,Z$ 和 $z$ 保留整数，不约模后再当短向量。私有对象 repr 不输出秘密矩阵。

本 IBS 的真实掩码分布就是均匀整数，加上拒绝步骤，不涉及 Gaussian；这不是用均匀数冒充离散高斯。无偏抽样使用 bit mask + 拒绝，无偏稀疏位置/符号抽样保证每列/向量挑战的规定重量。

## 2. 与原文和 R1 的对应边界

依据 [固定原文](../../../papers/2024_ibs_without_trapdoors_luo.pdf)，PDF 第 6–9 页；源文件 SHA-256 在核验记录固定。缓存语义沿用 [R1 解释](../2026-10-08-r1/Luo2024IBS实施规格.md)：Algorithm 6 调用同一个带缓存 Extract Oracle。未宣称已获得作者确认或完整复核其安全归约。

H1 为矩阵值函数，各列为独立固定重量的带符号挑战；矩阵 1-范数使用列范数约定。H1/H2 分域，输入按版本、完整公开配置上下文、身份和矩阵/承诺/消息等长度前缀编码。SHAKE-256 是实际工程实例化，不等于证明实现了理想 ROM/QROM。

发钥采用 Algorithm 2 的包含边界 $\|Z\|_\infty\le\gamma_1-\beta_1$；签名/验签采用严格边界 $\|z\|_\infty<\gamma_2-\beta_2$。不从旧 SisIBSBackend 借用非零向量条件，原文 Algorithm 4 并没有该条件。

## 3. 可恢复对象和错误处理

统一研究标识为 `IBME/LUO2024/MATRIX-REF/1`，区分 PUBLIC、USER-PRIVATE、MASTER-PRIVATE、SIGNATURE。字段使用 Core 长度前缀；模矩阵沿用其规范编码，秘密整数使用有符号 64 bit 参考编码。

- 严格拒绝未知版本/类型、截断、追加、重复字段、非法维度/模数、非规范模系数和错误挑战重量。
- 恢复主状态检查 $AS=T$，恢复用户密钥检查 $AZ=W+TH_1(W,id)$；缓存必须身份唯一、按字节序规范排列且属于同一公开上下文。
- 抽样/缓存有公开预算；耗尽时发钥和签名显式中止，不生成默认对象。验签遇到非法数据或哈希抽样预算耗尽返回 False。
- 随机源缺省来自系统 SecureRandom；固定流仅在测试/审计显式注入。恢复密钥与缓存，**不保存/恢复测试随机流**；新签名继续取新随机性。

私有快照是私钥表示，尚无加密存储与并发事务保证。审计只保存尺寸/摘要和公开攻击材料；跨进程测试的私有状态留在 pytest 临时目录，未提交仓库。

## 4. 参数、数据和实际结果

两组都是手选研究配置，只计一个算法实例，不计两个新方案。第一组来自 R1，第二组用更大的挑战空间进行错配/随机伪造功能测试，仍未估计 SIS 难度。

| 字段 | R1 小参数 | 扩展挑战功能配置 |
|---|---:|---:|
| $n,m,k$ | 4, 8, 4 | 4, 8, 32 |
| $q$ | 65537 | 2147483647 |
| $\eta,\kappa$ | 1, 2 | 1, 8 |
| $\gamma_1,\beta_1$ | 128, 2 | 4096, 8 |
| $\gamma_2,\beta_2$ | 2048, 256 | 131072, 32768 |
| 实测公钥编码 | 280 B | 776 B |
| 实测签名编码 | 259 B | 947 B |
| Alice 用户密钥编码 | 679 B | 3431 B |
| 安全声明 | none | none |

原始审计 [Windows](functional-audit.json)、[WSL](functional-audit-wsl.json)：5 次功能 Setup + 1 次攻击对照 Setup；72 条诚实签名全部验签通过，12 份缓存身份密钥恢复后相同；扩展挑战配置的 96 项有效长度身份/消息修改被拒绝。身份为 3–9 B，消息为 0–32 B，包括空、二进制、重复及 UTF-8 消息。所有完整公开 transcript、尺寸和攻击结果在两环境一致。

**小参数负面对照是真实公开伪造。** R1 的挑战空间为 $\binom42 2^2=24$。审计只用公钥、选择零 $z,W$，枚举挑战和消息；11 次 H2 查询找到验签通过的伪造，未发用户密钥、未做签名查询。该结果说明本研究参数不安全，不是对合法参数论文方案的破解。较大挑战功能配置的矩阵维度仍只有 $n=4,m=8$，也没有安全资格。

本轮只有 IBS 单体数据，未执行完整 IBME 加解密、合法安全参数或算法性能基准。尺寸是当前未压缩参考编码的真实值，不与论文模格压缩数据或其它安全等级公平比较。

## 5. 测试、环境和复现

- Windows Python 3.14.6 / pytest 9.1.1：相关研究与共享依赖 254 passed，其中 M1 65 项。
- WSL 的指定 `~/miniconda3/envs/sage` Python 3.13.14：同一 M1 的 65 项通过；没有调用 Sage 格采样算法。
- 新进程用私有快照恢复同一个用户密钥，并在相同显式测试随机流下重放相同签名；另一个新进程仅用公钥/公开签名验签成功。
- CI 加入 M1 检查，完整本地 CI 命令对应 247 passed、3 xfailed；旧漏洞 XFAIL 仍为未修复，不是安全通过，批次有重叠不能相加。

```text
python -B -m pytest -p no:cacheprovider -q tests/test_luo_matrix_reference.py tests/test_primitive_spec_audit.py tests/test_encoding.py tests/test_lattice_core.py
python -B -m experiments.research.luo_matrix_audit --output docs/research/luo-reference/functional-audit.json
wsl --cd /mnt/d/zcode_projects/ibme bash -lc '~/miniconda3/envs/sage/bin/python -B -m pytest -p no:cacheprovider -q tests/test_luo_matrix_reference.py'
wsl --cd /mnt/d/zcode_projects/ibme bash -lc '~/miniconda3/envs/sage/bin/python -B -m experiments.research.luo_matrix_audit --output docs/research/luo-reference/functional-audit-wsl.json'
```

首次检查的跨进程/CLI 入口缺少本地包路径，加入与现有研究脚本一致的 checkout 路径入口后修复。审查另发现验签会漏报哈希预算耗尽异常，先用失败用例复现再修复为 False；最终均有通过回归。完整命令/结果、来源和本轮限制见 [核验记录](verification.json)。功能测试和公开攻击对照不能替代安全证明。

## 6. 下一轮

M1 已完成。按 [主 AI 清单](../../workplans/2026-10-08/主AI任务-IBS集成与优化.md)进入 M2：独立 IBSBackend 契约、适合正式尺寸的参数/格式，以及 SIS/查询损失和成本估计。矩阵参考的尺寸/32 bit 模数和挑战长度上限是研究资源限制，不能通过更换 profile 名称成为安全后端。模格 Hint 与精确模数仍按 R1 处理。队友继续 CHKP；两边单体契约通过后再集成。
