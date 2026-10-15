# Yu IBS 公共后端与固定发钥服务契约

版本：`Yu2026-IBS/1`。本文件说明独立原语，不代表默认框架已登记、Wang 组合已通过或正式安全准入。

## 1. 来源与代码对应

- Yu–Liu–Li, *Identity-based signature and identity-based matchmaking encryption from lattices*, TCS 1082 (2026), 116152，DOI `10.1016/j.tcs.2026.116152`；仓库 `papers/2026_ibs_ibme_yu.pdf`。
- 原语四算法：论文 Fig.5 → `experiments/research/candidates/yu/standalone.py`；真实 AP09、ExtBasis、RandBasis、GPV → `trapdoors.py`；BPR 数值函数/密钥输入 NAND 电路 → `bpr.py`、`circuits.py`；公开/私有同态求值 → `evaluation.py`。
- 新增字节后端：`src/ibme/ibs/yu/`。不依赖尚未合并的 Foo–Li PR，不重写格采样器；固定服务只复用其已审查的存储设计。
- 文献条件、严格有限谱范数界、仍未匹配的论文条件，见[条件核验](../research/team-b-delivery/2026-10-15-yu-backend/CONDITIONS.md)。有限语义测试不等于证明整个电路族属于 NC1。

## 2. 五方法与对象

```python
from ibme.ibs.yu import YuIBS, YuParams
backend = YuIBS()  # 默认系统随机源；测试可显式注入 read(n)
pk, master = backend.setup(YuParams())
key = backend.key_extract(master, b"A")
sig = backend.sign(key, b"M")
assert backend.verify(pk, b"A", b"M", sig)
assert backend.verify(pk, b"A", b"M", backend.load_signature(pk, sig.to_bytes()))
```

这只是调试用法，不能保护真实通信。执行环境：WSL `~/miniconda3/envs/sage`。

| 方法 | 输入/输出与失败约定 |
|---|---|
| `setup(YuParams)` | 真实 AP09 一次尝试；返回 PublicKey、MasterSecret。无隐式重试。 |
| `key_extract(master, identity)` | 固定身份发钥；先记 pending、再采样、保存 issued 后返回。缓存命中不取新随机数。 |
| `sign(key, message)` | 身份固定在 key 内；每次使用新盐、新匹配位及真实 GPV 样本。不是确定性签名。 |
| `verify(pk, identity, message, sig)` | 仅使用公开材料，检查对象上下文、维度、非零/范数及模方程。不会查询发钥白名单。 |
| `load_signature(pk, wire)` | 严格解析签名；任何截断、追加、非规范数值、字段重复或公钥上下文不匹配均拒绝。 |

对象提供规范 `to_bytes`、`from_bytes`（签名解析额外需要公钥）。SK 保存规范身份及身份摘要，MSK 包含完整固定发钥账本。私钥恢复验证完整整数格、维度、模方程、行列式及身份求值关系；这些检查**不能证明采样来源或分布正确**。

## 3. 无歧义字节编码与实际容量

身份、消息分别编码为 `uint32_be(length) || bytes || zero-padding`，再按每字节最高位优先转为定长比特串。身份不能为空，消息允许空串；因此空消息与一个零字节不同，`A` 与 `A\0` 不混淆。身份和消息占据不同固定位置，使用不同公开 PRF 块；最终输入仍为论文的 `id || message || salt`。

没有用哈希把任意长输入压成短串，也没有新增 ROM 假设来掩盖容量不足。对象类型、版本及 SHA-256 公钥上下文属于外层对象绑定，不是替代 Yu 的同态身份/消息绑定，更不能阻止 `q·e₁` 反例。

默认 `debug-bytes-q3`：

- 格参数 `n=1, q=3, m=15, w=2`，根/用户/签名维度 `15/17/19`；`gamma²=32768, delta²=67108864`；RandBasis 总向量预算32，`epsilon_bits=16`，显式 LLL 后处理。
- 身份上限1字节，消息上限1字节；对应40/40位，盐4位，签名 PRF 输入84位。
- BPR 矩阵维度/列数均1，模数32，Gaussian width2，票据32位；身份/签名电路密钥输入1285/2693位。
- 原有 `tiny_profile()` 不变：它是2位身份、2位消息、BPR维度2的另一套小参数。两者结果不可混合统计。
- 新配置允许有限的1–4字节容量组合，但总输入≤128位、密钥输入≤8192、门数≤500000、深度≤4096、采样和 LLL 原上限均不放宽。不承诺每个资源上界内配置都会通过实际采样。

## 4. 规范对象与资源边界

线格式为类型/版本域标签、uint32载荷长度、规范ASCII JSON。排序字段、精确字段集合、精确Python整数（排除bool/float）、唯一键、长度和剩余字节均检查。单对象≤16MiB，签名坐标为有符号128位，私有基坐标≤1024位；在昂贵格运算前先查形状、大小和范围。

参数快照包括全部算法及资源字段，而不仅是 `q`。`backend_spec().check_object` 与外层配置逐项比较。签名 JSON 长度随整数位数变化：描述符返回保守最大线长，实验记录实际线长，不把上界当实测尺寸。

## 5. 固定发钥、保存和恢复

`FixedIssuer(directory)` 使用一个专用本地目录：

- 永久OS锁：同一OS本地文件系统中串行化跨进程写入。
- `master.bin`：完整明文私有状态，原子替换并请求fsync。
- `master.bin.pending`：在操作前持久化保留；异常、中断或写盘失败时保留，禁止自动重试或自动清除。
- 同身份重复请求返回原密钥；已保存后重开进程仍返回同一把钥。签名本身继续取新随机数。
- 默认最多16个身份，失败/pending身份也占名额；私有快照可恢复所有账本状态。

首次发钥会调用 Sage/PARI HNF，后台线程可发生底层崩溃。公共后端的初始化、新发钥、签名、私钥恢复只允许进程主线程；已存在身份的纯缓存读取可在线程内进行。固定服务所有入口要求进程主线程，并发请求应使用多个进程，由永久锁排队。线程限制先于随机数、pending和文件修改。

这些是本地研究服务保证，不是恶意管理员、回滚、NFS、同步盘竞争或混合 Windows/WSL 写入防护。状态目录不要放Git、公共证据、同步共享目录；Windows ACL由使用者负责，原生Windows目录fsync没有跨平台保证。不要删除锁文件“解锁”，不要手动删pending后重复发钥；应私下核查中断状态。

## 6. 安全与组合边界

始终 `security_claim: none`、`backend_admitted: false`、`parameters_are_formal: false`。

`q=3` 下公开构造 `s=q·e₁` 即可通过任意上下文的模方程和当前范数门槛。错误身份、错误消息可能被接受，测试明确保留；不通过额外身份标签/白名单伪造密码学拒绝能力。

论文的渐近 NC1、Lemma7 较紧谱范数、PRF困难性、SIS归约参数、完整有限采样误差/中止组合预算还没有获得正式实例对应。研究运行与来源/条件核验完成，不等于这些前提已满足。

`registration.backend_spec()` 只是给统筹的显式交接描述符，不改默认注册表或CLI。当前容量连Wang签名域标签都放不下，组合预检必须明确失败。若以后扩大输入或更换电路/参数，需重验全部容量、电路、采样、分布和安全条件，不能直接把本轮独立测试计为HIBE组合验收。
