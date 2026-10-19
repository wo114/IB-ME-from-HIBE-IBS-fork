# Sageloli SIS／RSIS 独立 IBS 研究契约（v2）

2026-10-19 新增：[v3 环结构后端与论文 Table 6 两档实跑交付](../research/team-b-delivery/2026-10-19-sageloli-ring-target/README_zh-CN.md)。v3 采用大整数编码、环系数对象和结构化 Gaussian 采样；本页后续仍描述原 v2，因此其 128 维、int64 公钥和未执行大参数等范围说明不用于判断 v3。两版本不自动迁移，算法路线计数不变。

v3 的默认登记、公共恢复器、CLI 容量配置与完整组合验收另见[环版公共接入契约](sageloli-ring-ibs.md)；本页 v2 的接入欠项不用于描述该新版本。

本契约对应 HAL v1 的 *Shorter and Faster Identity-Based Signatures with Tight Security in the (Q)ROM from Lattices*，实现位于 `experiments/research/candidates/sageloli/`。矩阵 SIS 与 Ring-SIS 是两条独立原语路线，共用五方法和持久发钥服务，不读取 HIBE 私有表示。

本次完整度指独立算法、对象、固定状态、恢复、失败处理及验收路径齐备。功能实现、有限采样误差、论文安全游戏对应、困难性估计与正式安全准入分别判断。两套默认参数均为公开可伪造的教学参数，`security_claim="none"`、`backend_admitted=false`、`parameters_are_formal=false`，不授予 NIST 等级。

## 版本与来源

- 冻结论文：[`papers/2023_shorter_faster_ibs_sageloli.pdf`](../../papers/2023_shorter_faster_ibs_sageloli.pdf)，73 个 PDF 页，印刷页码比 PDF 页码小 1。
- SHA-256：`0e92f184828bc8643a774e9c334b14689346387981e766c311c596239ef73e3e`。
- 自适应算法：Figure 5（PDF18，SIS）、Figure 7（PDF23，RSIS）；Figure 6／8 是省略盐的非自适应方案。
- 对象魔数为 `IBME:SAGELOLI-IBS:v2`，H1／H2 域分隔和 pending 标记同步使用 v2。v1 的参数语义、哈希映射及采样有实质区别，**拒绝读入，不自动迁移、重抽或重新发钥**。旧状态及原始证据应保留在原位置；v2 实验使用独立的新状态目录。
- 本契约补充公共 IBS 约定；共享注册器、CLI、HIBE 组合及组合准入由统筹另行负责。

## 公共五方法与对象

| 方法 | 输入／输出 | 保证与失败 |
|---|---|---|
| `setup(params)` | `SISParams`／`RSISParams` → `(pk, msk)` | 真正生成各自公钥与根陷门；路线不匹配或资源参数错误时拒绝 |
| `key_extract(msk, identity)` | 主钥、非空身份 bytes → 对应 `SigningKey` | 身份首次抽盐并委派；已发身份返回相同钥；pending／failed、容量或采样失败均阻断 |
| `sign(sk, message)` | 用户钥、消息 bytes → `Signature` | 新消息盐、H2、完整 SampleD／SampleDR 原像；有限资源失败显式抛出 |
| `verify(pk, identity, message, signature)` | 公钥、身份、消息、签名对象 → bool | 上下文、盐长度、规范系数、非零、等式及两块范数全部通过才接受 |
| `load_signature(pk, data)` | 公钥、规范 wire bytes → `Signature` | 严格解析并绑定公钥；错误尺寸、非规范表示、重复／截断／追加字段拒绝 |

公钥、主钥、用户钥和签名均提供规范字节序列化。SIS 与 RSIS 的具体对象类型不可互换。公钥上下文是其规范编码的 SHA-256；参数完整纳入编码及上下文。主钥恢复核对根关系、状态账本及所有 issued 身份钥关系；身份钥恢复核对 `A*T_id=H1(r,id)−G`，环版还核对每个 negacyclic 展开块。结构与方程检查不等于状态真实性认证。

身份上限默认 256 B，消息默认 0–4096 B，身份盐与消息盐各 32 B。长度前缀、不同路线／H1／H2 的域分隔、公钥上下文共同绑定输入。H1 输出分别为 `n×nk` 个模 q 系数、k 个 d 次系数环多项式；H2 输出分别为 n 个模 q 系数、一个环多项式。实现使用 SHAKE-256 字节流作为随机预言机的工程实例，不把实际 SHAKE 称为理想 ROM／QROM 证明。

## 参数与宽度

| 默认字段 | SIS | RSIS |
|---|---:|---:|
| 结构参数 | `n=2,k=4,m=16` | `d=4,k=9,l=22` |
| `q=3^k` | 81 | 19683 |
| `identity_width_squared` | `2^28` | `2^36` |
| `signature_width_squared` | `2^56` | `2^66` |
| `r_squared` | 16 | 16 |
| 根／签名系数维数 | 16／24 | 88／124 |
| `max_users` | 32 | 32 |

宽度平方 s² 的密度约定为 `exp(−π‖x‖²/s²)`；连续物理方差是 `s²/(2π)`。v2 不再使用 v1 中互不一致的 `trapdoor_sigma`／`signing_sigma` 和 bound 字段。`s_id_squared`／`s_sign_squared` 是上述宽度字段的只读属性。不得将数值 s 直接传给采用物理标准差的旧采样函数。

`width_check.py` 对上述两个教学点检查 Table 2／4 的充分宽度式，采用 192-bit 区间、`epsilon=2^-64`、正文保守 `C=38`，并检查 r²=16 的条件。宽度不等于困难性或有限采样总误差准入。当前后端限制展开后签名系数维数不超过 128，RSIS 的 d 必须为至少 4 的 2 次幂；结构参数的资源可解析性不自动证明所有论文条件。

上表默认 RSIS 点满足论文 Table 4 的 `k≥4`、`l>max(2k,21)` 与 `l≤2k+k/2` 条件；参数类仍允许研究探索用的其它尺寸，这些非默认实例不会自动获得论文条件或安全准入。

论文 Table 6（印刷 p27／PDF28）只给出两组大 RSIS 点：`(k,d,l)=(65,2048,132)` 与 `(153,2048,308)`、`epsilon=2^-200`，表内 `log2(s_id)`／`log2(s_sign)` 分别约为 20.65／38.92 与 21.27／40.16。它们未在本后端执行，也不满足当前 128 维资源包络；本交付不复现论文 Table 7 的强度、尺寸或性能。论文未给出对应的 SIS 具体发表点，不人为补造。

## 根、委派与签名采样

矩阵根 R 的系数为 CBD1：0 的概率 1/2，±1 各 1/4。环根每个多项式的前、末 d/4 系数为 `4*CBD1`，中间 d/2 系数为 CBD1，符合 `P_(R,1/2)`。

构造 `A=[Abar | G−Abar*R]` 并存储 R。原文 Proposition 2 同时打印此负号和 `A[-T;I]=G`，两者以同一个 T 解释不一致。本实现明确采用 `T=−R` 传入根 sampler，令 `J=[−T;I]=[R;I]`；委派钥 `T_id` 满足 `A*T_id=H−G`，签名 sampler 则直接使用 `J=[−T_id;I]`。两个关系均作实际精确核验，不声称原文已有勘误。

完整原像步骤为：准备 `Pi=s²I−9r²JJᵀ`，在取熵前以**原始整数陷门**检查 `s²I−11r²JJᵀ` 为 PSD；抽全维相关扰动 p；令 `v=u−Ap mod q`；逐三进制层抽真实陪集 Gaussian（包括最后一位），最后返回 `z=p+Jx`。最终 carry 可非零，所需关系是 `Gx=v mod 3^k`。不再用满足 `T_top=R*T_bottom` 的低秩原像充当 Gaussian 委派，也不只在签名前半坐标加独立噪声。

SIS 委派抽 nk 个完整 m 维列。RSIS 委派抽 k 个完整 ld 维系数向量，再构建 k 个环列及其旋转；乘法按列作用保证 `C(A)Cf(z)=Cf(Az)`，且 `X^d=−1`。SIS 使用全局 `prepare_f`；RSIS 使用 block size=d 的 `prepare_p` Schur 数值解释。Sageloli 原文没有独立 SampleP 伪代码；此工程实现不声称逐字复现 MP12 内部连续核。

Gaussian 陪集表和整数舍入有有限截断、离散概率质量及中止预算。连续 tickets、Box–Muller、有限精度因子以及所有阶段合成的总体 TV **尚未认证**，因此原文抽象 `gamma^Sample` 不能直接赋给当前实现。私有计划只在当前主钥／用户钥对象内缓存，不序列化、不写日志。

身份钥的 raw 两块尾界是工程失败门；失败后标记 failed，不重新抽样。它不替代实际 raw J 的 PSD 准入，也不等于论文谱范数定理。公开签名先中心化再检查非零与分块界：SIS 为 `2m*s_sign²`、`2nk*s_sign²`，RSIS 为 `2dl*s_sign²`、`2dk*s_sign²`。合法签名尾界拒绝最多尝试 `max_sign_attempts`（默认64）次；采样器或熵源异常立即停止，不当作一次普通尾拒绝重抽。

## 无偏模 q 映射与失败预算

Setup 的均匀块和 H1／H2 共用拒绝取模：对 w 字节候选 X，仅接受 `X<256^w−(256^w mod q)`，再返回 `X mod q`。成功条件下，每个剩余类有相同数量的原像；不得用固定字节直接 `%q`。

每个系数默认至多 192 个候选，总字节上限 64 MiB；SHAKE 游标必须向前推进，拒绝后不复用前缀。在理想独立均匀字节且字节预算覆盖全部试次时，单系数试次耗尽概率至多 `2^-192`；总字节上限可提前中止。该界只针对这一步，不能作为 Gaussian 总 TV。错误返回类型、长度、熵源异常、试次或字节耗尽均显式 `UniformSamplingAbort`，不得偷偷改种子或重新哈希绕过失败。

## 固定发钥、恢复与持久状态

`FixedIssuer(path, backend, expected_public=None, expected_params=None, lock_wait_seconds=300)` 提供 `initialize(params)`、`public_key()`、`key_extract(identity)` 以及签验／解析转发。默认32身份账本计入 pending／failed 条目；对象和主状态编码包络均为16 MiB，配置较大容量不保证它能装入包络。

首次发钥流程：获取本地跨进程锁 → 创建并同步 `master.bin.pending` → 持久化 pending 身份 → 真实采样 → 验证身份／公钥绑定 → 原子替换并同步 issued 主状态 → 删除并同步 pending 标记。锁仅在获取阶段等待，默认总预算300秒；锁成功后不重试整个事务。

同身份重复请求或重启从 issued 账本返回完全相同的规范用户钥，且不消耗新发钥熵。独立进程用同一目录时由锁串行化。采样、保存、同步或进程崩溃导致不确定状态时保留 pending／failed，阻止自动重发；库不自动清理标记、回滚到旧状态或换根。容量满时在创建新事务前拒绝。

恢复拒绝损坏、截断、追加／重复字段、非规范尺寸、错误路线、陷门方程不匹配和指定 pin 不匹配。调用方可提供 `expected_public` 和／或 `expected_params` pin 住预期上下文；未指定 pin 时不能检测整份状态被替换成另一份自洽合法根。私有状态是本地明文，不提供认证存储、恶意回滚防护、断电下任意文件系统保证或侧信道防护；状态、陷门、随机带及签名样本不可提交到 Git。

原文 Figure 1（PDF11）的 `OSign` 每次调用 KeyExt 并生成新身份盐 r。本服务按身份固定缓存 r／钥，属于显式服务策略。Proposition 5 对固定身份钥多次签名的分布讨论，不自动证明这项服务策略与自适应哈希重编程游戏相同。固定服务的 ROM／QROM 归约映射仍单列，不能升级为已完成证明。

## 验收与剩余边界

要求两条路线分别覆盖：真实 Setup／Extract／Sign／Verify、恢复后签名、同身份重复发钥、独立进程恢复和并发、硬退出及持久化故障阻断、pin／参数／路线不匹配、损坏对象和状态、错误身份／消息／盐／公钥、截断／追加／重复字段、随机伪造及已知教学参数公开伪造。根与委派关系、环乘法、全维扰动及拒绝取模另有专属检查。

小参数中，中心化后所有候选系数向量甚至自动落在范数界内，公开线性求解可产生被接受的签名；这些反例必须保留。此次修复消除旧低秩委派与模偏差，不使教学点变成安全实例。论文归约、固定服务模型、有限采样误差、正式困难性估计和 HIBE 组合均未由生命周期测试代证。

本批运行收据、精确命令、环境、提交及结果入口见 [2026-10-16 交付说明](../research/team-b-delivery/2026-10-16-sageloli-complete/README_zh-CN.md)。
