# Wang–PW s0=4 独立研究后端与服务器验收

**WIP 检查点（2026-10-20）：完整环境与服务器 231 项回归通过；n512 单根主档于北京时间 09:53 启动，尚无最终结果。未推送、未建 PR。**

本批已交付独立 `wang-pw-target` 后端、C++ 有限整数 Gaussian/GPV 采样、规范对象、固定发钥服务、公共装配/CLI、参数审计和可监控的生命周期驱动。早批服务器 182 项与小参数回执保留；当前冻结 `b47cc6a` 完成 **231 passed / 0 failed / 0 errors / 0 skipped，61.37 s**、q257 三个生产随机根，以及 q32 磁盘恢复后的独立进程签名。**n512 已启动但尚未完成**，其完整生命周期、最终耗时和峰值内存仍待回填。

此前公网 SSH 连续超时发生在 n512 启动前。2026-10-20 连接恢复后，已补齐固定 `lattice-estimator` 并通过 Sage 导入，已有 Sage 环境采用 install 补齐，没有重建。历史 schema-1 `environment-ready.json` 只证明先前核心环境；完整环境使用新 schema-2 回执，须另核实际源码、归档、依赖锁和 native，不能沿用旧 ready 标记启动主档。

当前证据位于 [server-resume](evidence/server-resume/)：[环境](evidence/server-resume/environment-ready.json)、[源码传输](evidence/server-resume/source-transfer.json)、[JUnit](evidence/server-resume/server-tests.xml)、[启动前核对](evidence/server-resume/target-launch-preflight.json)、[本地复核](evidence/server-resume/review.json)与[23文件哈希清单](evidence/server-resume/manifest.json)。服务器解包的 3297 文件与归档逐项一致，18 份环境绑定源码与 Git `b47cc6a` 字节一致。`target-initial-running.json` 和 `target-supervisor-initial.json` 只是在 09:55 取得的 Setup 运行快照，不是完成回执，不据其早期 RSS 推断最终峰值。

主档是本项目选定的 `s0=4,n=512,q=4294967291` 有限研究候选，**不是原论文给出的数值参数表，也不是已准入安全参数**。全部代码与回执保持：

```text
security_claim=none
backend_admitted=false
parameters_are_formal=false
nist_security_category=null
```

依当前项目工作约定，理论性质以所选论文及明确工作假设为前提推进；本批没有新增安全证明、逐个 hybrid 或完整归约闭合任务，也不开展 s0=2 的有限实例论证。实现差异、参数不满足及实际失败仍单独记录。

## 1. 提交与入口

| 提交 | 已提交的任务边界 |
|---|---|
| `59c8448` — `feat(wang-pw): add isolated s0=4 native Gaussian research backend` | 新参数、五方法、哈希、G-trapdoor/basis 运算、C++ 采样器、四类规范对象及原语测试 |
| `fffc4f0` — `feat(wang-pw): persist fixed target issuance and audit parameter limits` | 固定发行服务、公共 selector、CLI 状态保护、参数审计与论文对应材料 |
| `9135ec8` — `test(wang-pw): add monitored lifecycle and complete task environment` | 环境安装/验收工具、分阶段运行与 RSS 记录、真实 LATTE 组合测试及补充故障测试 |
| `8373da5` — `feat(wang-pw): supervise target runs with explicit resource limits` | 外部时间/进程树 RSS 监督器，信号与异常清理、公开退出回执及 10 项真实子进程测试 |
| `5d93c5a` — `fix(wang-pw): make environment recovery and readiness verifiable` | 保留已有 Sage、可续取冻结 estimator、原子发布 schema-2 ready 与 15 项故障测试 |
| `8a157db` — `test(wang-pw): verify fixed-source SIS rejection and native service recovery` | 实际条件 SIS 工具拒绝、显式库存路径、真实发钥服务跨进程零熵复用 |
| `8abe24c` — `feat(wang-pw): sign restored keys in isolated interpreter and retain safe failures` | 独立恢复签名、公开失败白名单、真实独立进程组合；保留早期 debug GS 拒绝 |
| `b47cc6a` — `docs(wang-pw): distinguish target implementation and pending server acceptance` | 本次服务器运行源码冻结点；后续回执不追写为新源码 |

实现见 [目标后端](../../../src/ibme/ibs/wang_pw_target/)、[接口契约](../../specs/wang-pw-target-ibs.md)、[参数与论文对应](../team-b-delivery/2026-10-20-wang-pw-target/parameter-map.md)；实测驱动和完整操作说明见 [实验目录](../../../experiments/research/wang_pw_target/README.md)。本目录日期为本批服务器交付日期，保留既有参数对应文档的路径。

旧 `wang-pw` / `WangPW-research-v1` q17 后端与 PR #67 数值探针均保留。新 selector 为 `wang-pw-target` / `WangPW-target-s0-4-v1`，不能自动退回旧后端、mock 或另一套采样。算法总录仍把两种 selector 归为同一条 Wang–PW IBS 路线。

## 2. 对原数值探针的关键纠正

1. **高斯单位。** `s0=4` 表示 `rho_s(x)=exp(-pi*x²/s²)` 的宽度；根采样的标准差为 `4/sqrt(2*pi)`。原探针 `normal(0,4)` 的 4 是连续正态标准差，而且结果经过舍入。其历史计时、范数和 estimator 数字不能直接迁移到本档。
2. **真正的用户陷门。** 根公开矩阵为 `A=[Abar | G-Abar*R]`。发钥按列采样 `X`，满足 `A*X=G-H1 (mod q)`，因此 `F_id=[A|H1]` 有 `F_id*[X;I]=G (mod q)`。只检查 `A*X=-H1` 的旧方程探针不等于完成这一委派。
3. **主秘密隔离。** 用户对象只含自己的 `X`、身份/身份盐、公开根和参数。主 `R` 和主完整核基不交给用户。把含 `B_master` 的块核基直接当用户密钥会泄露主陷门，不能作为 IBS 发钥方案。
4. **委派宽度。** 本档使用 `s_del=8*root_gs_limit`；没有再乘 `sqrt(m)`。维数平方根属于向量范数或矩阵谱范数估计，不能重复塞进每坐标采样宽度。签名宽度单独根据用户 basis 的 GS 门设定，不能沿用主 basis 的观测。
5. **验签与 SIS 输入。** 验签范数门在采样前固定，使用整数平方范数和方程双检查。论文根 SIS 的列数为 `m`，签名维数为 `M=m+w`；一条实测签名范数不是论文提取的统一 `beta_SIS`。
6. **精确模运算与内存。** q32 乘法按有界整数 limb 分解，超范围向量使用 Python 整数累加；不让 int64 溢出改变方程。密钥只保存紧凑陷门，确定性重建 basis；进入用户准备前释放主稠密缓存。紧凑 wire 不等于稠密 GPV/QR 工作区也同样小。

## 3. 已实现算法与对象

公共五方法为 `setup/key_extract/sign/verify/load_signature`。H1/H2 与 PW 外层身份/消息转换使用四个独立域及 uint32 长度前缀；H1/H2 还绑定规范公钥摘要及完整参数上下文。身份盐随用户密钥固定，消息盐每次签名重新取样。公开验签只使用公钥、身份、消息和签名，检查上下文、维数、非零性、固定范数门与 `F_id*z=H2`。

用户恢复从公开 `A` 和既有 `X` 确定重建自己的完整整数核基及数值 QR 工作区，不调用 Setup/KeyExt，不重新抽取 `X` 或身份盐，也不需要主密钥。该路线是 **G-trapdoor 转完整 basis 后执行 GPV/Klein**，没有把它标作 MP12 Algorithm 3 perturbation sampler 的逐项复现。

| 对象 | 规范编码 | 主要检查 |
|---|---|---|
| 公钥 | `WPTPK001`，完整参数与 uint32 矩阵 A | 固定维数、规范模 q 系数、完整参数 |
| 主秘密 | `WPTMS001`，嵌入公钥与 int16 R | 根陷门方程、编码范围 |
| 用户秘密 | `WPTSK001`，嵌入公钥、身份、固定盐与 int32 X | 身份/公开根绑定及 `A*X+H1=G` |
| 签名 | `WPS1` 头、公开上下文、两盐与 int64 z | 固定维数、整数范数门、规范 wire |

所有格式严格拒绝截断、追加、未知版本、错误长度、非规范参数、错误公开根和越界整数。分配大矩阵前先检查公开预算；窄化整数前检查范围。对象持久系数不允许调用者重新打开写权限。wire 尺寸由 `objects.wire_sizes()` 无大矩阵分配计算，并在真实运行中核对实际输出。

## 4. C++ 有限整数 Gaussian 与随机源

采样器从有限整数质量直接抽样，没有调用连续正态后取整。给定 binary64 中心 c 和标准差 sigma，其窗口为 `floor(c) ± (ceil(20*sigma)+1)`，未归一化整数质量为：

```text
w(x)=floor(2^192 * exp(-((x-c)^2-dist(c,Z)^2)/(2*sigma^2))).
```

默认使用 256-bit MPFR 定向区间、192-bit 质量、20 个标准差窗口和每次 4096 个拒绝提案预算；区间仍无法决策、熵获取失败、整数溢出、中心/窗口/资源超限均明确中止，不返回半份样本，不偷偷改参数或重抽根。GPV 逐坐标反向循环在 C++ 内执行，整数更新使用受检查的 128-bit 中间值。

生产采样由 OpenSSL `RAND_bytes` 获取新种子，再以域分隔方式初始化 ChaCha20 流；公开矩阵、盐等 Python 侧随机性使用系统 `SecureRandom`。固定种子只允许显式 `test_only=True`；注册工厂把公共测试随机流明确标成测试，不作为生产随机性。

本地显式库由 `IBME_WANG_PW_TARGET_NATIVE` 指定。旁置 JSON 回执绑定 C++ 源码 SHA-256、二进制 SHA-256 和 ABI，已加载库再导出 ABI 与编译源码哈希供核对。指定库错误时不自动编译替代库。绑定用于检查构建连续性，不宣称认证未知编译器。

浮点 QR/Gram–Schmidt、中心运算、有限窗口和质量量化仍是该研究实现的明确条件。参数审计的连续尾概率、floor 质量损失诊断不能代替完整移位离散高斯或整链分布界，`total_tv_bound=null`、`gs_bound_certified=false`、`abort_probability_bound=null` 保持原值。

## 5. 固定发行、装配、CLI 与组合

原始 `Backend.key_extract` 仍是随机化五方法，不含身份账本，因此 registry 如实登记 `persistent_identity_cache=false`。外层 `service.FixedIssuer` 提供另一层固定服务语义：同一身份返回同一已发布 X 和身份盐；pending 预约先于采样，权威状态提交先于返回；采样、写入或发布失败后由 pending/failed 状态阻断偷偷重抽。恢复验证身份顺序、状态、容量以及同一公钥/参数绑定。

固定服务采用 `WPTISS01` 流式二进制快照，总量小于 4 GiB；主档默认最多一个用户，debug 默认四个。主档申请两个用户会在采样或创建状态前触发容量拒绝。其私密状态为明文文件，锁针对同一操作系统上的合作进程；不宣称分布式事务、恶意回滚防护或未验证的硬断电恢复。服务测试覆盖线程/进程并发、重启复用、硬进程退出、损坏状态和发布前后失败。

公共装配提供 `s0-4` 与 `debug-small` 参数预设及 `reference` 签名格式。发现、参数快照、尺寸计算和预检不采样、不读取熵、不编译或写状态。CLI 对目标后端增加同身份 sender 复用与中断标记；旧 sender 文件损坏时拒绝重新发钥。

已验收的组合层次分开记录：

- CLI 生命周期测试使用真实 debug Wang IBS 和 **mock HIBE**，只验证 CLI 状态与传输，不作为真实 HIBE 组合证据。
- `test_wang_pw_target_combination.py` 使用 **真实 LATTE + 真实 Wang debug-small**，沿用共同 `run_combination_matrix.run_case` 驱动，Hybrid + BYTEAUTH，显式 1 MiB payload/4 MiB capsule 预算，LATTE backend id 为 `latte3-cosac-fix-v1`。LATTE 数学参数保持作者档 `n=1024,q=68718428161`、768-bit FFT；默认 2 个接收者、每人 2 个子身份缓存足够。
- 真实组合共 **32 项**：诚实收发、对象恢复、错发送者/接收者/两者均错、截断/追加/重复/版本、BYTEAUTH 篡改、IBS 错身份/消息、改动与随机签名、有效新 OTS 下旧 IBS 签名重绑、确认拒绝实际到达 IBS，以及空消息。该项已包含在下述服务器 182 项中，不重复相加。

这证明公共实现能够组合执行。Wang 小维数档明确非安全，不作为 n512 组合性能或安全参数的证据。底层 HIBE 在 Hybrid 下只加密 32 B seed，无需与 IBS 共享 n/q。

## 6. 论文来源与参数边界

| 资料 | 本批对应位置与使用范围 |
|---|---|
| [Wang ePrint 2022/1718](https://eprint.iacr.org/2022/1718)，仓库 [PDF](../../../papers/2022_identity_matchmaking_wang.pdf) | PDF 7–8 页 Lemmas 2.5–2.7；16 页 Figure 4 与 Parameter Selection；17–19 页 Theorem 5.1/算法 B。实现/参数关系详见既有参数对应表。 |
| [Pan–Wagner ePrint 2021/970](https://eprint.iacr.org/2021/970)，仓库 [PDF](../../../papers/2021_short_ibs_pan.pdf) | 既有交付对应 PDF 12 页 Figure 5 的身份盐、消息盐与外层转换；固定发行账本作为工程服务另列。 |
| MP12 basis 转换 | `math.full_basis` 采用 G-trapdoor 到完整核基的路线；主/用户 basis 分开。不能把代数关系测试等同于认证其有限实现分布。 |

主档参数如下；完整快照以源码和运行 JSON 为准：

| 参数 | 本批值 |
|---|---|
| n / q / k | 512 / 4294967291 / 32；q 是素数，非 `2^32` |
| w / m_bar / m / M | 16384 / 16384 / 32768 / 49152 |
| 根宽度 / 委派宽度 / 签名宽度 | 4 / 4096 / 8388608；均按 rho_s 宽度 |
| 根 GS / 用户 GS 工程门 | 512 / 1048576；数值接受门，不是全体输出的认证界 |
| 公开验签平方范数门 | 3458764513820540928 |
| 身份/消息入口容量 | 256 B / 4096 B；两盐各 32 B |
| 主档默认线程、Setup/Extract/Sign 次数 | 16 线程；各 1 次，无隐藏重抽 |
| 主档签名 wire | 393320 B；公钥/秘密 wire 长度含完整参数与身份字段 |

`parameter_audit.audit()` 不运行 estimator、不生成目标矩阵或安装依赖。它按原文提取形式 `[I_m|Rhat](z_forged-z_reference)` 接收有来源的统一参考范数界与模拟矩阵谱范数界，缺失时真实 `beta_SIS` 保持 null。历史单样本 153.70 等位数没有作为本档准入结论。

当前配置采用与公开验签门相同的参考包络时，即使乐观投影谱界取 1，也得到 `beta=5260239171 >= q=4294967291`，已进入平凡 SIS 区，因此这个已配置参考包络不合格。[本地真实调用](evidence/local/parameter-screen.json)已收到固定 estimator 的预期输入拒绝，成本与位数均为 null；该历史回执绑定调用当时的文件字节，后续库存路径支持修订不追写旧哈希。审计没有据此宣布所有可能更紧包络均不可能，也没有把源码能运行写成参数已完成。按正确统一 beta、根列数 m 和冻结成本模型的参数决策仍未交付；本批不安排新增基础安全证明来替代这一事实。

## 7. 历史核心环境与当前完整验收

[环境回执](evidence/environment/environment-ready.json) 在源码 `9135ec8` 下先完成 Python/Sage 导入、Wang native ABI/哈希与 LATTE metadata 检查，随后才执行测试和算法。回执中的 `cryptographic_experiments_run=false` 描述环境准备步骤本身；后续算法证据另存于 `evidence/public/`。

该历史核心回执的 `status=ready` 不表示新增后的全部任务环境已经完成。冻结 `lattice-estimator` 版本为 `53da5982597709ba0fdf94ea37a84d822310fd84`；2026-10-20 服务器已完成完整 schema-2 验收和 231 项回归。当前[服务器工具回执](evidence/server-resume/parameter-screen.json)真实收到同一配置参考包络 β≥q 的预期拒绝，记录当前源哈希；这不是完整攻击成本估计，不产生经典/量子安全位数。

| 项目 | 服务器记录 |
|---|---|
| 系统/编译器 | Linux 6.8.0-139-generic，glibc 2.39，x86_64；g++ 13.3.0 |
| CPU / 实际物理 RAM | 16 vCPU；132785688576 B，约 123.666 GiB |
| 主要运行时 | Sage 10.9，Python 3.12.15，NumPy 2.5.4，SciPy 1.18.1 |
| 辅助包 | pytest 9.1.1，psutil 7.2.2，gmpy2 2.3.2，cryptography 50.0.2 |
| 依赖锁 | [venv requirements](evidence/environment/requirements.lock.txt)、[Sage 显式锁](evidence/environment/sage-explicit.lock.txt)；锁哈希及两 native 源/二进制哈希见环境回执 |
| 冻结 lattice-estimator | 2026-10-20 完整新 ready 已含固定版本/导入；真实条件输入筛查预期拒绝，未给正式成本 |

[pytest 日志](evidence/public/server-tests.log) 为 **182 passed in 16.88s**；[JUnit](evidence/public/server-tests.xml) 精确记录 182 项、0 failures、0 errors、0 skipped。它覆盖 9 个 `test_wang_pw_target_*` 文件和 `test_cli_selection.py`；未把 n512 Setup 作为常规单测执行。

资源监督器在本地规定的 WSL Sage 环境中与 CLI registration 一起复跑：
`python -B -m pytest -q -p no:cacheprovider tests/test_wang_pw_target_runner.py tests/test_wang_pw_target_registration.py`，
**25 passed in 21.36s**（其中 runner 10 项）。它覆盖正常/非零退出、时间与整树 RSS 超限、TERM 后 KILL、残留后代、信号及监控异常清理。
这些结果与早批服务器 182 项和当前 231 项存在重叠，不相加作为独立覆盖数。当前 231 项包含监督器及新增独立进程测试；另有 [debug-supervisor](evidence/server-resume/debug-supervisor/receipt.json) 对真实 q32 生命周期进行整树资源监督，正常退出且后代清理为零。

| 独立算法实测 | n / q；重复 / 恢复 | driver 总时长 | 采样 RSS 峰值 | 结果 |
|---|---|---:|---:|---|
| [debug-q257-three.json](evidence/public/debug-q257-three.json) | 2 / 257；3 个顺序 CSPRNG 新根 / 内存规范往返 | 0.412003428 s | 69345280 B | 3 根均完成全部 6 阶段，观测公钥各异 |
| [debug-q32-disk.json](evidence/public/debug-q32-disk.json) | 4 / 4294967291；1 个 CSPRNG 新根 / 私密磁盘实际读回 | 0.352356696 s | 74903552 B | 6 阶段全部通过 |
| 当前 [q257 三根](evidence/server-resume/debug-q257-three.json) | 2 / 257；3 个顺序 CSPRNG 新根 / 内存规范往返 | 见回执 | 见回执 | 当前冻结代码全部阶段通过；恢复仍为同进程 |
| 当前 [q32 独立恢复](evidence/server-resume/debug-q32-independent.json) | 4 / 4294967291；1 个 CSPRNG 新根 / 私密磁盘实际读回 | 0.892022932 s | 148267008 B | 六阶段全过，恢复签名在新解释器执行；子进程自身 RSS 74543104 B |
| n512 主档 | 512 / 4294967291；单个新 CSPRNG 根 | **运行中/待最终回填** | **待最终回填** | 2026-10-20 09:53 启动；110 GiB / 21600 s / 16 线程；没有隐藏重抽 |

这两份 debug 实测均为身份 64 B、消息 32 B、4 线程、`OMP_NUM_THREADS=4`、`OPENBLAS_NUM_THREADS=4`。每根依次执行 Setup、Extract、Sign、公开 Verify/负例、Restore、Sign-restored。q32 恢复由真实落盘的 PK/MSK/SK/签名规范编码完成；秘密文件保留在服务器仓库外的私密目录，不加入 Git 证据。两份回执均记录源码运行期间未变。

上述 `duration_seconds` 是已导入驱动进程内的单调时钟区间，**不包含独立进程启动时间**，也不是纯采样内核时间；阶段包含相应序列化、磁盘操作和监控开销。q257 三根包含首根的初始化效应，不能把其最短阶段当稳定基准。RSS 是 psutil 每 0.1 s 采样并结合阶段观测的峰值，可能漏过短暂尖峰；它不是操作系统完整高水位，也不能从 n2/n4 外推到 n512。

按本回执覆盖的文件复跑测试，可在已准备的 Sage 环境中执行：

```bash
source "$TASK_DIRECTORY/environment/runtime.env"
PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m pytest \
  tests/test_wang_pw_target_{audit,backend,cli,combination,native,objects,params,registration,service}.py \
  tests/test_cli_selection.py -q --junitxml=/absolute/new-output/server-tests.xml
```

算法复跑使用 `experiments.research.wang_pw_target.run_lifecycle` 的 `debug-q257 --repetitions 3` 与 `debug-q32 --private-state <仓库外私密目录>`；按[驱动说明](../../../experiments/research/wang_pw_target/README.md)选择全新的输出与 phase-log 文件，不覆盖既有证据，不传固定测试种子即可保持生产 CSPRNG 模式。

## 8. n512 验收进行中

稠密用户 basis 单份约 18 GiB，根 basis 单份约 8 GiB；紧凑对象不消除 QR 工作区。本档审计规划约 123.314 GiB，含多个用户方阵、临时缓冲与 20% 余量，**不是实测上界**。服务器实际总 RAM 约 123.666 GiB，尚需扣除操作系统和其它进程，不能仅凭“128G”规格判定足够。

完整 schema-2 环境、源码与归档/锁/native、231 项回归、生产随机 debug 生命周期和独立恢复签名均通过后，已启动受监控的 n512。目标运行串行记录全部阶段、实际参数/线程、明确失败与资源门、规范磁盘恢复、独立进程恢复后签名、对象实际字节数、总时长和 RSS；外层 `/usr/bin/time -v` 原始文件保留服务器，公开副本去掉含私密路径的完整 argv 行。n512 最终结果待回填；失败阶段同样保留，不由小维数结果代替。目标规模资源验收与正式参数决策分开，功能测试和有限攻击未成功不构成安全证明或 NIST 等级结论。

本地独立进程测试首跑曾有一个生产随机 n2/q32 根被既定 GS 门 32 拒绝：[原输出脱敏副本](evidence/local/independent-first-run.log)、[失败记录](evidence/local/independent-first-run.json)。首跑未启 JUnit，未补造原 JUnit。接口测试的发钥 fixture 后改为已有明确测试种子，签名子进程仍为生产 CSPRNG；本次服务器整套 231 项通过不抹去该失败，也不把 debug 根拒绝称为 n512 失败。

已选定首轮单根监督限额为 **110 GiB / 21600 s**，采样进程树 RSS，超限先 TERM、最多等待 60 s 后 KILL；这是运行资源门，不是所需时间或内存的估计。启动命令模板如下，须先完成环境准备并选择全新公开输出目录：

```bash
python -u -m experiments.research.wang_pw_target.run_guarded \
  --max-rss-gib 110 --max-seconds 21600 --terminate-grace-seconds 60 \
  --output-dir "$TASK_DIRECTORY/public/target-supervisor" -- \
  python -u -m experiments.research.wang_pw_target.run_lifecycle \
    --profile target --threads 16 --repetitions 1 \
    --private-state "$TASK_DIRECTORY/private" \
    --output "$TASK_DIRECTORY/public/target-n512.json"
```

监督器回执的 `lifecycle_complete=null` 保持“未评估”：子进程正常退出本身不证明完成全部算法，必须另外检查生命周期 JSON 的实际阶段与状态。

## 9. 原根复用的后续验收准备（本地完成，目标规模未执行）

本地后续源码为 `f56e488`，由三个提交组成：`c2cb2c9`（显式管理导入与来源持久化）、`7b728f3`（随机源失败负例）、`f56e488`（独立进程真实组合复用驱动）。**服务器原主档仍使用 `b47cc6a`，没有修改运行目录、增加第二个 n512 根或重新发钥。** [本批运行快照与审查](evidence/reuse-preparation/review.json)取得时总运行约 1367.6 s，已完成 Setup 536.625661122 s，处于 Extract，整树采样峰值 36794908672 B（约 34.268 GiB）；这仍不是最终性能或完整成功。服务器 13 份绑定源码与原运行记录逐项核对无变化，原记录又与本地冻结 Git blob 相符。

本批实现和测试文件如下；未改变原算法、数学参数或采样器：

- [固定服务](../../../src/ibme/ibs/wang_pw_target/service.py)新增 `adopt_existing` 与 `key_origin`。导入保留 `imported` 状态，原服务首次发出的钥仍是 `issued`；二者在磁盘恢复后可区分。导入按规范编码检查根、身份、参数和精确密钥方程，不认证其原始采样分布或 GS 质量。
- [服务复用驱动](../../../experiments/research/wang_pw_target/run_reused_service.py)分别提供 adopt/recover 命令。两次独立解释器禁用 Setup、Extract 和密码学采样入口，核恢复后的完整密钥字节与原件相同，快照不变。导入证明管理操作及固定复用，不将原始 Backend 的发钥历史改写为服务完成。
- [真实组合复用驱动](../../../experiments/research/wang_pw_target/run_reused_combination.py)使用公开 SuiteRuntime/协议对象，保持原始二进制身份及规范 PK/SK，仅新建 LATTE 作者档根与两个接收钥。11 个顺序独立进程共新增一次 Wang 签名；同一密文覆盖诚实收发、重启恢复、三个身份错配、位翻转、截断、追加与有效新 OTS 替换拒绝。各角色只有公开状态与自己的钥，无主密钥。
- 测试为 `test_wang_pw_target_adoption.py`、`test_wang_pw_target_reused_service.py`、`test_wang_pw_target_random_failures.py` 和 `test_wang_pw_target_reused_combination.py`；驱动调用说明补在[实验 README](../../../experiments/research/wang_pw_target/README.md)。

规定 WSL Sage 环境运行 `python -B -m pytest -q -p no:cacheprovider tests/test_wang_pw_target_adoption.py tests/test_wang_pw_target_reused_service.py tests/test_wang_pw_target_random_failures.py tests/test_wang_pw_target_service.py --junitxml=...`：[64 passed / 0 failure/error/skip，23.86 s](evidence/reuse-preparation/reuse-and-random-tests.xml)。其中随机源测试覆盖错误类型、短读、长读及异常；仅在测试子进程 LD_PRELOAD 注入 OpenSSL `RAND_bytes` 失败，真实 Gaussian/GPV 明确中止、无重试或样本返回，未更改生产 ABI/库。

真实 LATTE 作者档＋Wang 非安全 n2/q257/s0=4 的新驱动及故障测试为 [4 passed，64.83 s](evidence/reuse-preparation/reused-combination-local.log)；该实际命令未启 JUnit，未为补证据重复运行或补造 XML。随后收紧失败类型白名单，相关两项 [2 passed / 2 deselected，1.75 s](evidence/reuse-preparation/reuse-child-failures.xml)。这些计数存在重叠，不相加为总覆盖，也不与服务器早批 231 项累加。

新驱动是**专用研究命令行＋公开组合 API**。通用 `ibme.cli` 只接受可打印 UTF-8，不能表示主档已经绑定的二进制身份，因此尚未完成通用 CLI 的 n512 实测；不能把身份换成 Alice 或十六进制文本冒充同一把钥。原始主档的六阶段成功也不自动证明目标固定服务或完整组合成功。等待原主档终止后，才能在外部资源监督下串行执行这些目标复用任务；失败保留回执，不重抽根、重新发钥或放宽门限。

本批六份公开材料由[manifest](evidence/reuse-preparation/manifest.json)绑定，另存原始运行快照，不覆盖早期启动证据；没有上传私密状态、密钥、盐、实际签名或本机原生库。正式参数的配置参考包络 β≥q 拒绝仍在，none/false/false/null 不变；研究代码与小规模组合通过不升级参数准入。
