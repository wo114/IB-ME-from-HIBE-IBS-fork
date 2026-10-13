# Yu IBS 独立实现：本轮做了什么

本轮按用户决定接手 Yu–Liu–Li 2026，只做 IBS 自身的代码。此前仓库只有 NAND 同态代数组件；这次补上 BPR 矩阵 PRF、电路编译、系统初始化、用户发钥、签名和公开验签。它是可以实际执行的研究实现，不是返回预设答案的模拟模块。

**本轮单体研究代码已完成验收：472 项测试通过，无失败、无跳过；最终 3 次独立系统初始化均完成整链，产生 12 个诚实签名、24 次对象/字节验签和 120 项负例或独立方程对照检查。** 实现提交：`3ddc623594bca4fc0a6ea744d6a7ca870a4260b2`。源代码和测试共 13 个新增文件；逐文件清单可由该提交或下方证据检查。

**当前配置只能用来核验代码，不能用于保密通信或签名认证。** `q=3` 时，任何人都能构造通过验签的公开向量 `3e₁`。代码和测试明确保留这个反例，`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。

## 1. 可以怎样理解这条链

1. **系统初始化**：真实生成一个带陷门的格矩阵，以及两组独立均匀的公开矩阵。
2. **给身份发钥**：把身份固定进 PRF 电路，再进行公开同态求值；用系统陷门委派并随机化出该身份的格基。
3. **签名**：把身份、消息和新随机盐放进另一条电路；用用户格基作离散高斯原像采样，得到满足签名方程的整数向量。
4. **验签**：只使用系统公钥、身份、消息和签名，重新计算矩阵，检查方程、非零和长度上限。验签不访问主私钥，也不需要查看“哪些身份曾经登记过”。

原文允许一次发出的身份密钥多次签名。`Authority` 为同一身份复用同一把用户密钥；原始 `keygen` 仍是一次独立发钥调用。两个用途在代码里明确分开。

## 2. 主要文件

| 文件 | 内容 |
|---|---|
| [standalone.py](../../../experiments/research/candidates/yu/standalone.py) | 四算法、固定身份密钥服务、签名编码与解析 |
| [bpr.py](../../../experiments/research/candidates/yu/bpr.py) | BPR 矩阵 PRF、有限高斯密钥分布及其电路编译 |
| [circuits.py](../../../experiments/research/candidates/yu/circuits.py) | 真正可执行的 NAND 加法、乘法、比较和电路检查 |
| [evaluation.py](../../../experiments/research/candidates/yu/evaluation.py) | 公开/私有同态求值、常量电路和匹配函数 |
| [trapdoors.py](../../../experiments/research/candidates/yu/trapdoors.py) | 复用既有 AP09、CHKP、GPV 格工具，连接到 Yu |
| [profiles.py](../../../experiments/research/candidates/yu/profiles.py) | 固定的小规模正确性配置 |
| [lifecycle_audit.py](../../../experiments/research/candidates/yu/lifecycle_audit.py) | 使用系统随机源运行真实生命周期，只输出脱敏收据 |
| [SOURCE_MAPPING.md](SOURCE_MAPPING.md) | 原文位置、代码对应，以及有限实现与论文理想算法的区别 |

原来的 [homomorphic_reference.py](../../../experiments/research/candidates/yu/homomorphic_reference.py) 保持不变，作为新实现的独立对照。没有修改共享格采样器或放宽其资源上限，也没有接入公共后端、HIBE 或 IB-ME。

## 3. 如何复跑

在仓库根目录，使用项目规定的 WSL Sage 环境：

```bash
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 \
~/miniconda3/envs/sage/bin/python -m pytest -q -p no:cacheprovider --tb=short \
tests/test_yu_circuits.py tests/test_yu_bpr.py \
tests/test_yu_evaluation.py tests/test_yu_prf_homomorphism.py \
tests/test_yu_trapdoors.py tests/test_yu_standalone.py \
tests/test_yu_homomorphic_reference.py \
tests/test_chkp_genbasis.py tests/test_chkp_basis.py \
tests/test_chkp_gpv.py tests/test_chkp_randbasis.py tests/test_chkp_basis_reduce.py

PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 \
~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.yu.lifecycle_audit \
--attempts 3 --output build/outputs/yu-lifecycle.json
```

Windows 管理的 worktree 若无法由 WSL Git 读取，可用 `--source-revision <Windows端git-rev-parse-HEAD输出的完整哈希>` 提供基点。收据中的逐文件 SHA-256 标识实际执行文件，不能只凭 HEAD 判断脏工作树的运行版本。

生命周期驱动会保留每次尝试的成功或失败、阶段和异常类别，不自动反复尝试直到成功；不会输出或保存主私钥、用户格基、随机种子或实际签名。测试缺少 Sage 而跳过，不能算通过。

## 4. 参数和结论边界

| 项目 | 本轮配置 |
|---|---|
| Yu 格维度 | `n=1, q=3, m=15, w=2`；根→用户→签名维度为 `15→17→19` |
| AP09 | `random_rows=m1=3, m2=12, hadamard_scale=8` |
| Gaussian 约定 | 密度正比 `exp(-π·‖x‖²/s²)`；`γ²=32768, δ²=67108864`，不是方差 |
| 随机化与后处理 | `max_vectors=32, epsilon_bits=16`，随机化后显式使用确定性 LLL |
| 身份、消息、盐 | 分别 `2、2、4` 位固定长度，不是任意长度字符串接口 |
| BPR | 矩阵 `n=m=2`，`q=32, p=2`；Gaussian 宽度 `r=2`；每系数 32 位有限采样随机带 |
| BPR 密钥电路 | 身份侧 276 个输入位、签名侧 1044 个输入位；全 1 公开输入时分别 7904/31616 个 NAND 门，深度 118/158 |
| 随机模型 | 算法不调用随机预言机；实跑使用 OS CSPRNG。分布分析条件仍是假设独立均匀随机字节 |

这些参数让算法步骤真正运行起来，但没有满足论文全部安全参数条件。BPR 使用高斯分布的有限近似，不用均匀数冒充高斯；误差证书来自区间算术和精确有理数。其全体密钥的误差按系数数量合成，不能只报单个系数的误差。

LLL 是本项目明确标出的有限实现后处理，原文 Figure 5 没有这一步。高斯采样有有限预算，零向量、过长向量或资源耗尽会让本次调用明确失败。这里没有把失败隐藏为重新采样，也没有暗改验证规则使错误身份必定拒绝。

Yu 的标准模型安全定理是文献结论；这份实现尚未核齐密钥输入电路的 NC1 条件和 Lemma 7 所用的谱范数界，因此不能把该定理直接贴到这套可执行配置上。小参数下错误身份、消息或盐可能通过模方程检查；这与上面的公开伪造共同说明配置不安全，不得将这些接受次数抹掉。

## 5. 可以写进报告的内容

可以写：补齐了独立研究实现；真实执行了源论文四算法的数据流；通过了所列功能、代数、边界和错误传播检查；用公开反例揭示并保留了调试配置的不安全性。测试结果、时间和编码尺寸必须附本轮参数与环境。

不能写：已经获得标准模型安全后端、达到某个安全位数、优于其他正式参数算法、可用于真实认证，或已经完成 Wang/HIBE 组合。有限测试也不能保证软件不存在任何未发现缺陷。

## 6. 本次验收结果与证据

- [validation.json](validation.json)：完整命令、472 项结果、测试文件哈希、环境和已修问题。253 项为新增 Yu 检查，47 项为原 Yu 组件回归，172 项为复用格工具回归；不重复累加子任务此前的运行数。
- [lifecycle.json](lifecycle.json)：最终固定源码整链收据。所有 3 次尝试都保留，每次使用系统随机源，2 个身份各签 2 条消息。
- [development-lifecycle.json](development-lifecycle.json)：开发期旧源码收据，记录 3 次尝试中的 1 次 Setup 采样中止、2 次整链完成。该批不合并进最终通过统计；其具体源码状态按逐文件哈希区分。

最终负例中，零签名、超范数、破坏模方程的单坐标修改、截断和追加全部按要求拒绝。错误身份和消息分别有 **8/12** 被接受，修改 `r_hat` 有 **8/12** 被接受，修改 `r_tilde` 和盐分别有 **10/12** 被接受；公开构造 `3e₁` 为 **12/12 接受**。这些结果均与独立方程一致，明确禁止将这套小参数的代码验收写成认证安全验收。

最终环境为 Windows 主机 Intel Core Ultra 7 255HX、WSL2、Sage 10.9、Python 3.13.15。小参数运行的中位数仅用于复跑排查：Setup **0.0086 s**（3 次）、KeyGen **4.8330 s**（6 次）、Sign **0.1466 s**（12 次）、Verify **0.1479 s**（12 次）。时间包含电路编译和检查，负载未隔离，不能拿来比较安全参数下的算法优劣。签名字节格式长 **345 B**，其中整数坐标使用固定 16 B 编码；这不是原论文的压缩尺寸或正式参数尺寸。

联合 pytest 因 JUnit 的 `record_property/xunit2` 格式兼容性产生 16 个报告警告，没有算法测试失败。开发期还修复了验签对异常坐标类型的再校验、随机源 `memoryview` 实际字节数检查、仅常量电路的求值，以及 WSL 对 Windows worktree 基点的收据读取。

## 7. 同步最新上游后的发布复核

本次以 `upstream/main e030d05` 为发布基线，通过 [wo114/IB-ME-from-HIBE-IBS-fork](https://github.com/wo114/IB-ME-from-HIBE-IBS-fork) 的 `codex/yu-ibs-standalone-2026-10-13` 分支向队长仓库提交 PR。旧同名仓库被 GitHub 标记为独立仓库，跨库 PR 被拒绝；现保留旧库并另建正确关联的 fork。此处记录发布复核；前六节中的原始批次和失败记录保持原样，不把多次运行合并成更大的通过数。

上游把三个格工具实现迁移到 `src/ibme/lattice/chkp/`，原实验目录成为兼容入口。发布前先合入该变更，然后重跑同一组 **472 项测试，全部通过、无跳过**。16 个警告仍仅为 JUnit 属性格式兼容提示。可核对[本次测试报告](publication-pytest.xml)；只移除了机器主机名，断言和测试结果未删改。

另在固定源码 `3d15c6e21f959fd1b4a6e51ded44fd66a7f636c1` 上重新执行 **3 次整链，3/3 完成，12 次签名、24 次对象/字节验签、120 项负例或方程对照**。本次收据同时固定兼容入口和实际实现等 **22 个来源文件**的哈希，见[发布整链收据](publication-lifecycle.json)和[发布复核说明](publication.json)。没有修改 Yu 数学算法或共用采样器。

本批仍观察到错误身份接受 **7/12**、错误消息 **8/12**、修改 `r_hat` **12/12**、修改 `r_tilde` **9/12**、修改盐 **8/12**，公开 `3e₁` 伪造仍为 **12/12 接受**。这些都与公开方程对照一致，按不安全小参数结果原样交付；不将功能验收写成认证安全验收。

[MANIFEST.json](MANIFEST.json) 列出此次 PR 的全部交付文件及 SHA-256（清单自身除外），包括实现、测试、来源对应、旧验收与开发失败记录、新发布证据及项目状态入口。源码、测试和这些材料同批发布；没有加入秘密密钥、随机种子、实际签名、论文副本或私人任务书。远端 CI 是否通过另以 GitHub 的实际运行状态为准，旧 CI 的覆盖不能替代这里的 Sage 单体检查。

下一阶段若要纳入正式候选，需要单独确认上述电路/范数与参数条件，再讨论公共接口和组合接入。
