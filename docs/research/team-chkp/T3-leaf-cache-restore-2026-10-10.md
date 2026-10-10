# T3 阶段交付：固定容量叶节点原像缓存与恢复

日期：2026-10-10。本文记录 T3 的一个可独立审查阶段：在 CHKP 叶节点只需要原像、不需要继续委派时，缓存已经生成的固定容量原像，并在受信任的私有快照中恢复。它不代表 T2 真实采样、完整两层 HIBE 或 T3 全生命周期已经完成。

## 1. 依据与边界

CHKP 原文 §5.3（作者版 PDF 第 22 页）要求同一身份重复提取时返回同一个解封装向量；原文给出的办法是保存状态、使用可重复随机性，或者使用当前基重新采样并付出更大的 `SampleD` 宽度。项目的 R1 规格也要求缓存键绑定完整公开上下文、身份路径和位置，并支持保存/加载恢复。

本阶段选择“状态缓存”路线。叶节点缓存只保存已经验证过的原像向量及其计划，不保存采样器、随机数发生器、根基、父基或叶基。缓存入口要求调用方提供完整公开上下文和已核验的叶节点计划；H/G 身份映射、生产公钥格式和完整 HIBE 生命周期仍未实现。

当前实现是研究模块，`security_claim: none`、`backend_admitted: false`。固定容量 2、最多 2 个发送者条目、公开玩具参数只用于验证状态机制，不能解释为正式密钥容量或安全参数。

## 2. 已实现的行为

- 同一 `(公开上下文、接收者、发送者、叶计划)` 再次请求时直接返回原向量，不调用采样器，也不消耗随机性。
- 叶计划绑定公开矩阵、模数、精确宽度、有序目标列表和采样器配置；矩阵、宽度、目标、采样配置或容量改变都会拒绝。
- 请求开始采样前完成身份、采样器、随机带和快照最坏情况大小检查。预检失败不占用缓存地址。
- 进入采样后先写入失败墓碑；任意异常、中断、部分采样或方程校验失败都会保留墓碑，后续不会自动重抽，避免同一身份产生不一致原像。
- 成功后只接受满足 `A x = y (mod q)` 的完整固定容量向量；快照使用有界、规范的二进制格式，拒绝截断、追加、重复地址、非规范整数、维度越界和错误方程。
- 恢复必须提供受信任的期望 `CacheScope`，并精确匹配公开上下文、接收者、容量和条目上限。
- 快照保存的是敏感明文原像。格式校验没有提供机密性、认证性或防回滚能力；生产版本还需要加密认证存储、事务提交和多进程一致性设计。

## 3. 实际核验结果

执行环境为 WSL2、Sage 10.9、Python 3.13.15。沿用 T2 已声明的四个固定种子，根维度为 10，叶维度为 30，`q=2`，`s_1^2=9064`，`s_2^2=15952640`；`epsilon_bits=16` 是采样器诊断参数，不是安全等级。每个种子缓存两个目标 `(0,)`、`(1,)`，并验证两次恢复后的向量和规范快照字节完全一致。

结果为：

| 检查 | 结果 |
|---|---:|
| 固定种子 | 4/4 通过 |
| 同一地址重复请求不重采样 | 4/4 通过 |
| 当前进程快照恢复 | 4/4 通过 |
| 全新 Python 进程恢复 | 4/4 通过 |
| 恢复后原像方程 | 每个缓存向量均通过 |
| 相关回归测试 | 556 passed，0 failed，0 skipped |

机器证据见 [T3-leaf-cache-evidence-2026-10-10.json](T3-leaf-cache-evidence-2026-10-10.json)，执行输出见 [T3-leaf-cache-execution-2026-10-10.log](T3-leaf-cache-execution-2026-10-10.log)，回归输出见 [T3-leaf-cache-validation-2026-10-10.log](T3-leaf-cache-validation-2026-10-10.log)。测试还覆盖了采样异常和 `KeyboardInterrupt` 的持久失败墓碑、计划冲突、容量上限、快照全截断点和同一所有者下的并发首次请求。

## 4. 与正式参数的关系

正式参数确定后必须重新测试，不能把当前小参数通过直接外推。至少要重新计算并核验：

1. 每层矩阵维度、模数位数、原像维度和快照最坏情况大小；超出研究模块上限时应拒绝并报告，不能截断或默默放宽。
2. 每个叶节点批量 `SampleD` 的随机带、时间和中止概率，以及失败墓碑对应的整体失败预算。
3. 原像范数进入真实加密/解密噪声界后的正确性；当前模块只核验格方程，不核验噪声解码。
4. 多比特载荷的目标数量、身份绑定、字节容量和私钥存储成本；当前两个目标只是固定测试容量。
5. 真实 H/G 输出、规范身份编码、完整 HIBE `Setup/Extract/Derive/Encaps/Decaps` 及 contract tests。

因此本阶段能复用的是缓存状态语义、固定容量和失败处理规则；矩阵宽度、容量、快照大小、噪声条件与安全估计必须在正式参数下重新给出证据。

## 5. 尚未完成与风险

- T2 的二级 `RandBasis` 仍受约 256 MiB 随机带上限限制，T2 仍是 WIP；本阶段没有修改采样器或放宽上限。
- 没有实现 H/G、生产公钥格式、完整 HIBE 字节载荷、噪声解密、加密快照、认证存储、回滚保护或跨进程写入事务。
- `A x=y` 方程验证不能证明原像来自目标高斯分布，也不能证明参数安全；有效的 `x+q` 替换示例也说明了快照格式不是认证机制。
- 当前结果不代表 CHKP 后端准入、128/192 位安全、ROM/QROM 安全或完整 IB-ME 正确性。

## 6. 可重跑命令

从仓库根目录，在规定的 WSL Sage 环境执行：

```bash
PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m experiments.research.chkp_leaf_cache_audit \
  --output docs/research/team-chkp/T3-leaf-cache-evidence-2026-10-10.json

PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m pytest -q \
  tests/test_chkp_genbasis.py tests/test_chkp_gpv.py tests/test_chkp_randbasis.py \
  tests/test_chkp_tobasis.py tests/test_chkp_t2_audit.py tests/test_chkp_basis.py \
  tests/test_chkp_basis_boundaries.py tests/test_chkp_t1_audit.py \
  tests/test_chkp_t2_conditions.py tests/test_online_sampling_reference.py \
  tests/test_chkp_basis_reduce.py tests/test_chkp_width_audit.py tests/test_chkp_leaf.py \
  tests/test_chkp_leaf_cache.py tests/test_chkp_leaf_cache_wire.py \
  tests/test_chkp_leaf_cache_audit.py --tb=short
```

## 7. 文件清单

- `experiments/research/chkp_leaf_cache_types.py`：范围、计划和缓存条目约束。
- `experiments/research/chkp_leaf_cache_wire.py`：有界规范快照格式和恢复检查。
- `experiments/research/chkp_leaf_cache.py`：单所有者固定容量缓存、命中复用和失败墓碑。
- `experiments/research/chkp_leaf_cache_audit.py`：四种子实际恢复审计；私有快照只存在临时目录。
- `tests/test_chkp_leaf_cache.py`、`tests/test_chkp_leaf_cache_wire.py`、`tests/test_chkp_leaf_cache_audit.py`：行为、格式和审计门槛测试。
