# PR75 审查与返工（WIP）

2026-10-20。审查原头 `938dd8e9c2ed7137abbdc80aa48ed81d96423cfe`；本次接收代码与安全字段兼容修复，不将尚缺的四组实验计为完成。[PR75](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/75)保留草稿，待原负责人补齐 B／C／Luo／Falcon 的安装版完整流程消融、准备及状态／内存成本后再作合并判断。当前进度统一见[PROJECT_STATUS](../../PROJECT_STATUS.md)。

## 审查发现与修复

| 提交 | 修复及验证范围 |
|---|---|
| `af96911` — `fix(review): integrate prepared backends with secure profile snapshots` | 当前运行收据从实际 Suite 复制 `secure/true/true`；只读校验兼容原始 `none/false/false` 快照，继续精确检查算法、数值参数、预算和编码 |
| `93c1d9f` — `fix(experiments): create private backups exclusively before copying` | 原备份先创建 0644 文件再改权限，有短暂暴露窗口及覆盖竞态。改为原子排他创建 0600 文件，已存在即拒绝，再分块复制并同步落盘；复现和测试只使用占位字节 |
| `ec2b09f` — `fix(srgg): keep prepared runtime separate from authenticated research` | 计划复用移入独立 `paper_runtime.py`，公共后端使用该适配；证据绑定的 `paper_backend.py`／`paper_samplef.py`保持原字节。保留每次独立熵预算、数值选项和原采样路径 |
| `9aee66e` — `fix(audit): require canonical optimization source bindings` | 拒绝包含 `..`、非规范拼写或越出安装根的出处路径；源码摘要必须是 64 位小写十六进制。原先五个可接受的无效输入现在全部拒绝 |
| `efa9c7b`／`0b67036` | 接收已审定 PR73 和远端 main，保留用户最新安全口径以及已知 Luo 矩阵小参数例外；最后一次合并没有源码差异 |

原优化代码另外核查了证书完整验证语句绑定、有界缓存、失败不缓存、消息签名逐次验证；SRGG 同一冻结密钥／相同选项的确定性准备复用；Luo NTT 整数结果一致性；接收会话的根和身份绑定、真实首次委派、原解密检查及关闭语义。接收会话保留秘密叶钥，成本不能写成原无状态 HIBE 的每次成本；清空 Python 引用不承诺物理清零。NTT 关闭控制仍使用同一源码的环构造，不能称为旧发行版全部准备成本消除。

## 实际验证

使用规定 WSL `~/miniconda3/envs/sage`，`PYTHONPATH=src:.`、`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`、`OMP_NUM_THREADS=1`、`OPENBLAS_NUM_THREADS=1`。Sage／原生测试没有使用 Windows Python 替代；Windows Python 仅执行 Git 源码绑定复核和不执行密码算法的 wheel 打包检查。各组有重叠，不合计为独立样本数。

以下选择均接在 `python -m pytest -q` 后：

| 选择 | 结果 |
|---|---|
| `tests/test_srgg_paper_plan_cache.py tests/test_srgg_paper_current_budget.py tests/test_srgg_paper_history_law_followup.py tests/test_srgg_paper_schur_finite_chain.py tests/test_srgg_paper_source_issuance_bridge.py tests/test_srgg_paper_assembly.py tests/test_backend_optimization_probe.py tests/test_backend_optimization_receipts.py tests/test_cert_certificate_cache.py tests/test_prepared_receiver.py` | 121 通过，0 跳过；含真实 Setup／Extract 后两轮 SampleF 与两条消息签名的输出及熵消费一致性 |
| `tests/test_backend_optimization_probe.py tests/test_backend_optimization_receipts.py` | 32 通过，0 跳过；含备份权限／排他性与五类出处输入拒绝 |
| `tests/test_project_admission.py tests/test_ci_catalog.py tests/test_backend_optimization_probe.py tests/test_backend_optimization_receipts.py` | 65 通过，0 跳过；包含最终安全配置与已知负控例外 |

最初集成运行 123 通过、6 失败，失败为安全字段更新后的探针与旧快照不兼容，已返工；出处测试在修复前实际出现 12 通过、5 失败。最终对应组已通过。历史来源绑定期间的失败没有通过修改旧收据解决。JUnit 见 [evidence](evidence/)，仅删除机器 hostname 属性，保留断言、时长与计数。

只读源码复核：

```text
python docs/deliveries/2026-10-20-pr75-review/verify_sources.py
git diff --exit-code 7caaff4 -- experiments/research/candidates/srgg/paper_backend.py experiments/research/candidates/srgg/paper_samplef.py
git diff --check
```

495 个安装清单 Python 文件全部与其声明提交 `b4b31d8f76654e108e4443e369e67729b2b6936b` 的 Git blob 一致。该检查读取公开源码，不读取私有状态，也不独立认证原生二进制；清单完整性和密码学重跑是不同结论。

源提交 `efa9c7bdcc51f819c491896661e96d2d32c34e84` 的 wheel 已离线构建，大小 2,066,528 B，SHA256 为 `dc0d76acaa904ff10862b45c5b6ffe1063fa62230a4a90c8ee3fcdc874859068`。四个关键包内源码逐字节匹配提交，没有发现私有状态文件。此为打包检查，不是这个新 wheel 的五组性能实跑。详细命令、文件与摘要见 [review.json](review.json)。

## 数据、参数与剩余工作

原 [A.json](../../research/2026-10-20-multi-backend-optimization/A.json)、wheel 摘要、源码清单和测量值不回写。该批 3 个独立 CSPRNG 根，各模式每根 3 次完整往返，身份各 64 B、消息 32 B；ML-DSA 原生验签调用由每次 2 次减为 1 次，仍每次验证消息签名。三根中位数之比为 0.992／1.086／1.339，中位比 1.086，不能据此宣称稳定翻倍。它属于原源码和原元数据快照，不冒称本次修复版的新实验。

新运行沿用已经完成的原配置：A 为 LATTE＋BNN/ML-DSA-44，B 为 LATTE＋SRGG PARAM-I compact，C 为 Lai C2＋Sageloli RSIS v3 PARAM-I；Luo／Falcon 为辅助对照。已完成配置按用户决定安全，当前为 `secure/true/true`；旧 A 记录保留 `none/false/false`。论文目标、ROM／QROM等模型分别引用原文，未增加 NIST 等级声明。Luo 矩阵的已知不安全小参数不在上述安全范围。功能和缓存一致性测试不能替代安全证明。

尚未完成：B／C／Luo／Falcon 四份完整公开数据、五组同环境复核、准备及保留状态／内存成本的最终表、最终发布版本复现。C 的单根会话摊销与另行需要的多根重复分别记账。全量 `verify_backend_optimization` 在五份记录齐全前不能返回全量通过，不从单元测试推断这些缺失结果。原负责人另机实验的运行状态未在本次审查中确认；不以本机没有进程断言其已停止。
