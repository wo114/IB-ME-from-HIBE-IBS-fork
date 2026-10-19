# Lai HIBE 完整研究后端发布整理

合入复核另见[参数边界修复与历史核验补记](INTEGRATION-REVIEW.md)；本文及原收据保留发布时的测试范围。

日期：2026-10-19。基线为上游 `b92967b92a94a4f8e18ae177ea299167b60aac67`，来源为本地主分支的 `8f3469d` 至 `b9688b6` 共 20 笔 Lai 提交。原工作树开工时没有未提交、未跟踪的非忽略文件；本批在独立分支整理已有提交，保留原分支现场。

## 交付范围

- [公共实现](../../../../src/ibme/hibe/lai/)、[P1 独立研究核](../../../../experiments/research/candidates/lai/backend.py)：两级委派、加解密、五类规范对象、严格恢复、公私参数绑定与生产 CSPRNG。
- registry、CLI、Sage CI、A 点默认 preset 与显式 C2 `target-research` preset；完整命令和限制见[契约](../../../specs/lai-hibe.md)。
- [目标参数筛选、估计结果与探针](../2026-10-18-lai-target-parameters/README.md)，以及[C2 冻结记录](../2026-10-18-lai-target-parameters/C2-FREEZE.md)。
- C2 密钥所需的 Hybrid 64 MiB component/key wire 上限；网络密文另按约 20 MiB 预解析上限检查。共享上限在 ABB 历史交付说明的一句话同步更新，无 ABB 算法改动。

本批修正 GSA/LGSA 元数据标签、过时的未实现状态和文档链接；错误身份驱动改用新建工作目录，拒绝已有目录，不再执行递归清理。冻结算法、参数、采样、随机源、对象编码和 Python 目标探针保持原内容。

完整差异路径见 [FILES.txt](FILES.txt)，20 笔来源与发布提交对应见 [source-lineage.json](source-lineage.json)，本轮源文件绑定见 [source-bindings.json](source-bindings.json)。本 PR 不包含未发布的 SRGG/DeepSeek 分支，也不包含任何运行私钥或 state。

## 本轮实际验证

在 WSL 的既有 `~/miniconda3/envs/sage` 中执行，Sage 10.9；精确环境和结果见 [validation.json](validation.json)。

```sh
PYTHONPATH=src:. OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
  ~/miniconda3/envs/sage/bin/python ci/run.py run lai-ideal-hibe \
  --output build/outputs/lai-publication-2026-10-19/primitive

PYTHONPATH=src:. OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
  ~/miniconda3/envs/sage/bin/python -m pytest -q \
  tests/test_hybrid_hibe.py tests/test_assembly.py tests/test_c_registration.py \
  tests/test_cli_selection.py tests/test_ci_catalog.py \
  tests/test_hybrid_key_binding.py tests/test_cli_receiver_state.py \
  --junitxml=build/outputs/lai-publication-2026-10-19/integration.xml

~/miniconda3/envs/sage/bin/python \
  docs/research/team-c-delivery/2026-10-19-lai-publication/verify_script_safety.py

python docs/research/team-c-delivery/2026-10-19-lai-publication/verify_delivery.py
```

| 检查 | 本轮结果 |
|---|---|
| Lai 四个专属测试文件 | 57 passed；112.33 s；0 failed/error/skipped |
| Hybrid、装配、登记、CLI、CI 目录与状态/绑定回归 | 210 passed；125.67 s；0 failed/error/skipped |
| shell 语法及工作目录保护 | 4 个控制流程场景通过；使用 fake CLI，未执行密码算法 |
| Windows 无 Sage 的登记/依赖拒绝 | 通过；发现后端与运行环境可用性分开 |
| 冻结算法与参数比对 | 与原分支 `b9688b6` 的冻结运行实现相同 |

两组 pytest 文件无重叠，共 267 项；shell 控制流程不计入密码算法测试。公开 JUnit 仅删除 hostname、规范换行；CI JSON 将本机解释器路径改为可移交写法，处理说明在 validation 中。原始收据保留于忽略的 `build/outputs/`。

## 参数与结论范围

- A 点：`n=256, q=2147484161, k=32, l=2, p=2, sigma=2, sigma_r=1`；默认研究配置。
- C2：`n=2048, q=274877976577, k=39, l=2, p=2, sigma=2, sigma_r=1`；显式 `target-research`，每层身份最多 86 B，消息/Hybrid seed 最多 32 B。
- 本轮没有重跑耗时的 C2 全生命周期、目标负测试或外部 estimator。保留的原 C2 运行和估计属于历史证据，不能计入本轮 267 项。历史目标原始 `/tmp` 回执未归档到公开包；公开内容为代码、原报告、估计 JSON 和冻结摘要。
- 采样仍为无 perturbation 的 Klein/GPV；二进制身份映射、委派类型解释和非单位标签失败见契约。原始 HIBE 的部分篡改会得到不同明文，外层 BYTEAUTH 提供该实现的完整性拒绝，不能声称原文 CCA 性质已由代码继承。
- PLWE 系数实例的 GSA 成本估计不是结构攻击评估或 NIST 等级。安全性与匿名性按现行 AGENTS 的论文引用/工作假设推进，本批不另补安全证明。
- 始终保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`；无 NIST category 声明。完整组合矩阵、残差统计、目标性能优化仍未完成。
