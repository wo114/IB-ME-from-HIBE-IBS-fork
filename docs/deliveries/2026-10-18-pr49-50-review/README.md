# PR49／50 ABB 公开筛选工具审查

本轮在 PR43／46／47／48 已接收的 `c7ecccca8e4a0570f581b101786bda53593edd89` 上，继续审查新开的两项 ABB 研究交付。按用户授权修复可验证的工程问题后尝试合并；不增加基础证明任务或算法数量。机器记录见 [validation.json](validation.json)。

## PR49：异常估计必须拒绝

原 head 为 `fcc79e4de670102c6ac39df01c7f231ff8d0468b`。独立复核确认严格整数边界公式、有限 CDF、四项原源码指纹及原卡的四组有限估计值均正确。

发现的 P2 是 `finalize_comparison` 只检查状态和数值类型，没有检查有限性。四项 `+inf` 或部分位置的 `NaN` 会错误进入数值候选；资源门仍会拒绝运行，安全声明没有升级。另外，同一报告先通过后改成未知输入再次处理时，两项候选摘要会残留旧 ID。

修复精确检查 `int/float`，拒绝布尔值、浮点转换溢出及所有非有限值，并在每次处理时重置摘要。新增 4 模型位置 × 5 类无效数值的 20 个回归，均先观察到原实现失败；每例还验证有效估计先通过、随后能够撤销候选。

在仓库规定 WSL conda Sage 10.7／Python 3.12.13 运行：

```sh
source ~/miniconda3/etc/profile.d/conda.sh
conda activate sage
PYTHONPATH=.:src:.pytest-tmp-sage-deps PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest tests/test_abb_noise_tradeoff.py -k invalid_numeric -q
PYTHONPATH=.:src:.pytest-tmp-sage-deps PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest tests/test_abb_noise_tradeoff.py tests/test_matrix_hibe_scaled_screen.py -q
PYTHONPATH=.:src:.pytest-tmp-sage-deps PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest tests/test_abb_*.py tests/test_matrix_hibe_scaled_screen.py tests/test_ci_catalog.py -q -rs
```

结果依次为修复前 **20 failed**，修复后定向 **47 passed**，完整相关回归 **198 passed、29 skipped、0 failed**（62.70 秒）。29 项原有跳过要求显式 native／Flatter 或已完成的私有见证，不记为通过。首次完整回归因缺少 `cryptography` 出现 3 项收集错误；在被忽略的临时依赖目录补齐项目兼容的 50.0.2 后，完整重跑得到上述结果。各轮原始 JUnit 均保留在 [evidence](evidence/)。

PR49 接收时的原 `parameter-card.json`（SHA-256 `a605b03942f611c149467960be440d424e25424f6559909bda68f8ba7558f6cb`）及 `runtime-summary.json`（`9756e02d3a18913f859963716c41f870069a3d1abf55b673b0c44e229d0c21a3`）已逐字节冻结为 `evidence/noise-*-original-v1.json`，保持原源码版本关系。[当时的重放](evidence/noise-reviewed.json)由以下命令在固定 `d89b65b` checkout 生成；该历史脚本对应 schema 1，不用于后来的 schema 3：

```sh
PYTHONPATH=.:src:.pytest-tmp-sage-deps python docs/deliveries/2026-10-18-pr49-50-review/evidence/replay_noise.py --output <new-output.json>
```

重算全部四行几何与有限 CDF，**复用原卡的估计器结果及其计时，没有重跑估计器**。除环境、当前源码指纹和运行时间外，完整数学 payload 与原卡一致；包括 CDF SHA-256 `62d12dbf8d50678755d08254332505d5a83aaac1e472e9f7c227d7fbf61e314e`、全部公式、估计内容与门结论。当前源码散列另行绑定。PR49 当时的单侧门为 3 个密文数值候选、0 个可运行目标配置；后续双侧门结果见下段；没有生成根、基、密钥或密文。

## PR50：版本 3 接收

原 head `69d3700` 的行参数绑定已补 8 个先失败后通过的回归，与相关测试共 87 passed。中断期间远端更新至 `e88cbdd7f503ed4f17156e4a223f46912e642935`，现已保留其根 SIS／密文 LWE 分离比较与显式实现研究层级，追加精确整数的行参数绑定。根侧未知不会升级为正式比较通过；三个实现研究候选仍被完整基资源门拒绝，完整运行候选为零。

原版报告完整字节归档为 `*-before-review.json`，更新后的远端版本归档为 `*-remote-e88cbdd.json`；原路径为当前探针真实重跑输出。逐字段比较确认，除环境、测量及当前源码指纹外，四行资源和候选分类与更新后的远端报告完全一致。所有当前源码／论文散列与输入卡散列吻合。

2026-10-19 在规定 Sage 环境重跑全部 `tests/test_abb_*.py`、`tests/test_matrix_hibe_scaled_screen.py` 和 `tests/test_ci_catalog.py`：**234 passed、29 skipped、0 failed**，63.22 秒；原回执为 [pr50-v3-regression.junit.xml](evidence/pr50-v3-regression.junit.xml)。跳过条件与前批一致，没有把它们记为通过。该接续审查与复验由主智能体独立执行，按用户要求未再调用子智能体。

所有材料保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。源码访问下界与数值估计不代表真实大参数运行或安全等级。
