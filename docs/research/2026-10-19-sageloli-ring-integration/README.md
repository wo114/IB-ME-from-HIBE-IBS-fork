# Sageloli RSIS v3 公共接入与真实 LATTE 完整组合

审查补充：远端 plain-Python 发现契约暴露了父包会提前导入 v2 sampler 的问题。父包已改为惰性公开导出，旧五方法、服务与类型 API 保留；同一远端冷进程用例在 Windows 实际复现通过，77 项相关 Sage 回归无失败/跳过。原始 CLI 和安装收据仍绑定当时源码，新增父包原字节快照，不重写旧数据；当前只读复核为696项。下文694项/191项是原交付批次记录，不累加为本轮独立实验。

2026-10-19，统筹接入交付。原始基线 `798226a` 已包含 PR58/59；实现冻结提交为 `28e5bee9adc095bb68439d3c3b1f743aea4c3e58`。本批复用 PR59 的环原生采样、两档 Appendix E 参数和 v3 编码，不再接收已关闭 PR57 的 v2 小参数登记。

## 已实现内容

- 默认 `sageloli-rsis` 选择器指向 `Sageloli-RSIS-structured-v3`，提供 `PARAM-I`、`PARAM-II` 与明确标为不安全的 `debug-small`；完整数字参数进入 Suite。
- 共同五方法、身份摘要薄包装、固定身份缓存和完整对象恢复已接入。私钥的规范字节不变；恢复校验根和每个用户陷门列的精确关系，并禁止新熵。
- CLI 增加通用 `--hybrid-limits` JSON／文件入口。显式 8 MiB 载荷预算适配 3,227,824／7,553,200 B 签名；不改变默认 64 KiB 或框架硬上限。
- 缺 Sage／显式原生库、v2 状态、错误版本／完整参数、错误陷门、不可容纳的满用户账本及不支持的签名格式均拒绝。
- wheel 包含原生 `native.cpp`，可从安装目录显式构建并独立恢复原状态。

参数、依赖和边界详见[公共接入契约](../../specs/sageloli-ring-ibs.md)；原有两档独立 IBS 的真实数据仍引用[PR59 交付](../team-b-delivery/2026-10-19-sageloli-ring-target/README.md)，不与本批完整组合混计。

## 实测和验证

验收配置为 **LATTE-3 seed32＋Sageloli RSIS v3 PARAM-I＋Hybrid＋BYTEAUTH**。身份各 64 B、应用消息 32 B，另外检查空消息；原始 v3 身份／签名输入限额为 256／4096 B，完整协议的应用消息上限为 3924 B。两档论文预设的标称强度不同，不作等安全性能排名。

论文规模测试使用一个新的系统 CSPRNG 根，不外循环重试。各 CLI 命令均为新解释器；同根组合矩阵复用该原始根与已发用户钥，后续负例与额外签名使用明确标识的固定测试流，不计为另一个全新根。失败、中止和新状态路径保留在本机私有目录。

实际结果：

| 检查 | 本批结果 |
|---|---|
| 新根完整 CLI | **15 步通过**，含固定发钥、完整加解密、三种身份错配和四种 wire 修改 |
| 原状态新进程恢复 | 通过，**0 次／0 B 新熵**；显式禁止 v3 Setup／Extract／Sign 和 LATTE 密钥生成 |
| 同根完整组合矩阵 | **34 项通过**，含内层签名修改、随机签名、重用签名绑定新消息、实际到达 IBS 的拒绝、对象恢复和空消息 |
| 仓库外最终 wheel 恢复 | 通过，159 个已加载项目 provider 全部来自隔离安装目录，原状态不变，新熵 0 |
| 同步最新 main 后回归 | **191 passed，0 failed，0 skipped**；另有冻结实现的早一批 148 项，不累加 |
| Windows 发现／容量 | 8 项标准库驱动检查通过；该 Windows 运行时未装 pytest，未声称执行 Windows pytest |
| 公开证据复核 | 694 项通过；无私有状态读取，无密码实验重跑 |

硬件为本机 Intel Core Ultra 9 275HX，WSL2、Sage10.9／Python3.13.14、NumPy2.5.1，OMP/OpenBLAS 各 4 线程；完整环境在收据中。单个 CSPRNG 根不足以估计失败率或给出公平性能排名，运行期间未隔离其它研究任务。

| 单次 CLI 处理阶段 | 秒 |
|---|---:|
| Setup | 6.299 |
| 发送者完整发钥 | 67.799 |
| 第一接收者发钥 | 39.250 |
| 首次完整加密 | 21.901 |
| 首次完整解密 | 3.686 |

这些计时从新进程中的 `CLI main` 开始，包含状态加载／校验和原生调用，不含 Python 启动及前置导入；不混称热路径吞吐。全部 CLI 加同根矩阵约 409.645 s，其中矩阵约 139.833 s。现有公共校验会重复读取较大私钥，仍有工程优化空间，本批未改变其校验语义。

完整密文 **3,363,679 B**，签名 **3,227,824 B**；CLI 公钥／主状态／发送者状态分别为 **3,527,590／156,740,482／144,089,767 B**。两个接收者状态为 160,225／160,120 B，含各自缓存。不同封装对象不相加声称去重存储。各 CLI Python 主进程峰值 RSS 的最大值为 **1,609,404,416 B（约1.50 GiB）**；该指标不包括并发原生子进程的 RSS，不是整个进程树的总峰值。

原始公开[完整流程收据](evidence/integration.json)、[安装恢复](evidence/installed-restore.json)、[安装包与 provider 核对](evidence/installation.json)、[最终回归](evidence/regression.xml)和[Windows 检查](evidence/windows-portable.json)由 [manifest.json](manifest.json) 固定。只读复核运行 `python docs/research/2026-10-19-sageloli-ring-integration/verify.py`，不读取私有状态、不重跑密码实验。

执行期间，队友合入 Lai 与公共 Hybrid 对象容量调整。本分支合并最新 main `941feec`，集成提交 `b46f015`；原 15 步 CLI／34 项矩阵继续绑定 `28e5bee`，不改写历史输入。受上游合并影响的两份共享源码按原字节保留于 `evidence/source-at-execution/`；其余原语和新适配器不变。最终 191 项回归和仓库外 wheel 恢复在集成树执行。两个版本与 154 个现有源码文件的指纹分别核对，不能把历史记录改称在新树重建过根。

最终回归命令（规定 WSL 环境，另设置真实 LATTE 执行路径）：

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=src:. OPENBLAS_NUM_THREADS=4 OMP_NUM_THREADS=4 ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_sageloli_ring_registration.py tests/sageloli_native/test_ring_assembly.py tests/test_assembly.py tests/test_combination_matrix.py tests/test_cli_selection.py tests/test_cli_state_lock.py tests/test_srgg_paper_registration.py tests/test_ci_catalog.py tests/test_hybrid_hibe.py
```

wheel 通过 `python -m pip wheel --no-deps --no-build-isolation --no-index .` 构建；Sage 使用 `pip install --no-index --no-deps --target <新的隔离目录> <wheel>` 安装，从 `/tmp` 运行本批探针的 `--restore-only`，`PYTHONPATH` 仅指定安装目录。wheel 内所有已用源码及 `native.cpp` 与交付树逐字核对；编译库的 source ID 与原算法源码一致。8 项 Windows 检查只读取公开描述符、完整参数和预检容量，并把 `SecureRandom.read` 改为一旦调用即失败，未生成密钥。

早期一次单元测试读错 CLI 输出键 `report`，修正为既有 `compatibility` 后全过；一次回归命令列了不存在的文件而未收集测试，已更正。两者不计成功用例，最终无遗留失败。最终回归和公开校验数据可独立复核。

## 使用方式

在规定 WSL Sage 环境，显式构建原生库（安装版也包含此源码）：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.sageloli.ring.native --directory ~/.cache/ibme-native-tools/sageloli-ring-v3
```

将构建返回的 `path` 设置为 `IBME_SAGELOLI_RING_NATIVE`；LATTE 仍按[原使用说明](../../specs/latte-hibe.md)设置 `IBME_LATTE3_EXECUTABLE`。Suite JSON 不能指定执行路径或导入代码。

```bash
export PYTHONPATH=src:.
~/miniconda3/envs/sage/bin/python -m ibme.cli check --hibe latte --hibe-params seed32 --ibs sageloli-rsis --ibs-params PARAM-I --transport hybrid --hybrid-limits docs/research/2026-10-19-sageloli-ring-integration/hybrid-limits.json --json
~/miniconda3/envs/sage/bin/python -m ibme.cli setup --state /新的私有状态目录 --hibe latte --hibe-params seed32 --ibs sageloli-rsis --ibs-params PARAM-I --transport hybrid --hybrid-limits docs/research/2026-10-19-sageloli-ring-integration/hybrid-limits.json
```

后续发发送者／接收者密钥、加密、解密沿用现有 CLI 命令，预算和唯一后端由状态读取。`PARAM-II` 已提供静态 Suite 和签名容量，但本批没有运行第二档完整组合。

重放同一套研究验收时，使用全新的私有目录和实际源码 SHA：

```bash
PYTHONPATH=src:. OPENBLAS_NUM_THREADS=4 OMP_NUM_THREADS=4 ~/miniconda3/envs/sage/bin/python -m experiments.research.sageloli_ring_integration --profile PARAM-I --source-commit 实际源码SHA --private-directory 新的私有目录
```

完整矩阵的显式选参文件为 [suites.json](suites.json)。`--plan` 只做静态预检；真实执行必须显式选择 `--suite-name latte-sageloli-rsis-v3-PARAM-I-byteauth`，不要把文件中未执行的第二档计入结果。

## 声明与未实现范围

本批是工程接入与一个论文规模完整组合的验收，沿用项目对论文安全性和 HIBE 匿名性的工作前提，不新增基础证明任务。采样器的有限浮点／FFT 总误差和原文模型边界保留；不以功能通过认证安全等级。全部安全字段继续 `none/false/false`。

未完成第二档完整组合、同口径多根性能比较、Web 新预设或新压缩格式；它们不影响第一档公共接入的验收。原 v2 SIS/RSIS 状态不迁移，矩阵 SIS 不由本批完成目标参数。私有状态是原有本地明文机制，无新增认证存储、防回滚或侧信道声明。
