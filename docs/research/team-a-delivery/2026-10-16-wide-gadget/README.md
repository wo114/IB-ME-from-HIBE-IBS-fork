# A3：高位模数公共 gadget 工具与 A 任务复核

2026-10-16；承接[成员 A 任务书](../../../workplans/2026-10-12/A-矩阵HIBE任务.md)。本轮先完成 [PR34 固定 head 审查](../2026-10-16-pr34-review/README.md)，远端已提交 `CHANGES_REQUESTED`，不合并。随后核对 A 的实物与缺口，补全[已有四组目标参数公开证据](../2026-10-16-target-parameters/audit.json)，再完成本批公共采样工具。实现冻结提交 `f8ecb93`（以audit记录的完整SHA为准）。三条储备 GKR、ABB 标准模型、CHKP 标准模型继续暂缓。

## 1. A 的实际完成与剩余项

| 任务 | 已有可审查实物 | 仍未完成 |
|---|---|---|
| A0 同组参数与资源 | 原有三条矩阵 HIBE 高维筛查；最新完整 H/G 的 4 组目标与 32 次根/密文比较模型估算；本轮补齐全部公开收据和散列 | 没有同时满足困难性、实现域、有限误差和模型对应的可运行正式配置；n4096/q77 的单父 R JSON 下界仍约 209 GB |
| A1 CHKP/MP12 公开 HIBE | 原 CHKP、MP12 变体及完整 H/G 结构化变体分别命名；真实六方法、五类对象、固定钥/恢复、Hybrid/组合与负控已有记录 | 原 CHKP 与 MP12 变体的定理、模型、固定服务和完整误差条件继续分别核验，不能相互继承准入 |
| A2 ABB-ROM | AP09 根、真实两次 BasisDel、固定维对象/恢复、2×2 生命周期与公共组合已有实物 | 真实困难维度、规范化质量条件化与 RO/分布对应仍未闭合；n1 教学结果不外推高维 |
| A3 公共工具 | 真实有限 DGS/GPV/RandBasis/结构化 SampleD 与委派；本轮新增独立高位模数 binary gadget 工具，已有两个消费者 | 完整 HIBE 的大矩形 R、精确 Schur 运算、整调用预算和大对象/wire 域仍受限；后端实际采用并验收 192 位累计配方仍待 |
| 场景比较/材料 | 各批算法对应、参数与原始功能收据 | 满足相同安全目标的完整 IBME 基线/消融与最终代表选择尚未具备条件；工具采样不计为端到端性能收益 |
| AR 储备 | 原有储备说明 | 本轮不启动三条路线 |

新代码不改变上述正式准入结论。特别是 `PrimeGadgetSampler(rows=4096, q=q77, ...)` 可以准备一个 **77×77 的公共块**，不等于构造 4096 维 HIBE 根或采样数百 GB 的委派钥。

## 2. 新公共接口及两个消费者

入口为 [prime_gadget.py](../../../../src/ibme/lattice/matrix_sampling/prime_gadget.py)，独立版本 `IBME/PRIME-BINARY-GADGET/1`。支持 3≤q<2²⁵⁶ 的已证明奇素数、1≤rows≤16384，输出坐标数≤2²⁰。q 始终为任意精度整数；不通过 uint64。它复用已有有限 GPV，不新增一种陷门、原语算法或困难假设。

```python
from ibme.lattice.matrix_sampling.prime_gadget import (
    prime_gadget_kernel, PrimeGadgetSampler,
)

# width_squared 与 epsilon_bits 须满足现有 GPV smoothing 门；
# options 显式选择有限精度、尾部、拒绝与整调用预算。
sampler = PrimeGadgetSampler(rows, q, width_squared,
                            epsilon_bits=192, options=finite_options)
values = sampler.sample(canonical_syndrome, rng=source)
certificate = sampler.public_certificate()
```

`prime_gadget_kernel(q)` 只构造 k=ceil(log₂q) 阶公共整数核格基，前 k−1 列为 `2e_i−e_(i+1)`，末列为 q 的二进制位；现有 `KernelBasis` 实际核对同余和 `|det B|=q`，不是只有子格包含关系。该同一基构造已用于前批分析，本轮将它移到有界公共入口。数学依据沿用固定 [MP12 作者稿](../../../../papers/2011_lattice_trapdoors_micciancio.pdf)的 binary gadget 与 [GPV 作者稿](../../../../papers/2008_gpv_trapdoors_full.pdf) §4.2 的陪集采样；没有新增安全定理。

`PrimeGadgetSampler` 逐行使用同一个公开 k 阶几何计划，完整采样所有 rows·k 个坐标，检查每行 gadget 方程。输出为 row-major binary blocks；不得与 Sageloli 的 digit-major 三进制布局混用。只展开 k² 项公共核格基，不展开 (rows·k)² 的乘积基。整个输出的随机带预算为 rows×单块预算，TV 上界为 min(1, rows×单块上界)，包含底层有限中止。非法 syndrome、非规范模值、过长生成器、输出维度和整调用预算均在读随机字节前拒绝；中止不重抽、不补零。宽度使用 `exp(-pi*x²/s²)` 的 s²，而不是统计方差。不是常数时间实现。

现有 `mp12_structured.gadget_block` 和 `structured_target_screen.analysis_gadget` 都调用同一个公共核格构造，消除原来的两份代码。前者仍先执行其原有 **61 位 q 门**；当前 HIBE 参数、身份 oracle、uint64 wire、委派尺寸和默认有限配方均不升级。新的公共工具是可执行 A3 子组件，未把目标投影登记为可运行 HIBE。

## 3. 本轮实际验证

硬件 Intel Core Ultra 9 275HX；Windows 宿主/WSL Linux 6.18.33.2，规定环境 `~/miniconda3/envs/sage`，Sage 10.9 / Python 3.13.14。新工具没有身份或消息参数，只采样公开 syndrome，不生成 HIBE/IBS 钥。完整专项仍实际重跑既有教学 fixture，包含临时测试根/父/叶：H/G 后端主 fixture 为 n2/q549755813911、两层身份各86 B、32 B seed，数学测试另有源码列明的小域。这些不登记为新的真实研究实例，也不重发原服务钥。固定随机流与默认系统随机源分开执行；有限 TV 口径仍以理想独立均匀随机字节为模型，不将系统随机源测试当作其证明。

| 验证 | 实际结果 |
|---|---|
| 新工具及原结构化采样/目标定向回归 | **62 passed / 0 skipped**，12.05 秒；其中新工具 28 项，计数与下行重叠 |
| 完整结构化专项加新工具 | **153 passed / 0 skipped**，75.43 秒；[JUnit](evidence/regression.xml) |
| CI 目录与专项登记 | **25 passed / 0 skipped**；[JUnit](evidence/ci-catalog.xml) |
| 高位模数实际采样 | q77 的 3 行产品陪集使用固定测试熵与系统熵；256 位素数边界实际 GPV 采样；只核方程/条件，不输出样本 |
| 仓库外 `python -I` 安装验证 | **passed**；单一安装根的 33 个项目 provider；3 个公开采样 case，以及全部 4 组目标参数/账本与旧结果逐字定义摘要一致；[收据](evidence/installed-final.json) |

可重放完整命令：

```sh
PYTHONPATH=src:. PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  ~/miniconda3/envs/sage/bin/python ci/run.py run a-structured-hg \
  --output test-results/my-wide-gadget-check
```

`ci/suites.json` 只为把新测试加入 A 专项而跨到共用测试清单，未修改协议、注册器、CLI、其它原语或安全目标。实际 153 项回归执行相同十个测试文件的显式 pytest 命令，精确文件/命令及源码散列见 [audit.json](audit.json)。

wheel 由 Windows Python 离线构建，随后仅安装到新的临时目标目录，没有改用户 Sage 环境。首次直接在 Sage 环境无隔离构建因缺少 `setuptools.build_meta` 失败；离线改用已有 Windows 构建依赖后成功，未下载或更换密码依赖。安装 probe 用仓库外 cwd 与 `-I` 执行[独立脚本](../../../../tests/install_probes/verify_prime_gadget.py)，未使用仓库源码兜底。没有重跑原 32 次 Estimator，也没有读取私有状态。

## 4. 实现域的结论与限制

本批实际补齐 **公共 gadget 的高位 q 数值域和可安装采样接口**。完整高维 HIBE 尚需不同层面的工作：大 R 的表示/实际采样与分布、精确算术和全树持久状态预算、版本化大模数/对象编码、后端实际接入新累计配方、两类 LWE 与完整定理/服务映射。不能通过删资源门、只改头部整数类型或从种子重放秘密扰动就宣布这些问题解决。

新高位工具和隔离安装 probe 不生成 HIBE 根/接收者/叶；原教学回归的临时钥与原服务实例分开记账。本批不主张完整协议提速，保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。实际工作涉及 ROM 后端的公共子组件；此处的采样器自身不调用随机预言机。公开方程、测试与比较模型不能替代安全证明。A 整体仍为 **WIP**，首个正式安全配置与完整可运行域是当前阻塞；三条暂缓路线没有启动。
