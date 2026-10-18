# SRGG 参数闭合续审（WIP，2026-10-17—18）

本批继续推进独立 IBS 的参数核验。原论文 Table 4 的三行、旧实验和优化候选均保留；不改 HIBE、共享接口、CLI、注册表或组合。**本批修复数值实现、收紧局部误差界，尚未得到正式安全参数。**

## 1. 已修复：区间端点被近似成“零宽”

Sage 10.9 的 `QQ(RealNumber)` 会寻找短有理近似，不能用于保存有向区间端点。独立探针发现，π、平方根和 `1/sqrt(2π)` 的上下端可能同时向内移动、甚至变成同一个有理数，导致错误的零宽误差。修复为先调用 `endpoint.exact_rational()`，覆盖：

- `paper_parameters.py` 的 π 区间；
- `paper_samplef.py` 的 Fourier/Gershgorin 上界、平方根、白化缩放及尺度误差；
- `structured_samplef.py` 的尺度区间；
- `sampling_error.py` 的平滑误差上端。

新增测试用独立 1024/1536 位区间检查低精度实现的包含关系，并要求相关尺度误差非零。底层 scalar Gaussian 使用的 `interval_bounds` 原已正确保存二进制端点，本批没有改其分布。

Table 4 十进制输入不变；标准差解释下采用的 `2π` 有理中点因修复而有极小变化。参数记录/对象格式未变，但**旧快照或同格式记录不能证明新实现的生成分布**。逐比特复现旧实现须固定旧 Git 版本；不能直接将旧有限误差搬到修复后的运行。旧收据作为历史保留，不覆盖为“修复后通过”。

`service_budget.py` 默认仍核验当前源码是否与冻结证据一致，本轮修复后会明确拒绝旧证据。新增 `--historical-only` 只对原 MANIFEST 哈希和字节数一致的旧公开收据做条件预算算术；报告将旧数值界标为未经重验、当前实现未验证。该模式不修补或替换旧哈希，也不恢复旧预算的有效 TV 声明。

## 2. 已收紧：固定 r 的全中心归一化界

[`paper_rounding_budget.py`](../../../../experiments/research/candidates/srgg/paper_rounding_budget.py) 使用严格有向指数区间，避免先向下取整 shape 的粗界。设 `C ≥ λI`、`a ≥ exp(-πλ)`，则

```text
t = 2a/(1-a³)
x = D·t < 1
sup_c |ρ_(C,c)(Z^D)/sqrt(det C) - 1| ≤ x/(1-x)
```

推导来自 Poisson 求和、`k² ≥ 1+3(k-1)` 和二项式/几何级数界，适用于所有中心。保留原实现的保守 rounding TV 比较 `min(1,8ε)` 及其 `ε≤1/2` 前提。

按“表中宽度为物理标准差”解释、仍用原 `r=1.16`，当前精确实现 shape 下得到：

| 原参数 | 阶段/维度 | 中心归一化相对误差上界（约） | 局部 rounding TV 上界（约） |
|---|---|---:|---:|
| PARAM-I | master/4096 | 2.38814e-8 | 1.91052e-7 |
| PARAM-I | signature/4608 | 2.68666e-8 | 2.14933e-7 |
| PARAM-II | master/6144 | 3.58221e-8 | 2.86577e-7 |
| PARAM-II | signature/6656 | 3.88073e-8 | 3.10459e-7 |
| PARAM-III | master/8192 | 4.77628e-8 | 3.82103e-7 |
| PARAM-III | signature/8704 | 5.07480e-8 | 4.05984e-7 |

六个局部归一化界均小于 `2^-24`，比旧 rounding TV 上界收紧约 100—160 倍。表格是便于阅读的数值摘要，严格有理上界见 [`rounding-budget.json`](rounding-budget.json)。

**局部维度通过不能替代论文选 r 时使用的更大维度。** 对 `m=(2+w)(d+1)n=10240`，同一实际精确 shape 的最短对偶向量质量下界已严格大于来源 `ε=2^-24`。这把先前的浮点诊断推进为该精确实现 shape 的必要条件失败证书；没有更改原文约到两位小数的 r，也没有确认作者的归一化解释。字面 density-width 分支的充分证书仍不通过。

JSON 明确分开历史 shape 和修复后 shape；历史数值误差标为 `unvalidated_due_to_endpoint_conversion_bug`，有效总 TV 留空。这个局部引理不识别 HNF 密钥分布或最终签名分布，也不建立高查询总误差预算。

## 3. 已量化：理想目标范数与 64 次重试

[`paper_norm_budget.py`](../../../../experiments/research/candidates/srgg/paper_norm_budget.py) 对**中心、整数格、对角** Gaussian 给出两段宽度的 MGF/Chernoff 界。Poisson 对偶 theta 随 shape 增大而减小，因此

```text
E exp(t||Z||²) ≤ ∏j (1-t λj/π)^(-Dj/2)
P[||Z||≥γ] ≤ exp(-tγ²) ∏j (1-t λj/π)^(-Dj/2)
D1=2dn, D2=(wd+1)n, 0<t<π/max λj
```

对物理标准差解释的理想目标，单次上界约为 `2^-1.535`、`2^-2.259`、`2^-2.968`；若每次尝试都条件于该法则，64 次耗尽上界约为 `2^-98.269`、`2^-144.574`、`2^-189.934`。这**不是实测拒绝率或安全位数**。

64 次幂界只约束范数重试耗尽，不是完整 Sign 操作的中止率；实现中的采样、数值或运行时异常可立即退出，须另作预算。

精确数值及两种宽度解释见 [`norm-budget.json`](norm-budget.json)。真实预算默认 `null`：仍缺对所有发钥结果、每次历史统一成立的真实 response-or-abort 法则桥。若显式输入这样的 TV 前提 δ，只能条件性使用 `(tail+δ)^64`。该桥还必须覆盖后端有理 midpoint 与理想 `2πs²` 的差异，以及 ζ factor 问题。

## 4. 已执行：同一 PARAM-III 根上的 160/192 位比较

[`paper_precision_audit.py`](../../../../experiments/research/candidates/srgg/paper_precision_audit.py) 只提高本次数值平方根级数截断精度，不修改 σ、r、γ、陷门支持或默认后端。固定原 `paper_audit` 的测试种子，根只生成一次、Alice 只发钥一次；两个精度使用**同一 witness 和同一用户密钥**，准备计划不消费熵。结果见 [`precision.json`](precision.json)，108.13 秒完成，原 γ 下签名用了两次尝试并验签成功。

修复端点后，160 位的 PARAM-III 签名计划仍只能导出公共数值误差粗界 `1`；192 位降至 `2^-96`。后者真实采样、按原 γ 重试并诚实验签成功。这里改善的是局部数值证书；rounding、卷积/HNF、签名法则和安全归约另计。默认160及旧证据保留，192为显式实验配置。

实验使用 n=512/d=4/b=31/w=2/p=16383/Q=15744063，身份5 B、消息32 B、固定测试随机数、一根一身份一次签名操作，ROM哈希接口。环境为指定 WSL Sage10.9/Python3.13.15、Intel Core Ultra7 255HX；不是作者 C/gcc 环境或性能复现，不是 NIST 等级。完整软件环境、次数、实际重试和耗时随 precision 收据记录；没有导出密钥、私有谱诊断或样本。

## 5. 来源与资源续审

[`completion.json`](completion.json) 另做标准库可复核的汇总：

- Table 1 摘要与 Table 4 参数/尺寸分别保留；两张表 MPK/签名尺寸不同，未推断差异原因。
- Theorem 1 的 `s1` 按 Section 3.1 响应椭圆映射到签名 `σ̄1`，避免误用主密钥 `σ1`。三行 `σ̄1·1.16` 分别为 977982.312、1214188.472、1436156.560；字面乘积和使用 `2π<44/7` 的双宽度转换上界都小于 Q。此条件算术不消除 `q/Q/2Q` 等来源对应缺口。
- n512/w8 与 n2048/w22 的公开谱界明确使用各自 digits；mod3 单列完整环界为406/2430 bit，共享16/66列后的界为402/2424 bit。这些是统计投影界，不是攻击成本。
- 硬度对照与 n512 实测收据分别绑定旧清单哈希。n2048 只是静态候选，当前 degree、digits、维度限制不通过；没有新增 n2048 密钥或实验。部分静态检查不冒充完整资源预检。

## 6. 未闭合与复核

本批仍为 **WIP**：q/Q/2Q、ζ factor、r 的源解释；完整有限 SampleF→HNF/签名法则及成功条件化；Ring-HNF/MSIS、完整 CRT/子域结构攻击；native-strong ROM/QROM 和外部服务故障模型均未闭合。历史 PARAM-II/III 同消息替换反例保留。所有产物均保持 `security_claim=none`、`parameters_are_formal=false`、`backend_admitted=false`、`nist_security_category=null`。

在仓库根目录，以 `PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python` 为 Python 执行以下模块；标准库汇总也可用 Windows Python：

```text
python -m experiments.research.candidates.srgg.parameter_completion --output <fresh>/completion.json
python -m experiments.research.candidates.srgg.paper_rounding_budget --output <fresh>/rounding-budget.json
python -m experiments.research.candidates.srgg.paper_norm_budget --output <fresh>/norm-budget.json
python -m experiments.research.candidates.srgg.paper_precision_audit --profile PARAM-III --output <fresh>/precision.json
python -m ci.run run srgg2025 --output <fresh>/ci
```

精确测试命令、结果、源码/产物哈希见同目录 `validation.json`、`MANIFEST.json`。有限功能测试与条件性引理不替代完整安全证明。

最终指定 WSL Sage 全量 `python -m ci.run run srgg2025`：**1520 passed，0 failed/error/skipped，322.14 秒**。此前开发回归的 1494 passed、1 failed、15 errors 均由旧源码 guard 拒绝产生，原收据保留在 `ci-initial-failed.json`；修复历史算术测试的模式后仍测试默认拒绝，未放松当前证据门。定向测试与全量存在重叠，不相加。CI 原始收据中的 WSL Git revision 为 unavailable，`validation.json` 另列 Windows 核验的父提交与当前源码哈希；该收据不虚构待提交版本号。

暂存检查后仅删除 `test_srgg_parameter_completion.py` 末尾一个多余空行，运行代码未变；该文件当前 4 项定向复核通过。`validation.json` 保留全量运行时测试文件的旧哈希、当前哈希及精确单字节差异，不将此格式修正伪装为另一次全量回归。
