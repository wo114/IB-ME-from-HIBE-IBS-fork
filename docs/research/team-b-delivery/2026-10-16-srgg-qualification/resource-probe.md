# SRGG 当前 sampler 的公开夹具资源实测

日期：2026-10-16。执行对象：当前真实 `prepare_f` / `prepare_p`，
代码入口 `experiments/research/candidates/srgg/resource_probe.py`。
本轮没有改动生产维度、平方宽度、精度、rational reserve 或任何采样语义。

**结果只说明公开 SPD 夹具的 sampler 工程行为，不是实际 IBS 性能，
也不表明大参数 SRGG 已可执行。** 未产生用户密钥或签名；没有 HIBE 依赖。

## 配置与证据

指定环境：WSL Ubuntu-24.04，`~/miniconda3/envs/sage`，Sage 10.9，
conda-forge Python 3.13.15，CPU Intel Core Ultra 7 255HX。
完整平台、解释器和源码 SHA-256 在 JSON 中。机器未固定 CPU 频率、亲和性或后台负载。

28 个配置每个在新子进程运行，含 Sage 导入的每例超时为 20 s；
prepare 成功后运行 2 次 draw。叶维度包含 2/4/8/16/32/64/128，
常规总维度不超过 128，另有 dimension=129 的拒绝边界探针。
形状是 `(r²+60)I` 或 `(r²+60)I+vv^T`，其中 `v_i=(-1)^i`；
所以即使平方宽度越界探针，其 residual 也至少为 `60I`，
不会把不正定形状误认作 scalar-width gate 证据。
中心是公开的 0 或 1/3。常规 `r²=4`，选项使用当前 `FullSamplingOptions` 默认值：
precision=192、ticket=128、tail=24、mass=64、rational_bits=8192、dense dimension=128。
只在一个专门拒绝探针中把 rational_bits 设为 2048，没有放宽任何上限。

字节源为独立的 `DeterministicRandom`，seed 由固定测试前缀和 case 名组成，
完整公开在 JSON；仅用于重放本夹具，不用于生产随机性。
没有消息或身份输入，因而不存在本实验的消息/身份长度指标。

本地证据均在 `build/outputs/srgg-admission-2026-10-16/`：

- `resource-probe.json`：完整配置、每例 prepare 与每次 draw 时间、熵及 RSS。
- `resource-probe.stdout.json`：完整 stdout 留存。
- `resource-probe.stderr.log`：每例状态流。
- `resource-probe-tests.junit.xml`：指定 Sage 测试结果。

这些 build 文件为本机输出；移交时需随交付材料打包，不能假定 Git 会包含被忽略目录。
可以用下方命令重新生成。

## 实测行为

网格共 **17 个配置成功、11 个配置预检拒绝**；成功配置共执行 **34 次 draw**，
没有观测到 draw abort、worker error 或 20 s timeout。
所有预检拒绝配置对注入的字节源均读取 0 字节。
代码分别记录导入、夹具构造、prepare、draw、预检拒绝；
不会把拒绝探针缺失的 draw 当成耗时为零的成功样本。

- SampleF 的对角及 rank-one 夹具叶维度最大成功点均为 32；64、128 在 prepare 时拒绝。
- SampleP 的总维度 128、叶维度 32 的 rank-one 夹具成功；
  同总维度下叶维度 64 和 128 在 prepare 时拒绝。
- 129 维 probe 被现有 dense dimension gate 拒绝。
- `r²=10^12+1` 的正定 residual 夹具被现有 scalar squared-width gate 拒绝。
- leaf=8、rational_bits=2048 的 probe 被 rational reserve gate 拒绝。

完整数字以 JSON 为准；只运行每个配置一次 prepare 和两次 draw，
没有将这批少量观测计算成稳态性能、吞吐排名或概率置信证书。

| 公开配置 | prepare 秒 | 两次 draw 秒 | final ru_maxrss KiB | 每次证书熵预算 B | 两次实际熵 B |
|---|---:|---|---:|---:|---|
| F diagonal 32 | 0.01368 | 0.00404 / 0.00307 | 212,584 | 196,352 | 2,062 / 2,258 |
| F rank-one 32 | 0.01792 | 0.00575 / 0.00385 | 212,412 | 196,352 | 1,764 / 2,003 |
| P rank-one total128 / leaf32 | 0.24580 | 0.02929 / 0.01967 | 226,104 | 785,408 | 8,935 / 7,544 |

上述三个配置均为公开 sampler 夹具；数字不是 Extract/Sign 时间。

## rational reserve 是独立扩维门

`_SampleFPlan` 的当前资源公式是：

```text
reserve = factor_denominator_bits + 2*ticket_bits
          + (leaf_dimension+2)*precision_bits + 32
mean_bits = rational_bits - reserve
require mean_bits >= 16.
```

在默认 192/128/8192 下，单是 leaf=64 的
`(64+2)*192+2*128+32=12960` 就已超过 8192，
不需要依赖某个特定私有形状或有理分母才能得出“不满足本资源门”。
这说明即使总维度不大，增大 SampleF 叶维度也会先触发资源预留拒绝。
反过来，128 维 SampleP 分成 32 维叶的公开夹具可以通过该层 admission。

这个拒绝是当前保守工程策略；它不证明高维 SampleF 数学上不可能，
也不提供精度误差或目标 TV 上界。后续若改 reserve、因子表示或叶划分，
需要单独论证全部路径的有理/数值预算，并保留当前的拒绝行为作为回归基线。

## 时间、熵与 RSS 的解释

`time.perf_counter` 的 prepare 计时包括在线 scalar sampler 的构造和
实际 exact-LDL/Schur 计划准备，不包括单独记录的导入及夹具构造。
draw 计时包括连续 tickets、变换、Gaussian rounding 和条件中心更新。
每例是新进程，避免把前一配置的 scalar cache 和 RSS 高水位当作本例结果。

`resource.getrusage(RUSAGE_SELF).ru_maxrss` 在本次 Linux 中以 KiB 记录，
分别给出 after-import、after-prepare 和 final；这是整个 worker 的高水位，
含 Sage/Python 导入、缓存及临时对象，不是矩阵本身的大小或瞬时 allocation。
没有把不同新进程的高水位差当作精确堆内存差。

每次 draw 的实际 entropy bytes 都不超过该公开计划
`public_entropy_upper_bytes`；两者分开保留，
不将观察到的少量字节用量当作所有随机路径的上界。
公开证书继续保留 `full_target_tv_upper_including_abort=None`。
固定 seed 的重放、预算检查和有限次无中止不证明采样分布正确或一般失败概率小。

`prepare_p` 的总维度/叶维度只是这一数学采样工具的输入。
成功的 128/32 夹具不意味着 `Params`、真实 SRGG 形状、用户对象或 wire
已经支持 n=32 或 n=128，更不能替代 `parameter-feasibility.md` 的
n=512 条件候选执行。当前依然需要结构化 shape、scalar 大宽度证书、
真实生命周期和未闭合的理论条件。

## 复现与测试

在仓库根目录、指定 WSL Sage 环境运行：

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.resource_probe \
  --output build/outputs/srgg-admission-2026-10-16/resource-probe.json \
  --repetitions 2 --timeout-seconds 20 \
  > build/outputs/srgg-admission-2026-10-16/resource-probe.stdout.json \
  2> build/outputs/srgg-admission-2026-10-16/resource-probe.stderr.log

PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_resource_probe.py \
  --junitxml=build/outputs/srgg-admission-2026-10-16/resource-probe-tests.junit.xml
```

指定 Sage 实际测试 **14 passed，0 skipped**，覆盖真实 F/P、固定流重放、
上述三类预检门、超时的 censored 状态和 worker error 不伪造结果。
超时测试使用受控异常检查报告逻辑；实际 28 项网格没有超时。

本实验不核验 ROM/QROM 归约；没有正式安全参数、困难性估计、strong premise、
总体采样误差或安全等级声明。所有标志保持 `security_claim=none`、
`backend_admitted=false`、`parameters_are_formal=false`。
