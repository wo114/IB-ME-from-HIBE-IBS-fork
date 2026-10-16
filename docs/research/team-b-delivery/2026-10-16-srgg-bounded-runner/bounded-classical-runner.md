# 显式 proof-public 的有界经典 Runner：闭合额外 global-cap 项

2026-10-16。本页记录新版本 `bounded_classical_runner.py`，保留 [冻结 v1](../2026-10-16-srgg-classical-rom/classical-runner.md) 的源码、证书和失败记录。新版本只闭合显式公钥本地 Run/fork 的**额外全局 source-byte cap**；不改变 HIBE、参数、生产 wire/hash、真实服务或底层采样 law。

`security_claim=none, backend_admitted=false, parameters_are_formal=false, nist_security_category=null`。

## 1. 新类型与冻结算法的边界

实现：[bounded_classical_runner.py](../../../../experiments/research/candidates/srgg/bounded_classical_runner.py)；测试：[test_srgg_bounded_classical_runner.py](../../../../tests/test_srgg_bounded_classical_runner.py)。新模块定义自己的 `Limits`、`ReplayBank`、bounded `FreeReplies`、Runner 构造器和 fork wrapper。它继承 v1 的 H1/H2、公开 U/E/known Sign、目标 Sim、范数门、owner、strong 日志、Rec 和最终验证方法；不 monkeypatch、不调用 v1 构造器，也不将新对象绕过 v1 的 exact-type guard。

输入仍是独立显式 `ProofPublic(Ahat,B)`、外部独立均匀 h_star 和公开 J，没有 root/master/目标 key。构造器验证格式，分布是证明前提。生产 seed 与显式矩阵的嵌入仍未由本模块建立。外部目标挑战不是固定输入 Run 自行抽的 coins，其生成费用另列，未偷加到 Run 内部 law。

默认 query profile 完整保留 `QI=8, Sign=8, H2 entries=128, H2 raw/point=65,536 B`。每轮攻击者随机带上限 1 MiB。新增全局 source-byte cap 为 4 GiB，单次 source read 仍最多 256 MiB；tape 按实际消费惰性增长，创建 bank 不分配 4 GiB。

## 2. 两轮精确保守包络

先以完全相同的参数和 query caps 重新计算冻结 v1 `resource_certificate`。记其每轮 non-free sampler/raw 上界为 R，完整 n-bit challenge 所需字节为 C，每轮 H2 entry cap 为 H，攻击者每轮 tape 上限为 A。v1 的 R 已包含目标 Sim 的 c；以下 free-H2 源只为 ordinary H2 另外收费，不再把已包含的目标 c 重复加一次。

```text
E_nonfree <= 2 R + 2 A,
E_free    <= 2 H C,
E_total   <= 2 R + 2 A + 2 H C.
```

两轮可自适应分叉，不假设第二轮消耗等于第一轮。每个有界 sampler、H1 point、H2 entry 均按每轮最坏路径收费。不同 label/fork 后新增后缀所需的 physical bank bytes 是两轮各消费区间的并集，故不超过它们的总和。相同 attacker label 的实际 unique bytes 至多 A，但本证书保守付 2A；label 名称和 Python 容器开销不是 source bytes。

每次 `free.next` 前，冻结 `_entry` 已通过 H2 entry cap 检查。一次构造若因 source/其它异常失败，本轮进入吸收 failed 状态；不能在失败点悄悄重新抽另一个 c。因此每轮最多 H 次新 free c，raw prefix/offset 重查只命中同一 entry。第 I 点前的 fork prefix 从首轮已有完整挑战复用，第二轮只对 I 及以后实际抽新挑战；按 H 次再次收费仍是上界。

物理 bank cap 取 `global_cap−2HC`，将两轮 independent free sources 的最坏预算预先保留。Runner 在**创建 RNG 或访问 source 之前**要求上述完整两轮包络通过，单次读取仍受 256 MiB 限制。bank 每次注册新 Run 还检查 `used+(R+A)<=bank_cap`，最多注册两轮；fork 要求 bank 初始为空。已通过全包络的 fresh fork 中，首轮 `used<=R+A`，因此第二次注册必定有足够 headroom。

默认 n512/d2/w8、b31、p16383、r²64，沿用冻结研究点：

| 项目 | 字节上界 |
|---|---:|
| 两轮冻结 non-free sampler/raw，2R | 3,255,750,784 |
| 两轮 attacker tape，2A | 2,097,152 |
| 两轮 free-H2 独立源，2HC | 16,384 |
| 全部 source bytes 合计 | **3,257,864,320** |
| 预留 free 源后的 non-free bank cap | 4,294,950,912 |
| 总 cap，4 GiB | **4,294,967,296** |

所以对通过 preflight 的此 profile，合法调用不会因新增 global cap 而额外失败；报告给出 `global_entropy_cap_abort_upper_exact="0"`。小于完整两轮包络的 profile `admitted=false`、该项为 null，Runner/fork 在取熵前拒绝；不通过缩小原 query profile 获得此结论。

这只证明 **source bytes** 的边界，不是峰值 RAM/CPU/运行时间证书。bank 的 bytearray、挑战 tuple、Python 对象和临时数组有额外存储开销；没有执行 n512 全 lifecycle 或一次分配上述容量。

## 3. 对手带、free 源和吸收失败

每轮 `attacker_rng` 是单独限流到 A 的 reader；从相同固定 label 重放。超过其公开额度是对手资源越界，返回 terminal abort，不是新增全局 cap 的随机失败。source 返回错误长度/类型或抛异常后，reader/bank 和本轮保持 blocked/failed，不退回其它 source。

free-H2 源独立于 non-free/attacker tapes，最多 HC bytes。第二轮保留 I 前完整 c，只刷新 I 及以后，unused raw bits/suffix 仍由冻结 non-free tape 重放。first run 不能带任意 prescribed prefix；测试可以明确注入固定测试 RNG，不将其分布当作 iid 安全实验。

fork 实际运行新 Runner 两次，检查两轮 strong 成功、相同 W/message、第二轮仍 free owner、仍为索引 I、c 不同，再独立验证非零短核。测试包含完整 c 不同但 eta 相同且响应相同的失败路径，也包含外部非重放状态导致 owner/index 错位的拒绝路径。sign-owner 直接与已经实际返回的目标签名作差，只用一轮。该 wrapper 未增加公平分支硬币；具体概率下界须与实际分支和状态共同推导，不能只因两次实跑成功就宣称证明。

Python callback 的可信边界必须明确：它只能通过公开 oracle、公开参数和 bounded `attacker_rng` 工作，且只由这些输入决定。直接访问/修改 `runner.coins/free/identities/h2_table` 等内部对象、使用独立 OS 随机数/时间/外部状态不属于所声明的攻击者接口。此代码不是隔离任意恶意 Python 的 sandbox；对这种越权程序不主张包络或 replay 定理。

## 4. 验收、参数与仍需支付的项

新测试在指定 WSL `~/miniconda3/envs/sage`（Sage 10.9/Python 3.13.15）执行真实 n8/d1/w3 公开 U/E、StructuredSampleF/u known Sign、目标 product-Gaussian Sim 和恢复方程，Alice 5 B、Bob 3 B，消息 32 B；一次各类型 lifecycle 及定向故障 case。所有测试固定 RNG 与安全随机源保持分离。提取/错位测试特意使用 `A=[I|0|0],h_star=0` 的已知公开短核代数夹具，并实际跑两轮和非目标 sampler；不将该夹具称为诚实/困难公钥分布。

n512 命令只读取冻结 `query-bounded-deep`，生成源码/输入 SHA-256、实际环境和零熵资源 JSON；测试也以禁止 RNG 构造/采样的 guard 验证该路径。CLI exclusive create，不覆盖旧收据。

```text
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_bounded_classical_runner.py --junitxml=build/outputs/srgg-bounded-classical-runner-2026-10-16/bounded-runner-final.junit.xml
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.bounded_classical_runner --output build/outputs/srgg-bounded-classical-runner-2026-10-16/bounded-runner-n512.json
```

原始开发 JUnit 与最终收据保留在新 outputs；root 统一封存公开副本。冻结 v1 的 `global cap=null` 不回写，新版本单独解决该项。它没有删除 finite Gaussian/连续 SampleF 近似、norm retries、H1 retained decode failure、HNF/key-law、alias、诚实服务态和实际/理想游戏的费用；损坏源/基础设施也没有概率零假设。

仍需明确完成的不同义务：完整经典两轮概率合成及诚实→公开 law；production seed/matrix/raw-frame/multi-mpk 嵌入；服务→游戏状态和 Delta0；all-path CPU/攻击者时间；QROM coherent oracle/reprogramming/提取；所选环/合数模数/CBD1 条件下的困难性与正式参数。额外资源项归零不等于这些义务归零，不提供 NIST category。
