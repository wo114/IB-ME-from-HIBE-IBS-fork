# WIP：显式公钥下的经典公开 Run 与真实两次 fork

2026-10-16。本项将 [direct-ibs.md](direct-ibs.md) 的公开程序做成本地可执行研究代码，使用实际有界采样器和独立 oracle 表。完成范围是 **typed、显式 proof-public 的经典实验**，不是生产 seeded 公钥的完整安全归约，也不提供参数准入。

`security_claim=none, backend_admitted=false, parameters_are_formal=false, nist_security_category=null`。

实现：[classical_runner.py](../../../../experiments/research/candidates/srgg/classical_runner.py)；验收：[test_srgg_classical_runner.py](../../../../tests/test_srgg_classical_runner.py)。

## 1. 输入、实际采样与秘密边界

`Runner(ProofPublic, h_star, J)` 只接收 `ExecutionParams`、显式 `Ahat/B`、外部目标 h 和公开目标索引。不接收 master、root witness 或目标用户 key。`ProofPublic` 有自己的规范 wire/context，**没有声称它等于生产 Public 的 seed/wire**。接口验证维度、模 Q 规范系数、严格整数和公开 query/byte caps。

h_star 必须在证明实验外独立均匀；构造器只验证其格式，不能从一个值判断其分布。`sample_uniform_target` 是可选的外部 mask/reject helper：每系数最多 128 次、没有整向量重抽、保留失败；条件于成功恰均匀。它不从 `A SampleDom` 产生目标，不存在隐藏目标 key，费用也不混进固定输入 Run 的预算。

非目标首次触及实际执行公开有限 Gaussian U 和 `[0,p)` 均匀 E0，再取

```text
Y=(center_Q(U_head+E0), U_tail), h=A Y mod Q.
```

raw U 与 final Y 的两个范数门均保留；失败仍保留这个 h 和固定 failed 身份状态，Extract/Sign 明确返回 blocked，绝不重抽另一个身份 key。pending 重入停止整轮实验。目标则保留 h_star 和 `target-unissued` 状态，始终 `key=None`。

非目标 Sign 实际调用 `StructuredSampleF` 的公开范数类与独立有限 scalar u；只有 final-response 范数失败会按公开 L 重试。有限 sampler abort/熵源异常不变成一次 norm retry。目标 Sign 实际抽独立二进制 c、公开有限 product-Gaussian z，检查范数后用 Rec 得到 W；只有 `(W,message)` 从未触及时才能编程，碰撞停止。failed Sign 从不加入 successful-return 日志。

所有这些是指定 sampler 的实现证据；是否与诚实 latent/key/Sign law 足够接近，仍由 direct-ibs 的逐历史条件和统计费用承担。

## 2. 首触及、跨身份 H2 与 strong 新颖性

H1 任意首次非空 raw 读取（包括只读 1 B、offset）立刻分配完整身份和 [conditional-XOF G_h](conditional-xof.md) 轨迹，随后 composite H1 与任意 prefix/suffix 读同一个点。G_h 包含原始 256 轮全拒绝事件，不是 `K_h=G_h|success`。raw 解码失败仍能读已经固定的 bytes，并标记 hashbad；composite H1 需要成功时才停止。真实 source failure 则封锁本轮，不能改读另一个 source。

H2 key 只有本轮 public context 隐含下的 `(canonical W,message)`，没有 identity。首次 raw 读取也先固定完整 n-bit c。ordinary/composite/known-key 内部访问的 owner 是 `free`；目标 Sim 只有真正新建并成功返回才获得 `sign` owner。后续跨身份命中保持原 owner。未使用高位与后续 raw bytes 使用独立固定带，与完整挑战 pack 保持一致。

成功 Sign 日志精确记录 `(identity,message,canonical_signature_bytes)`。`finish` 在调用最终 Verify 前快照 owner，避免将原本未查询的最终点错记成 free。它检查目标索引、显式 Extract、范数/规范形状、真正 H1/Rec/H2 验证、strong exact-triple 新颖性和 hashbad。这个 Verify 是本地 ideal-oracle 实验的一部分，可能创建 oracle 点/消耗其 coins；生产 Verify 的无熵语义没有改变。

## 3. 可重放 coins 与实际提取

`ReplayBank` 对非 free-H2 随机性建立独立 labeled byte tapes，包括公开 U/E、H1 raw、H2 unused/suffix、目标 Sim、known Sign 和攻击者的 `runner.attacker_rng`。新 Reader 从同一 label 的开头重放；仅未生成的后缀消耗 source。source 错误或总 cap 耗尽后 bank 保留 blocked 状态。

`fork_extract` 首轮成功后，sign-owner 直接与该 entry 已实际返回的目标签名差分；free-owner 则真正从空 identity/H2/log 状态启动第二个 Runner，使用同一个 bank，保留第 I 个 free 回复之前的 c，重采第 I 个及之后的完整挑战。

fork 接受要求两轮均有目标 strong 成功、相同 W/message、第二轮 owner 仍为 free 且 free index 仍为 I、完整 c 不同。最终还独立检查

```text
Delta != 0, ||Delta||² <= 4 Bsig,
[I | Ahat | B | -h_star] Delta = 0 mod Q.
```

仅“c 不同”不足以保证非零：eta(c)=c_low XOR c_high 的有效挑战可能碰撞。测试保留该反例，若响应相同则必须 fork-failed。输出的 Delta 是验证过的短核，不是恢复原用户 key。

攻击者 callback 必须由 Runner 接口和 `attacker_rng` 决定；任意闭包 OS 随机数、时间、进程状态和外部副作用无法由此 Python wrapper 固定。测试另故意使用不满足此约束的外部状态，造成第二轮 owner/index 改变，验证 wrapper 拒绝将其称为成功 fork。执行两轮及得到一个核只证明相应代码路径，**不证明 fork 成功概率、共同母空间耦合或完整 adaptive reduction**。

## 4. n512 零熵资源证书

命令读取冻结 `2026-10-16-srgg-bridge/integrated-bridge.json` 的 `query-bounded-deep`，记录输入/源代码 SHA-256 和环境；没有构造 RNG、抽 U/z/key/签名或运行攻击者。参数仍为

```text
n512, d2, w8, b31, p16383, r²64,
Q=13972913866395903,
Bsig=238255596480161099521436160.
```

默认公开 limits 为 QI=8、Sign=8、H2 entries=128、H2 每点 raw 输出最多 65,536 B、ReplayBank 256 MiB；H1 每点仍遵循独立的 `dn*4096 B` raw budget。H2 的 free c entropy 和非 free raw prefix/suffix 分开收费。非目标每 Sign 按最多 L=16 次实际 SampleF/u 收费，全部身份均按公开 U/E/H1 收费，故允许保守多算目标身份费用。

| 项目 | 字节上界 |
|---|---:|
| 每次 known-key SampleF 公共类 | 11,020,294 |
| 每次 known-key u batch | 642,980 |
| 每 Run 全 sampler/raw（含 free c） | 1,627,883,584 |
| 两 Run 全 sampler/raw | 3,255,767,168 |
| 两 Run 非 free sampler/raw | 3,255,750,784 |
| 实际 bank 物理 cap | 268,435,456 |
| 外部独立 uniform h helper 最坏 cap，Run 外 | 917,504 |

**现有物理 bank cap 不覆盖这个最坏路径上界**，也没有给其触发概率。因此证书明确 `global_entropy_cap_abort_upper=null`、`two_run_nonfree_upper_covered_by_bank_cap=false`，不能把 bank-cap 事件当作概率零或完整 finite→ideal 费用已闭合。攻击者自身时间/coins、所有 raw 无效 frame/其它 mpk 点、整个 seeded matrix embedding 和 all-path CPU bound 尚不在该证书中。当前代码有硬停止行为，完整概率模型与足够预算仍需另付，不以这里的 bytes 证书替代。

## 5. 实际验收与可复现边界

指定 WSL `~/miniconda3/envs/sage`，Sage 10.9、Python 3.13.15、Linux WSL2 x86_64。n8/d1/w3 真实有限采样和状态测试使用分离的固定测试 RNG；另有一次 SecureRandom 小实例只检查 support/方程/状态，不作分布检验。主要 honest-style 本地流程对 5 B `Alice`、3 B `Bob` 身份各使用 32 B 消息，一次 known Sign 与一次 target Sim。这里的 public Ahat/B 是显式公共样本，不宣称已经跑真实 seeded Setup 的全部归约。

提取测试刻意采用 `A=[I|0|0]、h_star=0` 等存在公开短核的代数夹具，并实际运行两次 Run 和非目标 U/E。它们检查回放/索引/owner/核方程，不属于困难实例，不是参数安全证据。采样 abort、retained hash failure、损坏熵源、norm/cap、target Extract、别名和 exact strong 日志分别有定向验收。测试次数是一组确定性 case 加一次 SecureRandom support case，没有性能比较、显著性或一般攻击失败结论。

```text
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_classical_runner.py --junitxml=build/outputs/srgg-classical-runner-2026-10-16/runner-final-pytest.xml
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.classical_runner --output build/outputs/srgg-classical-runner-2026-10-16/runner-n512-certificate.json
```

CLI 用 exclusive create 拒绝覆盖旧输出。raw JSON/JUnit 位于上面 ignored 目录；可发布证据由 root 统一复制并封存，ignored 路径本身不承诺随 Git 交换。n512 是零熵算术证书，未执行 n512 生命周期。

尚缺：生产 wire/seed/raw-XOF matrix 嵌入；全部 raw frame/多 mpk oracle 游戏；unmodeled cap/基础设施与诚实参考的完整 law 费用；真实 callback 及全部 query/time 预算的归约前缀证明；与实际服务态的 Delta0；完整经典 reduction 概率合成；QROM coherent oracle/reprogramming/提取；新参数困难性与正式准入。这里没有隐藏或声称消除这些条件，也不根据 Kyber/ML-KEM 的标准化等级给 IBS 颁布 NIST category。
