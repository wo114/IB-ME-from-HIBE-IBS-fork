# SRGG：有界重放、条件概率与量子关系核验（本地 WIP）

2026-10-16，基线本地提交 `a68e5a7`。本批继续保留 native strong，处理独立 IBS
的具体缺口，未改 HIBE、共享 CLI/registry、生产算法或研究参数。
按用户最新决定，**全部与 HIBE 选择无关的完整任务完成后才统一 fork＋PR**；
本批只本地提交，不能凭这份证据包称全部完成或提前推送。

安全标志仍为 `security_claim=none, backend_admitted=false,
parameters_are_formal=false, nist_security_category=null`。

## 这批实际完成了什么

| 材料 | 可以支持的结论 | 仍不能支持的结论 |
|---|---|---|
| [bounded-classical-runner.md](bounded-classical-runner.md)、[零熵 n512 证书](bounded-runner-n512.json) | 新 Runner 的两轮 sampler/raw、攻击者 coin 带与 free-H2 确定上界为 3,257,864,320 B，小于按需 4 GiB 总 cap；不足时采样前拒绝 | 不是 4 GiB 峰值 RAM/CPU 证书；未跑 n512 两轮对手；没有删去 sampler、hash、源故障的失败 |
| [probability-review.md](probability-review.md) | 对同一有界经典 Run，实际 owner 分支给 `a+max(0,b²/q−b2^(-n/2))`；仅有总成功率时有精确分段界、凸 Jensen 及完整显式账本 | 未证明生产服务到该 Run 的全部 law，也未证明底层困难性 |
| [raw-h2-relabel.md](raw-h2-relabel.md) | 固定 H2 域内任意 partial-byte/offset 的相干包装等式：至多 2 次 joint-prefix＋1 次 suffix query；未用位和 scratch 清理保留 | 参考工具是基态验证；没有实现量子设备、H1、全域 raw-frame 或量子提取 |
| [service-law.md](service-law.md) | 持久缓存/重开到同故障参考的条件状态对应；带历史状态、异常标签的自适应 TV 合成；保留已提交但未返回 key | 普通无故障 IBS 的完整 Delta0 仍需整体 kernel/故障模型，不把 fsync 测试写成故障率零 |
| [quantum-relation-review.md](quantum-relation-review.md) | 正确区分短原像/短核见证；OR 关系保成功率变换；原 full-c 和商验证器的带坏事件 2-soundness；核 DFMS 实际前提 | QCUR/collapsing 未证明；给定私钥辅助态的反例只排除所写明强模型，不宣称攻破无私钥随机公钥游戏 |

新代码是 `experiments/research/candidates/srgg/` 下的
`bounded_classical_runner.py`、`bounded_classical_cost.py`、`raw_h2_relabel.py`，
各有同名 SRGG 测试。冻结 v1、旧成本函数、bridge/classical/proof-followup
源码及证书保持原字节。此次用新版本解决旧 v1 的 cap 未认证项，不回写历史为成功。

## 参数、模型和验证

资源证书使用冻结 `query-bounded-deep`：

```text
n512,d2,w8,b31,p16383,r²64,Q13972913866395903,L16
QI8, Sign8, H2 entries128, raw-H2每点65536 B
attacker每轮最多1 MiB，总source cap4 GiB，单次read最多256 MiB
```

它取熵为零，只计算包络并绑定输入/源码 SHA-256。新真实 sampler 测试在
n8/d1/w3 运行公开 U/E、known-key Sign 与目标 Sim；Alice/Bob 身份5/3 B，消息32 B。
提取测试刻意使用已知公开短核代数夹具，实际跑两轮，不把它说成困难公钥分布。
小参数仍有公开伪造及错误身份反例。教师提出的 Kyber/ML-KEM、NIST 是评估目标，
当前研究点没有正式等级，也不能据测量结果作同安全强度比较。

概率推导采用明确的经典 ideal-XOF/RO 前提；量子包装是同一固定函数的 oracle
恒等式，不额外证明 SHAKE 的模型适配。每个文稿列明数学条件、有限验证或源码
对应分别能支持什么。功能与有限攻击测试不能代替安全证明。

最终源码的定向检查：指定 WSL Sage 下 Runner **28 passed**，成本工具
**121 passed**，raw-H2 **21 passed**；Windows 成本工具同一121项通过。
最终全 SRGG 一次回归为 **1266 passed、0 failures/errors/skipped**，117.33 s，
无 warnings。上述定向测试与完整回归重叠，不相加为独立覆盖数。完整回归和脱敏收据见
[validation.json](validation.json)，其中保留原始收据 SHA、转换方式和精确命令。
软件环境为 WSL2 Ubuntu24.04、Sage10.9、Python3.13.15；Windows 零熵检查为
Python3.14.7。主机为 Intel Core Ultra7 255HX（20 核/20 逻辑处理器），
物理内存33,676,681,216 B；没有测定 WSL 峰值内存。本批没有性能比较或故障发生率统计。

```text
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg*.py --junitxml=build/outputs/srgg-bounded-runner-2026-10-16/srgg-all-final.junit.xml
```

复现时改用新的输出名；不要覆盖已封存证据。公开 JUnit 仅移除 hostname 并按 XML/LF
序列化，测试名、计数、结果和耗时不改；原收据在 ignored outputs 保留。

## 只读核验及继续工作

本批复用已有完整性检查器，无需新增算法或安装依赖：

```text
python experiments/research/srgg_proof_followup_delivery_check.py --delivery docs/research/team-b-delivery/2026-10-16-srgg-bounded-runner
python -O experiments/research/srgg_proof_followup_delivery_check.py --delivery docs/research/team-b-delivery/2026-10-16-srgg-bounded-runner
```

[MANIFEST.json](MANIFEST.json) 是 Git 审查下的字节清单，绑定新源码、测试、文稿、
报告、脱敏收据和旧封存依赖。它不是数字签名或第三方来源认证，核验不会重跑密码学。
旧 proof-followup 检查仍独立执行，不把它的1522项重叠收据数当作一次完整回归。

完整目标仍 active/WIP：生产 seed/全部 raw-frame/多公钥对应与完整 Delta0、
H1 的 QROM 对应和实际量子提取前提、所选环/复合模数/CBD1 的困难性、正式参数与
新大规模真实运行仍缺。HIBE 未选定不解释或消除这些缺口；这些部分完成前不推送。
