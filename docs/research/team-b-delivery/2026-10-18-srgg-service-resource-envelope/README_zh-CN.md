# SRGG 原表固定服务的耗熵与状态容量：WIP

日期：2026-10-18。依据仓库冻结的 Jia、Liu、Tang、Wang 论文 `papers/2025_efficient_ibs_jia.pdf`（SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`）和当前 `SourceSchurBackend`、`FixedIssuer` 代码。本包只计算**后端 `rng.read` 返回的字节上限**；临时文件名等 Python/OS 随机性、峰值 RAM、总运行时间和作者 C/rANS 性能均不在此界内。

原表共同输入仍是 `n=512, p=16383, b=31, w=2, Q=15744063`；三档 `d=2/3/4`，论文宽度与 γ 未改。由于原文 Gaussian 记号尚有歧义，逐档保留 `table-standard-deviation` 和 `literal-density-width` 两种明确解释。详细公式、精确失败分数、源文件哈希见 [service-resource-envelope.json](service-resource-envelope.json)。没有调用真实 Setup/发钥/签名，也没有读出私钥。

| 档位 | 解释 | 一次 Setup 最多 B | 首次发一个身份最多 B | 一次 sign 最多 B | 当前状态格式最多容纳的新身份 |
|---|---|---:|---:|---:|---:|
| I | 表标准差 | 524,320 | 6,644,180 | 363,724,224 | 3 |
| I | 字面 density | 524,320 | 6,658,870 | 372,943,232 | 3 |
| II | 表标准差 | 1,179,680 | 9,659,520 | 491,366,656 | 2 |
| II | 字面 density | 1,179,680 | 9,691,270 | 513,032,960 | 2 |
| III | 表标准差 | 2,097,184 | 12,674,104 | 619,896,512 | 1 |
| III | 字面 density | 2,097,184 | 12,723,678 | 646,865,792 | 1 |

这些是**硬上限，不是实测消耗**。Setup 只读一次 32 B seed，每次尝试再读 `2d²wn` B CBD1 witness，当前至多 64 次。首次发钥的上限是原顺序 `PaperSchurSampleF` 的下块标量、连续 ticket、上块离散舍入三项，加上 `PaperGadget` 的 `dwn` 次标量预算。一次签名至多 64 次尝试；每次 `PaperSchurSampleF` 和全部 `n` 次 `u` 抽样共用一层实际安装的聚合字节帽。新增整次尝试中止已经包含在 `u` 批次聚合事件内，联合失败界不得再重复加一次。

固定发钥服务默认 `max_users=1`，可以指定更高容量，但当前 **2 MiB** 私有状态文件的保守预检使六行最大值分别只有 `3/3/2/2/1/1`。这是状态格式容量，并非论文安全查询数、发钥成功概率或 RAM 上界。`FixedIssuer` 必须显式传入 `SourceSchurBackend`；缺省后端是独立保留的 joint 路线。已缓存身份、错误状态和超容量请求在合法固定服务路径上不再调用后端采样；失败/待完成状态阻断自动重发。这个结论要求单根、可信合作本地存储且无回滚。

若外部明确限制**一次初始化、至多 U 个首次身份发钥尝试、至多 S 次签名调用**，则后端 `rng.read` 的确定性上界是

`E_setup + U × E_first_issue + S × E_sign_call`，其中 `0 ≤ U ≤ 当前状态容量`，`S ≥ 0`。

目前没有 `S` 的全局限额：拿到一把有效用户密钥后，可反复调用 `sign`，即使身份服务容量已满或重启。因此**完整服务终身耗熵上界仍为 null**；若也允许无限创建新 issuer 根，Setup 数量同样无界。`max_attempts=64` 只约束一次调用，不能冒充生命周期限额。这个无界反例无需修改协议或参数。

JSON 中另外给出每个发钥阶段与签名尝试的**有限标量采样中止**联合上界（精确有理数、要求独立均匀字节及已通过中心/准备检查）。实际 Setup 数值准备/重试失败、Schur 连续与舍入整链误差、完整发钥对象/签名分布、norm retry 用尽和磁盘故障没有闭合，仍是 `null`。现有状态大小/编码上限也不能推出峰值 RAM 或终止时间。这里不宣称原论文 C/rANS/1000 次运行结果、正式参数或安全等级。

使用项目规定的 WSL Sage 环境复算：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_service_resource_envelope --output /tmp/srgg-service-resource-check.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_service_resource_envelope.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python docs/research/team-b-delivery/2026-10-18-srgg-service-resource-envelope/verify_delivery.py
```

定向测试逐行比对六份既有原表实际生命周期回执的 SampleF 与签名上限，并直接检查 `_preflight` 的最大/首个拒绝容量。测试是代码上限对应证据；它不证明高斯分布、安全归约、故障概率或困难性。`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。
