# SRGG 原论文顺序实现：独立 IBS 交付，整体参数闭合仍 WIP

日期：2026-10-18。论文：Jia、Liu、Tang、Wang，*Constructing Efficient Identity-Based Signatures on Lattices*，DOI `10.1049/ise2/6684889`。版本为仓库冻结 PDF，SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。定向来源、原文符号差异与代码对应见 [algorithm-map.md](algorithm-map.md)。

**本批补上了原表规模的“离散下块 → 逆序逐环 Schur → 每环连续 Gaussian 与固定宽离散舍入”可运行路径。** 与既有全维 joint 路线分别保留；本批不把任一有限实现冒充作者 C 程序、无限精度采样器或完整安全复现。没有处理 HIBE。

## 具体交付

| 部分 | 本批结果 | 限制 |
|---|---|---|
| Algorithm 3 精确环代数 | 新增 QQ 负循环环逆元、Schur、条件中心参考；n2/n4 逐块对照独立 dense 结果 | 原 n512 公开 fixture 的一次准备达到 45 秒上限；保留导入源码和回执，不重试，不宣称所有精确实现不可行 |
| Algorithms 3–4 原顺序运行 | 区间 Fourier 逐层 Schur、dyadic gain、条件中心更新、每环连续位移后真实固定宽离散舍入 | 这是一次数值替代；新 chain 数值总 TV 和 Schur normalizer bias 尚未闭合，不能借用旧 joint 证书 |
| 独立原语生命周期 | 显式 `SourceSchurBackend`；复用原 Setup/Extract/Verify、规范对象和固定服务，独立实现有耗熵上限的 Algorithm 7 | 默认 joint 后端及其算法文件字节保留；无共享 CLI/registry/HIBE 改动 |
| Algorithm 7 耗熵 | 单次尝试同时覆盖 perturbation 和全部 n 次 u 抽样；有限 norm retry 的整次调用包络 | 不改宽度、标量权重或 trial 数；新增聚合中止单独计费；不是服务终身预算或 RAM 上界 |
| 原参数结构预检 | 实际分解模数、验证环因子次数、CRT/HNF/核维数、理想均匀矩阵可逆概率、seeded 支持与枚举资源边界 | 实际结构攻击成本、setup 接受条件化距离、其它素因子上的 planted CBD1 law 仍为空 |
| 公开失败出口 | 审计 CLI 不再输出任意底层异常消息或 traceback；两条 sampler 选择均有定向测试 | 不宣称消除所有侧信道或提供常数时间实现 |

## 原表真实运行

原数值保持 `n=512,p=16383,b=31,w=2,q=961,Q=15744063`，`d=2/3/4`，保留论文原 γ、近似 r=1.16、factor1 与两种显式 Gaussian 记号解释。三组主/签名系数维数分别为 `4096/4608、6144/6656、8192/8704`。没有用 w8 或 n2048 候选替换原表。

最终代码执行七轮：两种记号解释 × 三组原表，另加 PARAM-I 默认解释的一轮系统随机数运行。每轮一个根、Alice（5 B）、32 B 消息、两次成功签名（含原文 norm retry）、完整恢复，每轮 **37/37 功能检查通过**。确定性流仅用于测试；iid 字节概率模型不能由固定种子实验证明。公开 JSON 不含主私钥、用户密钥、真实签名或服务快照。

| 最终回执 | 功能结果 | 同消息 Q 平移替换 |
|---|---|---|
| [I 默认解释](param-i-bounded-final-lifecycle.json) | 37/37 | 无 eligible 候选，不能称安全通过 |
| [II 默认解释](param-ii-bounded-final-lifecycle.json) | 37/37 | 成功，保留反例 |
| [III 默认解释](param-iii-bounded-final-lifecycle.json) | 37/37 | 成功，保留反例 |
| [I 字面 density](param-i-literal-bounded-final-lifecycle.json) | 37/37 | 成功，保留反例 |
| [II 字面 density](param-ii-literal-bounded-final-lifecycle.json) | 37/37 | 成功，保留反例 |
| [III 字面 density](param-iii-literal-bounded-final-lifecycle.json) | 37/37 | 成功，保留反例 |
| [I 系统随机数](param-i-secure-bounded-final-lifecycle.json) | 37/37 | 无 eligible 候选，不能称安全通过 |

默认解释的单次签名尝试硬耗熵上限为 I/II/III 的 `5,683,191 / 7,677,604 / 9,685,883 B`；最多 64 次尝试的一次 sign 调用为 `363,724,224 / 491,366,656 / 619,896,512 B`。新增聚合预算中止每尝试至多 `2^-192`，64 次 union 至多 `2^-186`，条件为现有 perturbation 硬 cap 和 iid 均匀字节。不是实际耗熵测量；不含 norm-retry 用尽、基础 sampler 中止、数值 invariant 或基础设施故障的总概率。

[hardness-preflight-current.json](hardness-preflight-current.json) 的实际 Sage 检查给出 `Q=3·31²·43·127`；`X^512+1` 在 3/31/43/127 上分别为 `2×256、16×32、2×256、64×8` 次分解。固定 32 B seed 的信息论支持差距仅说明它不能无费用当作理想均匀 Ahat；不据此声称 SHAKE 或 IBS 已被破解。mod3 CBD1 界针对未筛选根；实际 setup 正定拒绝的条件化费用没有填成零。

## 重现与检查

在仓库根目录按项目规定使用 WSL `~/miniconda3/envs/sage`：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_audit --sampler source-schur --profile PARAM-I --output build/source-schur-i.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_audit --sampler source-schur --profile PARAM-I --interpretation literal-density-width --output build/source-schur-i-literal.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg*.py
python docs/research/team-b-delivery/2026-10-18-srgg-source-schur/verify_delivery.py
```

其余组用 `--profile PARAM-II/PARAM-III`；系统随机数增加 `--production-random`。环境、测试命令、最终结果、源文件哈希及历史失败见 [validation.json](validation.json)、[regression.xml](regression.xml) 和 [regression-provenance.json](regression-provenance.json)。CPU/软件证据见 [environment.json](environment.json)。多个实验进程有重叠，单次 Python/Sage 时延不是公平 benchmark；作者 C/ANS/1000 次 cycles 结果未复现。

初次七份 `*-lifecycle.json` 与中间七份 `*-bounded-lifecycle.json` 原样保留，最新结论使用含 `-bounded-final-` 的七份。旧 manifest 与优化/失败材料不改写。本批中间回归拒绝了修改过的旧后端源码绑定；最终把新增 sign 预算完全放入独立后端、恢复旧后端字节，未放松证书哈希检查。原失败测试回执另存，不混入最终通过结果。

## 尚未闭合，不能宣称完整安全交付

- 新 Fourier/dyadic chain 到精确原顺序 chain 的数值 TV、Schur normalizer bias、完整发钥/签名/history/fault law。
- 原文 Algorithm 4 的 d/f、正文下块 r/σ、Gaussian 归一化、近似 r、q/Q/2Q 与 ζ 因子对应；m10240 必要门严格失败的既有证据保留。
- 所有 Setup 接受根的分布、真实 ring-HNF/MSIS/CRT/子域困难性与正式成本、完整原生 strong/ROM/QROM 映射。已有实际替换反例与 native strong 目标冲突，不能靠成功签验消除。
- 作者采样细节、ANS 编码和 C 性能；服务终身耗熵、全路径峰值 RAM/时间准入。

上述属于 SRGG 自身的缺口，本批没有以等待 HIBE 为由搁置。按用户要求，一个困难点最多一次替代，未解决就留证并推进其它独立项，避免无限搜索。安全标记始终为 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。功能检查及有限攻击不能替代安全证明。本批仅本地提交，未推送。
