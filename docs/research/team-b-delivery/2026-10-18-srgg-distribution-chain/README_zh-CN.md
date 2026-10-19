# SRGG 独立 IBS：数学好根界与实现门控的条件分布界

修订日期：2026-10-19。本次修正范围与实现对应，不新增安全证明，不改变论文算法、原 Table 4 参数或 Gaussian 解释，不涉及 HIBE。

论文为 Jia–Liu–Tang–Wang，*Constructing Efficient Identity-Based Signatures on Lattices*，[DOI 10.1049/ise2/6684889](https://doi.org/10.1049/ise2/6684889)。冻结文件 `papers/2025_efficient_ibs_jia.pdf`，SHA-256 为 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。原参数保持 `n=512,p=16383,b=31,w=2,q=961,Q=15744063,d=2/3/4`，两种解释为 `table-standard-deviation` 和 `literal-density-width`。项目工作假设不是新增验证结果。

## 分版本的集合

| 名称 | 含义 |
|---|---|
| `A` | 论文数学正定门 `Sigma_p-r²I>0` |
| `G_C` | 数学条件 `C>64I` |
| `B_legacy` | 历史非门控后端一次准备成功 |
| `H_setup / H_sign` | 当前实际执行的完整 Setup／签名构造与审计门 |

当前 `SourceSchurBackend` 默认完整门控，`GuardedSourceSchurBackend` 是兼容别名，不重复审计。旧文档的 `B` 仅指历史 `B_legacy`。Setup 门失败重试、签名门失败固定密钥中止属于服务政策。

## 保留的数学结果

精确有理数比较给出 `G_C⊂A`，且理想 master Schur pivot 下界 `L2≈400780/572585/741172>64`。既有 CBD1→complex-Wishart trace moment 使用原阶数 `k=17/22/28`：

```text
mu(G_C^c) ≤ q_C,
TV(mu(.|A),mu(.|G_C)) ≤ q_C/(1-q_A),
64 次独立数学 G_C 拒绝的概率 ≤ q_C^64。
```

| 原表行 | 解释 | `q_A` | `q_C` | 数学根律 TV 界 | 理想数学重试界 |
|---|---|---:|---:|---:|---:|
| I | std | 0.205519 | 0.235130 | 0.295954 | `2^-133` |
| I | literal | 0.205519 | 0.487621 | 0.613760 | `2^-66` |
| II | std | 0.095133 | 0.113233 | 0.125138 | `2^-201` |
| II | literal | 0.095133 | 0.290989 | 0.321582 | `2^-113` |
| III | std | 0.046673 | 0.058256 | 0.061108 | `2^-262` |
| III | literal | 0.046673 | 0.193644 | 0.203125 | `2^-151` |

小数仅作近似显示；JSON 保存精确分数与向外取整的二次幂上界。这些是数学事件的结果，**实际服务的接受律与 64 次中止预算仍为 null**。

## 修正的范围错误

区间运算可靠只排除误接受，不能单独保证每个数学 `G_C` 根在固定精度下都认证成功。原数学门与理想 Schur 下界有余量，但覆盖全部 FFT／LDL／准备操作的统一数值误差包络未给出；保留的候选 gain/noise/object 常数不能替代它。

实际 C 门使用 192-bit 区间；数学 `C>64I` 允许贴近 64 的边界。不确定壳层的宽度／质量未界定，不能声称移动阈值后精确 `q_C` 不变。因此 `G_C⊂B_legacy` 的完备性证书、旧接受根律、统一有限准备包络、实际 C 门壳层质量、`TV(mu(.|A),mu(.|H_setup))` 和实际 Setup 中止概率均保持 null。重试的工程修复不自动给出概率界；六条固定根和三组边界回执只是功能见证。

## 实际通过完整门后的条件界

有限链、卷积、normalizer、发钥与签名的数值项使用门限 64、误差门及根无关预算。实际通过全部适用门后，保留既有 gate-uniform 条件范围。实际密钥律与参考使用同一个签名 guard 和 abort 语义：

```text
TV(guarded issue + s signs) ≤ min(1,δ_issue+s·ε_good)。
```

若发钥已暴露密钥字节，两侧均保留该输出，再执行相同签名门；不抹去一侧历史中的坏密钥。无 guard 的 `beta_bad` 仍为 null 且严格为正；guard 公式不把它设为零。

| 原表行 | 解释 | `δ_issue` | `ε_good` | 发钥+1签 | 发钥+2签 |
|---|---|---:|---:|---:|---:|
| I | std | `2^-25` | `2^-19` | `2^-19` | `2^-18` |
| II | std | `2^-25` | `2^-18` | `2^-18` | `2^-17` |
| III | std | `2^-24` | `2^-18` | `2^-18` | `2^-17` |
| I/II/III | literal | null | `1`（平凡） | null | null |

签名核比较包含两侧相同的 64 次 norm 重试与 abort，不给出 norm-exhaustion 的单独概率。字面 density 首发钥因 gadget normalizer 充分门失败保持 null。

## 历史及实测范围

仅覆盖**逻辑 API 输出与确定性持久状态**：返回密钥／签名、规范快照、缓存和共同逻辑错误。要求相同逻辑调度、相同 Setup／abort 模型，或明确条件于相同的成功 Setup 根。新身份支付一次发钥项；缓存重发不重复支付。

时间、锁调度、熵消耗、内部采样／运行轨迹，以及没有概率模型的磁盘／进程／回滚故障均排除。输出核界不能提升为这些可观察量的联合界；包含实际 Setup 律的完整服务历史仍为 null。旧紧凑编码的尺寸、时间、内存实测属于其冻结后端，不能直接继承为当前 guard 默认路径的实测结果。

作者 SampleZ/C 对应、原文 `r/σ`、Algorithm 4 `d/f`、ζ 与 `q>2γ` 来源歧义、native strong、结构困难性、正式准入及 NIST 等级保持原状态。本次不安排补充证明。

## 文件与复现

- [proof.md](proof.md)：分版本集合、原有公式及条件范围。
- [distribution-chain.json](distribution-chain.json)：六行数学界、条件发钥签名界、实际服务 null。
- [validation.json](validation.json)、[verify_delivery.py](verify_delivery.py)：固定证据、指纹及复核入口。
- `boundary-PARAM-I/II/III.json`：历史边界生命周期回执，不是概率证明。

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q \
  tests/test_srgg_paper_distribution_chain.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m \
  experiments.research.candidates.srgg.paper_distribution_chain \
  --output build/distribution-chain-new.json
```

`--lifecycle` 增加六行确定性回放；输出路径须不存在。冻结环境为 WSL2 / Sage 10.9 / Python 3.13.15；准确环境与命令见 validation。功能测试、指纹与有限 TV 界不能替代安全证明。

始终：`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。
