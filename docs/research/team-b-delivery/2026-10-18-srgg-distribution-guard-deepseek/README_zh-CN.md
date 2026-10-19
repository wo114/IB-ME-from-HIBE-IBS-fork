# SRGG 统一 guard：实际门控与条件分布范围

修订日期：2026-10-19。本文统一旧 v3 页首与正文的版本描述，不新增安全证明，不改变原论文参数、Gaussian 解释、签名方程，不涉及 HIBE。

论文：Jia–Liu–Tang–Wang，*Constructing Efficient Identity-Based Signatures on Lattices*，[DOI 10.1049/ise2/6684889](https://doi.org/10.1049/ise2/6684889)。冻结 PDF `papers/2025_efficient_ibs_jia.pdf`，SHA-256 为 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。原 Table 4 输入保持 `n=512,p=16383,b=31,w=2,q=961,Q=15744063,d=2/3/4`，解释为 `table-standard-deviation` 和 `literal-density-width`。项目采用的论文安全性工作假设不是新增验证。

## 当前代码版本

`SourceSchurBackend` 默认执行完整门控，固定发钥服务默认使用它。`GuardedSourceSchurBackend` 只是兼容别名，不叠加第二次审计。完整门包括 master/sign plan 构造、`SchurNumericalAudit`、`_source_gates`，以及 Setup 的 directed C 门和有限密钥对象包络。Setup 操作性门失败拒绝根并重试；签名门失败中止固定密钥，不重抽、不换钥。程序错误和任意运行异常不静默伪装成概率性拒绝。

文中旧“非门控后端”只指历史版本；旧探针已停用，不能把停用写成“搜索未找到反例”。

| 集合 | 定义 |
|---|---|
| `A` | 数学正定条件 `Sigma_p-r²I>0` |
| `G_C` | 数学条件 `C>64I` |
| `B_legacy` | 历史非门控准备成功 |
| `H_setup` | 当前实际完整 Setup 构造和门控 |
| `H_sign` | 当前实际完整签名构造和门控 |

旧 v3 中的 `G` 曾表示审计门，另一包却用它表示数学 C 门；现在不再混用。可靠区间给出 `B_legacy⊂A` 与 `H_setup⊂G_C⊂A`，不提供反向的实现完备性。

## 通过完整门后的统一条件界

公式依赖门限 64、gain/factor 误差门 `2^-128`、center 误差门 `2^-96`、固定数值窗口及根无关标量预算。六条根及第二条不同根只是门控非空的功能见证；实际 pivot/gain 数值只用于检查门，不替代公式中的统一常数。

| 原表行 | 解释 | master joint | signature joint | 首发钥 | 仅发钥容量历史 | 单次签名 |
|---|---|---:|---:|---:|---:|---:|
| I | std | `2^-26` | `2^-25` | `2^-25` | `2^-24`（3身份） | `2^-19` |
| II | std | `2^-25` | `2^-24` | `2^-25` | `2^-24`（2身份） | `2^-18` |
| III | std | `2^-25` | `2^-24` | `2^-24` | `2^-24`（1身份） | `2^-18` |
| I | literal | `0.6781…` | `0.8964…` | null | null | `1` |
| II | literal | `0.8173…` | `0.9666…` | null | null | `1` |
| III | literal | `0.8964…` | `0.9893…` | null | null | `1` |

这些数值**条件于全部适用门实际通过**、独立均匀字节及规定的无异常 MPFR 模型，abort 作为输出符号。literal 首发钥的 gadget normalizer 充分门失败，组合仍为 null；单次签名的 1 是平凡界。

## 数学好根结果不能直接变成服务预算

[数学分布链说明](../2026-10-18-srgg-distribution-chain/proof.md)保留 `G_C⊂A`、理想 master Schur 下界 `L2>64`，以及既有 trace moment 的 `mu(G_C^c)≤q_C`、数学条件根律 `q_C/(1-q_A)` 与理想数学重试 `q_C^64`。

统一有限准备误差包络尚未给出，192-bit C 门在边界附近不确定壳层的宽度／质量也未界定。因此旧 `B_legacy` 和当前 `H_setup` 相对论文接受律的 TV、实际门控拒绝质量、当前 64 次 Setup 中止预算仍为 null。常量赋值、边界探针和重试分支修复都不能替代这些概率界；本次不为此新开证明路线。

## 随机发钥后签名

实际与参考使用相同的签名 guard 及 abort 语义，保留已有 data-processing 条件比较：

```text
TV(guarded issue + s adaptive signs) ≤ min(1,δ_issue+s·ε_good)。
```

guard 公式无需单独的 `beta_bad`；无 guard 的质量仍严格为正且未量化，旧大尾反例保留。若发钥时已返回密钥，两侧历史都保留该密钥输出，再应用相同签名门。

std 三行的一签组合上界为 `2^-19/2^-18/2^-18`，两签为 `2^-18/2^-17/2^-17`。literal 组合仍 null。双方使用相同 64 次 norm 重试及 abort；单独 norm-exhaustion 概率未估计。

## 历史与实测范围

只覆盖**逻辑 API 输出与确定性持久状态**：密钥／签名、规范快照、pending/failed/issued、缓存和匹配逻辑错误。双方要求相同逻辑调度、共同 guard/abort 语义和相同 Setup 律，或明确条件于相同成功 Setup 根。新身份支付首发钥项，缓存重发不重复支付。

时间、锁调度、熵消耗、内部采样／运行轨迹不在范围。磁盘／进程／回滚／断电没有概率模型；故障历史仍 null。包含实际 Setup 律的完整服务历史仍 null，不自动加入数学 `q_C` 作为实现费用。

旧 compact 尺寸、时间和 RSS 在其冻结后端上实测，不能直接继承为当前 guard 默认服务的实测结果。作者 sampler 对应、来源歧义、native strong、结构困难性、正式准入及 NIST 状态均不升级。

## 文件与复现

- [proof.md](proof.md)：统一版本语义与条件模型。
- [distribution-guard.json](distribution-guard.json)：六行条件比较、探针状态及 null。
- [validation.json](validation.json)：测试、源和回执指纹。
- 源码：`experiments/research/candidates/srgg/paper_distribution_guard.py`。

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q \
  tests/test_srgg_paper_distribution_guard.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m \
  experiments.research.candidates.srgg.paper_distribution_guard \
  --output build/deepseek-distribution-guard-new.json
```

输出路径须不存在。历史环境为 WSL Sage 10.9 / Python 3.13.15，实际复核环境以 validation 为准。功能测试、文件指纹与有限 TV 界不能替代安全证明。

始终：`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。
