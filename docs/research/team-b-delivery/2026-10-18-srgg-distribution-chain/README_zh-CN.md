# SRGG 独立 IBS 分布链：好根蕴含、接受根界与 guard 组合（WIP）

本包只处理 Jia–Liu–Tang–Wang 独立 IBS，不涉及 HIBE、公共组合或正式安全准入。
基线为 `cd31389f91e5` 的独立分支；原文参数
`n=512, p=16383, b=31, w=2, q=961, Q=15744063, d=2/3/4` 与两种显式 Gaussian
解释（`table-standard-deviation` / `literal-density-width`）均未改动。论文为
`papers/2025_efficient_ibs_jia.pdf`，SHA-256
`258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。

## 一句话结论

本轮真正闭合的是**好根蕴含**：`G = {C > 64I}` 严格强于原论文数学正定门 `A`，
并给出 master Schur pivot 的统一下界 `L2≈4.0e5/5.7e5/7.4e5`、gain/factor/center/
entropy/object 的统一门限。因此**原后端接受集 `B` 包含 `G`**，于是
`P(A\B) ≤ P(A\G) ≤ q_C`，且 `TV(μ(·|A), μ(·|B)) ≤ q_C/(1−q_A)`。
这是对全部实际 CBD1 根的概率界，不是固定根外推。

随机发钥签名方面，guard 同时作用于实际与参考后，**`beta_bad` 被
data-processing 吸收**，不再需要单独界定：
`TV(guarded issue + s signs) ≤ min(1, δ_issue + s·ε_good)`。
无 guard 的 `beta_bad` 仍为 `null`（严格为正）；字面 density 解释的首发钥仍为
`null`，单次签名仍为平凡 `1`。

## 好根蕴含（六行）

`C = νI − ν²T*Σ⁻¹T`，`C_schur = a1I − (νa2/(a2−ν))RR*`，
`G = {C > 64I}`。所有比较均为精确有理数。

| 原表行 | 解释 | `T_A` | `T_C` | `T_schur` | `L2` | gain 上界 | factor 范围 |
|---|---|---:|---:|---:|---:|---:|---:|
| PARAM-I | std | 6246.722948 | 6197.457690 | 6246.716130 | 400780.155 | 252.6 | (250, 8192) |
| PARAM-I | literal | 6246.722948 | 5937.174656 | 6246.674566 | 400780.155 | 39.4 | (250, 8192) |
| PARAM-II | std | 8926.269269 | 8855.877898 | 8926.262453 | 572585.423 | 252.6 | (250, 8192) |
| PARAM-II | literal | 8926.269269 | 8483.981684 | 8926.220885 | 572585.423 | 39.4 | (250, 8192) |
| PARAM-III | std | 11555.616682 | 11464.494961 | 11555.609867 | 741172.329 | 252.6 | (250, 8192) |
| PARAM-III | literal | 11555.616682 | 10983.076458 | 11555.568297 | 741172.329 | 39.4 | (250, 8192) |

因为 `T_C < T_A` 且 `T_C < T_schur`，有

```text
G ⇒ A,      G ⇒ C_schur ⪰ L2 I,  L2 > 64.
```

进一步在 `G` 上统一得到：gain 系数误差 ≤`2^-256`、gain l1 ≤`2^14`、
stored factor 在 `(250,8192)`、adaptive center 递推误差 `<2^-96`、
输出/对象包络 <`2^64` bit。因此未修改的 `SourceSchurBackend.setup`
在 `G` 上必须接受，即 `G ⊂ B`。边界探针（`C` 刚过 64 的根）已在三组
profile 上跑通 Setup / C gate / master & sign audit / object envelope /
Extract / Sign / Verify。

## 接受根分布界

`B ⊆ A`（区间后端可靠时），`G ⊂ B`，故 `A\B ⊆ A\G`。用既有精确
complex-Wishart trace moment 在 `T_C` 处求值：

```text
P(A\B) ≤ q_C,     TV(μ(·|A), μ(·|B)) ≤ q_C/(1−q_A).
```

| 原表行 | 解释 | `q_A` | `q_C` | 接受根 TV 上界 | guard 64 次中止（若全部重试） |
|---|---|---:|---:|---:|---:|
| PARAM-I | std | 0.205519 | 0.235130 | 0.295954 | `2^-133` |
| PARAM-I | literal | 0.205519 | 0.487621 | 0.613760 | `2^-66` |
| PARAM-II | std | 0.095133 | 0.113233 | 0.125138 | `2^-201` |
| PARAM-II | literal | 0.095133 | 0.290989 | 0.321582 | `2^-113` |
| PARAM-III | std | 0.046673 | 0.058256 | 0.061108 | `2^-262` |
| PARAM-III | literal | 0.046673 | 0.193644 | 0.203125 | `2^-151` |

精确分数见 `distribution-chain.json`；上表小数只作阅读。**重试模型必须分开**：
原后端只对 `WitnessGeometryError` 重试，区间/gain/center/资源失败是
`ValueError` 直接中止；所以 `q_C^64` 只适用于“所有 `G` 失败都重试”的
guarded 重试模型，原后端的非重试失败只有单次 `q_C` 上界。

## 随机发钥签名与无故障历史

`G` 上首次发钥 TV 为 `δ_issue`。签名 guard `g`（signing plan audit）同时作用于
实际密钥律 `P_K` 与理想参考 `Q_K`；由 data processing：

```text
TV(g#P_K, g#Q_K) ≤ TV(P_K,Q_K) ≤ δ_issue.
```

好密钥上一次签名的核距离为统一的 `ε_good`；坏密钥两侧都 abort。于是

```text
TV(guarded issue + s signs) ≤ min(1, δ_issue + s·ε_good).
```

无 guard 的 `beta_bad` 仍为 `null`（大尾反例证明严格为正），但 guarded 定理
不需要它。标准差异解释的数值与既有回执一致：

| 原表行 | 解释 | `δ_issue` | `ε_good` | guarded 发钥+1 签 | guarded 发钥+2 签 |
|---|---|---:|---:|---:|---:|
| PARAM-I | std | `2^-25` | `2^-19` | `2^-19` | `2^-18` |
| PARAM-II | std | `2^-25` | `2^-18` | `2^-18` | `2^-17` |
| PARAM-III | std | `2^-24` | `2^-18` | `2^-18` | `2^-17` |
| I/II/III | literal | `null` | `1` | `null` | `null` |

字面 density 三组的 `ε_good` 是平凡 `1`，但 `δ_issue` 缺失，所以 guarded
发钥+签名的组合界仍为 `null`；不能把单独的签名核界 `1` 当作组合界。

无故障完整历史在 guarded 服务下为
`min(1, δ_issue + s·ε_good)`；若参考根律取论文的 `μ(·|A)` 而不是同一
`G`，再加 `q_C/(1−q_A)`。缓存重复请求不重复计费；每个新身份付一次首发钥项。
外部磁盘/进程/锁/回滚故障没有概率模型：注入概率 `p` 的读故障给出 TV=`p`，
所以有故障历史仍为 `null`，不能从无故障界推出。

## 仍为 null（不静默置零）

- 无 guard 的 `beta_bad` 质量；只有严格正性，没有数值上界。
- 全部 `B` 接受根上的有限链/发钥统一或平均界：`q_C` 只是根律距离；
  `B\G` 的每根误差仍未界定，guarded 服务只接受 `G`。
- 原后端非重试 64 次中止；只有单次 `q_C`。
- 字面 density 解释的首发钥 `δ_issue`（gadget digit-normalizer 充分门失败）
  与单次签名（平凡 `1`）。
- 作者省略的 `SampleZ`/C 程序逐位实现、原文 `r/σ`、Algorithm 4 `d/f`、
  `ζ` 因子、`q>2γ` 等来源歧义。
- native strong、结构困难性、正式参数准入、NIST 等级。
- 故障概率与有故障完整历史。
- norm-exhaustion 的单独概率（只包含在一次签名核距离里）。

## 文件与复现

- [`proof.md`](proof.md)：模型、假设、推导、原文/代码对应、null 账本。
- [`distribution-chain.json`](distribution-chain.json)：六行精确有理界与 null 原因。
- [`boundary_probe.py`](boundary_probe.py)：`C` 边界见证的确定性搜索 + 完整门控生命周期探针。
- [`boundary-PARAM-I.json`](boundary-PARAM-I.json)、[`boundary-PARAM-II.json`](boundary-PARAM-II.json)、[`boundary-PARAM-III.json`](boundary-PARAM-III.json)：三组边界回执。
- [`validation.json`](validation.json)：测试命令、边界探针、报告与文件哈希。
- [`verify_delivery.py`](verify_delivery.py)：纯 Python 复核精确恒等式、六行覆盖和边界回执。
- 代码：`experiments/research/candidates/srgg/paper_distribution_chain.py`。
- 测试：`tests/test_srgg_paper_distribution_chain.py`。

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q \
    tests/test_srgg_paper_distribution_chain.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m \
    experiments.research.candidates.srgg.paper_distribution_chain \
    --output build/distribution-chain.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m \
    experiments.research.candidates.srgg.paper_distribution_chain \
    --lifecycle --output build/distribution-chain-lifecycle.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python \
    docs/research/team-b-delivery/2026-10-18-srgg-distribution-chain/boundary_probe.py \
    --profile PARAM-I --output docs/research/team-b-delivery/2026-10-18-srgg-distribution-chain/boundary-PARAM-I-new.json
/usr/bin/python3 docs/research/team-b-delivery/2026-10-18-srgg-distribution-chain/verify_delivery.py
```

输出路径必须尚不存在。环境：WSL2、Sage 10.9、Python 3.13.15；详见 JSON 中的
platform 与依赖 SHA-256。功能测试、边界探针和有限 TV 上界都不是安全证明。

始终：`security_claim=none`、`backend_admitted=false`、
`parameters_are_formal=false`、`nist_security_category=null`。
