# SRGG 参数来源与定理门审计

本批只处理 SRGG 独立 IBS 的参数来源和定理条件，不读取或修改 HIBE、公共组合、CLI 或注册表。可执行审计为
[`parameter_closure.py`](../../../../experiments/research/candidates/srgg/parameter_closure.py)，公开收据为
[`parameter-closure.json`](parameter-closure.json)。

审计冻结的论文为 `papers/2025_efficient_ibs_jia.pdf`，SHA-256 为
`258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。核对位置是 Theorem 1（p.4）、Table 3（p.6）、Algorithms 7--8（p.8）和 Section 5.1/Table 4（p.9--10）。

## 本批闭合的可复查事实

三行原参数都固定为 `n=512`、`p=16383`、`b=31`、`w=2`、
`q_gadget=31^2=961`、`Q=p*q_gadget=15,744,063`。Theorem 1 的显示条件是奇数模数
`q > max(2γ, s1*η_ε(Z^m))`；验证和响应关系使用 `2Q`。收据把三种可能的模数识别分别列出：

| 论文行 | `γ` | `q_gadget` | `Q` | `2Q` | `Q>2γ` | `2Q` 奇数且 `2Q>2γ` |
|---|---:|---:|---:|---:|---|---|
| PARAM-I | 42,086,491.7 | 961 | 15,744,063 | 31,488,126 | 否 | 否 |
| PARAM-II | 63,653,172.0 | 961 | 15,744,063 | 31,488,126 | 否 | 否 |
| PARAM-III | 86,573,930.5 | 961 | 15,744,063 | 31,488,126 | 否 | 否 |

因此不能把 Theorem 1 的 `q` 静默改成 `Q`，也不能把偶数 `2Q` 当成定理中的奇数 `q`。每行所需的最小奇数 `q>2γ` 和固定 `p,b` 下的诊断性首个宽度 `w=3` 也记录在收据中。`w=3` 产生 `Q=488,065,953`，这是新参数诊断点，不是论文复现；它没有继承原表的高斯宽度、范数、采样预算或困难性估计。

## ε 与 r 的来源分支

Table 3/Section 5.1 的公式经 PDF 页面复核，根号覆盖普通数字 `256`，因此来源读法为：

* 来源读法：`ε = 1/sqrt(Q_s*256) = 2^-24`；
* 另保留 `ε = 1/sqrt(Q_s*2^56) = 2^-48` 和 `ε = 1/(sqrt(Q_s)*256) = 2^-28` 作为转录敏感性分支。

这只确认了 PDF 中的公式分组，不等于作者已明确说明 `r` 应按物理标准差还是 density shape 使用。对每一行使用论文维度
`m=(2+w)(d+1)n` 和字面 `r=1.16`，在 `exp(-π x^T Σ^-1 x)` 的 shape 解释下，最短对偶向量给出严格必要条件反例：
`2m/243` 大于两种 ε，故两种分组下字面 shape-width 都失败。这个检查只是否定必要条件，不是充分平滑证书；把表中数值当作物理标准差并转换为 shape `2πr²` 是另一条待作者确认的解释。

对来源 `ε=2^-24` 分支，收据另外给出物理标准差的高精度数值诊断：固定 `m=4·5·512=10240`、`r=1.16` 时，首向量质量项约为 `5.9703494432×10^-8`，而 `ε=5.9604644775×10^-8`；要通过这一条必要门，诊断下界约为 `r=1.1600361835`。这不是区间证明，也不是作者归一化的确认，但说明把 `1.16` 当作已闭合的精确平滑参数仍然不成立。

同一批还保留 ζ 算子产生的 shape factor 2 与 Algorithm 7 字面 perturbation factor 1 的冲突。它们不能通过统一单位或接口改名自动等价。

## 仍未闭合

这份收据没有把任何候选提升为正式参数，状态仍为
`security_claim=none`、`parameters_are_formal=false`、`backend_admitted=false`、
`nist_security_category=null`。后续独立 IBS 工作仍需：

1. 固定作者对 ε、`r`、`q/Q/2Q` 和 ζ factor 的解释；
2. 将有限 SampleF 误差从顺序参考采样器桥接到 HNF 发钥和最终签名 law，并补完整服务中止预算；
3. 复核环/CRT/子域结构攻击与 MSIS/Module-LWE 对应，区分论文自报 Core-SVP 与本地启发式估计；
4. 补 native strong、ROM/QROM 查询损失和固定发钥失败接口的完整映射。

## 复核命令

```text
python -m experiments.research.candidates.srgg.parameter_closure \
  --output docs/research/team-b-delivery/2026-10-17-srgg-parameter-closure/parameter-closure.json
python -m pytest -q tests/test_srgg_parameter_closure.py \
  tests/test_srgg_source_correspondence.py tests/test_srgg_closure_ledger.py
```

本批结果是参数来源和必要条件的审计证据，不能替代安全证明、完整采样分布、困难性估计或 HIBE 组合验收。

## 2026-10-18 续审：数值修复与局部预算（WIP）

[续审说明](completion.md)记录了 Sage 区间端点的严格转换修复、固定原 r 的全中心 theta 界、条件性签名范数/64次重试界，以及同一原 PARAM-III 根上的160/192位数值比较。旧参数、失败与优化尝试保留；旧有限数值收据涉及的端点保证须重新核验。

机器材料为 [来源/资源汇总](completion.json)、[归一化预算](rounding-budget.json)、[条件范数预算](norm-budget.json)、[同根精度实测](precision.json)和[历史条件预算](historical-service-budget.json)。六个局部归一化维度通过 `ε=2^-24`，不替代论文 `m=10240` 的条件；后者对当前精确实现 shape 已有严格必要条件失败证书。正式参数、HNF/签名分布与完整安全归约仍未闭合。

本批修改文件、完整测试命令与结果见 [validation.json](validation.json)，源码和公开产物哈希见 [MANIFEST.json](MANIFEST.json)。[旧失败回归](ci-initial-failed.json)保留源码 guard 的拒绝结果；[最终回归](ci-final.json)与 [JUnit](ci-final.xml)对应修复后的版本，两者不混作同一次验证。端点错误的[修复前诊断](interval-endpoint-probe.json)只保留为历史证据，当前包含关系由独立端点回归检查。
