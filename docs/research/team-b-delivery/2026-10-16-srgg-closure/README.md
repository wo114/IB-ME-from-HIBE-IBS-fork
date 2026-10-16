# SRGG 第②③④项统一核验账本

日期：2026-10-16。本文把 SRGG 的三项后置工作放进一份可复查的账本：

1. 原论文—实现—实际反例对应；
2. 有限 SampleF 误差、内部中止和退化上界；
3. 完整经典归约、QROM、困难性和其它剩余条件的逐项状态。

机器可读收据为 [`closure-ledger.json`](closure-ledger.json)，生成器为
[`closure_ledger.py`](../../../../experiments/research/candidates/srgg/closure_ledger.py)，
测试为 [`test_srgg_closure_ledger.py`](../../../../tests/test_srgg_closure_ledger.py)。
它只汇总已有证据并保留未闭合项，不修改 SRGG 算法、参数、公共 registry、CLI 或 HIBE。
收据同时记录冻结论文、输入票据和生成器自身的 SHA-256，便于复核时发现版本漂移。

## 已核对的内容

论文 PDF 固定为 `papers/2025_efficient_ibs_jia.pdf`，SHA-256 为
`258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。
三组 Table 4 输入、`ζζ*=2`、2Q 恢复和 HNF 代数对应已经有来源映射与精确夹具。
实现仍保留 `factor1`、两种 Gaussian 解释、论文给出的 `r≈1.16` 和 centered
模代表；没有用修改参数来消除歧义。

当前实现的真实观察也保留：PARAM-II/III 出现同消息 `±Q` 替换后仍通过验证。
这是 native strong 目标的实现反例；它不是 fresh-message EUF 伪造，也不自动否定论文
普通 EUF 结论。默认 PARAM-I 没找到候选只说明该次探测没有命中。

## 有限采样结果

账本直接引用 `sampling-error-default.json` 和 `sampling-error-width3.json`。在
`table-standard-deviation` 解释下，已有保守 SampleF 总界约为：PARAM-I/II
`2^-15`，PARAM-III 主扰动 `2^-14`，PARAM-III 签名扰动退化为 `1`。在
`literal-density-width` 解释下，三组公开总界均退化为 `1`。这些数字是“有限实现对声明的
顺序参考采样器”的保守上界，包含内部采样中止；它们不是实测 TV、最终 HNF 密钥分布距离、
签名输出分布距离，也不是安全优势。

同一收据还列出三组原参数的 `Q−2γ`、奇偶性和字面平滑必要条件：三组均有
`Q<2γ`，而验证工作在偶数 `2Q` 上；按字面 `r=1.16` 的必要平滑检查也均失败。
这只说明原文符号映射或归一化需要澄清，不能把它改成替代参数或直接判定论文方案无效。

退化原因已经单独写入收据：literal-width 下全维平滑条件不满足；PARAM-III 签名的
center 数值证书自身超过 1。后续可以在不改论文参数的前提下收紧数值证书，但在证书闭合前
不得把 `1` 改写成“已证明高精度采样”。

## 仍未闭合的条件

账本对 12 个 IBS 归约项和 11 个前提逐项保留状态。`delta_issue`、`delta_pub`、
`delta_sim` 等只标为显式模型下的 conditional；`delta0`、实际 alias、非目标已知密钥
签名、seed/H1 overlay 和完整生产失败接口仍为 `null`，不能用局部 `2^-177` 或
`2^-178` 自动填充。QROM 的 coherent first-touch、H1 编程、DFMS/QCUR、复合环
collapsing，环 HNF/MSIS 与 shared-A CBD1 Module-LWE 困难性也仍未闭合。

因此本批的统一结论是：原文与实现的对应已部分核清，有限采样只有条件性局部界，完整经典
生产归约、QROM、正式困难性参数和 native strong 安全均未完成。收据继续使用
`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。

## 复核命令

在仓库根目录运行：

```text
python -m pytest -q tests/test_srgg_closure_ledger.py
python -m experiments.research.candidates.srgg.closure_ledger --output build/outputs/srgg-closure-2026-10-16/closure-ledger.json
```

该生成器不需要 Sage；它只校验冻结论文摘要和已有 JSON 收据的 SHA-256。完整 SampleF
证书和 SRGG 生命周期仍按各自目录的 WSL Sage 命令复核。
