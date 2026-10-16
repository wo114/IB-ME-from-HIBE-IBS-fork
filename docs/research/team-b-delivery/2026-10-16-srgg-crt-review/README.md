# SRGG：mod 3 联合分布与剩余归约条件

2026-10-16。本批继续独立 SRGG 六项联合目标，基于本地 `515ca5a`，保留
native strong。用户要求全部与 HIBE 选择无关的完整工作完成后才统一 fork＋PR；
本批仅本地提交。**完整目标仍为 active/WIP，未得到正式安全参数。**

```text
security_claim=none
backend_admitted=false
parameters_are_formal=false
nist_security_category=null
```

## 本批得到什么

1. [CRT 分布推导](projection-law.md) 与
   [可执行工具](../../../../experiments/research/candidates/srgg/crt_projection.py)：
   对真实 CBD1 系数计算单因子及完整 mod 3 投影的联合分布，包含公开 Ahat，
   保留两个 CRT 因子之间的秘密相关性。按相同 Ahat 的独立列合成；固定
   `B=pG−(Ahat S+E)` 的平移及符号不增加 TV。
2. [经典完整输入域审查](classical-namespace-review.md)：在明确的单一理想
   byte-XOF 模型及相同语义 kernel 下，完整 raw-frame、其它 public 查询、
   重复 seed 的共享矩阵、首次 prefix/offset 和失败均可条件同分布对应。
   单纯扩充输入域的费用为零；生产对象接入及整体 Delta0 另列。
3. [量子 collapsing 路线](collapsing-route.md)：核查可用的一手定理，给出
   uniform ring-HNF collapsing 到实际响应关系的条件变换，并明确结构化
   公钥分布、允许的辅助信息和参数条件。条件变换不等于其假设已经成立。

对于 mod 3，令 `t=3^(dn/2)`、`c=(57/512)^(dn/4)`、`C=(3/8)^(dn)`。
完整两因子、单列、包含均匀公开 Ahat 的平均 χ² 恰为

```text
t² C² + 2t c(c−C) − 2c + C.
```

工具采用精确整数／有理数，给出 TV 的保守 dyadic 上界：

| 公开算术点 | 完整 mod 3 单列 TV 上界 | 全部共享 Ahat 列的 TV 上界 |
|---|---:|---:|
| n512 / d2，16 列 | 2^-406 | 2^-402 |
| n2048 / d3，66 列 | 2^-2430 | 2^-2424 |

该结论适用于 `3 | Q`、独立 CBD1 S/E 以及已声明的均匀 Ahat 模型；不要求
base=3。它只排除“mod 3 因子次数低就足以区分”的推断，**没有证明 3 的高次幂、
其它素因子或完整 Q 下的困难性**，也不是同一安全强度下的性能比较。

## 证据和复现

新测试为 [test_srgg_crt_projection.py](../../../../tests/test_srgg_crt_projection.py)，
覆盖独立的 81 输入加权除法、F9 完整公开 A/noisy-value 联合枚举、n4 完整
负循环环的 81³ 加权枚举、真实 Sage 商环、严格输入和多列费用。
精确命令、计数、环境及原始收据散列见 [validation.json](validation.json)。
Windows 的真实 Sage 商环检查会跳过；指定 WSL Sage 的专项检查必须实际执行。

root 另用原负循环多项式乘法、未调用新工具，枚举 n4/d1 的全部 81 份 A 和
各 81 份 S/E，得到 χ²=`205665/16777216`，与四种差分零模式公式一致。
收据为 [independent-mod3-enumeration.json](independent-mod3-enumeration.json)。
所有新实验均为零熵算术／穷举，不生成用户、消息、密钥或签名，没有新增攻击
执行或大维真实生命周期；随机重复次数不适用。身份和消息长度不适用。
ROM 用于单独的经典模型讨论，不把真实 SHAKE 描述为已被统计证明的随机函数。
功能测试和有限枚举不能替代安全归约。

[parameter-collapse-gates.json](parameter-collapse-gates.json) 另保留两份既有
参数的 `Q/√Bsig` 精确有理区间：n512 点小于 906，新 n2048 候选严格在 2 与
3 之间。这些比值不是 collapsing 定理的完整参数验收，也不能用固定阈值替代
论文的渐近条件。后者还需具体的噪声分布、结构化归约与时间／优势预算。

```text
python -m pytest -q tests/test_srgg_crt_projection.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_crt_projection.py
python -m experiments.research.candidates.srgg.crt_projection --output build/outputs/srgg-crt-new.json
python experiments/research/srgg_proof_followup_delivery_check.py --delivery docs/research/team-b-delivery/2026-10-16-srgg-crt-review
python -O experiments/research/srgg_proof_followup_delivery_check.py --delivery docs/research/team-b-delivery/2026-10-16-srgg-crt-review
```

输出须使用不存在的新文件名。[MANIFEST.json](MANIFEST.json) 是 Git 审查下的
字节清单，核对新源码、测试、文稿、报告、收据与旧冻结依赖，不是数字签名或
第三方安全认证。原始输出留在 ignored `build/outputs/srgg-crt-review-2026-10-16/`；
本地交付镜像和提交列表另存两工作目录的 ignored checkpoint。

## 六项目标仍需完成的部分

ζ／Gaussian 约定、HNF latent 分布、有限 SampleF 输出和服务总预算已经有各自
限定的推导与证书，见 [上一批入口](../2026-10-16-srgg-bounded-runner/README.md)。
本批没有重写其原始数值或扩大适用范围。完整目标剩余内容为：

- 将诚实发钥／签名的全部条件 law、历史状态、服务故障参考和明确资源范围合成
  整体 Delta0；新的全 raw 域执行器若实施，必须另核 parser、表示和源字节预算。
- 完成 QROM H1 与目标签名的整场模拟，证明实际分布和允许辅助信息下的
  collapsing／量子提取，或建立另一条保留 native strong 的完整归约。
- 核完整环／复合 Q／CBD1 的困难性及归约时间和优势，按 Kyber/ML-KEM、NIST
  的长期对标要求筛定参数；此前的启发式高成本不构成等级。
- 对通过上述条件的新大维候选扩展实际资源和编码范围，运行真实发钥、签验、
  恢复、攻击验收及资源测量。n2048 点本批仍只做算术，没有绕过执行器资源门。

这些缺口与 HIBE 选择无关，当前没有将其标记为完成，也没有推送或更新 PR。
