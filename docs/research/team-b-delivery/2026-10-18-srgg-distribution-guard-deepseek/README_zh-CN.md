# SRGG 分布链：门控集上的统一界、显式保护与仍为 null 的量（独立审计）

本包只处理 Jia–Liu–Tang–Wang 独立 IBS 的分布链，不涉及 HIBE、公共组合或正式安全准入。
基线为 `cd31389f91e5` 的独立分支；原文参数（`n=512, p=16383, b=31, w=2, Q=15744063, d=2/3/4`）和两种显式 Gaussian 解释均未改动。
论文：`papers/2025_efficient_ibs_jia.pdf`，SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。

## 一句话结论

前人把六条固定根回执标成 `fixed_root_only`，但**回执里的每个数值项都只依赖审计门限 64 与根无关常数**：固定根只是"门控集非空"的见证，不是定理的定义域。真正缺的不是"所有接受根上的新分布定理"，而是**让后端真正执行这些门限（guard）以及门控事件的概率**。随机发钥的 `beta_bad`、数学/后端接受差 `P(A\B)` 仍是 `null`，且这份工作没有让它们变小。

## 哪些界真正闭合（标准差异解释行）

| 界 | PARAM-I | PARAM-II | PARAM-III |
|---|---:|---:|---:|
| master 有限→数学→理想联合 | `2^-26` | `2^-25` | `2^-25` |
| signature 同上 | `2^-25` | `2^-24` | `2^-24` |
| 首次发钥 TV | `2^-25` | `2^-25` | `2^-24` |
| 容量历史（3/2/1 身份） | `2^-24` | `2^-24` | `2^-24` |
| 单次签名调用 | `2^-19` | `2^-18` | `2^-18` |

字面 density 解释：数学联合界非平凡但很弱（P-I/II/III master `0.678/0.817/0.896`，signature `0.896/0.967/0.989`），首次发钥因 gadget digit-normalizer 充分门失败而保持 `null`，单次签名调用为平凡 `1`。这些界的前提：独立均匀字节、规定的 768-bit MPFR 无异常模型、中止作为独立符号、门控集 `G`（所有理想 Schur pivot ≥64、gain/factor 误差门、center 误差门等），**不是**全部数学正定事件 `A`。

## 真正新颖的两件事

1. **门控一致性证明与复核**：把 joint/issuance/sign 回执按门限 64 重算，逐项与冻结 JSON 完全一致（`joint-fixed-root.json`、`source-issuance.json`、`history-law.json`）；另一条不同的接受根得到完全相同的 master 界。因此 `fixed_root_only` 是回执范围标签，不是不等式范围。
2. **显式 guard**：`GuardedSourceSchurBackend` 在 Setup 与签名前执行 `SchurNumericalAudit` + `_source_gates`。Setup 把门失败当作根拒绝并重试；签名把门失败当作固定密钥中止。原始后端不执行这些门；guard 是服务/接受集变体，不是论文算法本身。

## 仍为 null 的量（原因见 proof.md）

- `P(A\B)`：数学正定 ≠ 实际有限数值接受；缺 anti-concentration/conditioning 界。
- `P(B\G)`：原始后端接受但审计门失败；JSON 只有确定性搜索，不是概率。
- 接受根在 `A` 上的分布：需要上面两个质量。
- `beta_bad`：理想 centered-HNF 发钥下签名门失败的质量；宽度远小于 `Q`，模 `Q` 不平滑，`P_D(S_h)` 没有目标一致下界；但严格为正（规范大尾见证）。
- 完整无故障随机发钥+签名历史：`min(1, alpha_root + delta_issue + beta_bad + s*epsilon_good)`，因 `alpha_root`/`beta_bad` 为 null。
- 故障历史：没有故障概率模型；注入故障可使 TV=1。
- norm-exhaustion 概率、native strong、结构性困难、正式参数、NIST 等级。

## 独立判断：GPT 的路线是否过度保守

- **正确**：全参考密钥一致证书确实不可能；`beta_bad` 与 `A\B` 确实不能由现有矩界给出；条件发钥分母是真正的瓶颈；不能宣称安全。
- **过度保守**：`fixed_root_only` 标签掩盖了"所有数值项都是门限常数"这一事实；任务实际剩下的是 **accept-set guard + 门控质量**，不是"所有接受根上的新分布定理"。guard 是前人"两条替代路线"之外的第三条路线；它是接受集/服务语义变更，不是原算法的证明，但便宜且可审查。
- **仍然困难且 guard 不会消除**：`P(A\B)`、`P(B\G)`、`beta_bad`、故障历史。

## 文件

- [`proof.md`](proof.md)：完整模型、推导、原文/代码对应、null 账本。
- [`distribution-guard.json`](distribution-guard.json)：六行参数/解释组合的界、null 原因、guard 探针。
- [`validation.json`](validation.json)：测试命令与结果、源/回执哈希。
- 代码：`experiments/research/candidates/srgg/paper_distribution_guard.py`。
- 测试：`tests/test_srgg_paper_distribution_guard.py`。

## 复现

```bash
cd IB-ME-from-HIBE-IBS
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q \
    tests/test_srgg_paper_distribution_guard.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m \
    experiments.research.candidates.srgg.paper_distribution_guard \
    --output build/deepseek-distribution-guard.json
```

环境：WSL `~/miniconda3/envs/sage`（Sage 10.9 / Python 3.13.15 / Linux 6.18.33.2 / Core Ultra 9 275HX / OMP4 OpenBLAS1）。
功能测试与有限样本不是安全证明。

始终：`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。
