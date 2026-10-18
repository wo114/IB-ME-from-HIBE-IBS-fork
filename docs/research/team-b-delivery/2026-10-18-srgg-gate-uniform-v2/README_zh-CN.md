# SRGG 门控一致范围 v2：重冻结说明

日期：2026-10-18。本包是 **范围标签的 v2 重冻结**，不是对 v1 数值回执的改写。
v1 的四个包（finite-chain、source-issuance、history-law-followup、
random-key-sign-law）保持原始字节和 MANIFEST 不变，继续作为“当时实际执行了什么”
的证据；本包只冻结纠正后的**适用域声明**、完整门控清单、guard 语义和剩余 null。

## 一句话

v1 的 `fixed_root_only` / `all_accepted_setup_roots_covered: false` 是**回执生成范围**，
不是不等式的适用范围。正确表述：

> 对任意通过**完整门控集**的 Setup 根或签名密钥，分别应用相应的条件界；
> 六条根是门可通过的见证，不是定理的定义域。

## 完整门控集

guard（`GuardedSourceSchurBackend`）必须检查全部下列项，缺一不可：

1. 所有理想 Schur pivot ≥ 64；
2. gain 系数误差 ≤ `2^-128`；
3. stored-factor 理想协方差误差 ≤ `2^-128`；
4. 同一成功历史上的 adaptive-center 递推误差 ≤ `2^-96`；
5. stored factor 落在 `(2, 2^32)`；
6. adaptive center 绝对值 < `2^240`；
7. scalar/aggregate 熵帽与整次尝试熵预算；
8. finite leaf/output 的 256-bit 对象门；
9. **发钥 centered-gadget C 门**（`C > 64 I`）；
10. 成功 finite-key 的对象/服务字节包络（raw 与 HNF key 均在 256 bit 内）。

guard 的语义：Setup 门失败 → 根拒绝并重试；签名门失败 → 固定密钥中止。
这证明的是**修改后的受保护接受集**，不能直接声称原论文未加门的算法也满足。

## 代码实现路径

- **live guarded 路径**：[`src/ibme/ibs/srgg_paper_service_guarded.py`](../../../../src/ibme/ibs/srgg_paper_service_guarded.py)
  的 `GuardedSourceSchurIssuer`，默认后端为 `GuardedSourceSchurBackend`；
  `tests/test_srgg_paper_service_guarded.py` 验证 initialize、首钥、重开与门记录。
- **v1 冻结证据**：`srgg_paper_service.py:FixedIssuer` 与 `SourceSchurBackend`
  保持原字节，不被静默改写；它们只作为“当时执行了什么”的证据。
- **默认 `srgg2025` registry 不变**：它走 `src/ibme/ibs/srgg/` 的独立路线，
  不是 paper source-Schur 链；本次修正不影响该默认路径。
- 若要让旧 `FixedIssuer` 符号本身改用 guard，需要修改 v1 源码并重冻结代码
  manifest（v1 字节证据将失效）；本包选择新增 guarded 服务，而不是改写 v1。

## 数值不变

条件界的数值与 v1 完全一致（标准差异解释行）：

| profile | master joint | signature joint | first issuance | capacity history | one sign call |
|---|---:|---:|---:|---:|---:|
| PARAM-I | `2^-26` | `2^-25` | `2^-25` | `2^-24` (3 ids) | `2^-19` |
| PARAM-II | `2^-25` | `2^-24` | `2^-25` | `2^-24` (2 ids) | `2^-18` |
| PARAM-III | `2^-25` | `2^-24` | `2^-24` | `2^-24` (1 id) | `2^-18` |

字面 density-width：master ≈`0.678/0.817/0.896`、signature ≈`0.896/0.967/0.989`；
首次发钥仍为 `null`（gadget digit-normalizer 充分门失败），单次签名调用为 `1`。

## 仍为 null（v2 不解决）

- `P(A\B)`：数学正定 vs 有限后端接受；
- `P(B\G)`：后端接受但完整门控失败；
- 被 guard 拒绝的根/密钥质量，以及接受根相对 `mu_A` 的分布；
- `beta_bad`：理想发钥下签名门失败质量（严格为正，无数值上界）；
- 完整随机发钥+签名历史（无故障/有故障）；
- norm-exhaustion 概率、native strong、结构性困难、NIST 等级。

## 文件

- [`scope-correction.json`](scope-correction.json)：四个 v1 包的 manifest 哈希、
  逐包纠正字段、完整门控集、数值表、null 清单。
- [`proof.md`](proof.md)：v2 范围证明与 guard 语义。
- [`verify_delivery.py`](verify_delivery.py)：纯 Python 校验 v2 文件、v1 manifest
  和全部 v1 条目字节、以及 guard 报告。
- [`validation.json`](validation.json)：命令与结果。
- guard 实现与审计：
  [`../2026-10-18-srgg-distribution-guard-deepseek/`](../2026-10-18-srgg-distribution-guard-deepseek/README_zh-CN.md)。

始终：`security_claim=none`、`backend_admitted=false`、
`parameters_are_formal=false`、`nist_security_category=null`。
