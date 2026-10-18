# SRGG 原生 strong 游戏与公开同消息替换（WIP）

2026-10-18。原文：Jia、Liu、Tang、Wang，*Constructing Efficient Identity-Based Signatures on Lattices*，DOI `10.1049/ise2/6684889`；冻结 PDF `papers/2025_efficient_ibs_jia.pdf` 的 SHA-256 为 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。本轮定向核对 PDF p.4 Definition 3，p.8 Algorithms 7–8、Theorem 2/G0；未据此声称全文或安全证明完成。

## 原文目标与游戏差别

Definition 3 的赢法要求目标 `(id, μ)` 没有请求签名；Theorem 2 虽写 `sEUF-ID-CMA`，其 G0 仍要求 `(id*, μ*, ·)` 不在签名列表。这两个文字游戏排除**同一身份、同一消息、不同有效签名**。若研究目标确为原生 strong，规范的签名应是唯一编码的 `(context,z,c)`，并把返回过的完整 `(id, μ, σ)` 记录下来；只要最终三元组未返回且身份未显式发钥，该同消息替换就属于该 strong 游戏的候选赢法。本包的公开替换只针对后者，**不**声称赢了论文 G0 的新消息游戏。

## 精确代数和必要范数条件

Algorithm 8 在 `R=Z[X]/(X^512+1)` 的 `2Q` 上恢复承诺。写 `A=[I_d|Â|B]`、`h=H1(id)`、`j=(ζ*,0,…,0)`：

```text
Abar_h = [2A | Qj−2h] mod 2Q
Rec_h(z,c) = Abar_h z − Qjc mod 2Q
Q = 15,744,063
```

第一块是 `2I_d`。任何前 `d` 个响应多项式中的系数单位向量 `e_(i,k)` 都满足 `Abar_h(±Qe_(i,k))=0 mod 2Q`。给定已经通过验签的 `(z,c)`，公开计算 `z'=z+sQe_(i,k)`，原身份、消息、challenge、恢复承诺和 H2 输入均保持不变。唯一还要过的原文验签门是 `||z'||²≤⌊γ²⌋`。若原系数为 `t`，所需充要条件是

```text
||z||² + Q² + 2sQt ≤ ⌊γ²⌋,  s∈{−1,+1}.
```

取 `s` 朝零方向得到两符号中的最小范数：`||z||²+Q²−2Q|t|`。等号允许通过。`z'≠z`，规范编码的字节串不同；`Signature.from_bytes`、`load_signature`、原始 `verify` 都接受时，它是另一条实际有效签名。模块先检查原始签名和公开 `2I` 形状，再计算该式并执行两个恢复式、严格对象往返与验签，不需要用户私钥或额外随机数。搜索范围仅是前 `d×512` 个**单基** `±Q` 替换，不是全部公开伪造。

## 原表参数实跑

[`strong-game.json`](strong-game.json) 是六次独立的 SourceSchurBackend `Setup→Extract→Sign` 后的公开诊断；每组只用第一个成功签名，身份 `Alice`（5 B），消息 `SRGG paper baseline: 32 bytes!!!`（32 B），同一基线测试种子标签由报告保存。三组原文 Table 4 数字、`w=2`、`n=512`、原 `γ` 和 factor1 未改。两种宽度解释是论文记号歧义的显式分支。测试种子只用于可复现研究运行，**不是**生产随机性；协议签名无单独 nonce 字段。

| Table 4 行 | 宽度解释 | 首签是否找到 `±Q` 单基替换 | 合格坐标数 / 搜索数 |
|---|---|---:|---:|
| PARAM-I | 表列物理标准差 | 否 | 0 / 1024 |
| PARAM-II | 表列物理标准差 | 是 | 82 / 1536 |
| PARAM-III | 表列物理标准差 | 是 | 2048 / 2048 |
| PARAM-I | 字面 density width | 是 | 1024 / 1024 |
| PARAM-II | 字面 density width | 是 | 1536 / 1536 |
| PARAM-III | 字面 density width | 是 | 2048 / 2048 |

五个成功行均实际证明了：原签名有效，替换签名满足原 `γ`，恢复承诺相同，challenge 不变，严格规范编码不同，原验签接受。报告只存公开公钥/签名的 SHA-256 和选中坐标、范数，不导出私钥、完整签名或陷门。默认 PARAM-I 这**一份**签名的 1024 个单基位置都未命中；这既不排除其它签名，也不是安全证明。单次确定性样本及合格坐标计数不估计攻击成功概率；特别不能把它直接提升成任意参数、任意身份或量子攻击结论。

复跑（仓库根目录、指定 WSL Sage）：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_strong_game --output build/strong-game-replay.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_strong_game.py
python docs/research/team-b-delivery/2026-10-18-srgg-strong-game/verify_delivery.py
```

本包的执行环境、六次 Setup/发钥/签名次数和严格界见 [`validation.json`](validation.json)。原文安全归约、适用的 strong 游戏、真实随机数下的攻击概率、完整采样分布和困难性成本仍待单独闭合。`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`；无 HIBE 工作、无正式安全准入。
