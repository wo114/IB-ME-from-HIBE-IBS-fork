# SRGG 原参数结构成本续审（WIP）

依据冻结的 Jia、Liu、Tang、Wang 原文 `papers/2025_efficient_ibs_jia.pdf`（SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`），本包只审计 Table 4 的独立 IBS。原参数、签名半径、采样器、后端均未修改，HIBE 不参与。详见[机器回执](structural-attack-followup.json)、[证明及范围](proof.md)、[验证记录](validation.json)。

新核验的精确结果：原验签矩阵为 `[2A | Qζ*e₁−2h] mod 2Q`，`ζ*=1−X^256`。只在最后一个响应多项式增加 `Qζ*`，前 `4d` 个多项式不动。因为 `(ζ*)²=−2X^256` 且 `−2h·Qζ*` 是 `2Q` 的倍数，这个改变量**对任意 A、h 都在验签矩阵的核中**。它只有两个非零系数，平方范数 `2Q²=495751039495938`，小于原表三档 `floor(γ²)`；构造本身不调用 BKZ。这个结论关于公开验签关系，不是新消息伪造，也不是一般 Ring-HNF／CRT／子域攻击成本。

更窄的最短性命题也得到证明：在“只改末列，改变量为 `Q·t`，且模 `2Q` 承诺不变”的整数多项式族中，最小非零平方范数恰为 `2Q²`。模 2 时，`ζ*·t=0` 强制 `t` 的前后 256 个系数两两同奇偶；若有奇系数，至少两处非零；若全为偶数，则任一非零系数绝对值至少 2。此最短性**不覆盖**允许改变其他列或不是 `Q` 倍数的所有核向量。

在一份以测试固定随机带生成的真实 PARAM-I／表标准差解释首签上，我们扫描最后多项式 256 对位置的最佳 `±Qζ*X^i` 替换。规范对象能往返，承诺保持相同，原签名有效；最佳替换平方范数为 `2164434734665119`，超过原范数上限 `1771272783614168`，因此实际验签拒绝。这个单例既不是攻击成功率，也不是安全通过；先前 `Qe_i` 路线的五份成功同消息替换证据仍独立成立。

| 原表 | `d` | `γ` | 末列见证是否落在单签名半径 | Ring-HNF／CRT／子域完整攻击成本 |
|---|---:|---:|---|---|
| PARAM-I | 2 | 42086491.7 | 是 | 未闭合 |
| PARAM-II | 3 | 63653172.0 | 是 | 未闭合 |
| PARAM-III | 4 | 86573930.5 | 是 | 未闭合 |

有限路线的结论是：直接把原文通用 BKZ 位数搬到实际种子化、条件接受的环公钥上缺少分布与全环提升证明；改用系数 CRT 后，可精确得知“只在一个素数幂分量非零”的整数系数至少为 `Q/m`，但这不足以给出多项式因子中的短解、提升后范数或攻击成功率；最后核验了上述通用末列核，得到受限关系的零 BKZ 见证，仍不等于目标结构攻击成本。没有再扩展盲目参数搜索。

在规定 WSL Sage 10.9／Python 3.13.15 中运行：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_structural_attack_followup.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_structural_attack_followup --output /tmp/srgg-structural-attack-followup-fresh.json
python docs/research/team-b-delivery/2026-10-18-srgg-structural-attack-followup/verify_delivery.py
```

当前为 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。原文 Table 5 作者估计未由本包复现；不据此声称 NIST 等级或原生 strong 安全。
