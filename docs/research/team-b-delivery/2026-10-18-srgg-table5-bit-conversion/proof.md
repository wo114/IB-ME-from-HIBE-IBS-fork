# SRGG Table 5 的 β 到 Core-SVP 位数换算

范围仅为冻结 `papers/2025_efficient_ibs_jia.pdf`（SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`）中 §5.2.1（PDF p.9）与 Table 5（p.10）的**表内算术**。原文把 BKZ-β 的经典、量子 Core-SVP 工作量分别近似为 `2^(0.292β)`、`2^(0.265β)`。把指数视为位数，以下六个作者自报 β 逐个代入，按最近整数取整，恰得 Table 5 的十二个整数。

| 作者攻击类别 | 参数 | 作者 β | `0.292β` → 表中经典位数 | `0.265β` → 表中量子位数 |
|---|---|---:|---:|---:|
| 主密钥恢复 | PARAM-I | 358 | `104.536 → 105` | `94.870 → 95` |
| 主密钥恢复 | PARAM-II | 608 | `177.536 → 178` | `161.120 → 161` |
| 主密钥恢复 | PARAM-III | 874 | `255.208 → 255` | `231.610 → 232` |
| 签名伪造 | PARAM-I | 352 | `102.784 → 103` | `93.280 → 93` |
| 签名伪造 | PARAM-II | 586 | `171.112 → 171` | `155.290 → 155` |
| 签名伪造 | PARAM-III | 828 | `241.776 → 242` | `219.420 → 219` |

复算仅用标准库 `fractions.Fraction` 的精确十进制系数 `292/1000`、`265/1000`；六组均非半整数，最近整数取整无 tie 规则歧义。命令是：

```python
from fractions import Fraction
for category, betas in (("recovery", (358, 608, 874)),
                        ("forgery", (352, 586, 828))):
    print(category, [(b, round(Fraction(292, 1000) * b),
                          round(Fraction(265, 1000) * b)) for b in betas])
```

得到 `recovery: (358,105,95),(608,178,161),(874,255,232)`；`forgery: (352,103,93),(586,171,155),(828,242,219)`。这**只复现 β 到表列位数的换算**，没有从密钥恢复或伪造格输入推导作者 β，也没有证明 Core-SVP 成本模型适用于实际环结构、近似采样和攻击成功率。[密钥恢复输入](../2026-10-18-srgg-key-recovery-mapping/proof.md)和[伪造输入](../2026-10-18-srgg-forgery-input-mapping/proof.md)仍分别保留实际 primal/BKZ 与短原像成本为未知。因此 Table 5 不成为当前实现的安全等级，`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。本项无密码学样本，随机试验与性能重复次数均为 0；未使用 ROM 或 QROM 归约。
