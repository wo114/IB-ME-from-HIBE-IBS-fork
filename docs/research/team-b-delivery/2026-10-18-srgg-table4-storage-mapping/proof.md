# SRGG Table 4 裸尺寸与用户对象维数的逐字段核对（WIP）

来源为冻结 Jia–Liu–Tang–Wang 论文 `papers/2025_efficient_ibs_jia.pdf`，SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`；Algorithm 1（PDF p.7）定义 `mpk=(seed_A,B)`、`msk=R`，Table 4（p.10）给三档字节数。本页对 `mpk/msk` 只给与表格**算术一致**的一种裸对象编码，对 `sk_id/sig` 只核环元素维数；均不冒称作者已公开逐字 wire 格式。代码原表参数与对象见 `paper_profiles.py:60–75,135–155`、`paper_backend.py:118–133`、`paper_objects.py:60–81,177–198`。

令环次数 `n=512`、模块秩 `d=2/3/4`、gadget 位数 `w=2`、`Q=15744063<2^24`。Algorithm 1 的公开 `B∈R_Q^{d×wd}` 有 `d·wd·n` 个模 `Q` 系数；以**每系数 3 字节定长**存储，连同 32 字节 `seed_A`，得到 `32+3d(wd)n`。主密钥 `R∈R^{2d×wd}` 有 `(2d)(wd)n` 个 CBD1 系数；若以**每系数 2 位**表示 `−1,0,1`，正好需要 `2(2d)(wd)n/8` 字节。两种假设都省略参数描述、对象类型、长度前缀、状态与完整性封装；`Q<2^24` 与三值支持只说明这些位宽可用，不证明作者采用了这份具体编码。

| 原表 | `d` | `B` 系数数 | `32+3|B|` 字节 | Table 4 `mpk` | `R` 系数数 | 2 位打包字节 | Table 4 `msk` |
|---|---:|---:|---:|---:|---:|---:|---:|
| PARAM-I | 2 | 4096 | 12320 | 12320 | 8192 | 2048 | 2048 |
| PARAM-II | 3 | 9216 | 27680 | 27680 | 18432 | 4608 | 4608 |
| PARAM-III | 4 | 16384 | 49184 | 49184 | 32768 | 8192 | 8192 |

此处的 `R` 是 Algorithm 1 的 master witness，不是 Algorithm 2 的用户签名密钥。现有 `PublicKey.to_bytes()` 把参数、种子和 `B` 放进规范 JSON 包装，`MasterSecret.to_bytes()` 还包含公钥及发钥状态缓存；它们的实际字节长度**不是**上表裸对象长度。

## Algorithm 2/7 的用户对象维数

论文 Algorithm 2（PDF p.7）先形成 `y∈R^((2+w)d)`，只返回删除前 `d` 个环元素的 `y'∈R^((1+w)d)` 作为 `sk_id`。代码 `paper_backend.py:163` 取 `raw[p.rank:]`，`paper_objects.py:109–116` 将其验证为 `(1+w)d` 个环元素的 `tail`，`structured_execution.py:232–240` 用 `P,H1_P(id),tail` 重建被省略的 `d` 个头环元素。因此**裸用户密钥的环元素数**与原文一致；重建所需的公钥和身份属于算法上下文，代码的 `SigningKey.to_bytes()`（`paper_objects.py:128–130`）又把它们纳入 JSON 对象。

论文 Algorithm 7（PDF p.8）给 `sig=(z,c)`，其中 `z∈R^((2+w)d+1)`、`c∈{0,1}^n`。代码 `paper_backend.py:184–194` 生成响应与挑战，`paper_backend.py:204–210` 按 `p.columns+1` 环元素验签；`paper_objects.py:237–255` 校验二元挑战与响应坐标，并在 JSON 签名中另含 32 字节公钥 context。下表的挑战 64 字节仅是 512 位的**裸打包长度**，不是 JSON wire 长度。

| 原表 | `d` | `sk_id` tail 环元素 | tail 整数系数 | `z` 环元素 | `z` 整数系数 | `c` 裸字节 | Table 4 `sk_id`/`sig` 字节 |
|---|---:|---:|---:|---:|---:|---:|---:|
| PARAM-I | 2 | 6 | 3072 | 9 | 4608 | 64 | 4900 / 12148 |
| PARAM-II | 3 | 9 | 4608 | 13 | 6656 | 64 | 7396 / 17786 |
| PARAM-III | 4 | 12 | 6144 | 17 | 8704 | 64 | 9892 / 23516 |

论文 p.9 只说明 Table 4 的用户密钥、签名字节数依据预像熵、可用 ANS 批量编码，并未在该段给出精确熵分布、码表、块封装与取整约定。因此这里**只闭合维数**，不从元素数推出作者的 `sk_id`/`sig` 字节，也不把当前规范 JSON 尺寸当成作者 C/ANS 尺寸；这两个表格字节栏仍未复现。这里不修改 wire 格式，也不把编码/压缩当作另一套方案或性能优化。

复核命令（仓库根；纯整数，无 Sage 或随机输入）：

```text
python -c "from experiments.research.candidates.srgg.paper_profiles import profiles; rows=[(p.name, 32+3*p.rank*(p.digits*p.rank)*p.degree, (2*(2*p.rank)*(p.digits*p.rank)*p.degree)//8, p.author_report.master_public_bytes, p.author_report.master_secret_bytes) for p in profiles]; print(rows); assert all(a==c and b==d for _,a,b,c,d in rows)"
```

本次输出三行依次为 `(PARAM-I,12320,2048,12320,2048)`、`(PARAM-II,27680,4608,27680,4608)`、`(PARAM-III,49184,8192,49184,8192)`，退出码 0。它验证代码记录与上述算术，不验证真实 ANS 压缩、源码作者的 C 格式或安全性。本页无身份／消息／签名采样，重复次数 0，无 ROM 或性能实验。原三档参数不变，继续 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。

用户对象维数另以 `profiles` 只读整数检查：

```text
python -c "from experiments.research.candidates.srgg.paper_profiles import profiles; rows=[(p.name,(1+p.digits)*p.rank*p.degree,((2+p.digits)*p.rank+1)*p.degree,p.degree//8,p.author_report.user_secret_bytes,p.author_report.signature_bytes) for p in profiles]; print(rows); assert [(r[1],r[2],r[3]) for r in rows]==[(3072,4608,64),(4608,6656,64),(6144,8704,64)]"
```

本次输出三档 `(tail系数,z系数,c裸字节)` 分别为 `(3072,4608,64)/(4608,6656,64)/(6144,8704,64)`，退出码 0；作者 `sk_id`/`sig` 字节只作为同一输出中的 reported 字段，不作断言。这不测试采样分布或压缩率。
