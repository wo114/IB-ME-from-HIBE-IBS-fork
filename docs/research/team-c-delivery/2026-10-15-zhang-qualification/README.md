# CR：Zhang 2020 理想格 HIBE 实施入口核验（WIP）

本批完成 CR 储备任务的原文类型/模数方向/实施入口表，**未实现 HIBE**，
未运行 Setup、Gaussian、委派或加解密。不能把下列类型运算计为原语或组合成功。

固定来源：[Zhang 等，Adaptively Secure Efficient (H)IBE over Ideal Lattice with Short Parameters](../../../../papers/2020_ideal_lattice_hibe_zhang.pdf)，
Entropy 2020, 22, 1247，19页、1225215 B，SHA-256
`6b31a181e1461b491c69cd41ce637a63db14f0404c3105f2827e64347e191c60`。
本批已对照PDF第5/10/11/12页图像及全文文字。未取得作者勘误或对应可运行作者实现。

| 原文位置 | 明确的输入/输出 | 实施前需要澄清 |
|---|---|---|
| PDF5 §2.3 SamplePre | 输入长度m的公开向量及 `(m−k)×k` g-trapdoor，输出一个长度m的短原像 | 一个短原像不等同于可继续委派/采样的陷门 |
| PDF5 Algorithm1 SampleLeft | 五个输入 `(a,m1,Ta,u,sigma)`，输出长度 `len(a)+len(m1)` 的单个短原像 | 需要真实可采样陷门Ta，不能用上一层短原像向量冒充 |
| PDF10 §4.1 Derive | 公开向量增长为 `(l+1)m`；打印的SampleLeft调用省略u，私钥输出却仍为 `s∈R_q^(2m)` | 除首层外长度不一致；u的目标/分布、输出陷门类型与随机化必须明确 |
| PDF11 Decrypt.2 | 把SK作为SamplePre的陷门参数，并要求原像满足公开方程 | Derive当前打印输出是一个向量，不提供此处要求的陷门对象 |
| PDF5 ExtendBasis / SampleRight | 文中提到ExtendBasis，SampleRight先选独立核向量再转基 | 必须给出与Derive对应的完整生成/全格补全/范数分布/有限中止算法，不能把术语本身当作实现 |
| PDF11 Theorem4 / 式(13)–(14)；PDF12参数首条 | 正确性条件打印 `q≤C`，但式(14)是 `T≥q/C`、错误界为 `2exp(−pi*T²)` | 对固定正C，控制该界需要q/C足够大；打印上界不能单独给出这个充分条件。需澄清方向或附加条件，不自行把≤改成≥后称忠实复现 |
| PDF12 Theorem5 | 标准模型 RLWE 下 IND-ID-CPA 结论 | 本批没有取得两层收件人匿名性及Wang适配的完整对应；不因“自适应HIBE”标签视为匿名已通过 |

令m=8,k=3，仅作环元素个数的类型示例：根公开向量8、陷门5×3；
第一层公开向量16，若沿用§2.3的g-trapdoor表示应为13×3，而打印SK是长度16的短向量；
第二层公开向量24，应对应21×3陷门，打印SK仍为16。Decrypt所需原像长度也应为24。
这只是不同对象不能互换的检查，没有选取q、n、Gaussian宽度或安全参数。
完整机器可读类型和核验边界见[qualification.json](qualification.json)。

后续重新进入主编码前需固定：

1. 真正的层级私钥类型，以及短原像到可委派陷门之间是否有被省略的算法；
2. 每层公开/秘密/噪声维度，SampleLeft的目标u与实际参数；
3. 真实环陷门、扰动/陪集Gaussian和完整格委派工具、失败预算；
4. 正确性模数方向、有限误差界与困难参数，以及匿名/安全游戏对应。

不将Lai或矩阵HIBE的算法直接替换进来后改名为本方案。现有公共环运算可保留为工具，
不能消除这些接口与分布问题。按总计划停止条件，CR当前保留核验资料，主编码继续已就绪原语的公共接入。

环境：Windows Python3.14 / PyMuPDF只读提取和渲染；每项原文检查1次，未运行密码学随机实验，
消息/身份长度及重复签验次数不适用。原稿定理以标准模型表述，本批没有实例化该结论，
也没有建立ROM/QROM证明。保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`；
文档/类型核验不能替代功能测试或安全证明。
