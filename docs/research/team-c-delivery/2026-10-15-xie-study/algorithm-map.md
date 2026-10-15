# Xie 2016：原文冲突与修订研究核对应

这是 **WIP 修订方程研究**，不是原稿逐字复现、共同 `IBSBackend` 或新的已准入方案。
算法代码均为本项目实现；没有把 Falcon 或 DLP IBE 改名为 Xie IBS。

## 固定原文

- [Xie–Hu–Gao–Gao 原文](../../../../papers/2016_ntru_ibs_xie.pdf)：8 页，548574 B，SHA-256
  `0797847601224a3743cdf1597cad74aa31cfa966c5b466e4b945af07762a0559`。
- [GPV08 完整作者稿](../../../../papers/2008_gpv_trapdoors_full.pdf) §4.2，PDF 15–17 页：
  正确的随机 nearest-plane 坐标宽度及累加方向；复用本库已有有限 GPV/在线 Gaussian 工具。
- 本批核对文字提取及相关 PDF 页面图像。没有把表格数值猜成指数，也没有确认作者勘误。

## 可执行的原文疑点

| 位置 | 原文与核验 | 本研究核采用的显式改动 |
|---|---|---|
| PDF 4 页 Algorithm 3 / PDF 5 页 Algorithm 4.1 | Algorithm 3 重抽非单位；Algorithm 4.1 却写采样非单位，而随后 `h=g/f` 要求逆元 | 只接受 f、g 均为模 q 单位。不是照抄 Algorithm 4.1，也不继承其公钥近均匀结论 |
| PDF 5 页 Algorithm 4 的 B 与 Algorithm 5 方程 | `B` 的行是 `(f,g),(F,G)`，而提取要求 `s1+h*s2=t`。f=1,g=2,F=0,G=q,h=2 时第一行余量为 5，不在所需核中 | 将两类旋转行明确改为 `(-g,f),(-G,F)`，恰为 `(1,h)` 的核；完整整数行列式为 `q^n`，再做同格 LLL 预处理 |
| PDF 3 页 Algorithm 1 的坐标宽度 | 打印值为 `sigma / ||b*||²`；GPV08 是 `sigma / ||b*||`。一维 b=2,s=4 时两者分别为 1、2 | 使用已有 GPV08 有限实现，不使用打印的 Algorithm 1 |
| PDF 3 页 Algorithm 1 的返回方向 | 打印为 `v_{i-1}=v_i-z_i*b_i`。中心 c=1、b=2 时得到 v=0、−2 等概率，而目标高斯比值是 exp(−pi/2) | 用 GPV08 的正格点累加以及平移回目标陪集 |
| PDF 7 页 Table 2 | 实际打印 q 为 227、225、233、218、226，其中 225/218/226 与 q prime 冲突 | 原样保留，不改读为 `2^27` 等值；调试 q=12289 是另外选取的研究值 |
| PDF 5 页 Algorithm 5 / PDF 6 页正确性文字 | Algorithm 5 的 H 输出整个模 q 环；正确性段落又有三元限制文字 | 采用 Algorithm 5 的均匀模 q H；保留冲突，不宣称完整定理映射已闭合 |

前三类代数/采样问题有 `qualification.py` 的精确反例。反例说明打印算法不能直接采用，
不等于判定作者本意或整个研究方向错误。

## 实际执行链

| 研究步骤 | 代码与实际机制 | 范围 |
|---|---|---|
| Setup | `runtime.setup`：逐系数真实离散 Gaussian 采样 f/g，单位检查；整数 HNF 及变换矩阵验证 `(f,g)` 生成整数单位理想，得到 `fG1-gF1=1`；乘 q，精确 Babai 规约 F/G，检查整数 NTRU 方程与范数 | 没有固定根、隐藏的 native RNG 或均匀代 Gaussian；理想/范数条件导致的条件化分布尚未映射到公钥近均匀定理 |
| Extract | 旋转后的完整核格基经整数 LLL；`KernelBasis` 检查核包含与 det=q^n；`CHKPGPVSampler` 在 `(1,h)` 的目标陪集上作真实随机 nearest-plane | 复用 A 的公开格工具接口，不改其代码；私有 GS/TV 几何不作为公开收据或私钥格式 |
| 固定身份 | `Master.extract` 同身份返回原对象；新身份抽样前置 pending，熵/采样失败保留标记；快照保留已发和 pending 项 | 仅进程内锁和研究快照；没有磁盘事务服务、反回滚或外部状态认证 |
| Sign | 真实 Gaussian y1/y2；u=H′(y1+h*y2,message)，z=y+s*u；按 `min(1,exp(-pi*(||z||²-||y||²)/sign_width²)/M)` 有向区间/下舍入 Bernoulli 拒绝 | 有限 128 次默认上限、熵上限；没有超限换 seed/换根外循环；拒绝条件化总误差与全查询界未闭合 |
| Verify | 纯 Python 整数环运算、签名范数、稀疏挑战；重建 `z1+h*z2-H(id)*u` 再哈希 | 无私钥、Sage、native、Gaussian 或新熵；raw 方程有已证实的小参数伪造负控 |
| Hash | 规范长度前缀和域分隔 SHAKE256；H 均匀采样 Zq^n，H′ 均匀采样所有三元且 weight≤lambda 的元素，包含零 | 有限字节/拒绝预算；实际 SHAKE 实例化不是 ROM/QROM 证明 |
| 对象恢复 | 规范 JSON envelope，严格字段集合/类型/长度/整数/维度/版本/上下文/代数绑定；Public/Master/IdentitySecret/Signature 四类 | 明文私有快照；不在通用框架登记，因此不伪称冻结五方法/共同对象已完成 |

所有宽度表示 `exp(-pi*x²/s²)` 中的 **s**，不是统计标准差。根、身份提取、签名采用
三个不同的显式研究宽度；原稿单一 sigma 的定理不能直接套用到该选择。

## 线程、有限误差与攻击边界

Sage/PARI 在工作线程中新建有限域时实际抛出 `SignalError: Segmentation fault`。
本研究核在导入 Sage 前及新 Setup/Extract/Sign 等入口明确要求主线程；新 Extract 的
拒绝发生在熵和 pending 写入前。已发私钥的并发缓存重放、解析与纯公开验签可在工作线程执行。
不声称支持线程池中的新发钥，也没有删去这一运行失败记录。

标量采样有实际有限分布证书，GPV 有条件准入检查；统计诊断只检查实现失误，不能替代
整个根条件化、提取、拒绝签名、多身份/多查询的总误差及中止证明。Python/LLL/HNF 变时，
秘密内存未清零，没有生产侧信道保证。

已保留两类公开攻击：

1. 对有效签名某个 z 系数加/减 q，若仍在宽松范数内，会得到不同且有效的签名；
   这是本研究参数的强不可伪造反例，没有改验签算法掩盖。
2. 公开搜索 `H′(0,msg)=0` 后，零向量签名在不同未发钥身份下也通过。默认 lambda=4
   的挑战空间仅 34113（n16）/617089（n32）；有限攻击未搜到也不构成安全证据。

调试攻击不等于对论文目标尺寸的普遍攻破。修订研究核不继承原稿 Theorem 1/2 或 GPV
任意安全等级；`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。
作者澄清、正式参数/分布、强 UF/量子与 Wang 适配仍是停止准入的实质缺口。
