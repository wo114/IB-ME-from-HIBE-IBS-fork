# Sageloli 环版：论文大参数与结构化执行对应

冻结来源为 *Shorter and Faster Identity-Based Signatures with Tight Security in the (Q)ROM from Lattices*，Éric Sageloli、Pierre Pébereau、Pierrick Méaux、Céline Chevalier，DOI `10.1007/978-3-031-33488-7_24`。本仓库 [HAL v1 全文](../../../../papers/2023_shorter_faster_ibs_sageloli.pdf) SHA-256 为 `0e92f184828bc8643a774e9c334b14689346387981e766c311c596239ef73e3e`。以下页码为 PDF 页码。

## 实际采用的算法

| 原文位置 | 本批实现 |
|---|---|
| §7、p.23 Figure 7 | `RingBackend.setup/key_extract/sign/verify`：身份盐 r、消息盐 s、H1/H2、非齐次签名方程及两个分块范数门 |
| pp.52–53 Propositions 18/19 | 保存四分块 CBD 根 R；公钥 `A=[Abar | g-Abar*R]`；根采样使用 `J=[R;I]`，身份钥满足 `A*T_id=H1-g`，签名使用 `J=[-T_id;I]` |
| p.23 Table 4 | `q=3^k`、2 幂环次数、l 的范围、密度宽度与分块尾界；所有环运算模 `X^d+1` |
| p.28 Table 6、Appendix E | 两组完整结构参数 `(k,d,l)=(65,2048,132)/(153,2048,308)`；从附录公式用 320-bit 区间上端点取整得到 s_id²、s_sign² |
| 原文 p.9 Gaussian 密度定义 | 采用 `exp(-pi*x²/s²)`；物理方差为 s²/(2*pi)。Table 6 使用 standard deviation 一词不改变本实现所记录的密度约定 |
| 原文 p.13 Proposition 3 与环提升 | 完整相关扰动 p、残差 `u-Ap`、三进制陪集 Gaussian 和 `p+Jx`；每次 SampleDR 都执行精确模方程检查 |

论文附录脚本把 `4*sqrt(d*B²+1)` 放在 s_id 式中；这比正文 Table 4 的 `sqrt(16*d*B²+1)` 略大。本批沿用附录计数脚本的前者，向上取整平方宽度，未从 Table 6 仅两位小数的 log(s) 反推参数。`r²=ceil(r_(dk,2^-200)²)=49` 是实际固定舍入宽度。有限标量表的 tail_bits=256、mass_bits=320 是实现选项。

原文 Table 6/7 主要针对省略盐的非自适应实例计数；本批运行 Figure 7 的加盐版本。相同结构参数不意味着盐、长度帧和字节编码与原计数完全相同。

## 避免大矩阵展开的方法

对象直接保存环多项式系数。公钥形状 l×d，根形状 (l-k)×k×d，身份钥形状 l×k×d。它们不包含各环多项式的 d×d 旋转矩阵。

令 `J=[-T;I]`、`c=9r²`、`a=s²-r²`。原 SampleF 需要的连续密度形状为

`aI-cJJ*`。

在每个负循环 Fourier 频率计算 `G=J*J=U diag(lambda) U*`，采用稳定的低秩平方根

`L=sqrt(a)I-J U diag(c/(sqrt(a)+sqrt(a-c*lambda))) U* J*`。

直接相乘得到 `LL*=aI-cJJ*`。`tests/test_sageloli_ring_structured.py` 用小维度完整矩阵检查该等式，并检查输出均值/协方差。最大特征分解为 k×k，实际保存量为 `O(d*l*k+d*k²)`，不会分配 `d(l+k) × d(l+k)` 协方差。

在取熵前执行实际整数 T 的充分 PSD 检查：固定 radix-2 变换传播绝对误差包络，twiddle 由 MPFI 区间验证；每频率的 `||T||² <= ||T||_1 ||T||_infinity` 上界再用于 `s² >= 11r²||J||²`。私有谱上界、协方差、数值计划和样本均不发布。输入极值和不满足条件者明确拒绝。

连续部分使用二进制浮点特征分解、52-bit 中点网格 Box–Muller 和 FFT；这些数值近似的总 TV 尚未认证。随后逐系数执行真正的任意中心离散 Gaussian 拒绝采样，不是简单四舍五入。概率比较远离边界时走保守误差保护的矢量路径，近边界由 MPFI 决定；三进制每一层（包括末层）使用区间构建的 320-bit CDT。存在明确支持、试次、取熵和输出域限制，耗尽即中止。

## 大整数编码与精确运算

- v3 帧有固定魔数、类型、字段数及长度；拒绝 v2、截断、追加、重复/乱序账本、超长形状和非规范系数。
- 公钥按 q 的实际位数（104/243 位）编码，拒绝空闲高位与 `coefficient>=q`；不再受 int64 公钥或 uint128 参数记录限制。
- 根以实际支持内的 int8 槽保存；Gaussian 身份钥和签名以经过范围核查的 int64 槽保存。这里没有复现论文信息熵最优编码。
- 公共大模数点积使用 FLINT 整数多项式乘法、负循环折叠与模 q 约减。
- 私有小整数多项式矩阵使用两个 NTT 素数；先检查完整整数卷积幅度小于 CRT 模积的一半，再重建有符号整数。它们只是计算用的 CRT 模数，方案模数始终是 `3^k`。
- 原 v2 SIS/RSIS 后端和旧状态保持独立；没有自动迁移、重新发钥或改变默认公共注册器。

## 状态与证据边界

固定发钥以本地跨进程锁、同步 pending、原子替换和上下文 pin 工作。恢复重新检查根关系以及每个 issued 用户钥的所有环列，既有身份返回原钥而不取熵。私有文件为本地明文，不提供恶意回滚、认证存储或侧信道保证；采样计划不序列化。

本批引用原文安全性质作为项目工作前提，未新做安全/匿名性归约。实际有限采样误差、固定服务模型对应及正式安全等级不由功能实跑代证；元数据保持 `none/false/false`。本批完成范围是独立 RSIS 原语与恢复，不包含默认 registry/公共 CLI 的选择接入或 HIBE 配对。
