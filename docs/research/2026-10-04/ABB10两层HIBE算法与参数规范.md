# ABB10 两层 HIBE：算法、参数依赖与实现门槛

核验日期：2026-10-04。依据：Agrawal–Boneh–Boyen，CRYPTO 2010，§2–4，18 页作者 PDF，简称 [A]。页码均为 PDF 页码。本文只规范 §4 的经典随机预言机模型（ROM）构造，不借用 §5 的标准模型结论。代码审计基点仍为 `b15afd675b1c53029d9b8f8909569ccc7b060fa8`。

**结论：继续作为首套 HIBE 的数学参考候选，可以按本文建立独立的代数参考模型；尚不能作为已通过准入的安全后端。** 需要补全委派分布证明、有限参数、真实采样、字节载荷适配以及随机预言机实例化边界。当前 `src/ibme/hibe/abb10.py` 是拼接式教学后端，不能通过改名成为这篇论文的 §4 实现。

以下明确区分三种内容：标为“原文”的算法和渐近条件；标为“推导”的矩阵、尺寸和有限正确性公式；标为“适配决定”的项目输入、编码与验收约束。适配决定尚未修改冻结接口或密码代码。

## 1 对象、分布和约定

原文要求奇素数 $q>2$。$A\in\mathbb Z_q^{n\times m}$ 满秩，$T_A\in\mathbb Z^{m\times m}$ 是完整整数格基，列生成

$$\Lambda_q^\perp(A)=\{z\in\mathbb Z^m:Az=0\pmod q\}.$$

满秩时该格的行列式为 $q^n$。判定一个候选矩阵是完整格基，需要同时检查整数列独立、模方程和行列式；只检查 $AT=0$ 与秩 $m$ 不足。[A，§2.2–2.3、Lemma 1、§3.1，PDF 5–10]

高斯宽度 $s$ 使用密度 $\exp(-\pi\|x-c\|^2/s^2)$。它不是常用正态库的标准差；连续正态的标准差为 $s/\sqrt{2\pi}$，离散高斯的方差还受格与宽度影响。所有将来配置必须写明这一约定。

| 对象 | 形状或分布 | 用途及边界 |
|---|---|---|
| $A,u_0$ | $n\times m$ 模矩阵、$n$ 维模向量 | 主公钥；$u_0$ 均匀且独立 |
| $T_A,T_1,T_2$ | $m\times m$ **整数完整格基** | 主密钥、两级私钥；不能先约模 |
| $H_1,H_2$ | $m\times m$ 整数矩阵 | 身份前缀对应的公开变换；模 $q$ 可逆 |
| $F_1,F_2$ | $n\times m$ 模矩阵 | 两层的加密矩阵；列维度不增长 |
| $d_{id}$ | $m$ 维整数向量 | 解密时 SamplePre 的临时原像 |
| $c_0,c_1$ | $1+m$ 个模系数 | **一比特**密文，不含公开身份 |

“矩阵维度固定”不等于成本与层数无关。委派后的基范数、采样宽度、噪声容许度和所需模数仍随最大深度变化。

## 2 两层身份矩阵及算法到接口的对应

适配决定：第一层身份为接收者 `rcv`，第二层为发送者 `phi`。用长度前缀、层数和独立域标签编码身份元组，不能把字符串直接拼接。

设 $H_1=H((\mathrm{rcv}))$，$H_2=H((\mathrm{rcv},\phi))$。**原文的乘积顺序**和对应推导是

$$R_1=H_1,\qquad R_2=H_2H_1,$$
$$F_1=AH_1^{-1},\qquad F_2=A(H_2H_1)^{-1}=AH_1^{-1}H_2^{-1}\pmod q.$$

矩阵不交换；不能把 $R_2$ 写成 $H_1H_2$。[A，§4.1，PDF 12]

| 冻结接口 | 论文操作 | 输出及实现要求 |
|---|---|---|
| `setup(params, rng)` | TrapGen；独立均匀采样 $u_0$ | 公钥 $(A,u_0)$，主密钥 $T_A$，关联参数及上下文 |
| `extract(msk, rcv, rng)` | $T_1\leftarrow\mathrm{BasisDel}(A,H_1,T_A,\sigma_1)$ | $\Lambda_q^\perp(F_1)$ 的完整随机短基 |
| `derive(sk1, phi, rng)` | $T_2\leftarrow\mathrm{BasisDel}(F_1,H_2,T_1,\sigma_2)$ | $\Lambda_q^\perp(F_2)$ 的完整随机短基 |
| 根直接发第二层密钥（核验用） | $\mathrm{BasisDel}(A,H_2H_1,T_A,\sigma_2)$ | 与逐层委派的目标分布一致性需要核验，不能仅比较方程 |
| `encrypt(pk, rcv, phi, payload, rng)` | 先按下节实现一比特 Encrypt | 字节载荷适配尚待论证；不得冒充已完成接口 |
| `decrypt(sk2, ct, rng)` | SamplePre 后逐比特判定 | 失败映射及认证载荷尚待完成 |

主 AI 对接口冲突的决定：保留现有公开接口。先把论文一比特算法放在独立研究模型，**不注册为正式 HIBE 后端**。论文一比特 Decrypt 总会输出比特，并不自动识别错误身份；接口要求的失败返回与协议层的错配拒绝，需要后续载荷和验签适配共同说明，不能人为给密文增加公开身份字段来绕过匿名性。

## 3 三个不能省略的格操作

### 3.1 SampleR：公开身份变换的目标分布

原文 Definition 7 设 $\sigma_R=\widetilde L_{TG}\,\omega(\sqrt{\log m})$。目标分布是 $m$ 个独立 $D_{\mathbb Z^m,\sigma_R}$ 列向量构成的矩阵，**整体条件化于模 $q$ 可逆**。SampleR 采样整个矩阵；若模 $q$ 奇异，则重新采样整个矩阵。不能逐列筛掉不独立的列后继续沿用目标分布。[A，§3，PDF 9]

论文称素数 $q$ 时整批采样的期望尝试次数小于 2；对应论证指向 full version，本轮未取得该完整证明。有限随机带、截断高斯、拒绝次数上限都会引入额外误差，必须按所有身份查询累计。

### 3.2 BasisDel：变换、补全完整格基、再随机化

原文输入 $(A,R,T_A,\sigma)$，目标 $B=AR^{-1}\bmod q$。过程为：

1. 计算整数列集合 $T'_B=RT_A$。
2. 结合目标格的一个规范完整基，使用 Lemma 1 把该集合转换成 $\Lambda_q^\perp(B)$ 的完整基 $T''_B$，控制基质量。
3. 调用 RandBasis$(T''_B,\sigma)$，输出随机化完整基 $T_B$。

$RT_A$ 只有完整秩，通常只是目标格的子格。具体反例取 $q=7$、$A=(1,0)$、$T_A=\operatorname{diag}(7,1)$、$R=\operatorname{diag}(2,1)$。$R$ 模 $q$ 可逆，$B=(4,0)$，但 $RT_A=\operatorname{diag}(14,1)$ 的行列式是 14，目标格行列式是 7。它遗漏合法向量 $(7,0)$，子格指数为 2。**只对 $RT_A$ 做 HNF 仍不会补出遗漏格点。** 此反例是整数格代数检查，不是合法密码参数。[A，§3.1，PDF 9–10；推导与精确脚本]

RandBasis 自身也需要“采样足够的独立向量 + 转成完整格基”，不能只返回高斯列矩阵。随机化必须消除父基对输出分布的影响，不能把一次可解的方程当成委派安全性。[A，PDF 7–8]

### 3.3 SamplePre：解密原像

原文 SamplePre$(F,T,u,\tau)$ 输出目标陪集 $\{d:Fd=u\bmod q\}$ 上近似球形离散高斯样本。需满足 $\tau\ge\|\widetilde T\|\omega(\sqrt{\log m})$；典型高概率范数界为 $\|d\|\le\tau\sqrt m$。[A，Lemma 2，PDF 7]

不能用公开 gadget 分解、均匀整数或“分解后加一点噪声”替代。MP12 的 G-trapdoor 是另一种表示；即使按 MP12 Lemma 5.3 转成完整基，也要重算 TrapGen 质量、$\sigma_R$ 以及委派分布依赖，不是无条件替换 [A] 的黑盒。

## 4 原始一比特加解密和字节载荷门槛

原文 Encrypt：独立均匀采样 $s\in\mathbb Z_q^n$；采样 $x\leftarrow\Psi_{\alpha_\ell}$、$y\leftarrow\Psi_{\alpha_\ell}^m$；令 $h=\lfloor q/2\rfloor$，输出

$$c_0=u_0^Ts+x+bh\pmod q,\qquad c_1=F_{id}^Ts+y\pmod q.$$

其中 $\Psi_\alpha$ 是连续正态（标准差 $\alpha/\sqrt{2\pi}$）经乘 $q$、最近整数舍入、约模得到的分布，不能未经证明改成 $D_{\mathbb Z,q\alpha}$。[A，Definition 6、§4.1，PDF 6、12]

原文 Decrypt 设 $\tau_\ell=\sigma_\ell\sqrt m\,\omega(\sqrt{\log m})$，采样 $d\leftarrow\mathrm{SamplePre}(F_{id},T_{id},u_0,\tau_\ell)$，计算 $r=c_0-d^Tc_1\bmod q$。以 $r\in[0,q-1]$ 的整数代表元判断：若 $|r-h|<\lfloor q/4\rfloor$，输出 1，否则输出 0。[A，PDF 12]

最小的字节研究适配是独立逐比特加密：每比特必须使用新 $s,x,y$。长度为 $L$ 比特时，未压缩密文至少有 $L(m+1)\lceil\log_2q\rceil$ 比特，另加规范头部；隐私证明要用多消息或 hybrid 论证计入 $L$，正确性失败概率也要按 $L$ 累计。共享一份 $c_1$、缓存解密原像、KEM–DEM 与认证包装均属于另外的适配，不能把一比特定理直接用于这些优化。

冻结接口允许空字节载荷，论文只有一比特语义。将来载荷需有明确的版本、长度和规范编码；结构检查只解决解析错误，**不证明任何密文字节修改都会被拒绝**。IBS 验证解决错误身份及消息认证，但对“修改后仍解出同一载荷”还需独立的完整性机制。

## 5 原文参数链与有限正确性推导

### 5.1 渐近条件不能直接写成正式参数

原文 Theorem 1 对 TrapGen 使用 $m=\lceil6n\log q\rceil$，§4.2 工作条件写 $m>6n\log q$。有限选参时要统一严格边界、对数基和取整，不能悄悄把两处记法当成同一个精确参数组。

| 条件 | 原文位置 | 有限化仍需提供 |
|---|---|---|
| $\|\widetilde T_A\|\le\widetilde L_{TG}=O(\sqrt{n\log q})$ | Theorem 1，PDF 6 | 真实 TrapGen、质量上界、失败概率 |
| $\sigma_R=\widetilde L_{TG}\omega(\sqrt{\log m})$ | Definition 7，PDF 9 | 宽度数值、矩阵拒绝及统计误差 |
| 单步 $\sigma>\|\widetilde T\|\sigma_R\sqrt m\,\omega(\log^{3/2}m)$ | Theorem 3，PDF 10 | 隐藏常数和分布证明 |
| 多步 $\sigma>\|\widetilde T\|(\sigma_R\sqrt m\,\omega(\log^{1/2}m))^j\omega(\log m)$ | Theorem 3，PDF 10 | 直接提取与逐层委派共同条件 |
| $\|\widetilde T_\ell\|\le\sigma_\ell\sqrt m$；$\sigma_\ell>\sigma_{\ell-1}m^{3/2}\omega(\log^2m)$ | §4.2，PDF 13 | 各层上界及尾概率 |
| $\tau_\ell=\sigma_\ell\sqrt m\,\omega(\sqrt{\log m})$ | Decrypt，PDF 12 | 陪集采样误差及范数界 |
| $|x-d^Ty|<q/5$，以及 $q>2\sqrt n/\alpha_\ell$ | §4.2，PDF 13 | 正确性预算与 LWE 归约条件分别核验 |

原文 Equation (4) 的一组渐近设置为

$$m=6n^{1+\delta}=O(dn\log n),\quad q=m^{3d/2+2}\omega(\log^{2d+1}n),$$
$$\sigma_\ell=m^{3\ell/2+1/2}\omega(\log^{2\ell}n),\quad\alpha_\ell=[\sigma_\ell m\omega(\log n)]^{-1}.$$

最大深度 $d=2$ 时，$q$ 的幂次为 5，$\sigma_1$、$\sigma_2$ 的幂次分别为 2、$7/2$。这些是证明可行性的尺度关系，**不是建议把 $\omega$ 取 1 的参数文件**。需先解开 $n,m,q$ 的循环依赖，向上取整 $m$、取下一素数 $q$，再重验全部不等式。

### 5.2 可复核的有限噪声界（本项目推导）

本推导只处理诚实密文正确性，前提是采样和宽度已经合法。在事件 $\|d\|_2\le D$ 上，把未约模误差写成

$$E=q\left(X_0-\sum_{i=1}^m d_iX_i\right)+e_{rnd},\quad |e_{rnd}|\le\tfrac12(1+\|d\|_1)\le\tfrac12(1+\sqrt mD).$$

$X_i$ 独立、标准差 $\alpha_\ell/\sqrt{2\pi}$。解密的 $d$ 与诚实加密噪声独立。给定 $d$，正态尾界和 Cauchy–Schwarz 给出：除概率 $\varepsilon_{noise}$ 外，

$$|E|\le q\alpha_\ell\sqrt{1+D^2}\sqrt{\frac{\ln(2/\varepsilon_{noise})}{\pi}}+\tfrac12(1+\sqrt mD)=:B_E.$$

可以用 SamplePre 尾界合法得到的 $D=\tau_\ell\sqrt m$。选择 $B_E<q/5$，同时核验实际整数判定阈值；例如素数 $q\ge23$ 时 $q/5<\lfloor q/4\rfloor$。总失败预算还必须包含 $\|d\|>D$、近似采样、连续正态与舍入实现误差，不能只填 $\varepsilon_{noise}$。逐比特载荷用 union bound 累计。

此界保留了舍入误差，避免把 $\Psi_\alpha$ 错认成独立离散高斯。它没有补全 BasisDel 的安全分布常数，也没有给出攻击复杂度。

## 6 ROM、证明材料及可实现哈希的边界

原文 §4 要求 **矩阵值的 $H$ 本身是随机预言机**。作者明确提醒：用普通位串随机函数作 SampleR 的随机带，不满足所需的 indifferentiability 结论。[A，PDF 11]

因此未来 SHAKE 驱动的矩阵采样只能先标为工程实例化。需要独立记录有限随机带、身份输入域、公开上下文、条件分布和攻击模型；不能把“输出看起来像高斯”当成 ROM 或 QROM 证明。

Theorem 5 的自适应归约为 $\operatorname{Adv}_{HIBE}\le dQ_H^d\operatorname{Adv}_{LWE}+\operatorname{negl}$。两层损失为 $2Q_H^2$。例如**仅作预算演示**，$Q_H=2^{32}$ 会产生 $2^{65}$ 的乘数，若目标优势 $2^{-128}$，底层项需压到约 $2^{-193}$，并另外分配统计误差。实际组合中 $Q_H$ 要覆盖归约内部查询；逐比特适配和 Wang 组合的损失另计。这不是任何已确定安全等级。[A，Theorem 5 及其证明，PDF 14–16]

Theorem 3、Theorem 4 将关键分布证明交给 full version。当前 18 页 PDF 没有包含它们。本轮核对作者材料页：published paper 可访问；“full version (PDF)” 没有超链接；Agrawal 的研究目录链接回同一 Boyen 页面。本轮**未取得补全证明的版本**，不宣称世界上不存在该版本，不联系作者或老师发送消息。

SampleRwithBasis 是模拟器对非目标路径编程随机预言机的工具，不是线上公开哈希函数。它生成陷门用于归约；实际 $H$ 实现不得秘密调用它并把陷门留在服务端。[A，§3.2、§4.3]

## 7 数据格式草案及下轮验收

格式为新后端研究草案，未分配线上 magic，未覆盖旧格式：

- 公钥：版本、算法标识、完整参数摘要、$A,u_0$；模系数使用 $[0,q-1]$ 唯一代表元，拒绝非规范值。
- 私钥：公钥上下文、层数及规范身份、完整整数基；列顺序明确。私钥解析设置尺寸和整数位宽上限，不能丢掉符号或约模。
- 密文：参数上下文、载荷比特数、依次编码的一比特块；不含接收者或发送者身份。头部认证方式仍待确定。
- 新参数应独立保存 $\sigma_R,\sigma_1,\sigma_2,\tau_1,\tau_2,\alpha_1,\alpha_2$、误差预算与查询上限；不复用旧 `Params.s` 隐含全部宽度。冻结接口的参数类型适配在正式后端任务前单独冻结。

下轮可以实现的最小数学参考任务是：完整核格基、非交换前缀矩阵、BasisDel 的补全步骤与分布接口。验收先要求格方程、行列式 $q^n$、直接提取与委派的目标分布说明，再进入真实高斯采样和有限参数。仅有数值统计不能证明两个基分布不可区分。

## 8 本轮证据与安全声明

精确代数检查见 [脚本](../../../experiments/research/primitive_gate_audit.py) 和 [结果](原语准入精确核验结果.json)：前缀乘积顺序、完整秩子格反例。参数为代数反例 $n=1,m=2,q=7$，不满足密码选参条件，无消息加密、无重复随机实验。无生产随机数、无密钥文件、无新的攻击估计或性能基准。

当前教学后端的 $n=8,m=168,q=524288$ 仍未改变；该偶数模数不属于本文 §4 的奇素数实例。全部安全口径为 `security_claim: none`。上述核验和功能测试均不能替代 LWE、委派安全或组合安全证明。

[A] Shweta Agrawal、Dan Boneh、Xavier Boyen，*Lattice Basis Delegation in Fixed Dimension and Shorter-Ciphertext Hierarchical IBE*，CRYPTO 2010。[作者 PDF](https://crypto.stanford.edu/~dabo/pubs/papers/latticehibe.pdf)、[本地固定版本](../../../papers/2010_lattice_basis_delegation_agrawal.pdf)、[作者材料页](https://crypto.stanford.edu/~xb//crypto10/)。本地 SHA-256 与证明材料核验记录见 [第二轮核验记录](第二轮核验记录.json)。

[M] Daniele Micciancio、Chris Peikert，*Trapdoors for Lattices: Simpler, Tighter, Faster, Smaller*，ePrint 2011/501（后发表于 EUROCRYPT 2012）。本轮检查 §§2.3–2.4、4.2、5.1–5.5；不宣称全篇完成精读。[原文与元数据](https://eprint.iacr.org/2011/501)、[本地固定版本](../../../papers/2011_lattice_trapdoors_micciancio.pdf)。
