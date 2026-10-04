# 第六轮：Foo–Li 固定密钥经典 ROM 条件归约草案

日期：2026-10-04。起点：`8f1a89986f8af76868e3cb72df79d78fbc1666c9`。

**状态：WIP，独立的条件归约研究，尚未形成正式安全定理或完整 IBS 后端。** 本轮恢复 Foo–Li 的研究候选资格，保留第二轮对原游戏链的审查结论。固定王老师两层匿名 HIBE + IBS 通用构造，不实施 Boyen–Li 增强隐私。

本轮完成：定义带持久用户种子的固定密钥实验；构造两个保留身份分支的候选模拟器；核对哈希先于签名、重复消息、签后腐化及最终新身份；推导零 tag 的 SIS 提取、有限好矩阵条件和后验原像点概率。完整采样、具体参数链及整体归约的最终审查仍待完成。

## 1 来源、目标与准入结论

| 来源 | 固定文件和原文位置 | 本轮用途 |
|---|---|---|
| [Foo–Li 作者接受稿](https://research-repository.griffith.edu.au/server/api/core/bitstreams/bea45f34-cb40-47b4-b6da-4bde6690f252/content) | `papers/2023_tightly_secure_ibs_foo.pdf`；§3 / Figure 2，PDF 12–13；Figures 3、7–10，PDF 14–17；Lemmas 11–13，PDF 18–19；§5 / Figure 11，PDF 20–21 | 真实算法、固定状态及原提取结构 |
| [MP12](https://eprint.iacr.org/2011/501) | `papers/2011_lattice_trapdoors_micciancio.pdf`；§2.3，Lemmas 2.5–2.9，PDF 11–14；Algorithm 3 / Theorem 5.5、Algorithm 4，PDF 26–29 | Poisson/平滑、范数尾界、条件高斯和委派 |
| [Wang](https://eprint.iacr.org/2022/1718) | `papers/2022_identity_matchmaking_wang.pdf`；Lemmas 2.1–2.2，PDF 7；Definition 6，PDF 10；Construction 1 / Lemma 4.2，PDF 12–15 | 组合要求的是普通自适应 UF-CMA，条件原像的真实分布 |

Foo–Li PDF 页码含一页仓储封面，正文页码减 1。文件指纹仍以 [manifest](../../../papers/manifest.json) 为准；本轮不替换论文。在线元数据核对不等于获取了出版全文或修订证明。

第二轮发现的 Figure 9 转录差距仍成立：同一身份的两条不同消息，真实侧分支位相等概率为 1，按消息独立分支的模拟侧为 1/2。本文重建的是一条新路线，不继续沿用该次替换；也不把这项证明审查写成真实签名伪造。

项目的加强认证不自动要求强不可伪造 IBS。先证明普通 UF-CMA 可以满足 Wang 的 IBS 组合前提；旧消息新签名的强 UF、密文字节完整性和整个组合的量子模型均不由本轮推出。

## 2 真实候选与用户状态实验 E_FL

用 $q$ 表示质数，$k=\lceil\log_2q\rceil$，$w=nk$，$d=m+w$。公开矩阵 $A\in\mathbb Z_q^{n\times m}$；身份矩阵 $B_{id,b}=H_1(id,b)$；$F_{id,b}=[A\mid B_{id,b}]$。委派宽度记为 $s$，签名宽度记为 $t$，对应原文 $s,s'$。验证界为 $B_{ver}$，保留原文的完整有符号向量和一个比特。

以 $\mathcal H_1,\mathcal H_2,\mathcal H_3$ 区分秘密种子相关的预言机与公开 $H_1,H_2$。所有输入使用独立域标签及长度前缀；文中的逗号是有类型元组，不是无长度拼接。原文固定长度空间与项目可变长度空间的适配仍待冻结。

```text
Setup:
    (A,T_A) <- TrapGen
    k1,k2 <- independent uniform {0,1}^ell
    Users,Signed,Corrupt := {},{},{}

GetUser(id):
    if id not in Users:
        b := Hcal1(k1,id)
        psi := Hcal2(k2,id)
        B := H1(id,b)
        R <- DelTrap(A,T_A,B,I,s;psi), with B=A*R+G
        kid <- independent uniform {0,1}^ell
        Users[id] := (R,b,kid)
    return Users[id]

Key(id):
    key := GetUser(id)
    Corrupt.add(id)
    return key                  # also reveals kid in this project experiment

Sig(id,M):
    if (id,M) in Signed: return Signed[id,M]
    (R,b,kid) := GetUser(id)
    u := H2(id,M)
    phi := Hcal3(kid,id,M)
    z := SampleD([A|H1(id,b)],-R,u,t;phi)
    sigma := (z,b)
    Signed[id,M] := sigma
    return sigma

Finish(id*,M*,(z*,b*)):
    reject if id* in Corrupt or (id*,M*) in Signed
    reject malformed bit/vector or norm above B_ver
    return ([A|H1(id*,b*)]*z*=H2(id*,M*) mod q)
```

`-R` 为 MP12 负号陷门约定，因为 $[A\mid AR+G][-R;I]=G$；不能把加号形式的 R 直接传给 MP12 同号接口。这里没有更改现有 `src` 接口，也没有擅加原文未要求的零向量拒绝。

这是**本项目提出的实验**：Key 一并公开持久化用户种子，比 Figure 1 仅返回 Ext 的矩阵和比特更明确；不得声称原文已证明这种完整状态披露。缓存用于表示确定性签名的观察语义，真实实现可通过恢复同一 $k_{id}$ 重算，不必保存无限签名列表。

每个身份只有一个密钥生命周期、一个用户种子、一个公钥实例。重新加载必须恢复同一状态；独立重发多份密钥、换种子、轮换、多实例或多设备并发状态不在该实验内。

攻击者可自适应查询全部公开预言机、Key 和 Sig。允许其他身份先 Sig 后 Key，也允许拿到种子后查询其签名随机带。最终目标从未 Key；普通 UF 排除旧身份消息对，既不要求目标预先选择，也不要求目标以前从未 Sig。

## 3 为什么不能把所有签名都替换成理想高斯

单次 SampleD 输出接近陪集高斯，仅比较了随机带未被披露时的边际。对于先 Sig、后 Key 的其他用户，攻击者得到 $R,b,k_{id}$，可算 $\varphi=\mathcal H_3(k_{id},id,M)$ 并重跑确定性采样器。若之前返回了一个独立理想高斯向量，重算往往不一致。

因此两个模拟器的**所有非目标用户**始终用已知的真实分支陷门和相应随机带执行真实 SampleD，重复消息返回相同结果。委派密钥分布的替换必须先耦合密钥，再对相同随机带执行相同确定性函数；总变差的数据处理性质允许这样做。不能耦合完密钥后另随机化已被签过的向量。

只有 $B_{same}$ 的未腐化目标允许使用陷门无关理想分布桥接。该目标的用户种子与随机带没有公开；正确种子的外部预言机查询作为单独坏事件。$B_{other}$ 的目标也保留真实 SampleD，无需替换其签名向量。

## 4 目标槽位、查询预算与分支划分

开始交互前，选 $g\leftarrow\{1,\ldots,K\}$。身份第一次出现在公开 $H_1,H_2$、种子域预言机、Key、Sig 或最终验证时，按顺序注册槽位。对解析有效的身份预先选择一个隐藏、固定、均匀分支 $b_{id}$；矩阵与用户状态可以继续延迟生成。

令 $Q_{pub}$ 包含五个域的所有外部预言机查询，采用保守预算

$$K=\max\{1,Q_C+Q_S+Q_{pub}+1\}.$$

最后的 1 覆盖此前未出现的伪造身份。内部算法的递归查询不引入另一个身份；若使用含间接查询的更大预算也有效。**不能只数发钥或签名次数**，否则已见哈希点可能在猜目标前被错误编程。

正确猜中最终目标的参考执行不会被该目标 Key，因为成功事件本身禁止它。猜错的执行可在后续 Key 中止；不能删去先签名后腐化的权限来掩盖这一点。

为从未发钥的最终身份也定义潜在 $b_{id}$，成功事件完整划分为 $E_{same}:b^*=b_{id^*}$ 与 $E_{other}:b^*\ne b_{id^*}$。参考实验中 g 不参与真实算法，所以正确槽位且相应成功事件的概率为 $\Pr[E_c]/K$。模拟器接近该**包含 g 和潜在比特的联合实验**仍需最终审查，不能只援引单个比特边际均匀。

两个模拟器都对同一身份的全部合法签名返回固定 $b_{id}$，避免 Figure 9 的常数转录差距。

## 5 候选模拟器

输入统一是标准 SIS 挑战 $A\leftarrow U(\mathbb Z_q^{n\times m})$，无主陷门。每个编程矩阵的列使用独立 $D_{\mathbb Z^m,s}$ 原像；签名参考向量使用 $D_{\mathbb Z^d,t}$。它们目前是数学理想调用，不是把本轮符号工具中的标签当作采样器。

### 5.1 两者共同的非目标身份

固定 b；取独立 $R_b,R_{1-b}\leftarrow D_{\mathbb Z^{m\times w},s}$，编程

$$H_1(id,b)=AR_b+G,\qquad H_1(id,1-b)=AR_{1-b}.$$

H2 使用正常均匀随机预言机表。发钥返回同一个 $(R_b,b,k_{id})$；Sig 使用 $-R_b$、正常种子随机带和实际 SampleD。Key 后可重算旧 Sig。两个分支的 R 不得复用，用户种子不能从身份派生。

### 5.2 B_same：提取合法分支上的伪造

目标固定 b，编程 $H_1(id,b)=AR_b$；另一分支也可用独立 $AR_{1-b}$。目标不需要可披露陷门，因为其 Key 会中止，且合法签名已在隐藏随机带的桥接中替换为规范陪集高斯。

每个新的目标 H2 点，取 $\bar z_M\leftarrow D_{\mathbb Z^d,t}$，缓存并编程

$$H_2(id,M)=F_{id,b}\bar z_M.$$

目标 Sig 返回 $(\bar z_M,b)$；重复消息返回同一项。即使 H2 先于 Sig，也只用已缓存的向量；不重新编程已有点。

仅处理正确目标、普通 UF 新消息、$b^*=b$ 的有效伪造。参考与伪造均在零 tag 分支，可提取下节的 SIS 候选。

### 5.3 B_other：提取另一分支上的伪造

目标固定 b，编程 $H_1(id,b)=AR_b+G$，$H_1(id,1-b)=AR_{1-b}$。用前者的陷门正常 Sig，仍返回 b。

每个新的目标 H2 点，独立取并缓存 $\bar z_M\leftarrow D_{\mathbb Z^d,t}$，编程

$$H_2(id,M)=F_{id,1-b}\bar z_M.$$

正常签名使用相同 u，通过已知 $-R_b$ 在合法分支采样。参考向量保持隐藏。仅处理正确目标、新消息、$b^*=1-b$ 的有效伪造；提取使用 $R_{1-b}$。

### 5.4 三个一致性要求

1. H1/H2/种子预言机首次查询即确定槽位；H2 内部需要的矩阵不能等到 Sig 后才决定分支。
2. 新消息独立取参考向量；重复消息复用。同一 u 出现在不同消息上仍是两个不同点，**不假设 syndrome 永不碰撞**。
3. 对所有非目标用户、以及 $B_{other}$ 的目标，真实随机带和真实 SampleD 必须一致；无法完成有效采样时显式记录坏事件，不偷偷返回参考向量或均匀向量。

## 6 有限好矩阵条件：本项目的独立推导

“syndrome 接近均匀”需要强化成覆盖每个 u 的质量界，才能控制条件熵。定义 $\Lambda=\Lambda_q^\perp(A)$，

$$\Theta_A(v)=\rho_{1/v}(\Lambda^*\setminus\{0\}).$$

对满行秩 A，$\det\Lambda=q^n$。由 Poisson 求和，若 $\Theta_A(v)\le\varepsilon_0<1$，则

$$\rho_v(\Lambda+x)=\frac{v^m}{q^n}(1+e_x),\quad |e_x|\le\varepsilon_0.$$

而 $\rho_v(\mathbb Z^m)=v^m(1+\Theta_{\mathbb Z^m}(v))$，$\Theta_{\mathbb Z^m}(v)\le\Theta_A(v)$。所以所有 syndrome 满足

$$\frac{1-\eta}{q^n}\le\Pr[AX=u]\le\frac{1+\eta}{q^n},\quad
\eta=\frac{2\varepsilon_0}{1+\varepsilon_0},\quad X\leftarrow D_{\mathbb Z^m,v}.$$

若 $t\ge s$，同一个 A 的 $\Theta_A(t)\le\Theta_A(s)$，因此只需在较窄宽度 s 控制好矩阵。对任意 B，$F=[A|B]$ 的 $D_{\mathbb Z^d,t}$ syndrome 是 $A z_0+B z_1$；条件于 $z_1$ 是一次平移，故同样满足逐点质量界。

### 6.1 随机 A 的坏事件概率

质数 q 下，每个非零 $a\in\mathbb Z_q^n$ 的 $A^Ta$ 在 $\mathbb Z_q^m$ 均匀。利用 $\Lambda^*\subseteq\bigcup_a(\mathbb Z^m+A^Ta/q)$ 得到

$$\mathbb E_A[\Theta_A(s)]\le
\Theta_{\mathbb Z^m}(s)+(q^n-1)q^{-m}\rho_{q/s}(\mathbb Z)^m.$$

一维单调积分给出 $\rho_{q/s}(\mathbb Z)\le1+q/s$；令 $a_s=e^{-\pi s^2}$，几何级数给出

$$\Theta_{\mathbb Z^m}(s)\le
\left(1+\frac{2a_s}{1-a_s^3}\right)^m-1.$$

合并 Markov 与满秩失败的并合界，可用

$$\delta_A\le\min\left\{1,
\sum_{i=0}^{n-1}q^{i-m}+
\frac{(1+2a_s/(1-a_s^3))^m-1+(q^n-1)(1/q+1/s)^m}{\varepsilon_0}
\right\}.$$

秩项来自 $1-\prod_{i=0}^{n-1}(1-q^{i-m})\le\sum_iq^{i-m}$。这个有限推导参考 MP12 §2.3 的 Poisson/平滑工具；**上面整套显式界是本项目的保守推导，不是直接摘抄 Foo–Li 的原定理**。合数 q 不能套用非零 a 的均匀性步骤。

### 6.2 概率表与委派密钥的联合关系

对一列 $r\leftarrow D_{\mathbb Z^m,s}$，给定 $Ar=u$ 的分布精确为 $D_{\Lambda_u,s}$。因此“先抽 r 再公开 Ar”和“先抽均匀 u 再抽其条件高斯”联合距离等于 image 与均匀的距离。对 w 列可保守累计 $w\eta$。加 G 只是公开平移。

这说明编程 $H_1=AR+G$ 与披露 R 可以一起比较；R **不是**在观察 H1 后仍服从无条件整数高斯。真实 DelTrap 对每个合格主陷门、所有身份矩阵和历史，须统一接近上述列条件高斯，误差记为 $\epsilon_{del}$；真实 SampleD 对合格用户陷门须统一接近相应陪集高斯，误差记为 $\epsilon_{sp}$。

这两个有限误差及合格陷门条件尚未从完整实现获得。第二至五轮只实现了底层组件；不能直接将它们的 gadget 误差当作 $\epsilon_{sp}$。

## 7 SIS 提取与非零证明的条件论证

在选定零 tag 分支 c 上有 $F_c=[A|AR_c]$。有效伪造和参考向量给出

$$F_cz^*=F_c\bar z_M\pmod q,\quad e=[I_m|R_c](\bar z_M-z^*),\quad Ae=0\pmod q.$$

对带 G 的分支，同样计算只得到 $Ae+G(\bar z_1-z^*_1)=0$；一般不能推出 $Ae=0$。因此简单把原消息分支改成身份分支后照抄提取不可行。

### 7.1 隐藏原像的条件点概率

记 $Z_j(v)=\rho_v(\mathbb Z)^j\ge v^j$。给定任意公开 syndrome，由上一节逐点下界以及高斯单点权重至多 1，得到

$$\alpha_R\le\min\{1,q^n/((1-\eta)Z_m(s))\}
\le\min\{1,q^n/((1-\eta)s^m)\},$$
$$\alpha_z\le\min\{1,q^n/((1-\eta)Z_d(t))\}
\le\min\{1,q^n/((1-\eta)t^d)\}.$$

这是后验最大点概率，可转成最小熵 $-\log_2\alpha$；没有把无条件熵直接搬到条件分布。例：均匀 $r\in\mathbb Z_3^2$ 时，$r_0+r_1$ 精确均匀，但给定其为零，最大点概率从 1/9 增至 1/3，先验与后验总变差为 2/3。该有限例不是离散高斯替代品，只反驳错误的条件化推理。

### 7.2 非零提取的三个情形

普通 UF 保证伪造消息未 Sig。在两个模拟器中，这个点的参考向量一直隐藏，转录除 $F_c\bar z_M=u$ 外不使用它。因此猜中 $z^*=\bar z_M$ 的概率可由 $\alpha_z$ 控制。

若 $\Delta z=\bar z_M-z^*\ne0$，但子块 $\Delta z_1=0$，则 $e=\Delta z_0\ne0$。

若 $\Delta z_1\ne0$，选一个非零整数系数 j。给定其他列、公开 A 和 $AR_c$，事件 $e=0$ 至多确定一个 $R_c$ 的第 j 列整数向量；列条件高斯的独立性给出概率至多 $\alpha_R$。参考向量在给定 $F_c,u$ 后不进一步依赖 $R_c$，其他查询也须仅通过公开 $AR_c$ 使用它。因此候选非零失败界为 $\alpha_R+\alpha_z$。

**该论证的转录条件是证明义务。** 两个模拟器不把提取分支的隐藏 R 交给攻击者，不用它来真实 Sig，也不在交互前筛选其谱范数；只在最后检查解的质量。若先按范数重抽 R、暴露采样种子、复用 R 或引入依赖 R 的额外回复，必须重证上述后验熵，不能继续套该界。

非零向量差不能代替这一论证：数值例 $A=(1,2)$、$R=\bigl(\begin{smallmatrix}1&0&2\\2&1&-1\end{smallmatrix}\bigr)$、$\Delta z=(-1,-2,1,0,0)$ 非零，却满足 $[I|R]\Delta z=0$。

## 8 范数和全部失败预算

若 $\|\bar z_M\|\le B_{ref}$、$\|z^*\|\le B_{ver}$、$\|R_c\|_{op}\le\Gamma$，则

$$\|e\|\le(B_{ref}+B_{ver})\sqrt{1+\Gamma^2}=:\beta_{red}.$$

这使用整个验证范数，不假定两个分块分别满足更小的界。取 $B_{ref}=B_{ver}=t\sqrt d$ 时为 $2t\sqrt d\sqrt{1+\Gamma^2}$；后续 SIS 估计必须使用它，不能继续照抄原 Lemma 13 的渐近指数。$\beta_{red}\ge q$ 时存在平凡非零解 $q e_i$，必须排除该参数区间。

一个无需经验谱常数的保守选择：若所有 R 的整数项绝对值至多 $T_R$，则 $\Gamma\le T_R\sqrt{mw}$。以真正高斯尾概率 $p_R=\Pr_{D_{\mathbb Z,s}}[|x|>T_R]$ 预算最多 $2Kmw p_R$，再计有限采样误差。该选择可能太松，后续可改善，不能用实测谱范数替代证明。

新目标 H2 点数可保守取 $L\le Q_{H2}+Q_S+1$。未条件化参考向量的 $B_{ref}=t\sqrt d$ 尾概率由 MP12 Lemma 2.6 的零中心特例至多 $2^{-d}$，累计 $L2^{-d}$。真实陪集签名的正确性尾界另需实际格的平滑条件；不因参考向量的尾界成立而自动满足。

记 $\delta_{seed}$ 为经典秘密域桥接失败：主种子和未腐化目标用户种子的外部命中、预定义隐藏点等事件。理想隐藏随机函数模型下，可保守按三个域总查询预算取 $\delta_{seed}\le\min\{1,Q_{seed}2^{-\ell}\}$。本轮没有选择 $\ell$ 或完整随机带长度；针对真实有限随机带、种子公开及 oracle 编码的正式桥接仍待审查，不采用原文 QROM 的 $2^{-\ell/2}$ 作为经典查询损失。

对每个模拟器 c，完整转录比较可尝试以下保守预算：

$$\Delta_c\le\epsilon_{TG}+\delta_A+K\epsilon_{del}
+2Kw\eta+L\eta+\delta_{seed}
+\mathbf 1_{c=same}Q_S\epsilon_{sp}+\delta_{qual,c}.$$

$\delta_{qual,c}$ 必须含真实及模拟侧主/用户陷门质量、有限采样中止与所有提取范数坏事件。$\epsilon_{TG}$ 也要比较公开 A 与均匀挑战的分布；不能只验证陷门等式。候选比较顺序是先替换委派密钥及 $B_{same}$ 的目标签名、消去未披露主陷门，再替换公开 A，最后编程 H1/H2；不能在仍需主陷门时直接换入无陷门挑战。各项定义需避免重复或漏算；此预算是后续审查接口，不是本轮已测量的整体误差。

在全部接口和联合桥接成立的条件下，候选结论为

$$\epsilon_{FL}\le K\left(
\operatorname{Adv}^{SIS}_{B_{same}}+\operatorname{Adv}^{SIS}_{B_{other}}
+\Delta_{same}+\Delta_{other}+2(\alpha_R+\alpha_z)\right).$$

统一两个 SIS 优势上界时，主项至多 $2K\epsilon_{SIS}$。这是两个分支与猜槽位的保守损失，不是原文的常数 4，也不是紧归约。g 的联合耦合、隐藏种子桥接以及 $\Delta_c$ 的逐项实现映射仍须独立完成最终证明审查。

## 9 本轮工具究竟验证了什么

| 工具 | 验证内容 | 不验证的内容 |
|---|---|---|
| [符号与代数核验](../../../experiments/research/foo_li_fixed_key_audit.py) | 公开比特精确分布；目标槽位、提前哈希、重复消息、签后腐化；零 tag 方程、带 tag 反例、非零差但零提取反例、条件化计数 | 不生成真实 R、密钥、签名或随机预言机；标签不模拟 Gaussian |
| [有限好矩阵预算](../../../experiments/research/foo_li_matrix_mass_audit.py) | 上节坏矩阵与后验点概率的精确有理/MPFI 上界，弱参数给出空泛界 | 不验证 TrapGen/DelTrap/SampleD，不评估 SIS 攻击成本 |
| 独立测试 | 小矩阵穷举秩失败、独立高精度 theta、全部小 syndrome 后验对照、整数提取方程及故障路径 | 不证明真实密码安全或整体模拟器不可区分 |

好矩阵算术样例为 $(q,n,m,s,\varepsilon_0)=(17,1,32,6,2^{-40})$、$(257,2,128,8,2^{-64})$；弱对照为 $(7,1,2,1,2^{-4})$。全部手选、n 极小，不是完整密码参数；没有签名宽度 t、完整采样准入或安全估计。

| 算术样例 | 坏矩阵上界展示约值 | 解释 |
|---|---|---|
| q=17,n=1,m=32,s=6 | `3.5108e-8` | 仅好矩阵公式，不是整体优势界 |
| q=257,n=2,m=128,s=8 | `2.2598e-66` | 同样不是 SIS 安全位数；完整宽度与范数链缺失 |
| q=7,n=1,m=2,s=1 | 未截断 `128.29`，概率界截断为 1 | 保留空泛结果，不伪造准入证书 |

在指定 WSL 环境执行六个研究测试模块，**189 passed**，其中本轮 61 项、前五轮累计 128 项。原生 Windows 同一选择为 **77 passed,3 skipped**；三个跳过项是 Sage 专用模块，全部 112 项 Sage 检查已在 WSL 实跑。没有本轮失败测试；早期轮次记录保持不变。

MPFI 只参与一维 theta 尾的 π/exp 计算；其余为有理数。中间大有理数经向外舍入归档；过小正上界允许向上放宽至 $2^{-512}$ 以保持可序列化，不能据展示 float 宣称正式上界。计算工具资源范围为质数 $q\le2^{32}$、$1\le n\le m\le256$、$1\le s\le64$，不限制本文数学公式的维度，却限制工具的可运行输入。

符号实验身份为 `A`、`B`，各 1 ASCII 字节；消息为 `first`、`second`、`fresh`，分别 5、6、5 字节。使用有类型元组键，无真实协议编码或秘密种子。整数反例为 $q=7,n=1,m=2,w=3$，不满足完整 Foo–Li 选参条件。Monte Carlo 次数、Gaussian 样本、真实签名均为 0。运行环境和精确命令见 [第六轮核验记录](第六轮核验记录.json)。测试不能替代安全证明。

## 10 路线决定与下一项工作

Foo–Li **恢复为独立证明研究候选，正式后端仍未准入**。Wang + PW 的固定密钥版本也仍是条件草案；本轮没有以另一条未完成证明替换它。共同的 MP12 基础研究继续有效。

下一项单独工作：**有效 G-trapdoor 的 TrapGen 数学参考与公开矩阵分布核验**。使用指定 WSL Sage 环境及真高斯参考组件，分别验证符号、tag、矩阵维度、陷门等式、公开矩阵分布及质量预算；不同时接入完整 IBS/HIBE。

本草案的种子公开联合桥接、真实委派/签名误差、完整参数与猜槽位耦合形成明确待审查清单。取得完整采样后再对两条条件归约逐项代入，不能靠符号检查通过就登记安全后端。Boyen–Li 增强隐私继续明确排除。
