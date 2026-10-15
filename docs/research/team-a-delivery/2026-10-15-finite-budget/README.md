# A0/A3：结构化 H/G 的具体有限账本与完整参数域筛查

本批承接[真实后端与框架交付](../2026-10-15-framework-and-structured/README.md)，推进尚缺的具体卷积常数、全树/服务次数和正式参数第一阻塞。新代码给实际采样器证书增加分布预算，并提供零秘密、零熵的公共账本和整个现有参数域的乐观排除检查。HIBE/IBS算法数、协议、采样方程、现有wire与参数版本均保持原有含义。GKR、ABB标准模型、CHKP标准模型继续按用户要求暂缓。

**结论：当前结构化配置的累计模型上界落在 `(2^-98,2^-97]`，没有达到 `2^-128`；现有完整H/G实现域仅可能容许 `n≤5`。A尚未完成正式参数准入。** 概率预算指数与攻击成本分开记录，不把97称作安全位数。n2原有公开恢复攻击继续成立。所有材料保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。

## 1. 原文和具体卷积常数

原文：[MP12作者稿](../../../../papers/2011_lattice_trapdoors_micciancio.pdf)，本地PDF共41页，SHA256 `bf1160f088825ed28c343b299f5bc2acdca41cc50293310a03a4506d2fdbdb84`。定位为Lemma2.3/2.5/2.6、Lemma5.3、Algorithm3与Theorem5.5证明(5.1)，PDF28—29。论文在[作者出版物页](https://cseweb.ucsd.edu/~daniele/papers.html)登记，ePrint编号2011/501；本批核验使用仓库固定PDF，网络PDF的403不影响本地版本定位。

设 `T=[R;I]`、`w=n·ceil(log₂q)`、`D=prefix+w`，`B`为预先声明的R范数平方界，`K(d,b)=ceil(log₂(2d(1+2^b)))`。实际工具使用

```text
r² = 4 K(w,128)
γ² = 5r²
s² >= max(7r²(1+B), 10r²(w+B))
C = s²I − γ²TTᵀ.
```

Algorithm3两个smoothing前提分别成立：gadget格基最大GS平方≤5；`Λ=L(T)=Z^D∩span(T)` 在协方差 `r²TTᵀ` 下的dual质量对应 `Z^w`。`r²`超过Lemma2.3要求的标量因子。输出宽度还保证 `C≥2r²TTᵀ`，满足原文乘积Gaussian的矩阵条件。坐标置换不改变这些前提。

令 `ε=2^-128`、`t=(1+ε)/(1−ε)`。证明(5.1)中，gadget余类normalizer的倒数相对中心值落在 `[1,t]`；交格余类normalizer相对中心值落在 `[1/t,1]`。因此输出相对目标的未归一化密度比在共同常数乘以 `[1/t,t]` 内；再次归一化后密度比在 `[1/t²,t²]` 内。直接积分绝对差，得到具体保守界

```text
TV_convolution <= min(1,(t²−1)/2) = min(1,2ε/(1−ε)²).
```

这只展开已有证明的常数，没有改写原基础定理。代码为 `src/ibme/lattice/matrix_sampling/mp12_bounds.py`；实际 `StructuredPreimageSampler.public_certificate()` 读取自己的有限标量/GPV数据，加入新项。历史收据中的null按原版本保留。

## 2. 有限实现、范数和累计次数

扰动理想接受率≥1/4沿用原公开trace/normalizer门，512次全部拒绝的上界为 `(3/4)^512`。每次proposal最多有D个有限标量输出，标量TV已含其自身Gaussian/均匀拒绝中止。Bernoulli误差每次最多 `weight_width+2^-mass_bits`。所以单次SampleD的模型界为

```text
512·(D·δ_scalar + δ_Bernoulli) + (3/4)^512
  + n·δ_gadget_GPV + TV_convolution,
```

最后截于1。gadget项本身含GPV几何和有限标量中止，没有另把这些中止再加一遍。此界统一覆盖目标syndrome，可用条件耦合和union bound累计自适应调用，无须假定整棵树各失败事件独立。

范数门为 `||x||²≤D·s²`。Lemma5.3给出一个理论完整基的GS平方上界 `5(√B+1)²≤10(B+1)`；只用这个存在性界核验目标余类的smoothing，不生成该基。实际检查 `s²≥10(B+1)K(D,128)`。随后用指数Markov和Poisson质量界：

```text
Pr[||X||²>D·s²]
 <= (√2·exp(−π/2))^D · (1+ε)/(1−ε)
 <= (3/10)^D · (1+ε)/(1−ε).
```

代码向上取dyadic界，保留最大维度的有界JSON序列化。256位有向区间单独检查 `√2·exp(−π/2)<3/10`。根R是中心Gaussian，整个根范数坏事件可直接用Lemma2.6的 `2^(-2nw)`。所有范数截断在耦合后的理想Gaussian上计费，实际失败地址仍固定、不得重发。

默认同组参数仍为n2、q549755813911、根R平方宽16、qα4，身份上限86 B、seed32 B、2接收者×2发送者；w80，父采样88维、叶252维，全部宽度沿用原版本。完整树为320次根R标量、160次父SampleD、1024次叶SampleD。恢复和重复使用固定密钥不增加SampleD次数。

服务预算另声明 `2^20` 次封装、至多 `2^20` 个不同H地址和 `2^20` 条不同G路径（每路径256个位置地址）。重复查询固定。每次封装有508个真实rounded-noise标量和2个新均匀secret系数，整个服务有532676608个噪声标量。不同H/G地址的理想随机流内，单个模q拒绝事件用精确比率 `((2^k−q)/2^k)^128`；Setup均匀Â使用实际192次帽。实际SHAKE的构造安全损失没有用0填充。

| 累计项 | 当前算得上界的dyadic指数b，即该项≤2^-b |
|---|---:|
| 根R有限耦合 | 119 |
| 全父SampleD有限分布/中止 | 104 |
| 全叶SampleD有限分布/中止 | 100 |
| 理想父列范数中止 | 144 |
| 整服务有限rounded-noise耦合 | 99 |
| 范数条件下理想诚实解码失败 | 100 |
| 理想H/G有界拒绝中止 | 98 |
| 总累计模型上界 | 97 |

指数来自各实际有理数上界，不是实测失败频率。完整原始分数见本批证据。模型要求独立均匀随机字节、已准入的精确算术和正确MPFR/MPFI有向取整；工作区/OS/内存故障、任意坏熵源、侧信道、回滚以及SHAKE/LWE/组合安全均不在该数值里。公共投影没有验证每把真实R的Schur/中心位数路径；真实采样器照旧单独检查。

## 3. 完整参数域的必要维度上限

`structured_feasibility.py` 遍历 n=2…128、q位数k=2…61，两种噪声口径共15240个区间：当前整数噪声最低qα=1；另列满足 `qα>2√n` 这一经典归约必要条件的最低整数。每个区间取最大q=`2^k−1`（允许它合成，从而保持乐观）、最小合法根R平方宽4n，再推完整根→父→叶宽度。固定k时维度和宽度不随q变化，q越大解码phase半径越大；增加R宽度或qα只会增加要求。

把完整叶prefix `6n+2nk≤512`、列/项/宽度资源门与同组噪声门相交，n≥6的全部区间被排除。n5只有k≤48可能通过资源门；n6的k≤39即便取该区间最大q也不能通过同组噪声门。故**当前版本任何实际可执行完整配置都必须n≤5**；素性、快照、随机带及真实路径门还能进一步排除。这个结论覆盖整个当前输入域，超出该域的算法/参数方案未由它否定。

首n列公钥为I，真实有限噪声半径≤8192，因此枚举这n个噪声坐标会给出包含真实secret的至多 `16385^5` 个候选（向上指数71）。本批没有运行这个最大枚举，也没有证明候选唯一恢复或每个参数上的区分成功，不能把候选列表计数写成实际攻击成功率。已有n2原对象的真实公开恢复攻击见上批，保持原样。

正式维度的下一步必须改动实际资源算法和输入域，并重新核验同组条件；只换较大n或增加重复次数不能解决这个阻塞。有限累计目标还需重新分配scalar tail/abort、GPV epsilon、噪声与有界拒绝的预算，并显式版本化，不能悄悄修改原profile。

## 4. 运行与交接

在仓库根，Sage只用指定WSL环境；输出必须新建：

```sh
export PYTHONPATH="$PWD/src:$PWD"
export OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=1
~/miniconda3/envs/sage/bin/python -m experiments.research.structured_service_budget --output test-results/my-service.json
~/miniconda3/envs/sage/bin/python -m experiments.research.structured_feasibility --output test-results/my-domain.json
~/miniconda3/envs/sage/bin/python ci/run.py run a-structured-hg --output test-results/my-structured-check
```

公共账本没有生成根、密钥、Gaussian样本或消耗随机字节。所有原语诚实生命周期和异常语义仍由专项中的真实Gaussian测试验证；本批不重复生成昂贵系统根。已有同根2×2状态用原只读预算脚本复核实际父/叶证书，禁止新发钥/新采样/读熵。

初次公共账本遇到Sage QQ和Python Fraction混用的类型错误，修正为Sage内部用QQ、JSON边界用精确分数；未修改任何概率/资源门。失败命令、最终源码、实际测试与文件清单随audit交付。Windows可执行纯分数/域筛查；Sage专项执行全部真实机制，不将缺Sage跳过写成通过。

本批仍为**WIP：A整体未完成**。当前128-bit累计目标失败、正式困难参数不可在当前完整域落地，计算型根/匿名ROM/固定服务到Wang前提的对应与同安全目标的完整基线/消融继续待办。硬件/软件、源码和测试结果以本批audit记录为准；测试不能替代安全证明。
