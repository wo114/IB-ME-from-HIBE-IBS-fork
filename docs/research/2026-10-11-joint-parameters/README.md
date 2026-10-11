# 首套联合参数、原文噪声与183维根采样诊断

日期：2026-10-11；基点 `4bea689`。用户要求继续主AI可做的部分。本轮完成有限数值检查和真实根组件诊断，保持队友CHKP算法文件边界，完整两层HIBE与正式安全组合仍为WIP。

## 本轮得到的结果

1. **当前有限实现的参数门槛交集为空。** 不只是上一轮的v1不适配：全部35个可能的`(n,ceil(log2 q))`区间均无法同时满足现有AP09维度规则、GPV192/C1-exec和已选Lemma5.1的q条件。继续只改q或宽度无法闭合这些门槛。
2. **原文alpha与取整预算已能精确计算。** 检查器覆盖连续Gaussian取整、奇数q与平局、固定原像好范数、共享前导的多bit并集预算；未实现的噪声采样和TV/ABORT仍明确留空。
3. **真实183维根路径走通。** 两组固定公开测试根均成功生成；原GPV因坐标宽度拒绝；独立Sage LLL诊断经精确验证后，同一未修改GPV完成4个原像，方程4/4通过。没有筛选种子或隐藏原路径失败。
4. **数值可行与实现可运行已经分开。** 提供一个通过所列q/条件噪声关系的较大资源规划，并明确其全部关键当前资源门都未通过；它不是可以直接交给现有后端的配置。

工具为[联合条件计算器](../../../experiments/research/ibme_joint_parameters.py)与[根诊断](../../../experiments/research/ibme_root_sampler_audit.py)。机器结果分别为[joint-conditions.json](joint-conditions.json)、[root-diagnostic.json](root-diagnostic.json)，测试/文件/指纹汇总见[audit.json](audit.json)。

## 1. 为什么35个区间足以覆盖当前范围

这是对当前**程序选用的充分门槛**做有限整数核验，不是重做CHKP安全归约，也不声称论文或所有更紧的选参无法实现。

令`ell=ceil(log2 q)`，当前有限AP09要求`r>n*ell`、`m1>=r`、`m2>=2*n*ell+2*r`。因此

```text
m=m1+m2 >= 5*n*ell+3
D_leaf=3*m <=192  =>  n*ell<=12
```

对`1<=n<=16`的实现范围，只有35个可能区间。每个区间都使用最有利的`q<=2^ell`、最小叶维数、最小允许`epsilon_bits=2`，以及完整整数格基必有的`max GS²>=1`。这里是**最大**GS下界；不声称每个GS长度都至少1。

当前GPV的C1-exec给`s2²>=4*k`，`k=ceil(log2(2D_leaf(1+2²)))`；选定CHKP Lemma5.1/PDF19的q充分条件则要求`q²>=16*s2²*(D_leaf+1)²`。逐区间比较`2^(2ell)`与`64*k*(D_leaf+1)²`，35/35冲突。更大的m、epsilon_bits或实际最大GS只会收紧本下界。

最接近的一例仍失败：`n=1,ell=12,D_min=189,k=11`，即

```text
q² <= 4096² = 16777216 < 64*11*190² = 25414400
```

这里连非素数的端点4096都保留作有利上界，实际素数不可能填平差距。这不能推出某个教学实例绝对无法解密：论文q条件和C1-exec本身是充分条件。结论仅为**现有选定门槛的交集为空，下一步需要明确改变实现支持域或采用另一个经核验的采样/GenBasis路线**。

## 2. 原文噪声、alpha和多bit账本

核对[36页CHKP作者稿](../../../papers/2010_bonsai_trees_cash.pdf)的PDF12/§2.3.1、PDF18–19/§5.1和PDF20–22/§5.2–5.3。原文`chi_alpha`抽连续Gaussian宽度alpha，再输出`round(q*X) mod q`。它不自动等于离散Gaussian `D_Z,q*alpha`；宽度平方也不等于统计方差。本轮未开发噪声采样器，未用整数Gaussian代替原文模型。

对固定原像x，假设`||x||²<=B=s²D`。解封装误差为标量噪声减去x与前导噪声的内积；取整贡献至多

```text
R=(ceil(sqrt(D*B))+1)/2
```

连续部分的Gaussian宽度平方为`q²*alpha²*(B+1)`。解码按原文比较到0和`floor(q/2)`的模q距离，严格更近0才输出0；保守整数相位半径取

```text
M=floor((floor(q/2)-1)/2)
```

若`M-R>0`且

```text
q²*alpha²*(B+1)*(error_bits+1) <= (M-R)²
```

则在上述好范数与**精确原文噪声**条件下，每bit失败概率至多`2^-error_bits`。依据是连续Gaussian Chernoff尾界及`pi>ln2`；这是保守有限计算，不把它写成原文逐字定理或安全证明。取整/平方根和所有阈值采用整数/有理数。

原文多bit允许同一s与b前导、逐bit独立syndrome/原像及标量噪声。对N次诚实封装、每次L bit，条件噪声预算为`min(1,N*L*2^-error_bits)`；并集界不要求这些bit的误差彼此独立。真实噪声近似误差、坏原像范数、GPV TV/ABORT、基规约/资源失败和LWE难度仍单列，计算器不补默认零。

新增奇数q平局检查也避免错误地把`|error|<q/4`单独作为有限解码判据：q=5时，bit0加误差1仍在q/4内，但到0和`floor(q/2)=2`距离相同。这是接口边界核验，不是对原文安全定理的攻击。

## 3. 实际183维根：原路径拒绝与独立规约诊断

根参数和公共先验固定为：

```text
n=1,q=257,r=m1=55,m2=128,Cprime=21,m=183
AP09 GS² certificate upper=31685
root SampleD: epsilon_bits=32,width_squared=5196340
OnlineOptions保持原默认值；未更改任何原语上限
```

使用预定种子`ibme-joint-root-0/1`，每个执行一次GenBasis；随后各走原基与独立规约基两个明确分支。原基拒绝在抽样前发生，不存在“先抽失败再重试成功”。先前同种子探索是重放，不计新的独立样本。

| 项目 | seed0 | seed1 |
|---|---:|---:|
| 根生成 | 通过，31.59 s | 通过，30.17 s |
| GenBasis实际熵字节 | 7250 | 7250 |
| 原GPV | 坐标宽度超过10^12，拒绝 | 同左 |
| 独立Sage LLL后最小GS² | 1 | 1 |
| 独立Sage LLL后最大GS² | 5/2 | 1366/599 |
| 根原像方程 | 2/2，syndrome0/17 | 2/2，syndrome0/17 |
| SampleD公共最坏随机带上界 | 57151600 B | 57151200 B |
| 两个原像实际熵字节 | 26114 / 30108 | 29874 / 28654 |
| 规约诊断耗时 | 3.38 s | 3.50 s |

公开矩阵含中止TV证书上界约`1.0811e-5 <2^-16`；固定规约基的一次GPV TV证书约`4.2608e-8`。这些是指定独立均匀字节模型下已有工具的证书，**不是实测统计置信界或密码安全位数**。运行使用固定测试随机流，没有生产密钥。

Sage LLL的列变换幺模性、完整核格、最大GS、size reduction及`delta=99/100`的Lovasz条件均以精确算术检查。使用相同原始先验宽度，没有按测得的秘密GS调小s。没有导出基矩阵、变换矩阵或原像向量。

该诊断不替代队友当前`<=64`维的有界精确规约，也没有统一资源/失败证明；不是获准Setup步骤。未测内存峰值，表中时间包括额外核验，不能当公平性能对比。q=257的根诊断并不满足完整KEM所需q关系；没有两层委派、H/G、Encaps/Decaps或256bit缓存结果。

## 4. 大资源数值规划：关系通过仍不运行后端

默认规划输入`n=1,q=274877844481`、公开误差目标`2^-32`、采样epsilon_bits64、解码error_bits64、256bit种子、最多`2^20`次诚实封装。输出：

```text
r=m1=123,m2=322,Cprime=36
m0/m1_level/m2_leaf=445/890/1335
root GS² bound=187088
s1²=56126400,s2²=15185558784000
alpha=2^-33
```

上述q充分关系与条件噪声关系通过，条件寿命噪声预算`2^-36`。公开矩阵/秩失败/均匀拒绝分别分配四分之一目标，矩阵TV按原工具2^-80的向上舍入处理；不会忽略有限精度。

**当前资源全部未放行：**AP09根192与分块192、GPV192、叶单位GS坐标宽度10^12、固定bit容量32均不适配。真实标量宽度、随机带、RandBasis、规约和wire还没有运行/证书。n=1仅作诊断，LWE困难性及原文渐近常数未核验。此规划不是正式参数，不能只调大上限后写成安全或完整HIBE，也不与上一节q=257结果拼接为同一整链。

## 5. 测试与复跑

```text
python -B -m pytest -q -p no:cacheprovider tests/test_ibme_joint_parameters.py tests/test_ibme_root_sampler_audit.py tests/test_ibme_handoff_screen.py tests/test_chkp_paper_preflight.py tests/test_chkp_t2_conditions.py --tb=short --junitxml=test-results/joint-parameters-native.xml
# 112 passed,4 skipped in 0.32s

PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -B -m pytest -q -p no:cacheprovider tests/test_ibme_joint_parameters.py tests/test_ibme_root_sampler_audit.py tests/test_ibme_handoff_screen.py tests/test_chkp_paper_preflight.py tests/test_chkp_t2_conditions.py --tb=short --junitxml=test-results/joint-parameters-sage.xml
# 118 passed in 2.94s

python -B -m experiments.research.ibme_joint_parameters --output test-results/joint-conditions.json
# 预期退出码2：完整证据已输出，当前后端未准入

PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -B -m experiments.research.ibme_root_sampler_audit --output test-results/root-diagnostic.json
# 实际退出码0：两组根诊断路径完成，不表示完整HIBE
```

WSL均先进入仓库，Sage环境使用可移植的`~`路径。新增51项Sage可执行检查，相关118项不是全仓库；Windows的4个skip明确对应Sage证书/诊断及旧交接核验。环境：Intel Core Ultra9 275HX，Windows Python3.14.6、WSL Sage10.9/Python3.13.14、pytest9.1.1。实际root两个固定种子、每根两个syndrome，各一次；未调用身份H/G或消息加密，静态预算按256bit种子，不存在完整消息性能实验。

## 6. 修改边界、WIP及下一步

本轮15个文件清单见audit.json：新增独立主AI数值/根诊断与测试，更新规格、总进度、双方任务入口和基础CI。跨范围原因是首套的同参数接入和噪声语义需要统一；没有修改任何队友chkp_*算法、格工具、生产协议/CLI或现有参数。

下一轮主AI可继续原文噪声的有限实现与误差账本，队友优先明确根/父基规约或另一合格GenBasis、各级标量/向量/随机带支持域，再完成同组两层/256bit生命周期。已发表定理继续引用，不默认扩展安全证明工程。备用候选深入、独立优化及A+B<C比较后置。

完整CHKP、正式选参、实际噪声及其有限误差、统一规约/中止/资源、256地址/wire、端到端攻击验收均WIP。旧教育版两个认证漏洞继续保留。所有新对象与规划均`security_claim=none,backend_admitted=false,parameters_are_formal=false`；模型为经典ROM研究引用，不宣称QROM、标准模型或安全等级。功能/整数检查不能替代安全证明。
