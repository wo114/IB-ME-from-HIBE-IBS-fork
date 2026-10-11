# 首套原文噪声采样、有限误差与共享前导接入

日期：2026-10-11；基点`a0f2f01`。用户要求继续尝试，下一步优先紧急工作。本轮把[上轮条件式噪声计算](../2026-10-11-joint-parameters/README.md)所需的实际噪声组件做出来，保持CHKP候选和队友原语边界。完整两层HIBE仍为WIP。

## 1. 实际完成的工作

- [噪声采样器](../../../experiments/research/ibme_rounded_noise.py)：按CHKP原文的连续Gaussian取整分布构造有限CDF，提供signed、mod-q和向量抽样。
- [配置与组合账本](../../../experiments/research/ibme_noise_budget.py)：纯Python配置/资源检查、q/alpha绑定、原解码预算重算，按共享前导的D+L计入有限噪声误差。
- [六组实跑](../../../experiments/research/ibme_rounded_noise_audit.py)：98,304次抽样、独立mpmath PMF对照、默认/高精度/窄噪声/小模数配置；保留3组预期资源拒绝，不进行隐藏重试。

机器结果见[sampling-results.json](sampling-results.json)，文件/测试/源码指纹见[audit.json](audit.json)。没有修改队友chkp_*文件、旧Gaussian工具、生产HIBE/IBS/协议/CLI，旧教育参数和两个认证漏洞状态保持。

## 2. 为什么该组件需要独立实现

[CHKP36页作者稿](../../../papers/2010_bonsai_trees_cash.pdf)PDF12/§2.3.1定义chi_alpha：抽连续Gaussian宽度alpha的X，返回round(qX) mod q。令w=q*alpha，取整后整数z的概率为

```text
p_z = integral(z-1/2 .. z+1/2) exp(-pi*y²/w²)/w dy
```

现有SampleD的整数离散Gaussian按整数点的exp权重抽样，二者分布不同。例如w=1时，取整连续Gaussian的零概率约0.7899086，整数离散Gaussian约0.92044。独立积分检查保留了这个差异，因此不能直接将旧采样器当作原文chi_alpha。

本实现直接计算取整后的概率，无需先生成一个浮点连续数再round。它仍是有限误差的研究参考，不是精确无限分布或已准入生产后端。

## 3. 有限CDF与误差账本

使用[Sage/Arb实球区间算术](https://doc.sagemath.org/html/en/reference/rings_numerical/sage/rings/real_arb.html)计算F(z+1/2)的erf表达式。本机Sage10.9接口另行核验；浏览器手册为10.8，不把手册版本写成本机版本。

1. 公开截断半径R=ceil(w*sqrt(tail_bits+1))，在区间计算前用精确有理数/整数平方根检查资源。原分布外侧质量移动到两端点，不对成功或落在范围内的样本重新条件化。
2. 对N=2^mass_bits，取每个内部CDF区间的下端点floor，并用前缀最大值保持单调。实际取整/区间误差逐点向上记账，最后CDF恰为N。
3. 一次抽样读取固定ceil(mass_bits/8)字节，只屏蔽未使用高bit；逆CDF输出非均匀整数，不使用模N偏置、拒绝抽样或默认零。错误熵源类型/长度明确失败，异常传递，不替换为系统源。
4. modulo-q为确定性投影，不增加分布TV误差。整个表不保存RNG或私钥状态。

连续Gaussian尾界给出tail TV<=2^-tail_bits。每个内部CDF点的误差e_i由整数区间上界计入，有限PMF的TV至多sum(e_i)，因此单次采样证书为

```text
delta_chi <= min(1, 2^-tail_bits + CDF_interval_error_units/2^mass_bits)
```

在独立均匀字节模型下，固定一次读字没有算法拒绝中止；故该项为0。故障熵源不在该概率模型中，运行时异常仍向外传播。CDF证书/指纹只是可复核证据，不是用户提供JSON的真实性证明。

## 4. 六组实跑与拒绝控制

每组预定测试流、16,384个signed样本，无种子筛选或失败后重抽；重放同种子不计新增独立样本。

| 配置 | q / alpha | R | 量化bit/区间精度 | 实际熵字节 | 单样本TV上界近似 |
|---|---|---:|---:|---:|---:|
| unit-width | 17 / 1/17 | 9 | 128/256 | 262144 | 8.27e-25 |
| width-four | 257 / 1/64 | 37 | 128/256 | 262144 | 8.27e-25 |
| candidate-default | 274877844481 / 2^-33 | 288 | 128/256 | 262144 | 8.27e-25 |
| candidate-high-precision | 同上 | 407 | 192/320 | 393216 | 6.84e-49 |
| narrow-noise-control | 257 / 2^-16 | 1 | 128/256 | 262144 | 8.27e-25 |
| small-modulus-fold | 7 / 3/7 | 27 | 128/256 | 262144 | 8.27e-25 |

默认tail_bits80；高精度tail_bits160。六组独立mpmath PMF数值差异均小于各自证书；单位测试另使用独立数值积分，而非复用Arb构造器。统计记录不替代区间证书、不估计2^-80尾部或给出安全位数。窄噪声控制的16,384次结果全部为0，符合该近似分布，**不是零值回退或适用于安全HIBE的选参结论**。

另3组在抽样前明确拒绝：q*alpha超出支持域、支持半径超限、精度小于mass_bits+32。记录原输入类别及理由，没有用均匀/零噪声代替。合法配置和这些参数变体都不增加HIBE/IBS算法实例数。

## 5. 接入上轮条件式预算

原文PDF19多bit复用同一s及b前导，每位拥有独立标量噪声。D维前导与L个bit共抽D+L次chi，而不是L*(D+1)次。对M次诚实封装，有限噪声实现与理想模型的耦合误差上界为

```text
delta_noise_implementation <= min(1,M*(D+L)*delta_chi)
```

组合器先重算原有q/alpha/宽度/取整预算，核对证书配置和全部误差项；缺失项、错q/alpha、非规范参数、伪造的零误差或改写的理想预算均拒绝。没有认证外部证书或核验私有原像的好范数。

上轮规划D=1335,L=256,M=2^20，实际需要1,668,284,416次标量噪声调用。默认配置的有限实现耦合预算约1.38e-15，高精度约1.14e-39。原条件寿命解码噪声预算2^-36在加上该项后仍保留明确数值。这里都是**给定固定原像好范数的条件预算**；规划本身尚未运行生成/两层委派，也未满足当前其他资源门。

供队友调用的最小接口：

```python
from fractions import Fraction
from experiments.research.ibme_noise_budget import RoundedNoiseParams
from experiments.research.ibme_rounded_noise import build_rounded_noise

noise = build_rounded_noise(RoundedNoiseParams(q=274877844481, alpha=Fraction(1, 2**33)))
errors = noise.sample_vector(D + L, mod_q=True)  # 缺省系统CSPRNG；测试流必须显式传rng
preamble_errors, bit_errors = errors[:D], errors[D:]
certificate = noise.certificate()
```

该示例只演示噪声接口，不能据此注册整个规划为安全后端；前导s、矩阵/身份、原像缓存和真正Encaps仍由CHKP原语负责。

## 6. 验证、环境与修改边界

```text
python -B -m pytest -q -p no:cacheprovider tests/test_ibme_noise_budget.py tests/test_ibme_rounded_noise.py tests/test_ibme_joint_parameters.py tests/test_ibme_root_sampler_audit.py tests/test_ibme_handoff_screen.py tests/test_chkp_paper_preflight.py tests/test_chkp_t2_conditions.py --tb=short --junitxml=test-results/rounded-noise-native.xml
# 160 passed,5 skipped in 0.41s

PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -B -m pytest -q -p no:cacheprovider tests/test_ibme_noise_budget.py tests/test_ibme_rounded_noise.py tests/test_ibme_joint_parameters.py tests/test_ibme_root_sampler_audit.py tests/test_ibme_handoff_screen.py tests/test_chkp_paper_preflight.py tests/test_chkp_t2_conditions.py --tb=short --junitxml=test-results/rounded-noise-sage.xml
# 206 passed in 4.67s

PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -B -m experiments.research.ibme_rounded_noise_audit --output test-results/rounded-noise/audit.json
# 6组/98304抽样、3拒绝控制、退出码0
```

指定WSL Sage环境，先进入仓库；~路径不写死用户名。新增88项Sage可执行检查，其中48项可移植元数据/账本、40项实际CDF/积分/随机源检查。Windows的5个skip对应需要Sage的检查/模块，已经在指定环境执行；批次206不是全仓库。

环境：Intel Core Ultra9 275HX，Windows Python3.14.6，WSL Sage10.9/Python3.13.14，pytest9.1.1、mpmath1.4.1。本轮没有H/G身份输入、消息/密文或密钥生成；D+256预算为静态调用计数。时间/统计均为组件诊断，不是完整HIBE/IBME基准。

当前资源范围为2<=q<=2^61-1、0<alpha<1、1/256<=q*alpha<=16384、tail_bits8–256、mass_bits8–512、precision_bits128–1024且至少mass_bits+32、R<=公开max_radius<=16384、向量长度<=65536；R超限或区间无法核验时拒绝。默认max_radius8192。精度与表大小不是密码安全等级，Sage依赖/可变时间/有限表范围不自动成为生产条件。

本轮15个文件的完整清单见audit.json。跨范围原因是主AI补跨原语的原文噪声工具并冻结队友接入接口；没有修改队友专属算法或现有生产代码。基础CI增加可移植账本和明确Sage跳过边界，上轮CI已确认成功。

## 7. 下一步与安全声明

噪声组件及其局部分布/误差核验已交付；完整CHKP仍需同组根/父基和标量/向量/随机带支持域、256或更多固定地址及wire、实际H/G/bit KEM/字节适配。接到真实组件后继续完整加解密、篡改/错配/伪造及实际资源验收。候选资格保留，最终三组代表按完整组合的实际结果选择。

原像坏范数、GPV TV/ABORT、基/规约/资源失败、实际LWE估计与完整ROM引用条件仍为WIP；不能只靠此噪声模块解决当前维度交集为空的问题。旧教育版两个认证漏洞仍未修复。所有新对象、配置、数据和组合账本保持`security_claim=none,backend_admitted=false,parameters_are_formal=false`；不宣称QROM、NIST安全等级、完整匿名性或A+B<C。测试不能替代安全证明。
