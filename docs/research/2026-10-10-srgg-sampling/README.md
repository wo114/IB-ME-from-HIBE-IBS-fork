# SRGG 第二轮：有限误差高斯 gadget 采样

日期：2026-10-10；基点 `ae572cd`。开工时工作树干净，远端无新增提交或开放PR。上一轮GitHub CI [run38022075184](https://github.com/youzi258/IB-ME-from-HIBE-IBS/actions/runs/38022075184)两个任务均已成功。本轮承接[代数与几何基础](../2026-10-10-srgg/README.md)，在独立候选目录实现随机 gadget 采样与交接核验，没有修改队友CHKP、生产协议或既有原语接口。

**已交付有显式误差界和中止行为的离散高斯 gadget 内核。** 40项新增检查在指定WSL Sage通过；实际核验36,864次标量抽样、27组精确有限联合分布、369个标量原像及384次带随机gadget的原像/密钥重建。结果见 [audit.json](audit.json)。它仍不是完整IBS，全部 `security_claim: none`、`backend_admitted: false`。

## 1. 原文与宽度决定

使用用户提供的[SRGG完整PDF](../../../papers/2025_efficient_ibs_jia.pdf)，SHA-256仍为 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。定位为Table3/PDF6、§4.2.2的SampleZ配方、Algorithms5/6/PDF7以及Algorithms2/7的重建关系。也复查了[出版社当前正文](https://ietresearch.onlinelibrary.wiley.com/doi/10.1049/ise2/6684889)；本轮没有取得作者C实现。

本项目采样密度约定为 `exp(-π(x-c)²/s²)`；s是密度宽度，不是物理标准差。使用精确平方宽度，不先计算浮点平方根。离散分布的实际方差也不直接设成s²/(2π)，而是按PMF算出并测量。

令 t 按中心−v/b、宽度r的整数高斯抽样，再令 z=bt+v，则指数变成 `-π z²/(b²r²)`。因此输出在bZ+v上，宽度为br，平方宽度为b²r²。Table3的σ=br与这一配方相符；Algorithm6字面写的是宽度r。二者的输出分布不同，不能只更改变量名字就当作相同。

主AI在独立研究内核中的决定：**调用者必须显式给出digit_width_squared**；主用例取b²r²并标为Table3/SampleZ配方，字面r²另作对照。没有悄悄更改生产协议或宣称作者勘误已经确认。仿射宽度等式与配置映射已核验，原文记号差异仍待版本/作者依据解决。

签名中的ζ乘法使系数形状放大2，而原表签名扰动减去r²的对应问题，本轮没有自动关闭。主扰动按σ²而非正文一处r²的解释沿用上一轮。

## 2. 实际实现

[sampling.py](../../../experiments/research/candidates/srgg/sampling.py)复用已有公开 `gaussian_reference.build_gaussian_table_squared`，没有覆盖格工具文件。每个b陪集构建一个MPFI外向区间权重表，整数CDF采样；表记录无限尾部、区间/权重量化和随机整数拒绝中止的上界。这是可变时间研究实现。

对规范目标u，取e=u mod p、v=(u−e)/p。逐位采z_i于bZ+v，更新v=(v−z_i)/b。**负整数进位完整保留**，不会截断成0或回退到确定性digits。由于q=b^w，最终严格满足：

```text
p * Σ b^i z_i = u - e (mod Q),  Q=pq.
```

这里e采用明确的规范代表元0..p−1；没有把其范数误记为中心化余数的范数。SampleGadgetF按模块/多项式/系数的固定顺序组装结果。新 `extract_with_gadget`接入真实随机gadget输出，调用者仍提供扰动，核对Ay_raw=H−e，再由原HNF方法重建Ay=H。报告中的这些扰动是代数夹具，**没有伪装成高斯SampleP**；用户向量的完整分布和范数尚未准入。

缺省随机源来自系统CSPRNG；固定测试流仅用于诊断。显式传入的随机源即使布尔值为False也不会被替换。错误字节类型/长度直接失败，拒绝预算耗尽抛 `GadgetSamplingAbort`；即使已有第一位，也不返回部分向量或默认值。非法输入先拒绝再消费熵。

## 3. 不能漏掉的整个向量偏差

逐位高斯的误差很小，不能据此把整个递归向量称为精确球形高斯：每位分母是当前陪集的无限高斯质量Z_a，它随进位的陪集变化。

参考沿用既有gadget研究的保守预算方法，令K=max Z_a/min Z_a（区间上界），C为标量抽样次数。理想递归与目标无限球形fiber的TV上界取min(1,(K^C−1)/2)；有限实现另外累加C次标量误差，标量误差已经包含中止。不把中止再重复计入总TV。多项式/模块组合使用blocks×w的次数，界对所有规范目标统一。这只是gadget fiber层的预算，不覆盖扰动卷积、HNF后的密钥或签名。

| 配置（b=3,w=2） | digit平方宽度 | 标量组合有限误差 | 递归归一化偏差界 | gadget总TV界 |
|---|---:|---:|---:|---:|
| Algorithm6字面r²=4 | 4 | 约9.41×10⁻²⁸ | 1（本界不给非平凡保证） | 1 |
| Table3配方r²=4 | 36 | 约9.41×10⁻²⁸ | 约1.0462×10⁻⁵ | 约1.0462×10⁻⁵ |
| Table3配方r²=16 | 144 | 约9.09×10⁻²⁵ | 约4.4372×10⁻²² | 约4.4463×10⁻²² |

这些是手选教学用例的**gadget层误差预算**，不是安全位数；上界为1也不是已经找到了攻击。完整精确有理数和每个标量证书在JSON中，表中小数仅用于阅读。

精确有限PMF忽略随机抽数中止事件，不能被描述为“真实执行在所有步骤未中止条件下的分布”。独立联合密度比较也明确限制为相同有限盒：它是诊断，不是无限尾部证书。无限目标预算使用上述单独的区间/归一化分析。

## 4. 参数、检查与结果

采用与上一轮相同的小环参数：

| n/d/w/p/b | Q | 每目标标量用例 | 随机gadget提取/重建 | 合计标量抽样 |
|---|---:|---:|---:|---:|
| 2/1/1/5/3 | 15 | 每个u抽3次 | 128次 | 301 |
| 4/1/2/5/3 | 45 | 每个u抽3次 | 128次 | 1294 |
| 4/2/2/7/3 | 63 | 每个u抽3次 | 128次 | 2426 |

三组提取采用digit平方宽度36、对应SampleZ平方宽度4。独立Sage整数商环核对369个标量原像、384个近似原像及384个HNF精确关系，全部成立。枚举全部u时，规范误差e的计数按p个值均分；这不自动证明真实身份哈希或提取分布均匀。

三种宽度的每个3陪集各抽4096次，共36,864次，记录均值、实际方差、|z|≥12的计数及整数PMF期望。全部经验TV诊断小于0.1，未观察到中止；零次中止不能替代理论预算。较宽配置实际尾部计数为88/45/49，说明代码确实保留高斯尾部，不是固定小整数或均匀掩码。

另对三种宽度、9个quotient目标，共27个联合PMF，逐点用独立进位计算核对精确有理概率、归一化和模关系，独立用256bit区间指数计算有限盒球形密度。仿射SampleZ配方按三个陪集分别核对；其与Algorithm6字面宽度的有限分布差异都大于0.15。

研究限制继承Params的n≤8、d≤2、w≤4、p≤257、奇数b≤31及128bit系数预算。平方宽度/b²限于[1/4096,64]；tail_bits=80、mass_bits=128、precision_bits=192、max_trials=128、max_radius=128。TableOptions的其它值有严格上限/精度关系，达不到尾部目标即失败；有限PMF枚举有最多200000状态的显式QA预算。没有运行作者n=512配置。

## 5. 复现、文件和交接

环境为Intel Core Ultra9 275HX；Windows Python3.14.6/pytest9.1.1；WSL指定conda Sage10.9/Python3.13.14。新40项采样检查在Sage通过。Windows相关回归122 passed、1 skipped（整个Sage采样模块）；Sage候选/Yu/SRGG/旧高斯工具回归217 passed。没有身份或消息输入；ROM未实例化，没有安全等级或整体性能结论。

```text
wsl -- bash -lc "cd /mnt/d/zcode_projects/ibme && ~/miniconda3/envs/sage/bin/python -B -m pytest -p no:cacheprovider -q tests/test_srgg_sampling.py"
wsl -- bash -lc "cd /mnt/d/zcode_projects/ibme && PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -B -m experiments.research.candidates.srgg.sampling_audit --output test-results/srgg-sampling-audit.json"
python -B -m pytest -p no:cacheprovider -q tests/test_candidate_foundations.py tests/test_yu_homomorphic_reference.py tests/test_srgg_algebra.py tests/test_srgg_geometry.py tests/test_srgg_sampling.py
wsl -- bash -lc "cd /mnt/d/zcode_projects/ibme && ~/miniconda3/envs/sage/bin/python -B -m pytest -p no:cacheprovider -q tests/test_candidate_foundations.py tests/test_candidate_preflight.py tests/test_yu_homomorphic_reference.py tests/test_srgg_algebra.py tests/test_srgg_geometry.py tests/test_srgg_sampling.py tests/test_gaussian_reference.py"
```

首次多样性断言对128次采样任意要求超过16种输出，实际15种而失败；已去除这个无统计依据的阈值，检查固定输入能产生多个带负进位的输出，分布诊断由精确PMF及独立密度核对承担。最终检查无失败、无XFAIL；Windows依赖跳过如上说明。

本轮文件共13个：

| 范围 | 文件 |
|---|---|
| 新参考/独立核验 | `experiments/research/candidates/srgg/sampling.py`、`experiments/research/candidates/srgg/sampling_audit.py` |
| 新测试 | `tests/test_srgg_sampling.py` |
| 新报告/公开结果 | `docs/research/2026-10-10-srgg-sampling/README.md`、`docs/research/2026-10-10-srgg-sampling/audit.json` |
| 候选交接 | `docs/research/2026-10-10-foundations/catalog.json`、`docs/research/2026-10-10-foundations/候选基础卡与队友接手任务.md` |
| 历史报告/规格跟进 | `docs/research/2026-10-10-srgg/README.md`、`docs/research/2026-10-08-r1/SRGG2025IBS实施规格与条件.md` |
| 当前进度 | `README.md`、`docs/PROJECT_RESTART.md`、`docs/workplans/2026-10-08/主AI任务-IBS集成与优化.md` |
| CI说明 | `.github/workflows/basic-checks.yml` |

跨参考代码/测试/研究文档是为了让队友取得可执行的采样组件及真实接入条件。复用公开高斯和随机源接口，没有读取其它生产模块的私有字段，也没有覆盖队友文件。审计保存源文件LF规范化哈希，不输出主/用户向量或私有形状。

**下一项**：实现SampleP/SampleF的相关扰动参考，并与此gadget卷积相接，逐项预算分布、范数和中止；随后才接XOF、规范哈希、固定身份缓存及完整四算法。签名ζ尺度、底层强结论和q/Q/γ条件仍须核验。CHKP交接到达时仍优先首套集成；候选基础继续服务于之后三组代表的公平选择，优化后置。

WIP：完整扰动/卷积、重建密钥分布/范数、签名宽度、哈希和完整IBS/IBME；旧education两项认证反例仍未关闭。全部none/false，测试和采样误差预算不替代密码学安全证明。

