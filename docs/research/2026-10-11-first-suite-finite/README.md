# 首套集中闭环：有限误差、系统随机源与237维真实输入

2026-10-11，基点`7e58efa`。本轮移除叶原像采样依赖Sage公开测试seed的限制，推进真实生产熵API及有限误差账本。它仍是独立数学实现，根/父级来源、实际困难性、七入口和完整组合尚未准入。

## 实现及来源

新增`first_suite/entropy.py`、`finite_gaussian.py`、`finite_gpv.py`、`finite_randbasis.py`。有限uniform-box拒绝Gaussian和一般基GPV沿用现有数学参考/T2契约的精确公式，另设版本化宽度/维度/随机带支持域，不修改队友原代码或旧guard。拒绝次数、尾界、区间/量化误差、Poisson归一化、GPV几何偏差、所有syndrome/非中止路径的有理中心位数、秩/范数中止和最坏随机带均由实际输入重算。

| profile | 支持域 | 原限制 |
|---|---|---|
| FIRST-SUITE-FINITE-DGS/1 | 精确s²在1..2^80，半径≤2^48，rational≤8192bit，单scalar/vector tape≤1TiB | 旧Online参考s²≤10^12、半径≤2^30、256MiB保持 |
| FIRST-SUITE-FINITE-GPV/1 | ≤256维，输入≤1024bit；C1-exec、精确GS/投影、全路径中心及标量证书 | 旧CHKP GPV≤192维及其scalar/tape规则保持 |
| FIRST-SUITE-FINITE-RANDBASIS/1 | FirstFiniteGPV＋既有canonical ToBasis，仍受ToBasis≤192维；整次tape≤1TiB | 旧RandBasis≤256MiB及原ToBasis域保持 |

默认tail128/mass256/precision320/abort128/uniform_trials192，无Sage native RNG或seed。`rng=None`来自`SecureRandom`，显式测试流仍用`DeterministicRandom`；熵wrapper验证真实bytes/长度、跟踪实际消费并在达到公共预算时中止，源异常传播，无uniform/zero/新seed回退。最坏随机带是熵消费上界，不预分配1TiB内存，也不宣称所有可选输入都能在现场资源内运行。

依据仍为GPV08 §4.2及项目既有T2有限适配；不是新密码学定理。扩大width/radius后，权重指数先用精确QQ计算并在mass_bits前截断，区间exp只处理有界参数；相对区间误差式不依赖绝对width。更大支持点数重新进入量化误差，尾界及接受率以新参数的区间上端核验，没有沿用旧数值证书。版本label和参数范围本身不是分布证明。

## 真实输入与实跑

复用上轮保存的、明确公开教学fixture的父级私钥；没有重新生成父钥，也没有更改其256个旧地址。原输入的237维叶基标量s²最大约3.862e13，旧192维及10^12门同时拒绝。使用相同实际H/G、预定Sage诊断规约和新有限GPV，给独立比较状态生成256个新原像：

- n=1，q=1073741827，叶s²=63276067520；内部P/C身份86B，原身份Bob/Alice 3/5B，种子32B。
- 本次GPV epsilon_bits=128，实际输入逐项满足C1-exec；这是对所给固定基的采样核验，不是证明原HIBE公共宽度覆盖所有生成结果。
- 256个原像全部通过真实目标方程和声明范数；快照457222B，恢复保持向量且不重抽。
- 全部使用OS CSPRNG；实际叶抽样消耗24618430B，最坏每向量149357376B、整批38235488256B。实际用量不是最坏界替代品。
- 单向量与理想陪集Gaussian的TV上界含中止，约2^-118.526；256向量联合约2^-110.526。该数值不是安全等级或LWE难度。
- 两个OS随机32B种子在真实连续Gaussian取整噪声alpha=4/q、tail64/mass96/precision160下512位全对；raw capsule均2069B。约137.027s包含读取/验证旧父钥、规约、构造、256抽样和恢复，不是公平端到端IBME基准。

只有一次预定输入批次；不把有限成功样本写成可靠性或匿名性证明。根与父级还是旧public-test/native来源，整个链没有变成生产HIBE。完整参数/散列/测试和已知限制见`audit.json`及机器结果；私钥、真实熵字节和随机种子不归档到git。完整per-coordinate证书留在被忽略的test-results，公开摘要保存其SHA与有限误差值；这些是公开fixture的诊断，禁止对真实秘密基发布basis-dependent证书。

## 检验

新测试覆盖：与旧参考相交域上的精确有限PMF/相同byte stream差分；超旧width的独立均值/方差与证书；实际默认OS源；错误熵和预算中止；193维实际原像、旧guard保持；真实有限RandBasis及失败不重试。其他条件仍靠源算法/数学对应，测试不是证明。

```bash
PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m pytest -p no:cacheprovider -q --tb=short \
  tests/test_first_suite_finite_sampling.py tests/test_first_suite_delegation.py \
  tests/test_first_suite_identity_state.py tests/test_first_suite_seed_sage.py \
  tests/test_chkp_gpv.py tests/test_chkp_randbasis.py \
  --junitxml=test-results/first-suite-finite-regression-sage.xml

# 需要上轮本地生成的公开fixture私有文件；不通过恢复失败重启生成器。
PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m experiments.research.first_suite.finite_sampler_probe \
  --manifest test-results/first-suite-tree-qbig/private/public-restore-manifest.json \
  --private-directory test-results/first-suite-finite/private \
  --output test-results/first-suite-finite/result.json
```

## 剩余关键项

新scalar/GPV/RandBasis具有真实CSPRNG入口和有限账本。当前父级158维在RandBasis/ToBasis支持域内，但本轮大输入仅对旧父基完成新叶采样；不以小维RandBasis测试宣称大父级生成已验收。根GenBasis还须以CSPRNG/正确分布产生，联合闭合近均匀、n/困难性、GS宽度/噪声/寿命/资源。随后接主父叶对象及真实七入口、字节/CLI、Luo引用条件和Wang/HYBRID/BYTEAUTH完整攻击；旧education两项认证反例仍未修复。声明仍固定`security_claim:none,backend_admitted:false,parameters_are_formal:false`，整体目标保持进行中。
