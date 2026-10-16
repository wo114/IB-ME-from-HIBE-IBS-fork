# SRGG 归约公开变量的实际有界研究采样器

本页闭合的是独立公开 product sampling 的实现与有限误差。它不读取私有陷门，不调用连续 SampleF，不更改生产后端、正式参数或安全标志，也不建立完整 IBS 安全证明。固定 n512 数值沿用 `63ea9fc` 中的研究 bridge；参数仍为条件研究候选。

## 1. 变量、算法与理想目标

新增 `experiments/research/candidates/srgg/reduction_samplers.py` 只接收经过校验的公开 `ReductionParameters`。输出顺序为每个向量的系数顺序，后续 reshape、E/HNF repair、Rec 和范数门由调用方显式完成。

| API | 维数 | 理想目标 | 实际失败与预算 |
|---|---:|---|---|
| `sample_public_u` | `N=(2+w)dn` | `D_(Z^N),sqrt(v_master),0` | 冻结 scalar product＋aggregate cap；失败直接抛出 |
| `sample_simulator_z` | `D=((2+w)d+1)n` | `D_(Z^D),sqrt(v_signature),0` | 同上；没有事后范数条件化 |
| `sample_uniform_e` | `H=dn` | `[0,p)^H` 均匀 | 每坐标最多 256 个 masked 候选；有界失败保留 |
| `sample_binary_challenge` | `n` | `{0,1}^n` 精确均匀 | 一次读取 `ceil(n/8)` B，丢弃未用高位；合规源无抽样失败 |

高斯记号的**平方宽度**为 `v`，密度正比 `exp(-pi*||x||²/v)`，不是标准差平方。`U` 和 `z` 在理想模型中均为独立坐标乘积，因此逐坐标调用中心 0 的冻结 `WideScalarGaussian` 合法；没有把旧连续扰动/离散递推联合 SampleF 偷换为 product law。

对第 i 个有限 scalar kernel 与理想 scalar Gaussian 的统一、包含 bottom 的 TV 界 `delta`，顺序 kernel coupling 给出整组 `count*delta`。额外 aggregate cap 将停止路径变为 bottom，最多再支付 `epsilon_cap`。工具直接复用 `batch_certificate` 的两项和，有限尝试、有限字节及所有中止均保留。独立均匀字节、MPFR/MPFI 正确舍入假设与原 scalar 证书一致；固定测试 RNG 不能建立这些假设。

## 2. 实际有限资源与输入检查

scalar 配置逐项等于冻结的 `query-bounded-deep` 标量部分：`tail_bits=192, mass_bits=256, precision_bits=384, gaussian_abort_bits=192, max_uniform_trials=256, target_tv_bits=160`；aggregate 的 `error_bits=192`。保留 scalar 构造器自身的半径、Gaussian 尝试、输出位数、单标量 tape 和 interval 检查。没有调用 Series 配置、生成任何私有矩阵或绕过旧 sampler 准入。

公开 degree 限于 2 到 4096 的二次幂，rank≤16、digits≤64、p≤2^64、平方宽度≤2^96；派生坐标数≤2^20。输入必须为 Python 精确 int，bool/float 不接受。每项 Gaussian 计划先由构造器和 batch 证书校验，再创建随机源或消耗字节。byte cap 默认上限 256 MiB，不适配的计划明确 ValueError，不启动整个 batch。E 的 exact-certificate 中间指数限制为 `candidate_bits*max_trials≤8192`，避免任意长有理数输出。

`SecureRandom` 是默认源；复现源只由调用方显式注入。返回类型为整个 tuple；任意子采样失败使调用整体抛出异常，既不返回部分 tuple，也不重试整 batch、重选 U/z 或切换随机源。错误字节类型/数量同样拒绝；调用方不得将故障路径解释成“重新抽一个直到成功”。

## 3. E 的完整失败律与精确 c

E 每候选先读取 `b=ceil(k/8)` B，`k=bitlength(p-1)`，再 mask 为 k 位；只有 `<p` 时接受，**不是取模 p**。独立均匀字节下拒绝率 `rho=(2^k-p)/2^k`。每坐标最多 T 次候选时，失败率为 `rho^T`；H 坐标全成功概率 `(1-rho^T)^H`，成功条件下恰为均匀 product。包含 bottom 的 law 到理想 product 的 TV 恰为 `1-(1-rho^T)^H`，证书输出易计算的上界 `H*rho^T`。

全部有界执行至多读取 `H*T*b` B；本实现先要求这一最坏路径预算适配，再按此 cap 读取，因此**预算额外中止概率为 0**。采样拒绝中止仍存在。p=1 时 E 恒零、不读取熵。

c 一次读取 `ceil(n/8)` B，取大端整数的第 j 位为系数 j。每个 n-bit 输出有恰好 `2^(8*ceil(n/8)-n)` 个等概率原像，故是精确 n-bit 均匀向量。丢弃的只是未使用高位，没有拒绝或取模偏差；损坏随机源不是概率模型中的“诚实抽样中止”，会作为错误抛出。

## 4. n512 deep 证书：没有抽样生命周期

使用 `n=512,d=2,w=8,p=16383`、`v_master=1031865954433`、`v_signature=22159188660729268928705`：

| 变量 | count | 有效硬字节 cap | 原全路径 cap | 到理想目标的 TV 上界，含 abort |
|---|---:|---:|---:|---|
| U | 10240 | 11,104,872 B | 14,770,176,000 B | `<2^-177` |
| z | 10752 | 13,744,738 B | 31,610,880,000 B | `<2^-177` |
| E | 1024 | 524,288 B | 同左 | `≤2^-3574` |
| c | 512 | 64 B | 同左 | `0` |

U、z 各自的 aggregate **额外**中止上界为 `2^-192`；各自包含既有 scalar 中止的总中止界 `<2^-178`。标量半径分别为 6,873,924 和 1,048,011,465,934；坐标输出整数，无枚举这些巨大支撑。两组高斯各自均适配原 256 MiB 总预算。

上述一组 U/z 采样误差不能直接称为整个 IBS 优势。若特定归约确实每个 reachable history 都只进行至多 `q_U` 组 U、`q_z` 组 z、`q_E` 组 E，则该采样混合项可按 `q_U*delta_U+q_z*delta_z+q_E*delta_E` 累计。次数、raw/HNF gates、程序化、image 分布、取钥/签名的不同理想 law 及量子模型仍需各自论证。

## 5. 执行证据与复现

在指定 Ubuntu-24.04 WSL `~/miniconda3/envs/sage` 中执行；Sage 10.9、Python 3.13.15、Linux 6.18.33.2-microsoft-standard-WSL2 x86_64。没有安装新依赖。原始 JSON 包含平台、Python/Sage 版本、公开输入与五个源码 SHA-256；未导出抽样值或密钥。

```text
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.reduction_samplers --output build/outputs/srgg-classical-rom-2026-10-16/reduction-samplers.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_reduction_samplers.py --junitxml=build/outputs/srgg-classical-rom-2026-10-16/reduction-samplers.junit.xml
```

测试结果 **53 passed**。小维度使用真实 `SecureRandom` 对 U、z、E、c 各做一次路径验收；U/z 另以固定 test stream 与冻结 scalar 的逐坐标输出做完全一致性比较。p=3、H=2、T=2 枚举全部 256 条 masked-candidate tape：九个输出各 25/256，abort 为 31/256；3-bit c 枚举全部一字节输入，每个向量恰有 32 个原像。非随机故障源触发拒绝、坏字节与预算拒绝；它们只检查控制路径。

n512 测试和 JSON **只构造证书**：测试禁止 RNG 构造和调用任意 scalar `sample`，实际熵读取 0 B。没有新发钥、签名或攻击实验；identity/message 长度和随机重复次数对此证书不适用。ROM 与 QROM 的 oracle 接口均未在本工具实现。安全声明仍为 `none`，`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`；这些有限实现测试和预算推导不是 Ring-SIS/IBS 或 NIST 等级证明。
