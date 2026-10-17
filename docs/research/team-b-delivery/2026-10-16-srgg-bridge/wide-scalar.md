# SRGG 独立大宽度整数 Gaussian

日期：2026-10-16。实现 `experiments/research/candidates/srgg/wide_scalar.py`，
测试 `tests/test_srgg_wide_scalar.py`。这是显式启用的研究工具；没有修改
`OnlineScalarGaussian`、`OnlineOptions`、`Config`、runtime、旧收据或 wire。

**完成的是 n512 条件候选的实际 scalar 宽度支持，不是完整 n512 IBS。**
分布目标为 `D_Z,s,c`，其中 `s²=width_squared`，密度权重
`exp(-π(x-c)²/s²)`；物理方差近似 `s²/(2π)`。采用已有
`online_gaussian_reference.py` 同一个有限 uniform-box rejection 数学，
没有换成连续正态、均匀替代噪声或截断 CDF 枚举。

## 算法和可复用部分

独立构造器完整验证本身的 public class；不继承后跳过旧构造器，不使用
`object.__new__`、monkeypatch 或先构造小宽度再篡改属性。
复用的严谨原语是 `exact_integer/exact_rational`、`capped_exp_minus_pi`、
MPFI 精确端点提取、`draw_uniform_integer` 和 `FiniteByteTape`。
宽度对应的构造公式、整数权重与 rejection 顺序逐项保留。
重叠范围中，新旧类在相同有限选项下的完整有限 law、各证书值和同熵输出均精确一致。

给定精确中心 `c=h+a`，`h=floor(c)`、`0≤a<1`，选最近整数 j 为 0 或 1。
取支持 `[-R,R]`（a=0）或 `[-R,R+1]`（a≠0）。候选来自该区间的精确均匀分布；
用下端点质量

```text
w(k)=exp(-π((k-a)²-(j-a)²)/v),  v=s²
m(k)=floor(2^B * lower_MPFI(w(k)))
```

执行 B-bit Bernoulli。`argument≥B` 时质量置零；真实权重小于 `2^-B`，
计入同一个量化界。两层拒绝均有固定次数上限，失败抛出 `SamplingAbort`，
没有隐藏重抽、熵扩展或回退。默认源为 `SecureRandom`；固定 seed 仅用于测试。

## 有限误差、中止和资源证书

以下公式与旧算法相同，误差针对最终整数输出；使用正确的 directed MPFR/MPFI
转换和初等函数、无未建模指数异常、独立均匀字节这些显式条件。

设 N=`2R+2`，P 为区间精度，B 为质量位数，
`e=bit_length(B-1)`、`η=2^(e+8-P)`。每个权重区间宽度上界为 η。
这一步只对有界 `argument<B` 执行 exp，因此与 v 的大小无关；大指数先安全裁剪。
每点质量亏损≤`η+2^-B`，总亏损及 normalized-law TV 可由
`E=N(η+2^-B)` 控制：最近整数质量恰为 1，归一化总质量至少 1。

任意中心的支持外相对质量用相同几何级数控制：

```text
T(R)=2 exp(-π((R+1)²-1/4)/vmax)
       / (1-exp(-π(2R+3)/vmax)).
```

构造器二分搜索 R，但最终区间上端点必须实际满足 `T(R)≤2^-tail_bits`。
不假设有限精度端点严格单调。对于 v≥vmin，Poisson 归一化充分界为
`sqrt(vmin)(1-θ)`，其中
`θ≤2exp(-πvmin)/(1-exp(-3πvmin))`；θ 使用外向上端点。
接受质量下界为 `A=max(1,normalizer_lower-T-E)`，
单次 Gaussian 接受率至少 `p=A/N`。

取 `G=ceil(abort_bits*upper(log2)/p)+1`，得到 Gaussian 拒绝中止≤`2^-abort_bits`。
每次 uniform-integer 的条件成功输出精确均匀，中止≤`2^-U`，
联合界为 `G*2^-U`。最终包含 abort 符号的 TV 上界为
`min(1,T+E+2^-abort_bits+G*2^-U)`，同时公开两个中止分项。
额外总 TV 准入门要求该值≤`2^-target_tv_bits`；没有把弱证书默认为通过。

每个 scalar 的全部路径熵上限严格为

```text
G * (U*ceil(bit_length(N-1)/8) + ceil(B/8)).
```

byte-budget wrapper 在每次 read 前检查上限，并检查源返回的真实字节数，
不预分配该长度。定长 tape 入口要求精确公开长度；该长度上的理论 tape 耗尽概率为 0。
公开 profile 还限制宽度、radius、G、P、B、输入有理位数和输出位数。
过大的字符串在 Sage 解析前拒绝；非法宽度、中心或所有路径输出界在取熵前拒绝。
对接收的中心，输出绝对值≤`ceil(abs(c))+R+1`。
证书另外给出相对 exponent 最终有理数的保守位数界
`3*rational_bits+2*bit_length(R+2)+4`，不把它称为完整堆/时间证书。

默认研究 profile：tail=128、mass=192、precision=256、Gaussian abort=128、
uniform trials=192、Gaussian trials≤100000、radius≤`2^56`、
width_squared≤`2^96`、rational_bits=8192、output_bits=1024、
单 scalar tape≤256 MiB、总 TV≤`2^-96`。
更宽的显式 profile 仍受硬上限 `width_squared≤2^128`、radius≤`2^80` 及全部证书门约束。
特别宽的 `vmax/vmin` 比可能因接受率、次数、tape 或 TV 门被拒绝；不保证帽内任意类都可运行。

## n512 实际宽度口径

对 `formal_candidates.conditional_candidate(n=512,d=2/3/4,w=8)`，
实际 Z 核包括 SampleF 舍入及 signing u 的 `r²=64`、
master lower `second−b²r²`、signature lower `second−2r²`。
没有把候选等同于已准入正式参数；HNF 分布、原文前提和困难性仍需单独核验。

gadget 原始宽度 `b²r²=61504` 的目标是 `bZ+a` 上的 coset Gaussian。
令 `x=a+bk`，其 Z 核为宽度 `r²=64`、中心 `−a/b`。
因此该项已由 r² 核覆盖；不能拿 Z 上宽度 61504 的抽样冒充真实 coset。
测试覆盖全部31个 residue 的精确密度映射和真实抽样；旧 gadget tables 不变，
没有把此工具接入整个 gadget 递推。

## 实测和边界

指定 WSL Ubuntu-24.04、`~/miniconda3/envs/sage`；Sage 10.9、Python 3.13.15，
Intel Core Ultra 7 255HX。未固定 CPU 频率、亲和性或后台负载。
九个配置各32次固定流 draw、完整固定流重放，再各做1次 OS CSPRNG draw。
身份/消息均无输入；不产生密钥或签名。OS 样本未保存，固定流只保留输出摘要。
源码哈希、选项、所有证书、计时及实际熵保留在 JSON；少量观测不代表吞吐排名或概率证明。

指定 Sage 测试 **47 passed、0 skipped**。覆盖新旧完整有限 law、独立高精度无限
Gaussian 归一化比较、所有 n512 实际宽度及有理中心、31个 coset residue、
定长 tape、巨大精确中心平移、全路径输出拒绝、uniform/Gaussian 明确中止、
过大 public profile、非法源及旧 API 的拒绝界保持。

九个配置共 **288次固定流 draw + 288次重放 + 9次 OS draw**，未观测到 abort；
所有重放一致。固定流首次 draw 共读取100824 B，OS draw 共读取1982 B。
这些观测不替代中止上界；九个配置的实际证书均满足 **TV≤`2^-126`**。

| d | master lower 平方宽度 | signature lower 平方宽度 | master radius | signature radius | master 单次 tape 上限 B | signature 单次 tape 上限 B |
|---:|---:|---:|---:|---:|---:|---:|
| 2 | 1031865892929 | 22159188660729268928577 | 5721925 | 886906172012 | 600600 | 1245384 |
| 3 | 2321698259009 | 74787191713363151290433 | 8600240 | 1633767161177 | 794376 | 1248912 |
| 4 | 4127463571521 | 177273285232720131129409 | 11483373 | 2520162892275 | 795168 | 1251264 |

共同 r²=64 核的 radius=42、G=955、单次 tape 上限206280 B。
本轮每例只 prepare 一次，记录0.00060–0.00159 s；每例32次首次固定流 draw
记录0.00343–0.00871 s。没有把它们换算成完整 Extract/Sign 时间或速度提升。
上述最大宽度的支持仍以固定整数边界表示，不分配相应长度数组。

本地证据：`build/outputs/srgg-bridge-2026-10-16/wide-scalar.json`、
`wide-scalar.stdout.json`、`wide-scalar-tests.junit.xml`。

此工具的每个 scalar admission 不代表整个向量 admission。
例如 d2 master lower 每次保守 tape 上限约 0.60 MB，8192 次的逐项和约4.92 GB；
signature lower 512次的和约638 MB，均超过当前完整 sampler 的256 MiB门。
不能以观测到的少量实际字节替代全路径上界，也不能直接放宽生产门。
后续需要严格的新全局 tape/abort 包络，或另行声明并验证完整 sampler 的资源 profile。

仍未实现结构化 SampleF/SampleP、n512 Gaussian 因子/误差证书、
完整对象/发钥/签验/恢复生命周期或 NIST 安全等级。
所有标志保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。

## 复现

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_wide_scalar.py \
  --junitxml=build/outputs/srgg-bridge-2026-10-16/wide-scalar-tests.junit.xml

PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.wide_scalar \
  --repetitions 32 --output build/outputs/srgg-bridge-2026-10-16/wide-scalar.json \
  > build/outputs/srgg-bridge-2026-10-16/wide-scalar.stdout.json
```

build 为本机输出；Git 不保证包含它，跨机器移交须打包或复现。
