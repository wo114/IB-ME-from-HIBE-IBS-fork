# SRGG 独立结构化四算法研究执行

2026-10-16。一次 `n=512,d=2,w=8` 的系统随机性执行已完成：一个 root、一次用户发钥、内存 root／用户密钥恢复、恢复后的一次签名和验证。错身份、错消息及一个随机小响应／随机挑战签名均被拒绝。未按成功与否重选 root 或用户密钥；本次签名第一个尝试即满足范数门。

这是独立研究执行器。没有扩大 legacy `Params`／`Config` 的准入范围，没有修改公共后端、登记、wire 对象或持久服务，也没有完成正式参数、安全模型或 HIBE 组合准入。`security_claim=none, backend_admitted=false, parameters_are_formal=false`。

## 1. 论文／已有实现到本执行器

原文版本为 DOI `10.1049/ise2/6684889`、已归档 PDF SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。本轮依据既有 source review 与库内 `algebra.py`／`runtime.py` 做逐式实现对应，没有重新宣称完整阅读或重新证明原文安全定理。

| 原文／已有代码 | 独立执行器中的实际行为 | 证据与限制 |
|---|---|---|
| Algorithm 1，`algebra.build_public` | 从系统熵采样 CBD1 witness；`B=F-[I,Ahat]R mod Q`；检查 `A[R;I]=F mod Q` | `ExactRing.build_public` 与 legacy 小维度逐项相等；仅一个 root，无失败后换根 |
| Algorithm 2，`extract_with_gadget` | 真实 joint SampleF 扰动；residual；真实逐系数 gadget recurrence；形成 raw vector；raw 范数门；HNF 居中头恢复 | 独立检查近似抽取方程及 HNF 精确方程；失败直接传播，无发钥重抽 |
| Algorithm 3／4 的目标形状 | 用新的 isotropic joint `StructuredSampleF` 入口，精确环 matvec + 有证书平方根多项式 + Gaussian 整数舍入 | 不是旧顺序 Schur 的逐行／逐位相同有限 law；误差证书比较明确的联合目标离散 Gaussian |
| Algorithm 6，第 6 页 `z=b*SampleZ(-v/b)+v` | 每位取 `a=state mod b`，实际 `k~D_Z,r²,-a/b`，`z=a+b*k`，`state=(state-z)/b` | 与旧表具有相同理想 coset law，有限核改用 WideScalar，不能声称与旧表逐位相同 |
| Algorithm 7，`runtime.sign_attempt` | 真实签名扰动；commitment；消息 challenge；真实 `u`；响应；仅 norm rejection 可重试 | `zeta=1+X^(n/2)`，`zeta*=1-X^(n/2)`，`zeta*zeta*=2`，所以 `u` 中心为 `-zeta* c/2`；签名形状减去 `2r² T_sig T_sig*` |
| Algorithm 8，`recover_commitment` | 在 `2Q` 下恢复 `A_id*z-Q*J*c` 并重算 challenge；检查 context、维度、整数、二元 challenge 和范数 | 独立小维度与 legacy 的签名矩阵、响应和恢复结果逐项相等；随机负控不是安全证明 |

`ExecutionParams` 是单独的严格 bounded 参数类；Sage ZZ 多项式实现负循环整数乘法，不构造 n×n 系数矩阵，也不使用浮点 FFT。小维度测试另用手写 schoolbook 作对照。所有真实采样路径使用原始 SecureRandom；确定性来源仅用于明确标记的测试。

H(ID) 与 Hbar(commitment,message) 用独立研究 namespace、规范 JSON 公共记录及长度前缀域分隔。Hbar 不直接接收 identity；身份按原方程进入签名矩阵／承诺恢复。本命名空间与生产 wire 不兼容，不能把研究对象直接送入公共 backend。

## 2. gadget 的完整有限误差范围

每个整标量核实际在 Z 上抽宽度平方 r²、中心 `-a/b`，经 `a+b*k` 后得到 `bZ+a` 上宽度平方 `b²r²`、中心 0 的有限近似。逐位 state 更新保持确切同余。输出所有 `dnw=8192` 个实际 Gaussian digit，再核验每个 coefficient 的近似 gadget 关系；没有用确定性 b 进制代替采样。

每个可达 residue 都在读熵前通过 scalar 输入检查。`batch_certificate` 对全部 digit 的合计 rejection／uniform 候选数给已证实的全局 cap，保留 scalar 自身 trial abort，并计入完整 law。

`normalizer_certificate` 给 coset 正规化相对误差 epsilon；m 次抽样的正规化乘积除以共同常数位于 `[1-x,1/(1-x)]`，`x=m*epsilon<1`。对 ideal recurrence 以该乘积倾斜并正规化，得到同一 fiber 的球形 Gaussian，故 TV 至多 `x/(2-x)`。这里是给定 target 的同一倾斜计算；不能仅由一次 recurrence 观察结果断言分布正确。

`GadgetRecurrence.certificate()` 报告

```text
finite_Z_kernel_tv_including_batch_abort
+ ideal_recurrence_to_spherical_fiber_tv_upper
= total_fiber_tv_upper_including_abort   (最后截到 1)
```

其范围是 gadget fiber。它不独自证明卷积后的 raw law、HNF law、PSF 或强不可伪造。

## 3. 先选有限精度，再做一次实跑

`structured-execution-profiles.json` 是零熵预检，无 root、密钥或签名。以下 bits 是精确有理上界的十进制展示 `-log2(TV)`；所有通过判断均使用精确有理数。

| profile | master / sign 的 J | master / sign 完整 sampler TV bits | `q_new=q_sign=2^40,L=16` 有限采样 hybrid TV bits |
|---|---|---|---|
| default | 197 / 257 | 114.34 / 114.18 | 69.98 |
| query-bounded | 197 / 257 | 178.65 / 174.82 | 130.81 |
| query-bounded-deep（本次选择） | 295 / 385 | 178.65 / 178.58 | 134.38 |

deep profile 的 SeriesOptions 为 `P=1024,ticket=768,B=384,series_error_bits=384,aggregate_abort_bits=192`；WideScalar 为 `tail=192,mass=256,P=384,Gaussian_abort=192,uniform_trials=256,target_tv_bits=160`。修改的是独立执行器传入的现有有界 options，没有改冻结的 SampleF 源码或正式原语参数。

这里的查询界只计算有限采样 hybrid：

```text
q_new*(epsilon_masterSampleF+epsilon_gadgetFinite)
+ q_sign*L*(epsilon_signSampleF+epsilon_uFinite).
```

它要求逐可达历史一致的公开 witness class、新鲜熵和一致的 fixed identity ledger。独立执行器本身没有实现该持久 ledger。gadget 到 spherical fiber 的偏差、卷积／HNF／PSF、norm failure 和安全归约由各自桥梁单列，不能把约 `2^-134` 写成整个 IBS 的安全优势或真实持久服务的最终预算。

## 4. 一次 n512 实测收据

固定研究参数：`n=512,d=2,w=8,p=16383,b=31,r²=64,Q=p*b^8`；master target squared `1031865954433`；signature target squared `22159188660729268928705`；raw norm cap `169060917974302720`；user norm cap `338122385570209792`；signature norm cap `238255596480161099521436160`。这些来自 conditional builder，属于研究／工程参数，未正式安全准入，未推定 NIST category。签名模型采用 ζ 一致 factor 2；原文 normalization、q/Q 与安全前提的缺口继续保留。

输入是一个 37 B 公开测试身份、一个 32 B 消息；重复次数为一次独立 root／一次发钥／一次签名，不是性能 benchmark。执行环境和直接 SRGG 源码 SHA-256 固定在 JSON；Sage 10.9、Python 3.13.15，指定 WSL `~/miniconda3/envs/sage`。同机 `lscpu` 现场核验为 Intel Core Ultra 7 255HX、WSL 可见 20 logical CPUs；未固定亲和性、频率或后台负载。ROM 风格哈希使用 SHAKE256，未建立 QROM 归约。

| 实测项目 | 结果 |
|---|---|
| Setup | 0.212 s，一个 root |
| KeyExt | 14.021 s，一次实际发钥，8192 个 gadget Gaussian digits |
| 内存恢复后 Sign | 15.190 s，一个尝试，无 norm 重试 |
| 总算法时间 | 30.422 s；含进程启动的外部 wall 31.97 s |
| 峰值 RSS | 236420 KiB（外部 `/usr/bin/time`）；进程内收据 235460 KiB |
| 真实随机字节 | 15099738 B |
| 公开记录 JSON 大小 | 282400 B |
| root／key 私有内存快照大小 | 74027 / 67586 B；没有写入收据或文件 |
| 签名 JSON 大小 | 134915 B；没有导出签名 payload |
| 检查 | root/key snapshot roundtrip 相等、诚实验证、错 ID 拒绝、错消息拒绝、随机小响应／随机二元 challenge 拒绝 |

收据：`structured-execution-n512-d2w8.json`；外部时间／内存原始记录：`structured-execution-n512-d2w8.stderr.txt`。两者保留首次实跑结果，没有为了更漂亮的数据再次采样。

### 单次 audit 的全路径熵包络

原始收据保守标记 `audit_extra_abort_probability_certified=false`。独立后验文件 `structured-execution-entropy-envelope.json` 固定该收据与源码哈希，计算：

```text
32                            Setup seed
+32768                        Setup CBD1 coefficient bytes
+10503886                     master joint SampleF（已含 midpoint tickets）
+7651821                      gadget batch cap
+16*(11020294+642980)          sign joint SampleF + u batch，最多 16 次
+11264                        一个随机负控 response/challenge 的原始读取
=204812155 < 268435456         audit 全局 cap
```

`structured_execution.py:698` 的负控一次读取 `(columns+2)*degree` 字节：前 `(columns+1)*degree` 字节的低两位生成 CBD1 小响应，最后 degree 字节的低位生成二元 challenge。它没有额外隐含随机源。

每个本地 `AggregateByteSource` 在转交读取前检查本地 cap，任何本地数值／熵 abort 都立即结束 audit；仅签名 norm rejection 可继续。因此全局 CountingEntropy 不会先于上述本地 cap 触发，**本次单身份 audit** 的额外全局 cap 中止上界为 0。各本地 probabilistic cap 的中止仍保留在对应完整 sampler TV／abort 证书内。这个确定性路径和不是 `2^40` 次查询服务的全路径熵上限，更不处理基础设施故障。

## 5. 测试与复现

以下命令均在仓库根目录、指定 WSL Sage 中运行。

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q \
  tests/test_srgg_structured_execution.py \
  --junitxml=docs/research/team-b-delivery/2026-10-16-srgg-bridge/structured-execution-tests.junit.xml

PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.structured_execution \
  --degree 512 --rank 2 --digits 8 --certificate-profiles \
  --output docs/research/team-b-delivery/2026-10-16-srgg-bridge/structured-execution-profiles.json

PYTHONPATH=src:. /usr/bin/time -v timeout 300 ~/miniconda3/envs/sage/bin/python \
  -m experiments.research.candidates.srgg.structured_execution \
  --degree 512 --rank 2 --digits 8 --profile query-bounded-deep \
  --output docs/research/team-b-delivery/2026-10-16-srgg-bridge/structured-execution-n512-d2w8.json
```

测试结果 **31 passed，4.53 s**，对应 JUnit 收据。测试覆盖独立负循环乘法、公钥／trapdoor／raw extraction／HNF／ζ／2Q parity，真实小维四算法、两种快照恢复、canonical/duplicate/truncated/append 拒绝，重算 checksum 后的错误 root 关系／过大 key 范数拒绝，错误公钥／参数绑定，有限 SampleF／gadget／u abort 传播和 norm-only 尝试上限。快照 checksum 是错误检测而非加密认证或状态回滚防护。

功能测试、实际采样和有限负控不证明 SIS/LWE、IBS 不可伪造性、强不可伪造或王老师组合前提。尚未在 n512 公共五方法、规范生产对象、固定持久服务、正式攻击估计或任何 HIBE 组合中运行本独立执行器。
