# Yu 电路、谱范数与参数条件核验

日期：2026-10-15。侧支基线：`8ba7ebf`，共享分支 `codex/yu-backend-2026-10-15`。

**结论：本轮补齐了有限电路的可执行检查和参数条件账本；没有完成正式安全准入。** 原有 raw tiny 保留；新的公共字节 profile 由主线实现。本侧支不替代公共后端、固定服务、真实采样链或 HIBE 组合的验收。

本文件严格区分：**原文事实**、**针对当前代码的推导**、**有限实例实测**。`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false` 均不变。

## 1. 固定来源和修改范围

- Yu、Liu、Li，*Identity-based signature and identity-based matchmaking encryption from lattices*，TCS 1082 (2026), 116152，[DOI](https://doi.org/10.1016/j.tcs.2026.116152)。本地 [PDF](../../../../papers/2026_ibs_ibme_yu.pdf) SHA-256：`f10d8672d952d9923a00c883a7d65feb36a15fb67fbef1c52ee64254f5301948`。本次阅读 PDF 第6—7、11—13页，且查看了第12页 Fig.5 的渲染图；没有宣称重审整篇安全归约。
- Banerjee、Peikert、Rosen，*Pseudorandom Functions and Lattices*，[作者版](https://web.eecs.umich.edu/~cpeikert/pubs/prf-lattice.pdf)，2011-09-29。核对 §2 式(2.1)、§5.1 Definition 5.1、§5.2、§5.3 Theorem 5.2；该作者版 PDF 第17—18页，不套用会议版页码。既有本地 PDF 位于 `build/outputs/yu-source/bpr-prf-lattice.pdf`，SHA-256：`c216374a14b27e0650cc2189f0939024dd2f895d7b2821ce4d9c32af0216ac00`；文本为同目录 `bpr.txt`。
- 公共字节配置实际读取 [params.py](../../../../src/ibme/ibs/yu/params.py)，初审快照 SHA-256：`c15428cc34c09c2d111be9a0e8d2a812ca4e134603a8b862196e56e647f9d025`。最终实测所调用文件散列另保存在核验 JSON 的 `source_sha256`，后续主线改动应按散列复核。

本侧支只新增 [qualification.py](../../../../experiments/research/candidates/yu/qualification.py)、[test_yu_qualification.py](../../../../tests/test_yu_qualification.py) 和本说明；[bpr.py](../../../../experiments/research/candidates/yu/bpr.py) 只把 `input_bits` 的允许上限从64改为128。**没有改 `circuits.py`、`evaluation.py`、`standalone.py`、`trapdoors.py` 或公共后端目录。** 按协作要求由主线统一提交。

## 2. 原文事实：要求是什么

| 来源 | 原文要求／结论 | 本次对应 |
|---|---|---|
| Yu PDF6 Lemma 7 | NAND 电路满足 `A_C = A R_C + C(x)⊗G mod q`；同时给出 `s1(R_C) <= O(4^d m^(3/2))` | 代数等式和谱界分开；下面只对当前实现另给保守界，不替换原文的界 |
| Yu PDF7 Lemma 9；BPR §5.1—5.3 | PRF 需有相应计算伪随机性和参数前提；BPR矩阵版为按次序的子集矩阵乘积加舍入 | 数值、编译电路、同态计算交叉核对；有限 CDF 误差不等于 PRF 安全 |
| Yu PDF11 §3.3 | `x_tilde = x_hat + ell + kappa`，`m=O(n log q)`；gamma、delta 满足生成／随机化／采样条件；beta 覆盖归约输出长度；q 满足 SIS 条件 | 输入拼接和有限宽度门槛可计算；渐近常数、归约多项式和安全等级不能凭空赋值 |
| Yu Fig.5 | `gamma` 用于第一层 RandBasis；`delta` 用于第二层零原像；验签要求非零、范数和模方程；盐长为kappa | 当前代码是平方宽度 gamma²、delta²，不是方差；单次失败不重试、不降低范数门槛 |

BPR 作者版 §5.2 的矩阵讨论给出 TC1 上界并提到预处理，其讨论中的矩阵预先固定；Yu 的调用把 PRF 密钥作为变量。**有限编译器能运行，不等于已经给出满足原文参数推导的 NC1 电路家族。** 当前没有修改算法语义去宣称这一缺口已消失。

## 3. 当前代码的推导：精确谱上界

### 3.1 针对一个整数矩阵的上下界

设 `R` 是 `a×b` 整数矩阵。`spectral_bounds_squared` 用精确整数计算

\[
L=\max\{\max_i\sum_j R_{ij}^2,\ \max_j\sum_i R_{ij}^2\},\qquad
U=\min\{\sum_{ij}R_{ij}^2,\ \|R\|_1\|R\|_\infty\}.
\]

则 `L <= s1(R)^2 <= U`。理由：取标准基向量作用于 `R` 和 `R^T` 得到下界。Frobenius 上界来自逐行 Cauchy–Schwarz；另一上界来自

\[
|(Rv)_i|^2\le (\sum_j|R_{ij}|)(\sum_j|R_{ij}|\,|v_j|^2),
\]

对行求和后得到 `||Rv||² <= ||R||inf ||R||1 ||v||²`。因此两个上界取小仍有效。整个计算不调用浮点 SVD；单元测试另以 Sage 实代数数域中的精确特征值核对。

这证明的是**被输入的这个矩阵**的界；不证明随机矩阵的高概率分布结论，也不自动证明所有电路家族的界。不得公开真实秘密见证的矩阵或其依赖秘密的诊断值。

### 3.2 针对现有 NAND 递推的普遍粗界

代码的私有递推是 `R_new = -R_left D - x_left R_right`，其中 `D=G^{-1}(A_right)` 为 `w×w` 的0/1矩阵。若两个输入见证的逐系数绝对值均不超过 `C`，则新见证逐系数不超过 `(w+1)C`。深度0的输入见证界为 `C0`，字面常量见证为零；按电路深度归纳：

\[
\max_{ij}|(R_C)_{ij}|\le C_0(w+1)^d,\qquad
s_1(R_C)^2\le mkw\,C_0^2(w+1)^{2d},
\]

其中 `k` 是**电路输出位数**，`R_C` 是横向拼接的 `m×kw` 输出见证；不要和 BPR 的输入长度符号混用。死门仍计入当前实现的最大深度，故使用这个深度是保守的。`coarse_spectral_squared` 逐项实现此式；`compose_match` 把匹配电路接在 PRF 后，避免漏算第二段深度。

**此式是当前代码递推的粗界，不是 `O(4^d m^(3/2))`。** 即使有限样例的实际范数很小，也不能据此换掉增长底数、忽略输出列数或声称 NC1。`parameter_conditions().lemma7.status` 因而仍为 `pending`。

## 4. 两个 profile 的有限检查

| 项目 | 原 raw tiny | 新公共字节默认 |
|---|---:|---:|
| BPR dimension / columns | 2 / 2 | 1 / 1 |
| BPR模数／ticket位／高斯宽度 | 32 / 32 / 2 | 32 / 32 / 2 |
| 身份输入位数 | 2 | 40 |
| 消息输入位数 | 2 | 40 |
| 盐位数 | 4 | 4 |
| 签名PRF输入位数 | 8 | 84 |
| 身份／签名PRF密钥输入位数 | 276 / 1044 | 1285 / 2693 |
| PRF输出位数 | 4 | 1 |
| Yu格参数 `(n,m,q,w)` | `(1,15,3,2)` | `(1,15,3,2)` |
| gamma² / delta² | 32768 / 67108864 | 同左 |
| 根／身份／签名格维度 | 15 / 17 / 19 | 同左 |

字节映射为 `uint32_be(len(x)) || x || zero_padding`，每字节 MSB-first。默认每段最多1字节，所以各40位；签名拼接为 `id40 || message40 || salt4`。身份非空、消息可空。测试枚举空消息及全部256个1字节消息，257个编码互异，特别区分空串与 `0x00`。它是固定输入域编码，不是哈希，也没有因此引入随机预言机。

主配置允许身份／消息最大长度分别1—4字节，但同时限制签名输入总位数不超过128、密钥输入不超过8192；不能理解为所有4×4组合都有效。例如两个最大长度均为4时，加盐后超过128位而拒绝。16种默认盐的容量组合已逐项测试。默认1字节身份只覆盖256种身份，`max_users=16` 又限制实际服务；**不是完整 Wang 组合所需任意载荷的可用性保证。**

### 4.1 宽度可执行门槛与正式条件分别登记

现有 GPV 的 C1-exec 使用

`width² >= 4 L² ceil(log2(2 D (1+2^epsilon_bits))))`，

其中 `L²` 必须是该次输入基的最大 GS 平方界，`D` 为该次格维度。代码用整数 `bit_length(N-1)` 算上述上取整，避免浮点边界差异。

- AP09 公共确定性根 GS 平方界为368；延拓保持该界。`D=17, epsilon_bits=16` 时所需 gamma² 为32384，当前32768覆盖它。
- raw RandBasis 成功后的公共 GS 平方上界为 `gamma²×17=557056`；`D=19` 时所需 delta² 为49020928，当前67108864覆盖它。
- 以上只检查充分宽度门槛，**不包含标量宽度、随机带、路径有理数资源、秩、尾事件、总中止概率和实际成功率**。由于主配置还做确定性 LLL，不能把 raw RandBasis 的 GS 界直接贴在处理后的基上；实际基仍须由原采样器检查。
- 代码中的平方宽度与论文 `exp(-pi*||x||²/s²)` 约定一致。原文的大O／omega系数和完整概率组合未由这两个有限不等式补齐。

### 4.2 已知不成立与待核条件

| 条件 | 状态 | 可检查依据 |
|---|---|---|
| 长度拼接、有限电路语义、代数同态对应 | 已核（指定有限实例） | 本轮测试和核验JSON |
| 原 raw profile 的输出是否被128位扩容改变 | 未改变（已核固定回归集） | 修改前记录的6张电路 SHA-256 与修改后完全一致；原2/8位参数未改 |
| 当前配置不可伪造 | 明确不成立 | `s=q e1` 的平方范数9小于验签限 `delta²×19=1275068416`，任何公开矩阵乘它模q均为0 |
| AP09近均匀界 | 未获非空保证 | 既有公开证书的含失败TV上界为1；并非证明实际TV必为1 |
| BPR正式PRF条件 | 待核，不可引用安全 | Theorem5.2 含常数C、`n^omega(1)`、LWE困难性；将C及增长项暂置1的诊断检查在字节40/84位均不满足，但这个诊断不冒充原定理判定 |
| Lemma7谱界／NC1族对应 | 待核 | 当前交付的是上节保守界和有限谱检查，不是完整原文映射 |
| beta与SIS参数 | 待核且当前实例不安全 | `beta >= poly(kappa)*delta*sqrt(m+2w)` 中归约因子尚未具体化；当前q=3已有公开伪造，不能凭单次宽度通过给安全位数 |
| 固定发钥、保存恢复、线程限制、真实生命周期 | 主线负责 | 此侧支不重复实现，不把合成代数样例算成Setup/KeyGen/Sign成功 |

## 5. 实测结果与证据

执行环境：Windows共享worktree，实际Python来自 WSL 的 `~/miniconda3/envs/sage/bin/python`；最终JSON记录Python和Sage版本。没有安装新依赖。公开合成输入和矩阵由确定规则构造，不使用生产密钥、生产种子或采样陷门。测试只证明执行过的断言。

### 5.1 电路资源

| profile／输入 | 选中因子数 | NAND门数 | PRF深度 |
|---|---:|---:|---:|
| raw tiny身份，全1 | 2 | 7904 | 118 |
| raw tiny签名，全1 | 8 | 31616 | 158 |
| 字节身份，原始40位全1压力样例 | 40 | 34000 | 184 |
| 字节签名，原始84位全1压力样例 | 84 | 71400 | 201 |
| 字节身份，合法 `0xff` | 9 | 7650 | 150 |
| 字节签名，合法 `id=0xff,msg=0xff,salt=1111` | 22 | 18700 | 167 |

全1原始位串不是合法的长度前缀编码，只用于压力测试，不能算作合法消息统计。匹配电路另接在PRF后，其合成深度记录在每条谱界证据中。仍保留 `MAX_INPUTS=8192`、`MAX_GATES=500000`、`MAX_DEPTH=4096`，测试也覆盖128位和预算拒绝。`peak_live_wire_slots` 只是当前求值器的活跃wire计数，不是进程RSS或Python对象字节数。

### 5.2 谱检查必须保留退化情况

最终批次包含15组电路、45次数值／布尔对照、14次包括匹配电路的公私同态检查。其中默认字节profile的q=3样例见证会退化为零，JSON明确记录 `nonzero_witness=false`；不将其写成有说服力的非零谱实验。

另一个明确标记为 `auxiliary-q257-algebra-only` 的公开合成样例只把同态代数测试设为 `(n,m,q,w)=(1,15,257,9)`，沿用40位PRF电路。这不是后端的新配置，没有跑它的AP09／RandBasis／签名链，也不升级安全声明。匹配成功分支的精确谱平方区间为：

`604328475337315558285484305611770310915 <= s1(R)^2 <= 1205516325566862690358801637546975636521`。

匹配失败分支也得到非零见证；两者均验证模方程且在普遍粗界以内。除此之外，26个小矩阵／随机整数矩阵案例用 Sage 实代数特征值核对谱上下界，避免只拿同一公式自我核对。

### 5.3 命令与文件

以下命令均从仓库根目录，在指定 WSL 环境运行：

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q \
  tests/test_yu_qualification.py tests/test_yu_bpr.py tests/test_yu_circuits.py \
  tests/test_yu_evaluation.py tests/test_yu_prf_homomorphism.py \
  --junitxml=build/outputs/yu-qualification-tests-final.xml

PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python \
  -m experiments.research.candidates.yu.qualification \
  --output build/outputs/yu-qualification.json

PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q \
  tests/test_yu_standalone.py -k 'context_mutations or public_q_multiple' \
  --junitxml=build/outputs/yu-qualification-negative-tests.xml
```

- 第一条：最终 **155 passed，0 failed，0 skipped**，22.78秒。
- 第二条：退出码0，15组记录。JSON包含代码散列、两份参数账本、所有代数／范数结果；无私钥或生产熵材料。
- 第三条：**17 passed，73 deselected**，14.57秒；保留原参数的上下文变更／公开伪造检查。16条警告来自既有`record_property`与JUnit xunit2格式，不是算法跳过。接受弱参数攻击是被保留的反例，不是安全通过。
- 首次开发测试为152通过、2失败，原因是本侧支新测试错误期待4个活跃wire（实际3个）及错误期待ValueError（实际EncodingError）；均修正测试，未改变算法来迁就断言。随后新增非零代数样例得到上述最终结果。

上述收据保存在被忽略的本地 `build/outputs/`，由主线脱敏后纳入统一材料清单。原始JUnit可能含本机hostname／路径，不直接作为已脱敏公开文件。核验脚本报告成功只表示检查执行完成；其 `overall_formal_status=not_admitted` 不得省略。

## 6. 主线接收检查

1. 核对本侧支4个文件、主线params／codec快照和JSON的散列一致；只由主线统一提交。
2. 保留此处的失败、退化与待核标签，勿把“本批代码可合入”写成“全部理论条件成立”。
3. 若主线改变输入编码、PRF配置、参数或公开求值，重跑相关核验；改变线程防护不由本侧支改算法。
4. 默认1字节容量、q=3不安全、固定小服务限制应出现在总README。完整HIBE组合／正式参数另行验收，本批无相关结论。
