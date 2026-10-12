# Luo IBS 专属契约

本文件补充 [统一实现规范](../../IMPLEMENTATION_SPEC.md)，只约束 Luo 后端。当前推进模块、外部工作树和未合入结果统一见 [项目状态](../PROJECT_STATUS.md)。这里记录本 checkout 的可执行契约；日期表示原冻结时间，不表示安全准入完成。

## 1. 模格算法与对象（MODULE-REF/1）

独立 `LuoModuleParams` 和 `MODULE-REF/1` 格式，不转换旧 Params。默认研究输入 degree=256、(k,l)=(11,10)、q=274877844481、NTT 512 阶根 153250464611、η=1、κ=64、γ₁=125440、γ₂=31470387200、γ₃=15270991360、d=28。实现论文 §4 Algorithms 7–16；Algorithm 15 第 9 行的 zid 按该节正文及 Algorithm 16 解释为签名 z。不增加 z 非零条件。H1/H2 用独立 SHAKE-256 角色域、规范输入和本 IBS 公钥上下文；A 为真实均匀显式矩阵，未实施原文 SHAKE-128 种子压缩。

多项式为 Z[X]/(X^N+1) 与 Z_q[X]/(X^N+1)：掩码、私有响应和 z 保留有符号整数；A、t、w 为 [0,q) 系数。负循环 NTT 用 twist/untwist 和 2N 阶根，整数运算不得溢出或截断 q。Power2Round 保留最高端进位（默认 w1 可为 1024）；Decompose 的 q−1 特例、MakeHint/UseHint 严格依原文，h 为逐系数 bit，不发明 hint 重量上限。

对象公钥/主状态/固定身份密钥/签名分别版本化、类型化、长度前缀编码；参数和模系数为 uint64，z/私有系数为 int64，c 为 signed int8，h 为 bit 字节，w1 宽度由参数决定。解析拒绝未知版本、重复/截断/追加、维度/范围错误、错误公钥上下文；主状态恢复校验 t=As1+s2，身份密钥恢复校验 Az1+z2=w+tH1(w1,id)。同一身份缓存同一份密钥，RNG 不进入快照，私有 repr 隐去秘密。

公开资源限制：N 为 2–256 的二次幂，k/l≤16，消息≤65536 B、身份≤256 B、缓存≤64 身份、wire≤16 MiB；均匀抽样/Extract/Sign 均有显式预算，超限抛 IBMEError 的采样中止而不返回默认值。大素数仅接收校验器列出的已有 Sage 核验模数，小素数独立核验；不把资源/方程通过当作 MLWE/MSIS 或完整 QROM 安全。`security_claim: none`、`backend_admitted: false`，已有研究 CLI 接线不等于安全后端注册；任何新组合仍须独立核对签名容量并执行完整攻击验收。

2026-10-09 模格 MSIS/Hint 核验口径：论文 §4.4 式 (4.1) 引入 u′ 的系数无穷范数界 `κ*2^(d−1)+2γ₃+1`，本地默认输入对应 39131917313，不能仅用 z 的界代替。已签身份条件分支的矩阵为 [A|I_k]；新身份分支在 MLWE 将 t 换为均匀后采用 [A|I_k|t]，对应系数维度分别 (2816,5376)/(2816,5632)，后一分支的小挑战乘积块单独限制为 128。筛查的共同放松界为 78279890946，采用固定版本工具的无穷范数模型，记录块界/放松方向、模型与局限。HighBits→完整 w 的升举在最高 w1=1024 时必须保留低部 −62464，H1 仍作用于 Power2Round(w) 的原高位编码。

非零条件须分支记录：整数二次幂分圆环是整环，小挑战乘积的系数界小于 q，足以排除新身份分支的零模产品，无需错误假设所有挑战在 Rq 可逆；已签身份分支不能只由 c≠c′ 推出非零，需要原文公开模拟/固定缓存条件下的平均猜测界。此条件论证、启发式成本筛查及真实实现分别验收，尚无完整 QROM/侧信道/安全默认实例；研究代码与生产参数不得据此被无条件放行。

2026-10-09 `MODULE-COMPACT/1` 传输格式：只压缩签名字节，不改变参数、公钥/密钥格式、数学签名或 H1/H2 的既有输入编码。z 以偏移 `z+Zmax` 打包，`Zmax=γ₂−β₂−1`，宽度 `max(1,bit_length(2*Zmax))`；w₁ 宽度为 `max(1,bit_length(max_w1))`；默认分别36/11位。挑战使用N位存在位图和κ个符号位（按系数下标递增，1表示−1）；h 按全体 kN 个 bit 打包，不增加 Hint 重量限制。全部系数按多项式行序、最高位优先打包；末尾不足字节的低位必须零，不能接受非规范填充或未使用范围编码。

压缩 wire：`L24C1 || LP(IBME/LUO2024/MODULE-COMPACT/1) || LP(SIGNATURE) || LP(params) || LP(context) || LP(z) || LP(c_presence) || LP(c_signs) || LP(w1) || LP(h)`；params/context仍是136/64B，字段长度由已验证公钥参数推导，先核对参数/上下文，再解码固定大小字段。总长≤1MiB，拒绝截断、追加、重复、版本/上下文错误、维度/范围/权重和填充异常。编码/解码在合法数学签名空间与规范字节空间上互逆；BITPACK不是新的密码算法。

显式 `LuoModuleCompactIBSBackend` 复用原 Setup/Extract/Sign/Verify 四算法与密钥缓存，只包装 Sign 返回值及选定格式的加载；规范转换函数可用于参考/压缩差分。`luo-module-research` setup 支持 `--signature-format reference|compact`，缺省 reference；研究 state明确保存选择，既有缺少该字段的v1状态按已知 reference 格式读取。Encrypt/Decrypt 按state选择，不能用这个选项临时改解码器；compact加载器仅接收compact，reference仅接收reference。教育/mock配置不支持compact选项，既有哈希域及Wang/BYTEAUTH的输入和绑定均不改。安全声明和原语实例计数不因压缩改变。

## 2. 当前配置与资源上限

下表对应 [LuoModuleParams](../../src/ibme/ibs/luo_module.py) 的默认配置和校验器；资源上限不是困难性参数结论。外部候选参数必须以显式配置、独立证据和适配测试交付，不能静默改写这些默认值。

| 字段 | 本地默认 | 校验上限或条件 |
|---|---:|---|
| identity_max_bytes | 64 | 256 |
| message_max_bytes | 4096 | 65536 |
| max_extract_attempts | 1024 | 4096 |
| max_sign_attempts | 1024 | 4096 |
| max_uniform_attempts | 128 | 256 |
| max_cached_identities | 64 | 64 |
| degree / k / l | 256 / 11 / 10 | degree 为 2–256 二次幂；k、l≤16 |
| dropped_bits | 28 | 1–62 |

配置全部 17 个字段编码为正 uint64（136 B）；参数校验还要求 κ≤N、γ₁>β₁、γ₂>β₂、2γ₂<q、β₂<γ₃、κ·2^(d−1)<γ₃，并核验环与舍入条件。通过这些程序检查不等于总 Sign 中止概率或安全归约已经闭合。默认 H1/H2 的公钥上下文为 64 B。

同一主状态对象对发钥与缓存快照持有重入锁；缓存命中返回同一身份密钥，恢复时重建锁，不序列化 RNG。跨进程发布与固定 profile 的检查见 [传输与状态](transport-and-state.md)。

### C64B 显式研究配置

[luo_module_profiles.py](../../src/ibme/ibs/luo_module_profiles.py) 的 `c64b_params()` 固定完整17字段，ID为 `luo-module-c64b-v1`。N/k/l/q/root/eta/kappa/d 为256/11/10/274877844481/153250464611/1/64/28；gamma1/gamma2/gamma3 为190000/60000000000/27487784448，Extract/Sign 上限各4096，uniform上限128，身份/消息/缓存上限64/4096/64。它不改 `LuoModuleParams()` 默认值和两种 wire 版本。

专用研究入口显式 `make_research_runtime(ibs_params=c64b_params(), signature_format=...)`；Setup 传入其它 snapshot 时在消费熵前拒绝，公开对象读取器拒绝跨 profile 恢复。公共 assembly 可传完整 C64B 参数对象/JSON；它不自动成为默认 preset。reference/compact 签名分别29455/16383 B，完整组合容量另核，本轮最新 assembly 的最大3924 B应用输入实际往返见[合入记录](../deliveries/2026-10-12-pr-review/README.md)。参数或格式变化不算新 IBS 算法。

可用性证书是理想随机源/XOF、矩阵好事件及明确调用/查询预算下的条件界，不是安全位数。C64B 继续 none/false/非正式参数；MLWE/MSIS、固定服务及整体模型条件单独核验，不从接口或样本成功继承 QROM/安全等级。

## 3. 矩阵参考后端的兼容范围

M2-A Luo 研究适配（2026-10-09）：`src/ibme/ibs/luo.py` 实现冻结的 IBS 方法与对象基类，显式使用独立 `LuoMatrixParams`；旧 Params 不自动映射。配置为 `IBME/LUO2024/MATRIX-CONFIG/1`，完整字段且安全声明固定 none/false，JSON 解析拒绝重复/未知字段和错误版本。对象继续兼容 M1 的 `MATRIX-REF/1` 研究格式，主状态保存固定身份密钥而不保存 RNG，验签只依赖公开输入。程序对象类型错误为 TypeError，身份/消息错误为 EncodingError，配置错误为 InvalidParameterError，反序列化错误为 SerializationError；熵源错误为 RandomnessError，预算耗尽为明确的 LuoSamplingAbort。当前 n≤16,m≤128,k≤32、uint32 q、有符号 int64 整数及 8 MiB 上限是研究资源限制；分析报告里的大参数不能交给这个版本执行。方法形状、旧后端和 CLI 选择不变，未准入安全后端。算法对应、测试、完整格式及 CHKP 载荷交接见 [M2-A](../research/2026-10-09-m2/README.md)。

矩阵版本保留复现和比较用途，不因本文件仍记录它就重新成为 Luo 当前优先实施任务。其 CONFIG/REF 格式与 MODULE-REF/COMPACT 格式互不替代。

## 4. 独立验收

- 模格代数、NTT、舍入和 Hint：`tests/test_luo_module_math.py`。
- 模格发钥/签名/恢复与预算：`tests/test_luo_module_backend.py`。
- reference/compact 规范编码与差分：`tests/test_luo_module_codec.py`。
- 统一 IBS 契约和矩阵参考：`tests/test_luo_ibs_contract.py`、`tests/test_luo_matrix_reference.py`。
- 组合测试使用共同协议契约；完成签名单体测试不能代替完整组合验收。

算法—论文—参数证据入口：[M2 记录](../research/2026-10-09-m2/README.md)、[模格主线决定](../research/2026-10-11/IBS版本决策-模格版主线.md)。尚未闭合的条件只在项目状态更新，不将启发式估计、样本成功率或外部未审报告写成定理。
