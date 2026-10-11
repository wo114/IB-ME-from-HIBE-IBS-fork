# 首套根生成、同组参数与公开攻击验收

基点 `9ed1b83`，2026-10-11。目标仍是先完成第一套集中闭环。本轮补齐系统随机源下的根生成、有限分布近均匀账本及主状态接线；没有把首套判为完成。证据见 [根生成结果](root-result.json)、[公开攻击输入](public-n1-attack.json)、[独立攻击结果](public-n1-attack-result.json)、[尺寸压力数据](dimension-stress.json) 和 [交付审计](audit.json)。

## 结果与边界

- 新增独立的私有输入 Rust 接口和 Python 调用方。系统 CSPRNG 产生均匀 Abar 与真实有限离散 Gaussian R；qFALL 只负责确定性的 gadget / 完整基运算。不修改旧 public-test 前端，不以测试 seed 生成此次主密钥。
- 独立核验定义关系、完整核格、规范表示及公开 GS 上界；新主状态43068 B，跨进程恢复保持字节和公开上下文，恢复不生成新密钥。
- 同组83/166/249维规划通过公开宽度、所选模数充分条件和条件噪声预算。真实全有限父/叶采样及逐输入资源账本尚未执行，不能从尺寸门通过推断采样通过。
- 实测复现 n=1 困难性缺口：公开上下文、已知身份与密文足以恢复256位种子。独立进程枚举67个噪声候选，剩余唯一候选的种子散列匹配；未读取主/父/叶私钥、R 或真实 LWE secret。

根近均匀条件已获得实现依据；整套安全参数和准入仍未成立。`security_claim:none, backend_admitted:false, parameters_are_formal:false`。统计距离、Gaussian epsilon、种子长度不是安全等级。公开攻击针对 CHKP raw KEM 教学参数，不称完整 IBME 攻击测试。

## 算法与论文对应

| 本轮算法 | 依据 | 对应与限制 |
|---|---|---|
| A=[Abar\|G−Abar R] | [MP12](../../../papers/2011_lattice_trapdoors_micciancio.pdf) §5.2 Algorithm 1 | Algorithm 1 允许选择 R 分布。本轮用既有有限 DGS 的零中心独立乘积分布；先以 Sage `is_prime(proof=True)` 确认 q 素性，无库未核验 RNG |
| G-trapdoor 转完整短基 | MP12 Lemma5.3；[qFALL固定源码](https://github.com/qfall/tools/blob/b8eb4842fb80c36f7f3494930ea316472cb75793/src/sample/g_trapdoor/short_basis_classical.rs) | 保留公开 API / gadget 列顺序；重验 A·S=0、det(S)=q^n。依赖 MPL-2.0，固定revision，不宣称原创 |
| 根分布接近均匀 | MP12 §5.2 statistical instantiation 及其引用的 leftover-hash regularity | 用实际有限 R min-entropy 下界和共享 Abar 的 nk 列并集，不沿用旧 ternary 根的 TV |
| 父/叶公开宽度 | CHKP §3.4、§5.2；既有有限 GPV C1-exec | 父输出 GS²≤s1²·2m，再据此选叶宽度；仅将主 AI 持久 scope 的 epsilon 验收范围扩至128，旧采样/ToBasis guard保持 |
| 主状态、真实噪声 | 既有发钥树；CHKP §2.3.1、§5.1–5.3 | 新根接真实 H/G 配置、主状态；噪声为 round(q·连续Gaussian alpha)。未接七入口/字节后端、Luo或Wang/HYBRID/BYTEAUTH |

本轮用 MP12 根生成/完整基转换后接 GPV/RandBasis，**未实现或宣称采用 MP12 Algorithm 3 扰动式 SamplePre**。替换 GenBasis 的最终对应仍须与正式参数和 CHKP/Luo/Wang 引用条件统一核验，不凭论文名放行后端。

## 有限分布与公开基长

设 M 为中心0有限整数权重的归一化质量下界。每个权重≤1，所以单坐标最大概率≤1/M。支持[-171,171]且2·171<q，模q映射单射；独立 mbar 坐标的一列最大概率≤M^-mbar。均匀 Abar 的素数域哈希族给出保守界：

```text
delta_regular_conditional <= min(1, nk * sqrt(q^n / M^mbar))
root_abort <= n*mbar*2^-uniform_trials + mbar*nk*scalar_abort
```

第一项是所有有限抽样成功条件下的实际分布 regularity，中止另列。不假设共享 Abar 的列输出独立。平方根以精确有理数、整数ceil和向上取整计算；精度随64/128/192位目标调整，不复用不足的固定128位网格。R与理想Gaussian的联合TV另列，**不重复加入直接按实际有限熵算出的regularity**。错误熵源直接报错，不重试或回退；分布界假定独立均匀bytes。

MP12 Lemma5.3、binary gadget GS²≤5以及 `(||R||+1)^2≤2(||R||_F^2+1)` 给出无需测量秘密几何的公开 bound：

```text
root_GS² <= 10 * (1 + mbar*nk*radius²)
```

生成后以严格列范数证书或精确GS验证；宽度由公开bound预定，不按秘密实测值缩窄。私钥、熵字节和R仅在被忽略的test-results。公开攻击输入只含Oracle/context、编码身份、密文、公开噪声参数与种子验证散列。

## 实际参数和计数

| 项目 | 本次值 |
|---|---|
| n / q / k / mbar | 1 / 35184372088891 / 46 / 37 |
| 根 / 父 / 叶维度 | 83 / 166 / 249 |
| R 的 s² / radius | 1024 / 171 |
| 条件regularity / 根中止上界 | 约2^-64.476 / 2^-117.267；64是统计预算 |
| 公开根GS² | 497681830 |
| 父s1² / 父GS² | 272729642840 / 45273120711440 |
| 叶s2² / epsilon_bits | 24809670149869120 / 128 |
| alpha / 有限噪声选项 | 4/q；tail64 / mass96 / precision160 |
| 条件寿命错误并集 | 256bit×2^20次，≤2^-36；排除坏范数/采样/有限噪声误差，非安全等级 |
| 根实际 / 最坏熵消费 | 650576 B / 676213184 B；最坏预算不预分配内存 |
| 主状态 / raw capsule | 43068 B / 3127 B |
| 身份 / 消息 | Bob/Alice 3/5 B、规范身份86 B、种子32 B，无应用明文/IBME载荷 |

主状态探针新生成一次根、恢复一次、攻击一次；约1.171s含这些诊断，非完整HIBE/IBME基准。随后基于**同一保存的公开上下文**另生成一份密文归档，未读取或重生成私有根；公开输入在新解释器复验成功。已有主状态也再次只读恢复，无重抽。旧未保存根诊断与此根为不同生命周期，不混用熵计数。

环境 Sage10.9 / Python3.13.14，指定 WSL conda `~/miniconda3/envs/sage`；Intel Core Ultra9 275HX。固定binary/源码/产物散列及依赖版本见audit。无峰值内存或完整系统性能结论；测试不替代安全定理与参数适用核验。

## 正式闭环的瓶颈及下一项

父ToBasis≤192、叶有限GPV≤256，故两层根m≤85。MP12 gadget至少nk列，另有至少1列Abar。在当前q、k=46下：

```text
n <= floor((85-1)/46) = 1
```

当前实现域只能容纳已被公开攻击的n=1。即使只将同一n=1根的regularity目标提高至128，mbar=63预筛也达到109/218/327维，父/叶均被拒绝。统计精度或重复次数不能将此组输入变为安全首套。

按相同q、s=32、统计目标64与质量下界31.9计算 n=128/256 的**尺寸压力样例**：

| n（不代表安全等级） | mbar | 根 / 父 / 叶 | 根基wire至少 | 父基wire至少 | 256叶向量wire至少 |
|---|---|---|---|---|---|
| 128 | 1184 | 7072 / 14144 / 21216 | 300079104 B | 1200316416 B | 32587776 B |
| 256 | 2338 | 14114 / 28228 / 42342 | 1195229976 B | 4780919904 B | 65037312 B |

下界只计当前每私有整数最低6 B wire，不含主树、对象、临时内存或耗时。未执行生成/采样或核验这些样例的宽度/噪声/攻击成本，不能称正式候选。当前16 MiB对象及采样维度限制必须有实际工程改造，不能简单调大Python/Sage guard后宣称解决。

**下一项先核定正式困难维度/攻击成本与可实施的完整基委派、原像采样资源路径。** 确定同组输入后完成生产根—父—256叶链、七入口与字节/绑定对象，再接Luo/HYBRID/Wang/BYTEAUTH，验收四种匹配、公开伪造、恶意接收者重签、全字节篡改和跨进程状态。166维全有限父级实跑可核接口，但不继续把n=1扩样当解除困难性阻塞的主要工作。引用已有定理并核对条件，不扩展基础证明工程，也不因当前实现域失败否定CHKP本身。

旧education两项认证反例仍未修复。本轮不修复它们；正式准入完整组合仍为0。

## 复验

```bash
~/.cargo/bin/cargo build --release --locked --offline \
  --manifest-path experiments/research/reuse/qfall_probe/Cargo.toml \
  --target-dir test-results/qfall-target --bin ibme-qfall-private-root

# 仅公开数据，无私有文件/生成器/熵。
PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m experiments.research.first_suite.root_probe \
  --attack-only docs/research/2026-10-11-first-suite-root/public-n1-attack.json

# 仅接受新的忽略目录/公开输出，拒绝覆盖或私钥路径别名。
PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m experiments.research.first_suite.root_probe \
  --private-directory test-results/first-suite-root-new/private \
  --output test-results/first-suite-root-new/result.json

PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m pytest -p no:cacheprovider -q --tb=short \
  tests/test_first_suite_root_generation.py
```

最终新增33项通过，相关回归237项通过（批次重叠；最后追加路径/公开输入/强目标检查后重跑受影响根测试）；Windows36 passed / 2 skipped。Windows CI中的Sage/Rust依赖skip不记为根接口验收。早期测试误调不存在的DelegationScope.from_bytes，已改用实际MasterTreeState恢复；有理数双参数构造错误也已修正，无未解释失败。
