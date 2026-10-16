# SRGG 经典全 raw-frame／多 public：模型法则与工程边界

2026-10-16。只读代码基线为本地提交 `515ca5a`。本文在**经典 ideal
byte-XOF 模型**内给出完整 namespace 的条件对应证明；没有修改生产哈希、对象
类型检查或冻结 Runner，也没有实现新的 router。已完成的 seed 条件嵌入引理
仍以 [seeded-xof.md §§3、5、7](../2026-10-16-srgg-classical-rom/seeded-xof.md)
为准，不重新把它登记为未证事项。

结论分开使用：给定下文相同 kernel／失败语义，typed 实验扩充到全部原始输入、
其它 public 字节串和生产规范编码，**namespace 本身的额外 TV 为零**；完整诚实
服务与该实验的桥、底层困难性和可执行生产对象接入并不由此自动完成。
`security_claim=none, backend_admitted=false, parameters_are_formal=false,
nist_security_category=null`。

## 1. 核验对象与模型选择

生产实现位置为：

- `experiments/research/candidates/srgg/structured_execution.py`：
  `Public`（273 行）、`Key`（320 行）、`public_matrix`（376 行）、
  `identity_target`（384 行）、`message_challenge`（393 行）。
- `experiments/research/candidates/srgg/structured_backend.py`：
  `PublicKey`（90 行）、`SigningKey`（128 行）、`signature_shape`（284 行）、
  `Backend`（292 行）。
- `experiments/research/candidates/wang_pw/hashing.py`：`frame`、
  `XOFStream`、`uniform_values`；`src/ibme/core/encoding.py::encode_bytes`。
- `experiments/research/candidates/srgg/classical_runner.py`：
  `ProofPublic`（73 行）、`Runner`（193 行）、H1/H2 表及完整 strong 返回日志。

这里的 `P^F` 是生产算法在 ROM 中的明确解释：三种 SHAKE 输入均查询**同一个**
理想 byte-XOF `F`。每个完整输入字节串 `x` 对应一条固定无限 iid 字节流
`F(x)`，不同 `x` 的流独立；prefix／offset 查询读取这条流的相应区间。
实现时只需按需保存有界前缀，不预分配无限流。其它确定运算，包括规范 JSON、
上下文 SHA-256、模运算、序列化、维度／范数检查，在两侧相同。

把 SHAKE 实例放在此模型中分析，是公开的密码学模型选择；不是要求另外证明
固定 SHAKE 与随机函数有一个信息论 TV 上界。模型内也不能同时给对手一条独立的
真实 `hashlib.shake_256` 重算路线，却允许模拟器只编程 `F`。

例如在一个 fresh 点查询 `t` B，并检查回答是否等于固定真实 SHAKE 的 `t` B
前缀：真实 SHAKE 的等号概率为 1；与其独立的理想流为 `2^(-8t)`。
所以这种**混合两个不同 oracle 的实验**有距离至少 `1-2^(-8t)`，不能据它填写
“ROM 归约仍须统计证明 SHAKE 随机”，也不能把这一个建模错误当作 SRGG 攻击。

## 2. 完整输入域与唯一全局表

记 `C` 为实际 `_canonical`，`frame` 为逐字段 uint32 长度前缀编码，`D` 为
`structured_execution.DOMAIN`。固定一个已登记的当前 public，完整规范 wire 为

```text
P = C({schema: execution_schema, params: all_params, seed: seed_hex, b: B}).
x_A = frame(D, b"matrix", C(all_params), seed).
x_1(id) = frame(D, b"identity", P, id).
x_2(W,m) = frame(D, b"message", P, C(W), m).
```

`P` 不含显式 Ahat；Ahat 由 `x_A` 的有界解析恢复。H2 没有 identity 字段。
参数必须包含实际完整 `ExecutionParams`，不能删字段、只用参数名称或短 context。

全局表 `T` 的唯一主键是**完整原始输入 `x`**。先判定字节相等，再给该 entry
选择一份稳定分类及 source；不能先按“调用来自哪一个 public”分配独立的表。
所有外部、内部、重算、恢复、验证查询共用 `T`。

| 原始输入分类 | 固定的处理规则 |
|---|---|
| 与当前 `x_A` 完全相同 | 读取已初始化的 matrix 条件流；所有重算复用 |
| 当前 `P`、有效 id 的规范 `x_1(id)` | 首次非空读取时创建该 id 的唯一 latent/H1 entry，并固定其完整条件流 |
| 当前 `P`、有效规范 W/m 的 `x_2(W,m)` | 首次非空读取时固定完整 n-bit c、owner、free index、未用高位和 suffix |
| 其它 public wire 的 identity/message 点 | 作为各自完整 `x` 的普通独立 raw 流；不调用当前身份／H2 表 |
| 其它 matrix 点、其它 domain、非规范／截断／追加／无效 frame | 同样按完整 `x` 服务普通独立 raw 流 |

有效 id 使用实际非空、4096 B 上界。有效 m 使用 65536 B 上界。W 的维度、
严格整数、模 `2Q` 规范范围与 `ExactRing.vector` 相同，其原始字段必须恰为
`C(W)`；不可接受非规范 JSON 后把多个不同原始输入合并。解析整个 frame 时必须
恰好消费全部输入和预期字段数。对无效点返回 raw 字节不意味着把它当成合法
IBS API 输入；API 的错误返回仍由相同输入检查决定。

offset／长度的容量检查在两侧采用同一规则。零长度读取返回空串，不触发采样、
owner 或 latent entry；任何非空区间读取，包括只读远处 suffix，均在返回前完成
相应首次触及。首次触及固定整条有界解码轨迹及独立后缀，后来才能安全投影，
不能先返回一个不受约束的 suffix，再为已触及点重选 h 或 c。

## 3. 条件 namespace 对应定理

**定义（扩展 typed 实验 `E_typ`）。** 在现有 typed Run 之外显式加入 matrix
条件流、全部其它 raw 点的 lazy 表以及与生产一致的规范 public／对象编码。
此定义没有将现有 Runner 的 `ProofPublic.to_bytes()` 当成生产 `P`：其显式
`a_hat`、schema 和 context 实际不同，须使用独立的规范表示映射。

下列前提固定本定理的范围。

1. 当前 public 的 matrix、H1、H2 输入按 §2 唯一编码；matrix 初始化满足已有
   seeded-XOF 引理的 fresh-point／联合 law 前提。当前 P 必须在其任何相关
   H1/H2 原始查询之前登记；若允许更早的 Other 查询，则初始全局表、已读
   字节和辅助状态必须已与将采用的 H1/H2 kernel 有相同联合 law，或者将
   不兼容预触及保留为另行计费的 bad。仅有 matrix 点 fresh 不保证未来 P
   下的 H1/H2 点 fresh：攻击者可能预查 `identity_frame(P_guess,id)` 而
   从未查询其 matrix 点。Public B 的条件 law 属于所用 hardness hybrid，
   不能仅凭本定理假定 B 均匀。
2. `E_typ` 和 router 一侧对每个共同历史使用同一 latent pair、raw/final gate、
   pending/failed/issued 状态及已发 key 条件 kernel。H1 使用同一含失败 `G_h`
   或同一已明说并计费的成功条件 `K_h`；不能两侧混用。
3. H2 的 typed entry 以 `(P,W,m)` 为 key，在首次相关触及固定相同完整 c、
   free/sign owner、free index 和后缀；目标 Sign 只编程完全未触及点，碰撞、
   重试、失败和完整 `(id,m,signature_bytes)` 日志使用同一规则。
4. 域外 raw 点在两侧均为按完整 `x` 登记的独立 lazy 流。各项查询／source cap、
   parser 异常、随机源故障及服务故障的返回／异常标签使用同一共同历史条件
   kernel。故障不必概率为零；确定的配对故障也可作为条件输入。
5. 所有参与算法、对手的原始 XOF 调用均经过本表；经典自适应对手只通过已
   声明接口和自己的随机带行动，不直接读模拟器私有表或另调实际 SHAKE。

**定理。** 对任意满足共同查询上界的经典自适应对手，`E_typ` 与按 §2 路由的
`E_frame` 存在逐样本对应，使其完整输出 transcript 相同，包括 public／对象
wire、全部已读 raw 区间、重复／重叠查询、owner、索引、失败／异常标签和最终
strong 新鲜性判定。采用相同表示映射后，其联合 law 相同。因此纯 namespace
扩充额外费用 `delta_namespace=0`。

**证明。** 在一个共同母空间上，为两侧每个唯一原始点、identity latent entry、
H2 entry、采样器、对手及共同故障分配相同 source。初始当前 public、matrix
流及公共状态由前提 1 同配。假设处理 k 个接口动作后，所有已出现 raw 点的
固定流、typed entry、输出和状态均按 §2 对应。

第 k+1 个动作由同一历史和对手随机带决定。若容量／类型检查失败，两侧立即
给相同错误；零长度查询均不抽样。非空 raw 查询恰落入 §2 的一个稳定分类。
已存在 entry 只读取同一流的同一区间。新的当前 H1 点，两侧以共同 source 生成
同一 latent entry、门结果和完整 `G_h` 轨迹；新的 H2 点，两侧以共同 source
固定同一 c／owner／后缀；新的其它点，两侧初始化同一独立 raw 流。matrix
点无论从哪个调用入口出现，都命中已经固定的同一 entry。故本动作的回答、
异常和状态更新相同。

内部 H1 解析、H2 取位、Public 重算、签名、发钥及验证也只由这些相同 bytes
和相同 kernel 决定。规范表示映射是确定映射；对 strong 日志的相同、单射
重编码同时作用于已返回签名及候选签名，保持“是否为先前返回的同一签名字节”
的判定。它不能只重编码 public 而遗漏 context／签名外壳／返回日志。
采样或基础设施失败按前提 4 同配，不删除失败。于是归纳不变式保持。
有限有界 transcript 的逐样本相等蕴含联合 law 相等。证毕。

这是**给定语义 kernel 的精确路由定理**，不是诚实 production Extract 与公开
latent pair 的新分布证明，也不证明当前 Python Runner 已实现这些额外入口。
现有 production `Backend` 签名外壳与 Runner 的 raw `Signature` 外壳也不同；
若建立可执行 facade，必须提供并检验上述单射表示映射，不能把字段响应相同
直接写成两份原始签名字节相同。

## 4. 多 public、重复 seed 与未来登记

当前单公钥 IBS 游戏允许攻击者查询任意其它 public 字节串的 raw 点：这些点
作为独立 `Other(x)` 流已经被定理覆盖。对手自己在其它公钥下做本地计算，并不
使当前游戏额外提供其它公钥的 Extract/Sign oracle；后一种多密钥游戏需要另定
权限、挑战和费用，本文不擅自加入。

“其它公钥独立”只能指**不同完整 raw 输入**的独立，不能指每个 public 各有
一份矩阵流。对相同参数和 seed、不同 B 的 `P != P'`：

```text
matrix_frame(params,seed) 相同，因此 Ahat 必须相同；
identity_frame(P,id) != identity_frame(P',id')；
message_frame(P,W,m) != message_frame(P',W',m')。
```

后两行由长度前缀唯一性和完整 P 字节不同直接得到，不以 SHA-256 context 无
碰撞为前提。若 P 字节完全相同，它们是同一 namespace，H1/H2 latent entry、
owner 和 raw 流都须复用；同一 H2 entry 不因更换 id 而变成 fresh。

有限多个**预先登记** public 的推广相同：先按完整 matrix 点合并，再按完整
public wire 合并 H1/H2 namespace，对每个尚未出现的 raw 点执行既定 kernel。
若两个外部挑战要求为同一个 matrix 点嵌入不同 Ahat，则前提不满足；不能靠
按 public 分表掩盖冲突。重复 seed 可以沿诚实模型复用已有 Ahat，也可以按
明确的失败规则计 bad，但不可静默重抽 seed。

未来自适应登记有额外限制：某个原始点已经作为 Other 被读过后，不可把它
重新分类为一个可独立编程的 H1/H2 点。必须复用已有流，并证明新的条件处理
与之相容；或保留该 bad／失败事件并给出实际概率。任意攻击者选定 public
没有免费的“fresh public”概率保证。

对于新 Setup 的独立均匀 256-bit seed，已有
[seeded-xof.md §5](../2026-10-16-srgg-classical-rom/seeded-xof.md) 给出
碰中先前相关 matrix 点的条件上界。若第 k 次 Setup 之前，相同完整参数下
已有 `t_k` 个不同 seed 对应的相关点被触及／初始化，则保守使用

```text
Pr[any seed hit] <= sum_k E[min(1,t_k/2^256)].
```

其中 `t_k` 包含需保留的内部初始化／先前诚实 Setup；若它们已计入，不能再
加一遍同一生日碰撞项。也可把先前诚实 seed 单独列出，以
`K(K-1)/2^257` 加对手预查询项，但只能择一种不重复计费的分解。给定 fresh
seed 的条件 kernel／联合 law 前提仍不可省略；上述式子不适用于攻击者自行
选 seed 或量子预查询。碰中事件与所用停机规则显式保留，不重新选择 seed。
这个 `t_k` 只计相关 matrix 点，不自动覆盖预查未来 public 的 H1/H2 点。
若要按这些 frame 中的 seed 候选另作计数，须另证其与新 seed／B 的条件关系；
本文没有给未登记 public 的全部 H1/H2 预查询填写一个未经证明的数值界。

## 5. 完整失败及 adaptive 首次触及的分布费用

namespace 定理不删除拒绝采样失败。matrix 使用含失败的 `G_A`；均匀 A 混合
恢复完整 raw law，失败时 Setup 无 public 输出。它不是成功条件的求 SHAKE
逆像。H1 使用 `G_h` 时，raw 首次触及可以先固定完整失败轨迹，继续回答既定
bytes；真正 composite H1 有界解析失败时才按实验规则返回失败。证明可以另在
成功事件中排除 hashbad，不能在只读 1 B 时任意引入一条额外的可见终止。

已有 H1 条件桥仍适用：每个 h 的成功概率相同，`K_h=G_h|success`；若 latent
image law 的距离为 `delta_image`，完整 key/h/raw-prefix 联合比较的费用可按
已有引理取 `delta_image + beta_H`，再加实际 sampler／source kernel 的费用。
这是**语义分布费用**；统一 frame 层不再额外加一遍相同项。

对自适应查询，局部界必须对每个共同可达历史的完整条件 kernel 成立，而非只
对无条件 h 边缘成立。若首次触及至多 QI 次，每个新身份一次 beta_H；同点
prefix 扩展、Public 重算或重启后的重复读取不是新的独立拒绝采样试验。
有限 source cap、pending/failed cache、磁盘故障、提交但未返回等分支仍按
[service-law.md](../2026-10-16-srgg-bounded-runner/service-law.md) 的同故障
参考和条件 TV 分开处理，不由 namespace 等式设为零。

## 6. 当前已实现与仍欠实现的准确边界

已有成果为：seed/matrix 理想流嵌入及经典预查询引理、保留失败的 bounded
`ConditionalPoint`、typed 显式 `ProofPublic` Runner、同一固定 public 的 H1/H2
首次触及／owner、strong 日志及有界两轮 fork。本文补的是其全域编码推广的
条件证明，**没有新运行实验**。

生产 Python 代码尚无可注入的 XOF 接口。具体限制是：

1. `raw.Public.__post_init__` 直接 `public_matrix(params,seed)`；该函数创建
   绑定真实 SHAKE 的 `XOFStream`。保留 seed 却传入独立 Ahat 会被拒绝。
2. `PublicKey.__post_init__` 要求 exact `raw.Public`；`PublicKey.from_bytes`
   又按真实 SHAKE 展开。不能给它塞入新 proof public／代理类冒充通过。
3. `SigningKey` 要求 exact `PublicKey` 并构造 `raw.Key`；`raw.Key` 重算
   `identity_target`。恢复、发钥、签验中的 H1/H2 同样仍沿真实 SHAKE 路径。
4. `Runner` 要求 exact `ProofPublic`，其 wire/context 是实验专用；已有 typed
   表没有全部 raw-frame 的 parser、其它 public 流、matrix source 和完整生产
   外壳表示映射。bounded Runner 的现有资源证书也不包含这些新增点／字节。

因此，新增独立 raw router 可以成为 `P^F` 的可执行研究解释，但只做 parser
不会让当前生产 Backend 自动查询该表。若需要运行真实 guarded 对象上的
可编程实验，应协调一个明确的哈希依赖注入改动，并检查所有内部调用和恢复
入口；或新增严格隔离的理想模型 facade 并完整验证表示映射。两种方式均不能
采用 monkeypatch 生产哈希、绕过 exact-type guard、修改公钥语义或把显式矩阵
伪装成 seeded 公钥。本轮未选择／实现这类生产接口改动。

这一个工程限制**不妨碍在声明好的 ROM 中分析生产算法的抽象 `P^F`**。数学
证明不以先把 Python 的真实 SHAKE 变成可编程 oracle 为必要条件；工程实验
和 ROM 定理应分别报告。也不能反过来凭抽象证明声称已经跑通生产对象接入。

## 7. 对 Delta0 与后续工作的含义

在 ROM 内，按 §3 采用全部共用的接口解释并满足 kernel／失败前提时，
全 raw-frame／其它 public 查询的 namespace 转换本身没有未知统计项。
seed 的 fresh-point 条件和碰中费用按旧引理明确处理，不重复收费；一般的
“SHAKE 是否为真正随机函数”不作为待数值闭合的 Delta0 项。

仍须分别核验并合成：真实诚实 Extract/Sign 到所选 latent／Gaussian 参考的
完整条件 law，初始联合历史和 root／oracle 辅助信息，固定服务与无故障普通
IBS 游戏的关系、完整基础设施失败模型，以及所用 callback／query／运行预算。
若实施新 router，另给所有 Other 点、matrix 条件流、parser、表示映射及
all-path source/time 费用，不能移植原来只覆盖 typed 域的 4 GiB 证书。

QROM 的 coherent 首次触及、H1 编程和量子提取不属于本经典归纳定理。底层
环／复合模数／CBD1 的困难性与正式安全参数也仍需独立证据。本文没有改参数、
运行新 Gaussian／攻击测试或证明完整 IBS 安全；所用研究参数和 n512 资源点
继承冻结资料，不能据 namespace 等 law 宣称 NIST 等级。
