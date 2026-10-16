# H2 的 partial-byte/offset 相干包装：精确等式与查询成本

2026-10-16。本页补齐
[商挑战 §5](../2026-10-16-srgg-classical-rom/quotient-challenge.md)
留下的一个有限接口子引理：固定 SRGG H2 命名空间中，任意合法长度、offset 的原始
byte 查询可相干地由商挑战前缀及同源独立后缀模拟，反向亦可。
该等式适用于外部纠缠，但不是量子提取、H1 模拟或完整 QROM 安全归约。

`security_claim=none, backend_admitted=false, parameters_are_formal=false,
nist_security_category=null`。

## 1. 精确接口及位序

固定偶数二次幂 n，`P=ceil(n/8)`，raw 输出上界 L。当前独立执行器 n≤512；本工具
固定 L=65536 B。每个原始 H2 输入点 x 对应一条固定字节流 F(x)，不同点独立。
x 是原实现完整 frame，含 domain、`message`、规范 public、规范 W、消息；不加入身份。
本子引理的 x 已属于固定的 H2 命名空间，不把它与 H1 或 matrix 的输入点合并。

`structured_execution.message_challenge` 从前 P 字节按 little-bit 顺序取前 n 位。
将它们分为各 n/2 位的 a、b，定义作用于整个 P 字节的 CNOT 层

```text
G(a,b,u)=(a XOR b,b,u),    G^-1=G,
```

u 是 `8P−n` 个未使用位（n8/n512 时为空）。定义逐点流变换

```text
T(F)(x) = G(F(x)[0:P]) || F(x)[P:...].
```

G 是可逆线性映射，所以 T 是整个随机流空间的逐点双射。均匀 F 的 T(F) 仍均匀；
其商挑战 χ=a XOR b、冗余 b、u 与后缀互相独立。所有重叠读取投影到同一条流，
不能逐查询重抽前缀或后缀。对 n2/n4，u 也须保留，不许把未使用高位设零。

采用标准 XOR oracle：输入寄存器为 `(x,o,l)`，输出寄存器长度固定 L 字节。
合法 `0≤o,l, o+l≤L` 时

```text
U_F |x,o,l,t> = |x,o,l,t XOR pad_L(F(x)[o:o+l])>.
```

padding 在 l 之后全零，故不改输出寄存器的其它位。非法元数据以同一确定规则输出
零（或由两边相同的公开 validity 位标记），不会在 unitary 内抛 Python 异常。
有限宽整数比较、加减和选择都可逆地计算并清理。

## 2. 两次前缀 query 加一次 suffix query 的包装

给定 `U_F`，实现 `U_T(F)`。令一个 P 字节 scratch 初始全零；所有操作控制只依赖
`o,l` 和公开 n，不读 oracle 返回值作控制条件。

1. 以 `(x,0,P)` 查询，把 F 的完整前缀写入 scratch。
2. 对 scratch 施加 G，将 `[o,min(o+l,P))` 与前缀的交集 XOR 到 t 的对应位置。
   撤销 scratch 上的 G。
3. 用一次 raw suffix query 将 `[max(o,P),o+l)` 的有效部分 XOR 到 t 的对应位置。
   其长度为 `max(0,o+l−max(o,P))`，字节落点偏移为 `max(0,P−o)`。
   没有交集时使用长度零；合法末端查询仍不超 L。
4. 再以 `(x,0,P)` 查询，将 scratch 清零。

suffix 写入 t 的片段可由 query 前后的可逆寄存器置换/交换实现；其它位不变。
不需要把 suffix 值另存后再查询一次来清理。固定 L 字节输出寄存器与 P 字节 scratch
足够：两次 prefix query 各自在 query 前后交换 scratch 和 t 的前 P 字节，原 oracle
其余输出位因 padding 为零而不变。对可变 offset，可用 barrel-shift/选择网络实现
寄存器置换，保守计 O(L log L+n) 额外门；不声称这些门或字节接口是单位成本调用。

非法元数据分支可先可逆计算 validity 位；只控制将 scratch 复制到 t 的操作，并把
suffix query 的非法 offset/length 改为合法的 `(0,0)`。两次完整 prefix query 始终
执行并相消，再清理 validity/选择寄存器，输出为零变化。不需要假设免费的
controlled-blackbox query。这里点 x 属于固定的有限 H2 输入域；全域 frame 判定
仍按 §4 单独核对。

对任意计算基态，上述净效果恰为 XOR 相应 T(F) 切片，scratch 复零。于是整个 unitary
等于 `U_T(F) tensor I_reference`，由线性性，对元数据的量子叠加、任意目标寄存器和
外部纠缠均成立。算法不测量 x、offset、length、oracle 输出或攻击者状态。
因为 T 自逆，给定 T(F) 的 raw oracle，用完全相同包装可恢复 F 的 raw oracle。

查询数保守为**每次原 raw 查询 2 次完整 joint-prefix 加 1 次 suffix**，包括长度零。
这是相同 stream oracle 内的三个查询，而非三个独立重编程点。若使用独立的 χ、b
oracles，n8/n512 没有 spare 位，compute/uncompute 各调用两者一次，另一次 suffix，
共至多 5 次；n2/n4 还须计独立 u 的访问。若将全部 P 字节视为一个 joint-prefix oracle，
始终是 3 次，不把独立 component 的查询成本藏进一次调用。

## 3. 完整前缀的更紧身份

若只需要 joint-prefix oracle，在目标寄存器上直接共轭即可：

```text
G U_F^(full-prefix) G^-1 |x,t>
 = |x, G(G^-1(t) XOR F(x)[0:P])>
 = |x, t XOR G(F(x)[0:P])>.
```

它只需一次原 full-prefix query，附加 n/2 个 CNOT 在前后各一次；没有 scratch 或
suffix。反向同理。第 2 节的 3-call 上界是任意 partial/offset 包装的统一充分成本，
并非对 full-prefix 的最优计数。

## 4. 范围与完整游戏仍须核对的部分

本等式也可对任意**公开、确定、可逆判定**的原始 H2 命名空间作受控扩展，域外保持
原 F。要覆盖整个实际 raw API，仍需实现并核对完整规范 frame 的可逆判定、其它
public/参数命名空间及其 query/time 预算；不能只把任意 x 都解释为当前 n512 的 H2。
本工具没有实现这个全域判定，也没有读取或改变生产 SHAKE。

更关键的是，T(F) 的均匀分布和精确 oracle 身份不产生量子 extractor：

- H1 的 latent-key/失败与量子 chosen-identity 对应仍需独立处理。
- Sign 中 P/有限 u 的 law、固定服务、重试和强新颖性仍按各自条件付费。
- DFMS 等定理中的量子 PoK、collapsing/QCUR、witness 类型和归约损失仍需证明；
  此处不将普通 collision resistance 当成 collapsing。
- 若某定理按 oracle 查询数收损失，应先代入上述包装产生的次数；不能沿用原 q
  而省去额外 queries。完整公共 frame/seed/H1 的额外成本也不在该 3-call 项中。

因此可以把旧清单中“固定 H2 域 partial-byte/offset 的数学包装”移为已完成条件
子引理，但不能把“整个 raw-XOF QROM 游戏”或“native-strong QROM”移为已完成。

## 5. 参考代码及验证口径

`experiments/research/candidates/srgg/raw_h2_relabel.py` 是上述可逆操作在计算基态上的
纯 Python 参考；读取固定 oracle 表，无随机采样。它记录 2+1 query 计数、检查重复
prefix 一致和 scratch 复零。非法 API 输入在调用 oracle 前拒绝；量子模型内非法
元数据的零输出规则属于 §1 的可逆电路约定，不能把 Python 抛异常当作 unitary。

`tests/test_srgg_raw_h2_relabel.py` 用独立逐 bit 算法核全字节/输出寄存器基态的
共轭、位序、未使用位，以及 n2/4/8/16/512 的跨前缀、纯后缀、空读和最长读取。
它还核相同元数据的 query schedule 不依赖返回 bits。有限表不是量子攻击模拟器；
相干性结论来自 §2–3 的一般基态等式及其线性延拓。

本项无身份/消息实例、无主私钥/签名、无新 Sage Gaussian 或性能采样，取熵为零。
两份固定有限表及全部列举 case 是代数/接口验证，不代表真实研究参数的安全试验。
