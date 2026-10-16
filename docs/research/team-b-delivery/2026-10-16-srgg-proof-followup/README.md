# SRGG：证明补充与预算的本地可审查证据包

2026-10-16。本包封存 conditional raw-XOF、商挑战、量子定理义务、lossy 条件推导、经典 Run/fork 原型和固定服务预算。它是**本地可审查成果**，不表示所有 HIBE 无关目标已经完成；目标继续 active，当前不提交远端或推送。旧 classical/reduction/bridge 的证书和 MANIFEST 均保持原样。

`security_claim=none, backend_admitted=false, parameters_are_formal=false, nist_security_category=null`。没有因局部统计项小、功能测试通过或保留无解点而提高这些标志。研究安全目标按用户决定对照 Kyber/ML-KEM 与 NIST 标准化口径，但当前未授予任何安全等级。

## 1. 六项目标的实际状态

| 目标 | 已交付的局部结果 | 完整目标仍缺的部分 |
|---|---|---|
| 连续/有限 SampleF | 全路径有限采样、局部 TV/aggregate-cap 证书、连续调用条件账本；不把库/硬件故障概率写成零 | 含所有 oracle、先前状态和故障的整场游戏对应；不能把局部 TV 和未定项直接相加后宣称安全 |
| HNF 后 raw/final 完整密钥 law | latent/common-gate 的条件分布对应、公开 HNF 修复和 final 门额外失败为零的确定界 | 真实持久服务到理想 IBS 游戏的完整 Delta0，含历史发钥和异常状态 |
| ζ 因子与 quotient | ζ 像格/对偶尺度、规范化同 coset law、接受域 strong 双射、完整输出 oracle 重标记、有限 u 费用 | partial-byte/offset 相干包装、整体 finite-P/发钥替换和 QROM 游戏；非零短核不等于原 key witness |
| 原生强 IBS 的 classical ROM/QROM 对应 | 条件经典文稿、可执行条件 kernel、显式公钥下的真实 root-free Run/两次 fork 与短核验算，以及有限代数/量子定理前提核查 | 完整 Run/E 成功概率合成、seeded 公钥/全部 raw-frame/多公钥身份游戏、QROM 提取或完整 LOSS/损失；不以 fresh-message 替代 native strong |
| 正式参数与困难性 | 旧点的低成本负面筛查、新候选的有限算术和启发式比较；lossy 路线必要条件及保守充分界 | 全部环/复合 Q/CBD1 攻击、正式论文条件、采样/查询总误差、新大规模执行和资源；旧点不支持标准对标目标 |
| 独立公共五方法/严格对象/持久服务 | 实际工程已交付，固定发钥、恢复、异常阻断、并发/故障和真实服务验收另有封存 | 工程证据不闭合上述安全游戏；HIBE 配对、共享 CLI 和统一比较由统筹负责 |

上述“局部结果”保留各文稿中的全部条件。尚未闭合项不是另选一个 HIBE 就会消失的接口问题；同时不阻断已经独立完成的原语和工程材料。

## 2. 材料、来源和准确边界

| 材料 | 作用及限制 |
|---|---|
| [conditional-xof.md](conditional-xof.md)、[conditional-xof.json](conditional-xof.json) | 实现含原始拒绝失败的 G_h，保留完整轨迹、prefix/offset 缓存和同源 suffix；不是成功条件 K_h，不是可编程 SHAKE/QRO。n512 报告零熵，不运行大维轨迹 |
| [quotient-challenge.md](quotient-challenge.md)、[quotient-challenge.json](quotient-challenge.json) | 828 个 exact coset 指数检查、8 个非空固定 oracle 接受域夹具、有限 u 成本；不把代数夹具当真实 IBS 攻击试验 |
| [quantum-oracle-obligations.md](quantum-oracle-obligations.md) | 明确 GHHM/DFMS/Zhandry 的一手读取范围和待匹配前提；§6 已更新已完成的商引理，不重复把它们列为未实现 |
| [lossy-route.md](lossy-route.md)、[lossy-checks.json](lossy-checks.json) | 条件统计充分引理、Δt≠Δχ 反例、108 个小矩阵秩核查和六点零熵公式对照。现有点不满足界；w160/270-bit Q 是高成本公式对照，不是执行或参数推荐 |
| [lossy-arithmetic-original.py](lossy-arithmetic-original.py) | 原始核查脚本的逐字节公开副本；在指定 Sage 正常模式运行，使用显式数学断言。复制到 build 后复现，避免写入本证据目录 |
| [classical-runner.md](classical-runner.md)、[classical-runner.json](classical-runner.json) | 不输入 root/目标 key 的显式 proof-public 实验，实际 U/E、known/target Sign、owner/index 回放和两次 fork。n512 报告零熵，未执行对手；全局 bank-cap 失败概率仍为 null，不是完整 reduction |
| [service-budget.md](service-budget.md)、[service-budget.json](service-budget.json) | 绑定已冻结 audit driver 和真实研究参数；分别保留局部 cap、父子包装 cap、有限/理想/非数值未定项，不把所有错误概率置零 |

原始 conditional/quotient/quantum/lossy 文稿的规范位置在 [classical-rom 目录](../2026-10-16-srgg-classical-rom/)，预算规范位置在 [structured-service 目录](../2026-10-16-srgg-structured-service/)。本包文稿为逐字节封存副本，保留原文的相对链接上下文；例如 conditional 的 `seeded-xof.md`、`direct-ibs.md` 请从规范原位置打开。数学推导、论文原文、运行观察、参数估计和未完成条件均不混同。

lossy 原文末尾所说“ignored 原始材料不默认随 Git 传输”描述原来目录；**本 followup 现在包含脚本/JSON 的公开副本**，复现不再依赖原机器的 ignored 文件。

所有 JSON 按原始字节复制；原路径和 SHA-256 记在 validation。目录内窄范围 `.gitattributes` 保留 quotient JSON 的原 CRLF 字节；历史失败 XML 的行尾间隔和原始 stdout 末尾空行也保持，仅这两份归档证据不作 whitespace 诊断。实现源码仍按仓库正常规则检查。公开 JUnit 只移除 `hostname` 属性，再以 UTF-8/LF 序列化；测试名、结果、计数和耗时不改。原始收据仍保留在 ignored build，未覆盖它们。目录和公开命令使用仓库相对路径，无私人机器名或用户目录。

## 3. 已运行的验证

指定环境为 WSL Ubuntu-24.04、Sage 10.9/Python 3.13.15；另保留 Windows Python 3.14.7 的定向收据。所有收据计数以 [validation.json](validation.json) 为准，重叠套件不相加为不同测试或独立试验。

| 收据 | 结果 | 范围 |
|---|---:|---|
| conditional-sage.junit.xml | 61 passed | 40 个新 conditional 检查＋21 个冻结 seeded 回归 |
| quotient-sage.junit.xml | 34 passed | exact 环/coset、strong 双射和真实小维 finite-u 平移/失败 |
| budget-sage.junit.xml / budget-windows.junit.xml | 两端各 45 passed | 相同一套预算、source/input、cap 和未定项检查 |
| checker-windows.junit.xml | 40 passed | 完整性和负控；含正常/`-O` 子进程对哈希/source/input/JUnit/安全旗的显式拒绝 |
| sage-components.junit.xml | 159 passed | 40 conditional＋34 quotient＋45 budget＋40 checker，含前述重叠检查 |
| runner-sage.junit.xml | 42 passed | n8 实际有限采样、target/known 签名、owner/index、两次 fork/短核及故障；含一次 SecureRandom support 样例 |
| sage-full-final.junit.xml | **1096 passed** | 源码冻结后的一次全部 `tests/test_srgg*.py` 回归；0 errors/failures/skipped，原始 stdout 102.17 s、JUnit suite 102.126 s |

[最终 stdout](sage-full-final.stdout.txt) 按原始字节保留。最终全量环境为 Ubuntu 24.04.4 LTS / WSL2、Sage 10.9/Python 3.13.15；全量期间及之后没有更改源码，只补充公开收据、validation、README 和 MANIFEST。同套件多次运行、组件收据与全量收据均有重叠，不能把各行计数相加为独立测试或重复随机实验。

保留 [runner-development-failure.junit.xml](runner-development-failure.junit.xml)：初轮 40 tests，39 passed/1 failed，原错误为 `uniform rejection exact-certificate bit budget exceeded`。修复把 Run 外的 external-uniform-target helper 明确限为 128 次，使 `54*128<=8192` 既有 exact-certificate guard，仍保留拒绝失败，不修改冻结 sampler。中间 [runner-development-second.junit.xml](runner-development-second.junit.xml) 为 42 passed；最后只把生命周期消息改成真实 32 B，再得最终 42 passed。初轮没有保存可重产故障的源码快照，因此只将该收据作为开发历史，**不列入 required-pass 验收，不声称它对应最终源码**。封存制作阶段已显式核对其 XML 计数与确切错误消息，完整性检查器绑定其 SHA；它不重新解释这一已知失败的成功状态。

没有为本包重跑 n512 密钥/签名服务，也没有增加生产算法或参数。已有真实服务收据属于其独立批次。conditional 有一次 q129/四目标的 OS 随机小样例，quotient 有 n4/16 个挑战的显式测试随机流，runner 有 n8/d1/w3 的真实有限抽样和一次 SecureRandom support 样例（主流程身份 5 B/3 B、消息各 32 B）；本包大型证书、lossy 公式/矩阵检查均零熵，不是统计抽样性能或密码学攻击成本。runner 提取使用存在公开短核的代数夹具，不冒充困难实例攻击；身份/消息绑定的服务验收不由这些夹具替代。

## 4. 复现及只读封存检查

从仓库根目录，在已有指定 Sage 环境运行；无需安装依赖：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q \
  tests/test_srgg_conditional_xof.py tests/test_srgg_quotient_challenge.py \
  tests/test_srgg_service_budget.py tests/test_srgg_proof_followup_delivery_check.py \
  --junitxml=build/outputs/srgg-proof-followup-reproduction/components.junit.xml

PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg*.py \
  --junitxml=build/outputs/srgg-proof-followup-reproduction/full.junit.xml

mkdir -p build/outputs/srgg-proof-followup-reproduction
cp docs/research/team-b-delivery/2026-10-16-srgg-proof-followup/lossy-arithmetic-original.py \
  build/outputs/srgg-proof-followup-reproduction/check-lossy-arithmetic.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python \
  build/outputs/srgg-proof-followup-reproduction/check-lossy-arithmetic.py
```

新的报告路径应放在 build；conditional 工具要求 output 原先不存在。quotient 和预算证书的完整生成命令见各源文稿。不要用重产报告覆盖本目录冻结副本。

```text
python experiments/research/srgg_proof_followup_delivery_check.py
python -O experiments/research/srgg_proof_followup_delivery_check.py
```

检查器以受 Git 审查的 MANIFEST 为信任锚，显式检查文件大小/SHA、冻结基底、报告 schema/source/input、全部四个安全标志、JUnit totals/真实 testcase/失败元素及公开 hostname 清理。所有检查使用异常，不依赖 assert，因此 `-O` 仍生效。它是完整性和记录一致性检查，**不重新运行测试，不是数字签名，不独立验证数学证明、安全归约或原始运行真实性**。

## 5. 发布边界

用户要求全部独立工作完成后才推送。本轮保留可审查的本地进展；完整 native-strong ROM/QROM、正式结构化参数与新大规模执行仍未完成，不能通过缩小目标结单或提前推送。公共五方法/持久服务的完成与这些研究阻塞分开报告，HIBE 未选定不暂停独立核查。
