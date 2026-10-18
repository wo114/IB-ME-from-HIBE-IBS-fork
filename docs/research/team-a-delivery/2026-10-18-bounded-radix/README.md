# A：高基数3m采样链的有界实测与本轮收尾

按用户“还剩4天，不在A大参数上耗费太久”的约束，本轮只做**高基数最小接入＋预定小规模实测**。现已完成b1024/b4096、q93位的四组真实根→父→固定256叶与独立对象恢复，**停止本轮扩维**。后续投入转向完整系统比较、演示和报告，四天安排见[执行表](../../../workplans/2026-10-18-four-day-delivery.md)。这不是放弃已保留的66组目标候选，也不是硬件不足导致的算法不可行结论。

实现提交`7032c3b3aaec107170d49d583f052c866db01450`：`feat(research): add opt-in high-radix full 3m sampling profile`；命令行修正`949bf91562489ca43e82626405a6f6c67c07a6f4`：`fix(research): bind radix probe parameters explicitly at the CLI`。全部最终实测固定949bf91，源文件指纹在逐组收据中。原二进制默认、structured HIBE v1/v2、公共registry/CLI和协议未改。

## 实测结果

四组均固定已证明素数`q=5998976077229064136548861031`（93位），根平方宽`4n+1`，系统CSPRNG、每层86 B身份、完整H块及256目标。每个新私有目录仅执行一次算法，外部上限300秒，均在上限内成功。单组重复次数1，不作稳定性能、目标困难性或罕见中止率估计。

| 配置 | 根 / s | 父委派 / s | 256叶采样 / s | 最大RSS观察 / MiB | 实际父R编码 / B |
|---|---:|---:|---:|---:|---:|
| n2 / b1024 | 0.051244 | 0.360384 | 9.148669 | 222.996 | 1746 |
| n2 / b4096 | 0.049429 | 0.316335 | 7.609108 | 222.539 | 1602 |
| n4 / b4096 | 0.083250 | 0.937919 | 16.923437 | 223.863 | 6210 |
| n8 / b4096 | 0.217927 | 4.147297 | 44.775095 | 225.191 | 24642 |

逐阶段时间、实际持久对象尺寸、耗熵及公开证书分别见[n2/b1024](evidence/n2-b1024-q93.json)、[n2/b4096](evidence/n2-b4096-q93.json)、[n4/b4096](evidence/n4-b4096-q93.json)、[n8/b4096](evidence/n8-b4096-q93.json)。父R列数随基数变化，采样宽度也同步变化；这不是同一随机私钥的压缩实测。与前批n8/q80/二进制的22分钟数据参数不同，不计算完整系统加速倍数，不用这些小n耗时外推n4096。

每组生成进程内严格恢复通过；另起新Python进程只读恢复四套已有状态，[n2/b1024](evidence/n2-b1024-q93-restored.json)、[n2/b4096](evidence/n2-b4096-q93-restored.json)、[n4](evidence/n4-b4096-q93-restored.json)、[n8](evidence/n8-b4096-q93-restored.json)均检查256个叶方程、0熵、0新根/父/原像、文件不变。新版代码还[只读恢复前批原二进制n2/q40状态](evidence/legacy-n2-q40-restored.json)，没有换钥、重写旧wire或重跑该组生成。

## 实现边界

MP12固定2011作者版Theorem4.1的b≥2公开gadget接入真实采样：`prime_gadget_kernel`与`PrimeGadgetSampler`接受显式radix_bits，完整核基行列式q与GS条件实际验证；GenTrap、SampleLeft/Algorithm3、逐列委派Algorithm4统一使用相同b。输出仍有全部维度随机扰动，父仅保存自身R，未保留根秘密引用。精确残差包围、定向权重、范数/熵/资源中止和固定叶不重采样语义沿用。

`RadixPrototypeParams`/`RadixPrototypeContext`使用独立profile/magic `IBME/MP12-RADIX-BLOCKED-3M/1`，参数快照明确包含radix_bits。相同形状、不同基数也不能混读密钥。旧二进制参数不增加序列化字段，默认base2配方仍退化为原7/10系数。公式、对象和原文位置见[原型规范](../../../specs/mp12-blocked-3m-prototype.md)及[完整参数筛选规范](../../../specs/mp12-radix-screen.md)。

这是**根/父/256叶及codec的工程原型**，没有新增完整六方法HIBEBackend、q93 KEM、Hybrid/CLI接线或高基数IB-ME加解密成功声明。现原型保留2^24项/8192维运行门，目标n4096私钥未生成，mmap/外存和对象生命周期压缩未实施。66组目标候选和9 GiB父R投影继续保留，其实际时间/RSS未知；本轮没有为赛前追跑它们而延长研究。

## 检查、已修复失败与复跑

最终A完整专项**261 passed / 0 skipped**，Windows目录检查25 passed / 0 skipped；原始JUnit/指纹/命令见[测试清单](evidence/tests.json)和[完整A收据](evidence/strict-a.json)。新增测试覆盖高基数真实GPV、完整父委派与256叶、独立密钥/零熵恢复、严格版本/身份/基数拒绝、公开精确协方差逆对照、二进制旧快照和CLI参数转接。测试复用既有有限Gaussian/GPV统计与分布工具，不以功能成功替代分布或安全结论。

首次CLI调用在参数构造阶段出现TypeError：继承的dataclass字段排序使位置参数冲突。[失败记录](evidence/initial-cli-failure.json)保留源码版本和阶段，当时私有目录尚未创建、未消费私有熵、算法尝试次数0。已将radix_bits设为keyword-only并显式传参，补CLI回归；修正后才开始上述四组系统随机算法运行，没有采样失败后重抽。开发期260项旧专项与最终261项分别保存，不相加计数。

在仓库根和指定WSL环境，使用新目录复跑单组：

```sh
PYTHONPATH=src:. OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=1 \
timeout --signal=TERM --kill-after=10s 300s ~/miniconda3/envs/sage/bin/python \
 -m experiments.research.blocked_3m_probe --private-directory test-results/radix-new-n8 \
 --n 8 --q 5998976077229064136548861031 --root-r-squared 33 --radix-bits 12 \
 --source-commit 949bf91562489ca43e82626405a6f6c67c07a6f4
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.blocked_3m_probe \
 --private-directory test-results/radix-new-n8 --restore-only
PYTHONPATH=src:. PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=1 \
~/miniconda3/envs/sage/bin/python ci/run.py run a-structured-hg --output test-results/radix-final-tests
```

超时终止该次进程、保留pending和部分状态，不自动重发；四组均未超时。单组上限不代表每阶段允许额外300秒。公开摘要/源指纹核验：Windows `python docs/research/team-a-delivery/2026-10-18-bounded-radix/evidence/summarize.py`，读取公开收据与Git blob，不打开私有状态；[结果](evidence/summary.json)与[文件/提交清单](evidence/changed-files.json)随本分支提交。

环境为Core Ultra9 275HX、WSL2 Linux6.18.33.2、Sage10.9/Python3.13.14、OMP4/OPENBLAS1。每组独立Python进程，OS缓存保留；采样实测未与完整A回归或其它密码运算同时运行。10 ms进程树RSS是可能漏短峰的观察，内核累计高水位另列；它不等于高维目标需要的物理内存。原先同日机器总量快照见[环境参考](evidence/environment-reference.json)，每组运行时环境在各自收据中。

保留ROM、论文算法安全/身份匿名的用户工作前提；有限配置epsilon/tail/abort192、mass320、precision384、uniform256、扰动512，H/G residue帽仍为128。未把分析中192帽/2^20查询的累计账本直接移到本实跑。n2/4/8均是小规模研究参数，q93不是93位安全等级；全部`security_claim=none,backend_admitted=false,parameters_are_formal=false`。安全/匿名理论继续引用既有原文，不新增证明任务。

本批跨边界仅给现有A套件登记测试、维护当前状态和四天安排，并复用公共runner补[第三组完整系统基线](../../2026-10-18-full-system-luo/README.md)；没有修改B/C原语或公共协议。三条暂缓路线保持暂缓。下一批优先级已转T5/T6/T8/T10，本轮不再继续扩维或扫描参数。
