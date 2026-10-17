# PR34、PR36、PR37：固定版本审查与合入

2026-10-17。本轮审查全部当时未合并PR；三项均已合入远端main，最后合入源码为`cf6bd943a3aa8e27d7d4a0cb642725fa1d83a211`。当前排序和未完成项统一见[PROJECT_STATUS](../../PROJECT_STATUS.md)，不由冻结交付记录另发下一轮任务。

| PR | 固定head | 合入提交 | 结论 |
|---|---|---|---|
| [36：A finite192](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/36) | `bf3bc1c67d0a7025378abe90c118493c3b4e28eb` | `1976c0b23bbdcb959c338738f437ddc313b17fbe` | 参数版本与实际采样选项贯通，旧v1/默认入口保持；仅研究准入 |
| [34：Sageloli SIS/RSIS](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/34) | `a81773564253660d4ef16ebebee350d2d057f394` | `ca6d64ff45a8a5be57b06fa27b438d2afda09736` | 旧两项P1修复后重新批准；独立后端/服务接收，组合待接 |
| [37：SRGG累计交付](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/37) | `7353770c9563eb20abb15e27abde32f0e3e1eca3` | `cf6bd943a3aa8e27d7d4a0cb642725fa1d83a211` | 原默认、显式structured、独立paper及持久服务分别接收；完整diff为323文件，PR标题/说明已同步实际范围 |

## 复核内容

PR36逐项核对参数magic/descriptor/oracle绑定、根/父/叶实际epsilon192和Gaussian选项、噪声及共享RO/KEM真实拒绝帽。14份实现变更、15份严格专项源码、134份原安装provider和9份公共收据在审查时与该固定版本相符。已有Sage186项、Windows70项、系统随机2×2、12错配、新进程恢复、Luo-C64B完整34项及安装收据被复核，本轮没有重发该树或把历史测试计作新执行。PR36之后合入B代码会改变部分公共模块；不将原安装收据说成最终合集的新安装测试。

PR34已采用全维扰动p、残差u−Ap、完整三进制Gaussian及p+Jx，矩阵抽完整列、环抽系数向量再作旋转。原始整数陷门PSD在取熵前检查；Setup与H1/H2用有界无偏拒绝取模，SHAKE游标前移。v2拒绝旧v1和跨路线对象，保留失败状态、固定发钥、独立进程/并发、pin与损坏状态测试。原文、采样解释、根负号及固定服务的差异见其独立SOURCE_MAP；此次未重做基础归约。

PR37实际包含62份实现/支撑文件、48份测试和配套材料。重点核对公共注册器仍使用原默认研究profile，structured/paper各自参数和对象独立，三类服务的容量预检、pending/failed、锁/同步/原子保存、恢复及上下文绑定。原文三个published profiles保留n512/p16383/b31/w2/Q15744063、两种Gaussian解释、原gamma和factor-one；旧w8研究优化未被覆盖。13份清单的287个条目在固定head7353770上匹配，另13份paper源码/测试指纹与实现冻结点一致。条件证明组件按各自声明范围复核，不认定为已完成的ROM/QROM安全证明。

PR37范围`git diff --check`只报告两个新文件的末尾多余空行（registration.py与test_srgg_registration.py），不影响执行；保留冻结源码/清单字节，未改写旧证据。没有其它空白发现。最终本轮文档增量单独通过工作树diff检查。

## 本轮新执行与远端检查

| 判据 | 实际结果 | 公开收据 |
|---|---|---|
| PR34五个相关Sage文件 | 145 passed / 0 failed / 0 skipped，174.86 s | [JUnit](evidence/pr34.xml) |
| PR37完整srgg2025专项（全部glob文件） | 1431 passed / 0 failed / 0 skipped，238.85 s | [清单](evidence/pr37-srgg.json)、[JUnit](evidence/pr37-srgg.xml) |
| 三PR合入后装配/参数/CLI | 142 passed / 0 failed / 0 skipped，17.55 s | [JUnit](evidence/merged-framework.xml) |
| 远端PR36 | 46 SUCCESS、2预期手动strict-security SKIPPED；push/PR两次均同一head | 固定head的GitHub检查与[audit](audit.json) |
| 远端PR34、PR37 | 各23 SUCCESS、1预期手动strict-security SKIPPED；无失败/待执行 | 固定head的GitHub检查与[audit](audit.json) |

这些本地用例和历史收据部分交叠，不相加为全项目唯一测试数；PR37paper子批221项包含在本轮完整1431项中。测试环境为规定WSL `~/miniconda3/envs/sage`，Sage10.9，Python3.13.14，Linux6.18.33.2，Intel Core Ultra9 275HX，OMP4/OpenBLAS1。单次回归运行，不作性能比较。

准确命令、变更文件列表、源/收据摘要及合入版本见[audit.json](audit.json)。[PR36审查](evidence/pr36-review.md)、[PR34复审](evidence/pr34-review.md)、[PR37审查](evidence/pr37-review.md)同步保留公开正文；远端审查记录在各PR中。

## 参数与结论边界

A配置仍为n2/q1099511627689、86 B内层身份/32 B seed；条件账本上界(2^-132,2^-131]不表示LWE安全位数。Sageloli仍为SIS n2/k4/m16/q81及RSIS d4/k9/l22/q19683教学参数、256 B身份/4096 B消息上限和32 B盐，有限总TV与固定服务映射未准入。SRGG默认n8研究、structured显式n8/n512和paper n512三档分别记账，真实paper收据用5 B身份/32 B消息；具体Gaussian、raw/centered与finite界范围不混用。

SRGG的同消息Q-shift替换、factor-one/ζζ*=2、r归一化、某些finite界为1以及HNF/固定服务/ROM/QROM缺口均保留。原生strong未准入；这不等于已展示新消息伪造。Sageloli已有教学公开伪造，A n2也不安全。所有路线保持`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`，测试不是安全证明。

未替新structured/paper或Sageloli补做HIBE配对、正式参数、全队公平基准、界面或竞赛成稿。GKR、ABB标准模型、CHKP标准模型保持暂缓。本轮只审查仓库和本地教学测试，不对外部系统做安全测试；公开目录不含私钥、运行状态、随机带或签名样本。
