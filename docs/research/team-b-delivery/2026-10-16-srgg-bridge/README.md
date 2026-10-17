# SRGG 结构化真实执行与分布桥：本批交付

2026-10-16。本批已完成一次 **n512/d2/w8 的真实建根、发钥、内存快照恢复、恢复后签名及验签**，并将最终整数采样、gadget、卷积、HNF、范数门和查询预算串成同一份证书。它为现有独立原语补了可运行的大维研究路线。六项目标仍有安全归约、困难性估计和新路线公共服务接入未完成，整体保持 WIP。

当前采用有证据支持的工程路线：保持原语关系式、使用不筛根的公开 CBD1 支持谱界、以精确环平方根级数实现 joint SampleF。FFT 路线尚无公平性能对照，本批不声称全局最优或新安全定理。路线比较见 [route-comparison.md](route-comparison.md)。

## 六项任务现在到哪一步

| 任务 | 本批实际完成 | 尚未完成 |
|---|---|---|
| ζ、Gaussian、q/Q、native strong | 核对 ζζ*=2、密度 shape 与 factor2；保留真正的 2Q 恢复；给出原文定理逐项义务表及负控 | 原文 Theorem1/2 到实际分布、普通/strong 自适应游戏和 QROM 的适用性／新归约 |
| HNF 后发钥分布 | 全局混合域条件 law 的一般恒等式，包含 aliases；公开 kernel smoothing、像近均匀和条件熵 | 混合域、短域到源 SIG/PSF 的 one-wayness／碰撞困难对应 |
| 最终整数 TV | 真实 joint SampleF＋wide 标量＋gadget recurrence，精确谱界、数值/尾界、batch cap 和卷积桥 | 不同 target 形状、不同 sampler 或平台需重核；不把参考分布 TV 当攻击优势 |
| 固定服务与失败总账 | 现有小维持久服务继续保留；新路线逐历史范数/重试/查询账本；单次大维 audit 的全路径 cap 包络 | 新路线未接公共五方法、对象、固定持久服务；基础设施故障模型未知 |
| 独立正式候选 | n512/d2/w8 固定算术点；比较三种数值配置并选 deep；最终参考 TV／条件算法 abort 的查询界 | 困难性估计未执行、原文归约未闭合，不能称正式参数或授 NIST 等级 |
| 可行规模真实实验 | 一次系统熵 n512 完整四算法、真实 gadget 8192 digits、内存恢复、诚实验签和定向负控、资源收据 | 公共持久服务的大维生命周期、公平基准和正式安全验收 |

“接口和正式参数已授权”不等于可以跳过这些前提。本批独立执行 namespace 与原公共 backend 之间的边界是显式的；选定 HIBE 不影响本批数学与算法执行。旧 n8 的公开伪造仍保留在 [上一批 qualification](../2026-10-16-srgg-qualification/README.md)，没有用新范数门或白名单掩盖。

## 可复核的核心结果

- 指定 WSL Sage 10.9 / Python 3.13.15：**642 passed、0 failed/errors/skipped**。Windows Python 3.14.7 定向纯 Python 检查：**125 passed、0 failed/errors/skipped**。精确命令与 JUnit 统计见 [validation.json](validation.json)。
- 真实实验：1根、1个37B身份、1条32B消息、1次发钥、1次签名。无重选根或密钥；签名首个尝试通过。主私钥和用户密钥各做一次内存快照恢复；恢复后签名通过，错身份、错消息、随机小响应/挑战负控被拒绝。没有实际磁盘／并发服务恢复验收。
- n512 完整算法实测 **30.42秒**；外层进程31.97秒，峰值RSS236420KiB（约230.88MiB），实际取熵15099738B。单次、未固定频率/负载，不是公平性能排名。硬件 Intel Core Ultra 7 255HX、WSL2可见20逻辑CPU。公开研究编码公钥282400B、签名134915B，不与正式安全方案直接比较。
- `qE=qS=2^40,L=16` 的条件式账本：deep 配置的最终公开参考分布 TV 与条件算法 abort 充分界均约 **2^-134.3759**；default约2^-69.98，未通过2^-128算术门。查询数是数学输入，没有实际部署2^40用户服务。见 [integrated-bridge.md](integrated-bridge.md)。
- 包含全部 head aliases 的理想条件 min-entropy 下界144383位；加实际 TV 和成功条件化后，deep 配置已发密钥的保守下界177位。它不是 commitment entropy、one-wayness 或安全等级。
- 原始单次audit曾保守标记全局cap未给概率；后续 [全路径包络](structured-execution-entropy-envelope.json) 固定同一收据和源码哈希，证明最多16次尝试总量204812155B小于268435456B，所以该单次audit无额外全局cap中止。原收据未被改写。

参数固定为 `n=512,d=2,p=16383,b=31,w=8,r²=64,Q=13972913866395903`；全部 shape、范数门及数值选项见 [structured-execution-n512-d2w8.json](structured-execution-n512-d2w8.json)。ROM 风格 H1/H2 使用规范长度前缀、域分隔和 SHAKE256；没有建立 QROM 归约。参数是研究／工程算术点，非正式安全参数。始终保持：

```text
security_claim=none
backend_admitted=false
parameters_are_formal=false
nist_security_category=null
```

## 需要继续研究的实质问题

原文 Theorem1 写 EUF，Theorem2 使用 strong 前提却用新消息赢法；其模拟器会中止目标身份的签名请求，没有覆盖完整的自适应 IBS 游戏。当前 Hbar 不直接绑定身份，多个分区身份映到同一底层公钥时，还需处理跨身份的新鲜性。混合 key-generation 的 SIG/HVZK、UF-NMA/CUR、实际矩阵分布与困难假设也须对应。单纯增大 n、再跑攻击或加一层编译器不能修复这些义务。

来源页码、已证明与未证明的边界见 [theorem-obligations.md](theorem-obligations.md)。用户已明确选择下一阶段继续专攻 SRGG 安全归约、保留原生 strong 目标。本批未安装估计器、没有执行正式困难性估计。Kyber/ML-KEM 与 NIST 是用户设定的长期对标目标，不能把 KEM 的等级直接授予 IBS。功能测试、分布证明、困难性估计和安全归约分别验收。

## 文件、原始证据和复现

修改文件全表见 [MANIFEST.json](MANIFEST.json)；清单同时列出未改的运行依赖。主要入口如下：

| 内容 | 入口 |
|---|---|
| 完整独立四算法及真实执行 | `experiments/research/candidates/srgg/structured_execution.py`、[说明](structured-execution.md)、[独立审查](execution-independent-review.md) |
| joint sampler 与严格数值证书 | `structured_samplef.py`、[一般推导/审查](structured-samplef-review.md)、[公开夹具](structured-samplef-acceptance.md) |
| 实际类计划到最终账本 | `integrated_bridge.py`、[说明](integrated-bridge.md)、[精确分数](integrated-bridge.json) |
| HNF 全局参考与熵 | [mixed-domain.md](mixed-domain.md)、[theorem-obligations.md](theorem-obligations.md) |
| 归一化、卷积、谱界与固定预算 | [fiber-normalizers.md](fiber-normalizers.md)、[convolution.md](convolution.md)、[spectral-bounds.md](spectral-bounds.md)、[aggregate-budget.md](aggregate-budget.md)、[oracle-ledger.md](oracle-ledger.md) |

部分组件文档写于完整执行之前，其“尚未完整运行”是该组件阶段的快照；本 README、真实 n512 收据和 integrated 账本给出本批最终状态。旧 qualification 包、早期宽度配置和原始运行收据不覆盖。

原始输出留在同工作树 `build/outputs/srgg-bridge-2026-10-16/`。公开 JUnit 删除hostname并统一LF；time收据把本机Sage路径统一为 `~/miniconda3/envs/sage`，不改变计时/RSS。三个早期 Windows 生成的JSON（fiber-normalizers、mixed-domain、spectral-bounds）只统一LF，其余JSON逐字节复制；validation记录全部转换。源 hash 核对包含执行器和已加载项目依赖。早期 n512 master夹具只有事后源hash记录，不能当作事前冻结证据；完整 n512执行的8项源码hash已逐项核验。

便宜的只读校验（仓库根目录）：

```text
python experiments/research/srgg_bridge_delivery_check.py
python -O experiments/research/srgg_bridge_delivery_check.py
```

必要时重跑，给输出新目录以保留冻结证据：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_*.py tests/test_primitive_spec_audit.py --junitxml=build/outputs/srgg-bridge-recheck/sage.junit.xml
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.integrated_bridge --output build/outputs/srgg-bridge-recheck/integrated-bridge.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.structured_execution --degree 512 --rank 2 --digits 8 --profile query-bounded-deep --output build/outputs/srgg-bridge-recheck/lifecycle.json
```

本批只提交独立分支，更新现有PR37；不选择HIBE、不改共享组合、不合并上游、不接管其它B任务。原始教学参数的攻击负控和已知风险继续保留。测试成功不能替代密码学安全证明。
