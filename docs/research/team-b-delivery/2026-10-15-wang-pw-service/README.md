# Wang–PW：固定发钥、重启和故障恢复交付

这次补齐了独立 Wang–PW 发钥服务：**给同一个身份成功发过钥后，重启程序或多个进程同时请求，都会复用原来的密钥和身份盐；发钥中途出错则明确阻断，避免悄悄重抽。** 原有签名、验签和真实高斯采样继续复用。

上游基线 `a302766`；实现提交 `aa7af80`。本批是研究代码与可靠性验收，正式安全参数及整体 IB-ME 安全结论仍须另行核验。

## 这次做了什么

| 内容 | 现在的行为 |
|---|---|
| 同身份固定发钥 | 首次保存完整密钥；以后读取原密钥，不调用新的 KeyExt，也不消耗新熵 |
| 跨进程、重启 | 在同一本机目录内加锁，每次在锁内重新读取状态；两个进程同时请求只新增一次发钥 |
| 中途失败 | 先保存 pending 标记和账本，再开始采样；失败时保留阻断，磁盘允许时再保存 failed 状态 |
| 双重故障 | 补标记失败也会独立尝试保存失败账本；保留最初的异常，不用后来的存储错误覆盖它 |
| 严格恢复 | 拒绝错误身份、公钥或参数，以及重复字段、截断、追加、坏编码、超限和异常文件类型 |
| 容量 | 默认 16 个身份，上限 64；初始化前核算整个最大容量是否能装进 1 MiB 状态格式 |

实现入口是 [wang_pw_service.py](../../../../src/ibme/ibs/wang_pw_service.py)，使用约定见 [服务契约](../../../specs/wang-pw-issuer.md)。现有研究 `Backend.key_extract` 保留一次原始 KeyExt 的语义；需要固定发钥时显式使用 `FixedIssuer`。现有 registry/CLI 不会自动改接这个独立服务，已存在 HIBE 组合也不因此获得本服务的验收结论。

## 实际验证结果

| 验证 | 结果 | 能说明什么 |
|---|---|---|
| Wang–PW 全部定向测试 | **496 passed，0 failed，0 skipped** | 包含原有 410 项和新增 86 项服务测试；现有 CI 自动发现新文件 |
| 真实系统随机实验 | **3 套根、6 个用户、18 次主循环签验**，均完成 | 真实发钥、采样和签名可执行，没有按成功情况筛选根或自动重试 |
| 保存后恢复 | **6 次缓存恢复、6 次恢复密钥签名、6 次新进程恢复签名**，均通过 | 保存的是原密钥和身份盐；缓存恢复不取新熵 |
| 隔离安装 | 本地 wheel 离线装到临时目录，**2 用户、6 次主循环签验、各 2 次密钥／新进程恢复签名**通过 | 离开源码目录运行；41 个实际加载的项目模块均来自安装目录，哈希可复核 |
| 独立审查 | 发现的 **4 项问题已修复并复测** | 具体触发条件与返工见 [REVIEW](REVIEW.md)；不称为外部人工安全审计 |

同一测试可能出现在前期回归、服务专测和最终 CI 中，以上不再跨批次累加。最终完整运行见 [ci.json](ci.json)／[JUnit](ci.xml)，真实实验见 [lifecycle.json](lifecycle.json)，安装证据见 [installed.json](installed.json)。CI 收据中只把本机 Sage 可执行路径替换成了可移交的 `~` 写法；测试结果与源码指纹未改。

## 参数、尺寸与耗时

沿用现有调试参数：`n=1, q=17, m_bar=5, m=10, w=5`，签名向量维度 15；委派宽度平方 8127，签名宽度平方 25600113，密度约定为 `exp(-πx²/s²)`。系统随机实验使用 5／3 字节身份、0／5／16 字节消息，每套根最多 2 个用户。

本轮源码运行的实际规范 JSON 尺寸：

| 对象 | 实测字节数 |
|---|---:|
| 公钥 | 399—401 |
| 用户密钥 | 1123—1134 |
| 签名 | 342—350 |
| 含 2 个已发用户的整个服务私有快照 | 6590—6616 |

本机为 Intel Core Ultra 7 255HX，20 核／20 逻辑处理器；WSL2 x86_64、Sage 10.9、Python 3.13.15。未启用算法专属硬件加速，代码不是常数时间。新发钥／缓存取钥中位数约 78.57／1.11 ms，签名／验签约 15.11／0.062 ms，原始样本在 lifecycle 收据中。计时含对应检查与存储，测试时另有并行核验；这些仅是本研究配置的运行记录，**不用于同安全强度的算法排名或安全参数性能宣传**。

## 可以写进报告的结论和限制

可以写：本项目为 Wang 基本 IBS＋Pan–Wagner 转换实现了独立的本地持久发钥服务，并在明确研究参数下完成真实签验、固定身份恢复、并发和故障测试。四项审查发现均完成修复。

当前仍为 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。本轮保留公开伪造负控 **3/3 成功**；错误身份／错误消息接受分别为 **1/18、3/18**。这说明小参数不能作为安全实例；服务不能用白名单隐藏这些结果。

固定密钥服务的安全归约条件、根矩阵近均匀性、有限采样总误差与中止预算、正式参数以及完整 HIBE 组合仍单独核验。既有 [固定服务审查](../../2026-10-04-round3/Wang与PanWagner固定密钥接入审查.md)中的模型差异继续保留；不把缓存工程当作 PW 紧性或 Wang 组合安全证明。

私有快照为可信本地明文，须放在 Git、公共证据和同步共享目录之外。本轮真实磁盘测试覆盖 WSL/POSIX；未声称原生 Windows 目录持久化、恶意回滚／管理员、NFS、混合 OS 写入或硬断电安全。没有自动清除 pending 或自动修复状态的入口。

## 如何复核

在具备既有依赖的 WSL Sage 环境，仓库根目录执行：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m ci.run run wang-pw --output build/outputs/wang-recheck/ci
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.wang_pw_service_audit --attempts 3 --output build/outputs/wang-recheck/lifecycle.json
python experiments/research/wang_pw_service_delivery_check.py
```

CI 输出目录须使用新路径。安装复核先在已有 setuptools 的构建环境执行 `python -m pip wheel --no-index --no-deps --no-build-isolation . -w build/outputs/wang-wheel`，再由指定 Sage Python 运行同一 audit 模块，加 `--wheel build/outputs/wang-wheel/ibme-0.1.0-py3-none-any.whl --output <新的收据文件>`。本轮使用已有 Windows 构建运行时生成纯 Python wheel，再由 Sage 在仓库外临时安装；未改全局依赖，也未联网安装其它包。

[MANIFEST](MANIFEST.json) 列出本批代码、文档和脱敏证据的 SHA-256，不包含清单自身。公开包只保留尺寸、计数、耗时和源码指纹，不含私钥、生产种子、发钥状态、实际签名、密文或秘密派生摘要。只读交付检查同时核对最终源码、CI、真实运行及实际安装来源；它不代替重新执行密码算法，也不证明远端 Actions 已通过。
