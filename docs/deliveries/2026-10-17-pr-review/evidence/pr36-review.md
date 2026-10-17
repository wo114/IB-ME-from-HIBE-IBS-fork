固定 head `bf3bc1c67d0a7025378abe90c118493c3b4e28eb` 完成本轮合并前复核，未发现阻止本研究版本合并的问题。

- 逐项核对显式 v2 参数版本、独立 magic、完整参数和 oracle context 绑定；默认 v1 registry/CLI、七字段参数字节与旧概率账本保持。跨版本拒绝与失败地址保留有对应回归。
- 核对 epsilon192 和有限 Gaussian 选项确实传入实际根、父委派和完整叶 SampleD；噪声使用新配方。共享 RO/KEM 的 128 次拒绝帽与实际同组 q 进入概率账本，最终概率向外舍入，未提升现有资源门。
- 本轮复算文件散列：14 份实现变更、15 份严格专项源码指纹、134 份安装运行 provider 与冻结源码相符；9 份公开收据散列一致，27 份变更文件清单准确，不含私钥或运行状态。
- 复核既有固定源码验证：Sage 186 passed / 0 skipped、Windows 70 passed / 0 skipped；系统随机同根 2×2、4 匹配与 12 错配、新进程原树恢复、Luo-C64B compact 完整 34 项及隔离安装恢复通过。开发期路径失败及修复收据如实保留；不累加交叠计数。
- GitHub push 与 pull_request 两次 Catalog CI 均针对上述同一 head，全部结束，共 46 个 SUCCESS、0 失败/等待。另 2 个 SKIPPED 是既有 workflow_dispatch 且 strict_security=true 才运行的手动任务；本 PR 未改变该条件。`git diff --check origin/main...HEAD` 通过。

合并范围是 n=2、q=1099511627689 的可执行研究配方。条件模型中概率上界为 (2^-132,2^-131]，不是 LWE 安全位数；全部私有输入的精确算术/工作区失败界仍未知。保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`，功能与本次源码复核不替代独立密码学安全审查或安全证明。

A 后续仍需正式高维完整运行域、计算根与匿名/固定服务模型映射、等安全目标的完整 IBME 评测及消融；GKR、ABB 标准模型、CHKP 标准模型按用户要求继续暂缓。
