# C2：认证转换 ML-DSA 独立 IBS

实现提交 `a2ffb8cb6e89dfb7bf2a4c89d2d80c354b63db0b`，基线 `c67dc65864dcafe4c2bb4767502dac32c5442bde`，[PR24](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/24)。本批完成五方法、机构证书/用户公钥/消息签名、固定身份状态、四类对象与参数恢复及可选BackendSpec。按C2先ML-DSA后Falcon；LATTE匿名条件未闭合不阻塞此独立工作。三个参数集计同一条算法路线。

## 实际结果

| 执行 | 结果与范围 |
|---|---|
| NIST公开样本 | 210/210：75 keyGen、90 pure external sigGen（确定/随机各45）、45 sigVer，含拒绝样本 |
| WSL IBS专项 | 245 passed / 0 skipped；**包含上述210例**，另验三参数五方法、替换/重放/随机伪造、严格编码/私钥方程、容量/熵、锁/pending、原生IPC/nonce中止 |
| Windows同一专项 | 13 passed / 232 skipped；公开参数/元数据可运行，缺Linux native的232项不计成功 |
| Windows共同框架 | 427 passed / 5 skipped，口径partial；5项缺Sage/真实缓存，不累加成独立总用例 |
| 系统随机实物 | 三参数各1份：同根2个64 B身份、32 B消息、32次新签名；匹配、错配、真实组件替换及参数重放全部符合预期 |
| 新进程恢复 | 每份32次验签，0熵、0keygen、0新签名；同一主状态与已发SK，快照字节一致 |
| 仓库外wheel安装 | 32个实际provider均来自安装site；从随包源码重编译3引擎，恢复上述原实物完成96次零熵验签，再用恢复SK各签1份新消息；主快照不变 |

[公开证据](evidence)含原始XML和JSON。48个运行/辅助/CI文件与实现提交Git blob逐字一致，见[source-check](evidence/source-check.json)。WSL本地CI收据的revision为unavailable，Windows框架收据在提交前产生且标dirty；内容版本由上述Git blob检查另行确认。实物私钥、原生二进制、wheel仍留在忽略目录或本机cache，未提交。

## 参数、尺寸与来源

普通签名固定官方提交 `d35ba3fe5449bee3e6d43e1f296c3ca818bd36be`，NIST数据固定 `975de31eb83d87039ec88934fdc47d8c312b892d`。26份vendor原文件/CC0许可逐字保留；公开fixture中的秘密是**官方公布的TEST私钥**，不是项目实物。完整[算法/证明对应](algorithm-map.md)及[独立契约](../../../specs/certified-ibs.md)。

`identity_bytes=64`、`message_max_bytes=65536`、`max_identities=16`、`timeout_seconds=30`。每参数实物重复1次，32份签名均用系统CSPRNG的新32 B随机量；每份总熵1184 B（机构32＋两次发钥各64＋32次签名各32）。

| 配置 | 普通PK / 普通签名 B | 完整IBS签名 B | 实物总时 s |
|---|---|---|---|
| ML-DSA-44 | 1312 / 2420 | 6237 | 6.527 |
| ML-DSA-65 | 1952 / 3309 | 8655 | 6.718 |
| ML-DSA-87 | 2592 / 4627 | 11931 | 7.300 |

完整IBS包含证书、用户公钥、消息签名和全部编码。总时含Python编码、C子进程、文件写入、验证/负例和新进程恢复；三份并行且同机编译，只有1次重复，**不是公平横向基准**。阶段/RSS/私有状态尺寸见lifecycle收据。

环境：WSL2 Linux 6.18.33.2、Intel Core Ultra 9 275HX、规定的 `~/miniconda3/envs/sage` Python 3.13.14、GCC13.3.0；Windows公开测试为Python3.14。基础ML-DSA是FIPS204标准参数，不是教学小参数；完整认证IBS继续 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。底层SHAKE/RO、经典BNN条件和完整QROM/查询损失/强不可伪造分列，功能测试与公开向量不替代证明或NIST认证。

## 复验与文件

本次实际入口在WSL仓库目录执行：

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m ibme.ibs.certified.native.build
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python ci/run.py run cert-ml-dsa --output test-results/cert-mldsa/primitive-final
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.certified_ibs_probe --private-directory test-results/cert-mldsa/real-44-a2ffb8c --algorithm ml-dsa-44 --source-commit a2ffb8cb6e89dfb7bf2a4c89d2d80c354b63db0b
```

输出目录存在时禁止复用；重做选择新的忽略目录。65/87同样执行。已有实物在同一probe加 `--restore-only`，不重新keygen。安装验证从 `/tmp` 启动，仅设置隔离site及由该site编译的native目录，逐个断言provider不来自仓库。

完整[文件列表](files-changed.txt)：主要为 `src/ibme/ibs/certified/`、三个测试、NIST TEST fixture、probe与规格/交付。跨边界的包配置保证随包源码，CI配置保证新增单体实际执行，状态/目录/任务由本次统筹同步；没有修改HIBE、Core或旧协议语义。

开发失败保留说明：首次桥接链接重复展开namespace，修自己的桥后通过；首次安装校验脚本位于仓库忽略目录，入口自动进入sys.path触发隔离断言，移到仓库外后通过。没有改vendor解决它们，不把失败试跑计作成功重复。

未完成：Falcon；BNN原始具体归约、固定状态/腐化、完整QROM/定量损失和强不可伪造映射；默认登记/CLI、真实HIBE组合和统一比较。跨旧快照/多写者/回滚及文件外部认证属持久层，Python/C未完成生产侧信道和秘密擦除审计。下一批复用此核心补Falcon，统筹再逐项接入已就绪且适配的HIBE。
