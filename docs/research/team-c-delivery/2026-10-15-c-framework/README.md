# C1/C2：LATTE 与认证 IBS 接入统一框架

本批由统筹接收 C 的独立原语，默认登记 `latte`（同一 LATTE-3/COSAC-FIX 实现）、
`cert-ml-dsa`、`cert-falcon`，复用公共 SuiteConfig、Hybrid、BYTEAUTH、CLI 和状态事务。
没有另写组合密码协议，也没有新增算法计数或改变已有原语数学/私有分布。

三个实质接入修正：LATTE 参数钩子按共同接口接收 transport 字符串；共同版本标识
`latte3-cosac-fix-v1` 满足 Hybrid 的小写短标识约束（原语wire仍为
`IBME/LATTE3/COSAC-FIX/1`）；预检现在调用同一个 HybridLimits 验证器，提前拒绝无效元数据。
LATTE 公共导出改成按需加载，缺 Sage 的静态发现不导入执行引擎；认证 IBS 按所选具体参数
检查 native ABI，不能因默认引擎存在就推定其它参数引擎也存在。

## 运行边界

`ci/c-combinations.json` 明确选择10个研究配置：LATTE配 ML-DSA三档、Falcon两档、
Luo模格两种格式、Luo矩阵、Wang–PW、SRGG。这是一个HIBE与六种IBS算法的配对，
参数/格式变体不另算算法。默认框架的其它配对仍按各自实测状态展示。

开发版公共验收驱动10/10通过、338项检查，包括四种匹配、严格wire、恢复、
固定发钥、裸IBS负例，以及持有新OTS密钥重签后进入IBS验证而被拒绝的消息篡改。
该驱动使用显式固定TEST随机源，不能写成系统随机分布或安全证明。

系统随机CLI探针调用原有命令，每一步都开新进程，覆盖64 B身份、32 B消息、
重复发钥、三个错配与四种wire修改。原状态零熵恢复禁止 native Setup/Delegate/Extract、
普通Keypair/Sign，只允许公开元数据、格式检查、验签及已有叶的Decrypt。
探针及固定源码版本后的收据另行归档，私钥/主状态/完整诊断留本地忽略目录。

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.run_combination_matrix --suite-file ci/c-combinations.json --output test-results/c-framework/new-matrix.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.c_framework_cli_probe --private-directory test-results/c-framework/new-cli-44 --profile ml-dsa-44
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.c_framework_cli_probe --private-directory test-results/c-framework/new-cli-44 --restore-only
```

需先按各自交付构建固定 LATTE、ML-DSA、Falcon native 引擎；发现或预检失败时不换后端。
五档IBS参数和LATTE作者数值与前批一致；研究安全状态仍 `none/false/false`。
LATTE匿名性、修订采样总误差、认证转换的强UF/量子与固定服务模型、正式参数仍待核验，
不能将工程组合成功写成满足 Wang 全部安全前提。当前其它研究 IBS 的公开小参数反例继续保留。

跨边界范围：默认registry、共同Hybrid预检、CI框架测试清单及其旧pending断言、
框架用法/目录/状态/任务同步；没有修改基线协议、BYTEAUTH或Hybrid密码运算。
