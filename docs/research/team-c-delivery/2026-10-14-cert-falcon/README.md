# C2：认证转换 Falcon 独立 IBS

实现 `14c44a60e32399925e70c026aef4824031e0216c`，CI旧断言修订 `cf48c28d7e60f8597f0ba1965d2a67584a9d3811`，基点 `10563a6ed74c9d02a6bb3a47b26b8c16035562a8`，[PR25](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/25)。新增普通Falcon适配、严格对象格式与完整BNN认证IBS，复用[ML-DSA](../2026-10-14-cert-mldsa/README.md)的五方法转换和固定身份状态。两个参数仍计一条Falcon算法路线。

## 实际验收

| 执行 | 结果与范围 |
|---|---|
| Falcon专项 | **237 passed / 0 skipped**，含200组官方向量、两参数完整转换/严格对象/方程/恢复/攻击/pending/容量/并发/原生边界 |
| 官方向量 | 512/1024各100组：PK/SK与逐字压缩签名hash、真实正反验签；199例padded逐字一致，1例实际重采样后验签，没有跳过或截断 |
| 作者原始自检 | 半高斯、21组×100000个SamplerZ样本、FFT/多项式/签名/密钥/API和两档NIST聚合hash通过；自检为上述237项中的1项，交叠KAT不另加总 |
| ML-DSA回归 | 246 passed / 0 skipped，共用转换保持原有行为；与Falcon合计483个唯一pytest用例 |
| Windows两套原语 | 17 passed / 466 skipped；缺Linux native项不计成功 |
| Windows公共框架 | 427 passed / 5 skipped，partial；不与单体混加 |
| 系统随机实物 | 两档各1次：同机构2个64 B身份、32 B消息、32份新签名；匹配、错身份/消息、3项真组件替换和参数重放符合预期 |
| 新进程恢复 | 每档32次验签，0熵/0keygen/0新签名；复用同一机构/已发SK，主快照字节不变 |
| 仓库外安装 | 34个实际provider均来自独立site；随包源码重编译Falcon/ML-DSA；复用本批2份Falcon和既有3份ML-DSA实物，160次零熵验签、5次恢复SK新签名，主状态不变 |

原始[JSON/XML/日志](evidence)按字节保留，95个执行/辅助/测试/CI文件均与固定Git blob一致，见[source-check](evidence/source-check.json)和[审查](review.md)。WSL CI工具未取得revision，另以内容指纹核对；Windows框架记录cf48c28且工作树干净。cf48c28仅修改目录测试，原语和实物源码等同14c44a6。不提交私钥、native二进制、wheel或缓存。

## 参数、资源与来源

参数与算法见[对应表](algorithm-map.md)和[完整契约](../../../specs/certified-ibs.md)。普通Falcon v1.2 n512/1024、q12289，固定padded签名666/1280 B。18份MIT原文件逐字保留，源码包20211101与官方round3向量分别固定SHA-256；不是FN-DSA/FIPS206。

`identity_bytes=64`、`message_max_bytes=65536`、`max_identities=16`、`timeout_seconds=30`。每档实物重复1次，每次keygen/sign使用新的32 B系统CSPRNG种子，总熵1184 B（机构32＋两用户各64＋32签名各32）；真实Gaussian/ffSampling，无教学缩参。

| 配置 | 普通PK / 签名 B | 完整IBS签名 B | 双用户主状态 / 单SK B | 本次实物总时 s |
|---|---|---|---|---|
| Falcon-padded-512 | 897 / 666 | 2322 | 10833 / 4107 | 7.454 |
| Falcon-padded-1024 | 1793 / 1280 | 4447 | 19616 / 7538 | 7.695 |

完整IBS含用户公钥、机构证书、消息签名和编码；总时含Python/C子进程、文件写入、负例和新进程恢复。只有1次重复，且同机进行其它测试，不能作为同等安全目标的公平横向基准或完整IBME收益。阶段、RSS与字节数见实物收据。

环境：WSL2 Linux6.18.33.2、Intel Core Ultra9 275HX、规定的 `~/miniconda3/envs/sage` Python3.13.14、GCC13.3.0；Windows测试/构建为Python3.14、setuptools84.0.0。Windows生成纯Python wheel，隔离WSL从其C源码重编译；wheel SHA-256 `5d80642ea3dab3ee3ceeb9e04750f903a59fe4887a45265b036496773ad80fac`，1266589 B。

当前安全状态 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。统计/KAT/功能测试不替代证明；完整QROM、强不可伪造、固定服务查询损失、整体有限中止/数值误差、生产侧信道及外部状态认证/反回滚仍未准入。默认registry和真实HIBE配对由统筹下一层验收，不算本批完成。

复验（WSL仓库目录）：

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m ibme.ibs.certified.falcon_native.build --selftest
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python ci/run.py run cert-falcon --output test-results/cert-falcon/primitive
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python ci/run.py run cert-ml-dsa --output test-results/cert-falcon/mldsa-regression
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.certified_ibs_probe --private-directory test-results/cert-falcon/fresh-512 --algorithm falcon-padded-512 --source-commit 14c44a6
```

1024同样执行；输出目录必须是新目录，已有实例加 `--restore-only`。公开向量的确定性TEST熵与实物CSPRNG分离。安装核验的[脚本](evidence/installed-check.py)和[隔离入口](evidence/install-from-wheel.py)保留，复验须选择自己的新输出/安装目录；原ML-DSA实物若不存在，先按其交付生成。

开发失败保留：首轮2项描述符测试误用backend_id，改为接口现有id后通过；公共框架仍硬编码Falcon缺测试，改用未实现的Xie为负控，25项目录测试及完整框架随后通过。WSL无隔离构建缺setuptools，改由Windows现有构建环境产wheel、WSL隔离安装/重编译后通过。早期失败文件标development，未计入最终通过统计。

完整[修改清单](files-changed.txt)。跨边界修改仅为共同签名dispatch/对象算法标识、显式descriptor、wheel源码、独立CI/目录断言、共用probe及任务/状态同步；不改变Core、HIBE或协议语义。转换核心backend.py和原ML-DSA普通/native源码逐字不变。

剩余：本批准入/实际组合，C1 Lai与LATTE匿名/有限误差核验，C3 Xie原文冲突，CR Zhang实施入口。C2独立实现完成不等于C全部任务完成；整体QROM/强UF/固定服务查询损失/有限中止与生产侧信道仍须核验。
