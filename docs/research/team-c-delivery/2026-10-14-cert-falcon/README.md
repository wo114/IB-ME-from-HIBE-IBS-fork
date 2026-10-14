# C2：认证转换 Falcon 独立 IBS

基点 `10563a6ed74c9d02a6bb3a47b26b8c16035562a8`（PR24合入）。本批新增普通Falcon适配、严格对象格式与完整BNN认证IBS，复用已有五方法转换和固定身份状态；不复制IBME。普通签名和完整IBS分层验收，两个参数仍计一条Falcon算法路线。

当前实现已完成，系统随机实物、仓库外安装和远端CI证据正在收尾，交付状态 **WIP**。最终收据将固定提交与实际执行版本，早期试跑不计作最终结果。

参数与算法见[对应表](algorithm-map.md)和[完整契约](../../../specs/certified-ibs.md)。普通Falcon v1.2 n512/1024、q12289，固定padded签名666/1280 B。18份MIT原文件逐字保留，源码包20211101与官方round3向量分别固定SHA-256；不是FN-DSA/FIPS206。

当前安全状态 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。统计/KAT/功能测试不替代证明；完整QROM、强不可伪造、固定服务查询损失、整体有限中止/数值误差、生产侧信道及外部状态认证/反回滚仍未准入。默认registry和真实HIBE配对由统筹下一层验收，不算本批完成。

复验（WSL仓库目录）：

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m ibme.ibs.certified.falcon_native.build --selftest
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python ci/run.py run cert-falcon --output test-results/cert-falcon/primitive
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python ci/run.py run cert-ml-dsa --output test-results/cert-falcon/mldsa-regression
```

跨边界修改仅为共同普通签名dispatch/对象算法标识、显式descriptor、wheel随包源码、独立CI与共用研究probe；不改变Core、HIBE或协议语义。完整尺寸计用户公钥＋机构证书＋用户签名及编码，不以裸Falcon尺寸代替IBS尺寸。
