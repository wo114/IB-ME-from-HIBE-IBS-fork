# Sageloli 环版：CI 与上传材料复核

本目录补传此前保存在本地的独立核验说明与脱敏证据。算法、参数、两档原始实跑收据均不改，仍更新同一个 [PR59](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/59)。

## 结论

**固定源码 `32d0c0bd8d9c75efc1464cbbf91d665ba3574f52` 的实现与所需公开材料齐全，没有发现 CI 失败或漏传。** 两档参数的完整交付、公式对应和复跑命令见[中文主 README](../2026-10-19-sageloli-ring-target/README_zh-CN.md)。

| 检查 | 结果 |
|---|---|
| 固定版本 [Actions 39200527885](https://github.com/youzi258/IB-ME-from-HIBE-IBS/actions/runs/39200527885) | 23 项 SUCCESS；1 项预期 `strict-security` SKIPPED；0 失败 |
| 下载的 SIS／RSIS CI JSON 和 JUnit | 各 165 passed，0 failed/error/skipped；两组是同一测试集合，不相加成 330 |
| 干净提交归档重建原生库 | 数学＋原生专项 35 passed，9.55 s，无跳过 |
| 去重测试集合 | CI 的 165 项与专项的 35 项重合 20 项，联合正好覆盖已交付的 180 项 |
| 远端 Git 树、Git blob、SHA-256 和文件长度 | 原批次 36 项 PR 改动全部匹配；连同基线中的原论文 PDF，共 37 个必需文件齐全 |
| Param I／II 的 fresh 与 recover | 四份真实收据齐全，原始源码指纹和归档快照匹配 |

默认 CI 没有构建 `tests/sageloli_native`；这部分不是伪装成已在 CI 执行，而是按规定 WSL Sage 环境，从干净的固定提交归档另行重建和运行。公开验证器在普通及 `python -O` 下均通过，不依赖本机未跟踪文件或私有状态。

本表 CI 结论只对应 **被复核的 `32d0c0b`**。本目录增补及上游文档同步会产生新提交和新 CI，不能把旧 CI 的绿色状态直接称作新提交已经通过；新状态以 PR 页面为准。

## 文件

- `verification.json`：逐文件远端上传核对、四次大参数执行摘要和测试集合结论。
- `ci-status.json`：固定版本完整 CI 状态快照。
- `ci-sis.json/xml`、`ci-rsis.json/xml`：下载的实际 CI 收据与逐项测试。
- `clean-native.xml`：本轮干净归档重新构建后的 35 项专项结果。
- `verify.py`、`MANIFEST.json`：无需网络的材料、源码和去重测试集合核验。

JSON 只做规范化格式转换；JUnit 只移除 hostname 属性，不改变测试名称、结果或时间。原始下载件和输出仍保留在本地。

在完整仓库根执行：

```text
python docs/research/team-b-delivery/2026-10-19-sageloli-pr59-review/verify.py
python -O docs/research/team-b-delivery/2026-10-19-sageloli-pr59-review/verify.py
```

本轮没有重跑两档大参数的新建流程。fresh 分别固定在 `78f3267`／`03b0e5e`，最终恢复固定在 `c29b45d`；先前交付已保留这些版本的源码快照，不混称同一个运行版本。

私钥、种子、运行状态、实际签名样本、私有谱统计和本机二进制不上传，不能把这些有意排除项算作漏材料。原生库可从公开 C++ 源重新构建。有限浮点 Gaussian 总误差未认证，`none/false/false` 声明不变；本目录不新增正式安全或 HIBE 组合结论。
