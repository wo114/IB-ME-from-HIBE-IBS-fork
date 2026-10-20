# 来源与第三方材料说明

本项目实现文献中的密码算法，并复用下列第三方代码。项目的接口、组合、适配、测试和实验工作与所引用的算法、转换及上游实现分别说明；不将库复用、既有转换或参数变化直接列为原创算法。

根目录 [LICENSE](LICENSE) 是项目自有代码的许可声明。第三方源码保留其原版权、许可和作者信息，具体版本及逐文件摘要由各目录的 `UPSTREAM.json` 记录；不能把根许可解释为重新授权所有参考资料。机器可读索引见 [third-party-code.json](docs/third-party-code.json)。

## 仓库内复用代码

| 组件与路径 | 固定来源 | 保留的声明及本项目适配 |
|---|---|---|
| [LATTE 原生源码](src/ibme/hibe/latte/native/upstream/UPSTREAM.json) | cqs-technology/latte，`18cfbf9a671fca34785583b58ab9f28e3be21a3c`，`latte_3` | 原 MIT [LICENSE](src/ibme/hibe/latte/native/upstream/LICENSE)，Raymond K. Zhao。快照未改；构建器在临时副本中应用已列明的 COSAC 缓冲区修复和 AES 计数上限，并使用本项目桥接与 OpenSSL SHAKE 适配 |
| [ML-DSA 参考源码](src/ibme/ibs/certified/native/upstream/UPSTREAM.json) | pq-crystals/dilithium，`d35ba3fe5449bee3e6d43e1f296c3ca818bd36be` | 原 [LICENSE](src/ibme/ibs/certified/native/upstream/LICENSE) 与 [AUTHORS](src/ibme/ibs/certified/native/upstream/AUTHORS.md)；沿用清单登记的 CC0／Public Domain 选项，保留各文件署名。本项目另写桥接和 nonce 上限包装 |
| [Falcon 参考源码](src/ibme/ibs/certified/falcon_native/upstream/UPSTREAM.json) | Falcon 官方 `Falcon-impl-20211101.zip`，SHA256 `d9f982bd825b9903b57b686d6d26018dac173a1dff09f224cc39302f9d85a595` | 原 MIT 声明保留在 C／头文件中，作者信息见各文件；保留原 [README.txt](src/ibme/ibs/certified/falcon_native/upstream/README.txt)。本项目增加独立桥接、构建选项和资源上限包装 |
| [LATTE 采样研究快照](experiments/research/reuse/vendor/latte/UPSTREAM.json) | 同一 LATTE 提交中的 `latte_1/sample_z.c` | 保留原 MIT [LICENSE](experiments/research/reuse/vendor/latte/LICENSE)。仅用于研究来源核对，清单明确 `production_use=false` |

LATTE 的 `compat/libXKCP.a.headers/SimpleFIPS202.h` 是本项目 API 声明；当前实现调用 OpenSSL EVP SHAKE256，不包含 XKCP 实现。SageMath、cryptography、GMP／MPFR／MPC、OpenSSL 等环境依赖与上述仓库内源码分开记录。最终若交付环境、容器或原生二进制，还需根据该次实际构建记录依赖版本和随附声明；本清单不冒充尚未制作的二进制发行清单。

## 论文、模板与其它参考材料

`papers/` 中的论文和往届作品、根目录的 `支持特定功能的格基函数加密研究.pdf`、`978-3-031-51476-0_21.pdf`、`ib-me.pptx` 是第三方参考资料，不是本项目作品产出。它们的来源见[论文索引](papers/index.md)和各引用记录；保留引用，不据本仓库的代码许可推定其再分发权限。

[本届官方模板](docs/competition/2026/README.md)及报告采用的 CACR 标志也属于来源材料。原模板、提取标志和来源摘要按交付记录保存，不列为团队原创设计。项目报告、代码和文档中的引用及上游声明均须保留。

## 源码交付包

[.gitattributes](.gitattributes) 的 `export-ignore` 排除上述三个根参考文件。默认 Git／GitHub 源码归档保留 `papers/` 的 PDF，以供 CI 核验固定论文。精简交付包使用专用导出入口额外过滤论文 PDF，保留论文索引、项目代码、原许可、来源清单及本项目报告：

```text
python docs/deliveries/2026-10-20-source-notices/export_source.py --revision HEAD --output ibme-source.zip
```

该命令只导出指定提交，拒绝覆盖已有输出。过滤不改变工作目录或 Git 历史；直接复制目录、克隆仓库或普通 Git／GitHub 归档不应用专用过滤。包大小和文件数随提交变化，不沿用早期的 78 文件／约 2 MB 数字。作品平台的最终匿名提交件还须按[本届要求](docs/competition/2026/README.md)另行准备。

构建 wheel 时，以固定提交归档的全新解压目录为源。切换分支后复用原工作目录的 `build/` 可能夹带另一分支文件；交付检查逐个比对包内源码与声明提交，不以构建成功或少数文件一致代替完整比对。

精简源码包不含论文 PDF 缓存。核对论文缓存完整性的研究测试需要按论文索引获取其固定来源；这不影响包内代码和许可保留，也不表示这些缓存测试已在精简包中离线通过。打包复核命令及实际结果见[来源与归档检查](docs/deliveries/2026-10-20-source-notices/README.md)。

当前实现和安全配置以 [README](README.md)、[PROJECT_STATUS](docs/PROJECT_STATUS.md) 及公共 registry 为准：已完成配置按用户决定采用 `secure/true/true`，已知不安全小参数、教学档、未完成项和历史快照分别记录。来源许可说明不代替参数记录或安全依据。
