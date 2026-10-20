# 来源声明与源码归档检查

2026-10-20。基线为已接收 PR73 的 main `1c1e36e`。本批不改变密码算法、参数、采样或历史实验，只修正来源声明和精简源码归档边界。

原 NOTICE 将除三个根参考文件外的全部内容列为团队原创，并沿用早期教学安全字段和 78 文件／约 2 MB 打包数字；这些表述已经不符合当前仓库。现以四个已有 `UPSTREAM.json` 为索引列明 LATTE、ML-DSA、Falcon 和 LATTE 采样研究快照，保留原许可、作者、固定提交／压缩包与适配边界。官方报告模板和标志另作来源材料说明，未改原文件。

三个根参考文件继续在 `.gitattributes` 排除。`papers/` PDF 保留在默认 Git／GitHub 源码归档，供 CI 的论文缓存核对；专用 `export_source.py` 单独生成过滤这些 PDF 的精简交付包。项目报告 PDF、官方模板、论文索引和已登记上游源码、LICENSE／AUTHORS／README 保留。精简包的论文缓存研究审查需要按索引恢复原文件；普通源码、原生桥和 wheel 构建不读取论文 PDF。

## 复核

无需 Sage、编译器或密码学实验；使用 Git 与 Python 标准库：

```text
python docs/deliveries/2026-10-20-source-notices/verify.py --revision HEAD
python docs/deliveries/2026-10-20-source-notices/export_source.py --revision HEAD --output <本地忽略目录>/ibme-source.zip
python docs/deliveries/2026-10-20-source-notices/verify.py --revision HEAD --archive <本地忽略目录>/ibme-source.zip
# 将已核验归档解压至全新目录，进入该目录后执行下一条构建命令。
python -m pip wheel . --no-deps --no-build-isolation --wheel-dir <本地忽略目录>/wheel
# 以下检查由原Git工作区执行，并明确传入构建时的提交。
python docs/deliveries/2026-10-20-source-notices/verify.py --revision HEAD --wheel <本地忽略目录>/wheel/ibme-0.1.0-py3-none-any.whl
git diff --check
```

脚本按声明的提交逐字节核对四份清单中的 81 个文件，随后核对源码包的 Git 提交标识、排除项和应保留项目／许可，或 wheel 中三组原生上游文件与根 NOTICE／LICENSE。它只读取公开 Git 对象和构建包，不访问真实密钥、不执行算法、不安装外部依赖。检查结果及完整文件列表随本目录的 `verification.json` 归档；打包结果只代表被核验的那个提交。

基线归档含 24 份 `papers/` PDF；精简导出为 0，原工作文件保留。81 个上游文件、源码包必要文件、wheel 的 79 个原生上游文件及两份根许可声明按字节比对。另以无关提交的归档、加入占位 PDF 和缺失原许可的包检查拒绝行为，不使用实际私钥。各实际提交与包的摘要分别记录，不将先前包冒称最终发布版。

首次工作树构建虽通过许可检查，全量源码复核随后发现 `build/` 夹带另一分支的三个模块：`backend_optimization_probe.py`、`verify_backend_optimization.py`、`protocol/prepared.py`。该包被新增检查明确拒绝。`55b4fa6` 全新目录构建的 587 个包源码／数据文件逐字节匹配，含 498 个 Python 文件；原生上游和两份根声明另有核验。其记录保留在 `verification.json`，没有新增密码学性能实跑。

远端 `34b3557` 的 ABB 回归实际为245通过、10失败、39跳过，CHKP为1095通过、2失败、44跳过；失败为固定论文 PDF 缺失。容器 checkout 通过 GitHub REST 获取归档，全局 `papers/**/*.pdf export-ignore` 同时过滤了 CI 缓存。现已撤销该全局规则，保留默认归档论文，通过专用入口生成精简包；原测试及来源哈希保留。本地默认归档的24份论文逐字节匹配，对应ABB两模块27项、CHKP叶缓存审查3项全部通过、0跳过，见[evidence](evidence/)。旧失败不计作通过，远端结果以修复后提交的PR检查为准。

专用导出版 `da0a064` 已实际重建：默认归档保留24份论文，精简包为0；91个必要归档文件、587个包源码／数据文件、498个Python文件、79个原生上游文件及两份根声明通过核验。新 wheel 为2,054,598 B，SHA256 `98d44813b997a04e766910aa32aab07ff2bcd4caf129b735628319c00656730a`。完整源码与包摘要见 `verification.json`，此后收据更新不冒称一次新性能实跑。

当前已完成配置继续按用户决定安全，使用 `secure/true/true`；本批无新增参数、攻击、功能运行或安全等级声明，功能测试不能替代安全证明。环境／容器／原生二进制的最终发行依赖清单与作品编号、匿名复核和发布版本复现仍待完成。
