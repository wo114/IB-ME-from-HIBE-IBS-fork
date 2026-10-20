# 来源声明与源码归档检查

2026-10-20。基线为已接收 PR73 的 main `1c1e36e`。本批不改变密码算法、参数、采样或历史实验，只修正来源声明和精简源码归档边界。

原 NOTICE 将除三个根参考文件外的全部内容列为团队原创，并沿用早期教学安全字段和 78 文件／约 2 MB 打包数字；这些表述已经不符合当前仓库。现以四个已有 `UPSTREAM.json` 为索引列明 LATTE、ML-DSA、Falcon 和 LATTE 采样研究快照，保留原许可、作者、固定提交／压缩包与适配边界。官方报告模板和标志另作来源材料说明，未改原文件。

`.gitattributes` 增加 `papers/` 各层 PDF 的 `export-ignore`；三个根参考文件继续排除。项目报告 PDF、官方模板、论文索引和全部已登记上游源码、LICENSE／AUTHORS／README 保留。精简包不包含论文缓存；依赖缓存存在性的 `test_candidate_foundations.py` 等研究审查需要按论文索引恢复原文件，不能声称精简包可以离线通过这类缓存测试。普通源码、原生桥和 wheel 构建不读取论文 PDF。

## 复核

无需 Sage、编译器或密码学实验；使用 Git 与 Python 标准库：

```text
python docs/deliveries/2026-10-20-source-notices/verify.py --revision HEAD
git archive --format=zip --output <本地忽略目录>/ibme-source.zip HEAD
python docs/deliveries/2026-10-20-source-notices/verify.py --revision HEAD --archive <本地忽略目录>/ibme-source.zip
python -m pip wheel . --no-deps --no-build-isolation --wheel-dir <本地忽略目录>/wheel
python docs/deliveries/2026-10-20-source-notices/verify.py --revision HEAD --wheel <本地忽略目录>/wheel/ibme-0.1.0-py3-none-any.whl
git diff --check
```

脚本按声明的提交逐字节核对四份清单中的 81 个文件，随后检查源码包排除项和应保留项目／许可，或 wheel 中三组原生上游文件与根 NOTICE／LICENSE。它只读取公开 Git 对象和构建包，不访问真实密钥、不执行算法、不安装外部依赖。检查结果及完整文件列表随本目录的 `verification.json` 归档；打包结果只代表被核验的那个提交。

当前已完成配置继续按用户决定安全，使用 `secure/true/true`；本批无新增参数、攻击、功能运行或安全等级声明，功能测试不能替代安全证明。环境／容器／原生二进制的最终发行依赖清单与作品编号、匿名复核和发布版本复现仍待完成。
