# 本批验证边界

本目录的五组密码学测量均实际运行固定wheel `b4b31d8`，不是单元测试替身或当前修复版的重标记。A/B/Luo/Falcon各3个独立系统随机根、每根每模式3次完整往返；C为单根2次原解密、1次真实准备、3次会话解密。所有诚实结果和各组9项负例符合预期。Luo补充9对同随机流重放使用原三根，不增加根数或生产随机样本。

运行及收据检查：

```text
python -m experiments.research.backend_optimization_probe --label <A|B|C|Luo|Falcon> ... --repetitions 3 --operation-timeout 1200
python -m experiments.research.verify_backend_optimization --directory docs/research/2026-10-20-multi-backend-optimization
python docs/deliveries/2026-10-20-pr75-review/verify_sources.py
```

第一项的完整参数、私有持久目录、实际安装和输入见README及各原始记录；第二项返回consistent，只是只读一致性检查；第三项确认495个安装Python文件均匹配所声明提交的Git blob，既不打开私钥，也不独立认证原生二进制。运行后软件／文件摘要另外列于`native-environment.json`。

本线程在接收队友修复、补齐数据和恢复NTT矩阵关键字兼容后执行的定向回归如下。测试组不与独立根数或性能样本数混算：

| 选择（接在`python -m pytest -q -p no:cacheprovider`后） | 环境／结果 |
|---|---|
| `tests/test_backend_optimization_probe.py tests/test_backend_optimization_receipts.py tests/test_cert_certificate_cache.py tests/test_prepared_receiver.py tests/test_ci_catalog.py` | Windows Python 3.14：81通过，0跳过；见[公共回归](common-tests.xml) |
| `tests/test_luo_module_math.py tests/test_luo_module_backend.py tests/test_luo_module_codec.py` | Windows Python 3.14：147通过，0跳过；实际整数／模格实现，见[Luo回归](luo-tests.xml) |
| `tests/test_project_admission.py` | 指定WSL Sage环境：8通过，0跳过；含需要真实原生环境的CLI元数据预检 |

最初把最后一组混入Windows选择时出现81通过、1失败：该用例调用真实环境预检，Windows缺少WSL原生后端使容量为空。未放松生产检查；在指定WSL和原有原生桥下整组8项通过。原生缓存／SRGG一致性及历史源码冻结的队友审查回归另见[PR75接收记录](../../deliveries/2026-10-20-pr75-review/README.md)，不把其121项与这里重叠累计成独立验证次数。

新增接线测试明确使用TEST-ONLY模拟原语，不能计入密码学运行。五组原始记录使用真实后端，计数包装始终调用原函数；补充重放使用明确标注的测试随机流，并在完整流程内断言两臂密文和熵消费相等。它不用于生产随机性，也不覆盖原主批的不利数据。

本线程自审保留了队友的备份排他创建、当前安全字段／历史快照兼容、严格出处校验和SRGG运行适配分离；历史研究源文件与`7caaff4`逐字节相同。另修复Luo原`matvec(prepared=..., vector=...)`关键字兼容，新增控制选项只切换执行路径。该接口拼写修复不回写旧测量源码或收据。

图、表和JSON汇总均由同一只读复核结果生成；PNG已目视检查，SVG／PDF布局来自同一figure。图中的Luo主批回退、样本波动、C首次准备和单根限制全部保留。旧报告正文未编辑；数据属于原归档安装，最终发布版精确复现另列为发布工作。
