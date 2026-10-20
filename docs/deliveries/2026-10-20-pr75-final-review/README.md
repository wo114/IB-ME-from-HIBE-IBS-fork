# PR75 最终接收审查

2026-10-20。提交头`1e765f1`补齐了五组数据，本次接收main `1112ea7`（PR76来源归档、PR77报告重写指导），只解决`PROJECT_STATUS.md`的状态冲突。生产实现与提交头相比没有额外修改。首轮[返工记录](../2026-10-20-pr75-review/README.md)保留当时的WIP事实，不作为当前缺失数据清单。

## 结论

固定源码和实验依据可接收，待最终提交的远端检查通过后按精确SHA合并。已核对证书缓存的完整公开语句及逐消息验签、SRGG确定性计划与每次新采样熵、会话根／身份绑定及关闭、Luo精确NTT和原矩阵关键字兼容。SRGG历史研究源码与`7caaff4`逐字节一致。

新补数据保持原归档安装`b4b31d8`、参数、随机性和测量值。A／Falcon实际消息验签仍执行；B三根首次准备约0.18 s；C真实首次委派、额外叶钥及首条成本单列。Luo新随机主批加密收益比中位数0.582，补充相同随机流对照1.025，两个结果均保留。没有将局部收益写成稳定倍数或把C单根会话当成多根无状态基准。

## 实际验证

在规定WSL `~/miniconda3/envs/sage`执行，设置`PYTHONPATH=src:. PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1`：

```text
python -m pytest -q -p no:cacheprovider tests/test_backend_optimization_probe.py tests/test_backend_optimization_receipts.py tests/test_cert_certificate_cache.py tests/test_prepared_receiver.py tests/test_srgg_paper_plan_cache.py tests/test_luo_module_math.py tests/test_luo_module_backend.py tests/test_luo_module_codec.py tests/test_ci_catalog.py
python -m experiments.research.verify_backend_optimization --directory docs/research/2026-10-20-multi-backend-optimization
```

237通过、0失败、0跳过，包含真实SRGG Setup／Extract后的两轮SampleF与两条消息签名一致性。公开记录的只读全量复核返回consistent；[JUnit](evidence/regression.xml)仅去除hostname，[统计复核](evidence/optimization-verified.json)不读取私有状态。

Windows Python仅执行公开Git源码绑定：

```text
python docs/deliveries/2026-10-20-pr75-review/verify_sources.py
git diff --exit-code 7caaff4 -- experiments/research/candidates/srgg/paper_backend.py experiments/research/candidates/srgg/paper_samplef.py
git diff --check
```

495个安装Python文件与声明Git blob一致，冻结研究文件无差异。具体版本、选项和收据摘要见[review.json](review.json)。未重跑分钟级完整流程、未读取原实验私钥；小型确定性算法回归不计为新的生产随机性能样本。

当前已完成配置继续使用既有`secure/true/true`，原始性能收据保持执行时字段，不回写；本次不改变数学参数、安全目标或采样语义。发布版精确复现、C最大消息和多根重复仍由当前进度表管理。最终是否合并以PR远端状态为准。
