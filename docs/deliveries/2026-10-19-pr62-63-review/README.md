# PR62／PR63 审查与合并

2026-10-19。两份PR均已修正、复测并合并。远端固定版本与检查原始快照见[review.json](review.json)；[只读校验器](verify.py)核对快照和本地证据，不查询实时GitHub，也不运行密码算法。

| PR | 审定head | 合并提交 | 合并前远端结果 |
|---|---|---|---|
| [62：Lai C2收据](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/62) | `aa8dd3e` | `a9d9615` | 46成功、2个预期手动检查未执行 |
| [63：Sageloli v3接入](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/63) | `b9a06b1` | `7a53d17` | 46成功、2个预期手动检查未执行 |

每份PR的远端数字包括push和pull_request两套事件；各套23成功、1个手动`strict-security`未执行，不计作46种独立实验。CI快照是在上述head合并前完成采集，PR合并状态另经实时接口确认。

## 实际修正

1. PR63的候选包顶层立即导入旧采样器，破坏Windows无Sage的静态发现，远端框架检查实际失败。改为保持公开API的惰性导出。数学、数值参数、采样器、原生库与wire不变；旧执行时顶层源码另存显式快照，保留原运行／安装记录的来源。
2. PR62在“新state＋独立CT路径”下，写消息之前未创建state。现在分别创建目录，继续拒绝已有输入；fake-CLI路径回归只验证控制流，不计密码运行。
3. C2生成器先核对完整C2参数、组合版本和Suite摘要；公开校验器检查原收据SHA-256、完整三种错误身份／五种篡改、返回码与零明文输出，拒绝空负例集合。失败诊断不复制进公开收据，子进程有明确时间上限。
4. 后续集成对旧算法目录、状态页、默认登记表的改动会使历史发布绑定失配。三个文件按PR62审定版本保留文本快照，当前源码相同则直接检查，否则只允许对应的已声明快照。Lai运行源码等未声明差异继续失败。原267项回归、14 B消息／672.05 s解密等原始数据保持原值，并修正README中“没有重跑”的批次歧义。

PR62修正提交`a3030ac`／`aa8dd3e`已通过维护者编辑权限写回原fork分支；PR63修正为`b9a06b1`。集成后的发布绑定修正为`a620b39`。上述不包含新的基础证明或参数扫描。

## 本地复核

WSL统一使用`~/miniconda3/envs/sage/bin/python`，Sage10.9／Python3.13.14。关闭pytest自动插件，使用`PYTHONPATH=src:.`；原生LATTE与Sageloli库已明确配置。

```sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=src:. OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 \
  ~/miniconda3/envs/sage/bin/python -m pytest -q \
  tests/test_lai_target_receipt.py tests/test_lai_hibe.py tests/test_lai_target_parameters.py
# 33 passed, 0 skipped

PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=src:. OPENBLAS_NUM_THREADS=4 OMP_NUM_THREADS=4 \
  ~/miniconda3/envs/sage/bin/python -m pytest -q \
  tests/test_registry_extension_contract.py tests/test_sageloli_ring_registration.py \
  tests/sageloli_native/test_ring_assembly.py tests/test_sageloli_ibs.py
# 77 passed, 0 skipped

PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=src:. \
  ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_lai_target_receipt.py
# 合并树13 passed, 0 skipped；这13项包含在上述33项中
```

三次JUnit合计110个不同测试身份，不把重复运行累加为更多独立测试。公开XML仅删除hostname并规范换行。Windows Python3.12.14另用全新进程执行原契约中的静态发现脚本，隐藏Sage并阻止engine/runtime/sampling/full_sampling导入，结果通过；没有把Sage skip算成功。

只读发布检查：Lai当前49项来源绑定通过，使用3份显式历史快照；原`2180286`发布44项历史来源绑定通过；267项仅为原发布JUnit；Sageloli当前696项证据检查通过。所有校验器在`python -O`下工作。复制到隔离fixture后，未声明的Lai源码修改、快照修改和快照越界路径均被拒绝。shell语法、原4个fake-CLI工作目录场景与`git diff --check`通过。

```text
python -O docs/deliveries/2026-10-19-pr62-63-review/verify.py
python -O docs/research/team-c-delivery/2026-10-19-lai-publication/verify_delivery.py
python docs/research/team-c-delivery/2026-10-19-lai-publication/verify_delivery.py --historical
python -O docs/research/2026-10-19-sageloli-ring-integration/verify.py
```

复核来源固定在`d20642d`，需保留Git历史。主要修改文件为候选Sageloli包`__init__.py`、Lai目标工作目录／收据生成脚本、`tests/test_lai_target_receipt.py`，以及两份交付的README、校验器、指纹清单和显式来源快照；本目录保存审查JSON、CI快照、三份JUnit及Windows冷进程记录。完整选定源码路径与摘要在`review.json`中。

## 运行与安全范围

审查没有重跑PR62原14 B C2密码批次，没有修改原目标参数或原始收据。按用户下一项要求新增的32 B消息C2×四种IBS试验由[独立目录](../../research/2026-10-19-lai-c2-combinations/README.md)记录，不能混入上述回归计数或历史批次。

保留论文引用及用户确认的安全／HIBE匿名性工作前提。`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`保持；有限功能测试不构成安全证明。Lai采样差异、各原语数值误差、目标估计范围和尚未完成的多根公平评测继续依原契约说明；Sageloli第二档完整系统、未接入IBS及三条暂缓路线没有由这轮审查启动。
