# M1 矩阵 IBS 交付

日期：2026-10-08。基点 `faa004e`。完成主 AI M1 的真实算法参考、固定用户状态和保存恢复；不是完整 IBME 或安全参数后端。

## 修改文件

- 新增 `experiments/research/luo_matrix_reference.py`、`experiments/research/luo_matrix_audit.py`、`tests/test_luo_matrix_reference.py`。
- 新增 `docs/research/luo-reference/README.md`、`functional-audit.json`、`functional-audit-wsl.json`、`verification.json`。
- 更新 `.github/workflows/basic-checks.yml`、`docs/KNOWN_SECURITY_GAPS.md`，增加 M1 研究检查并保留三项旧 XFAIL。
- 更新 `README.md`、`docs/PROJECT_RESTART.md`、我方逐轮任务书，标记 M1 交付和下一轮 M2。
- 本交付文件。

研究、测试、CI 和进度跨文件是为了让实际算法、调用入口、缓存/格式和验证范围对应一致；没有修改 HIBE、队友格工具、旧生产 IBS/协议或参数注册。

## 实跑命令与结果

```text
python -B -m pytest -p no:cacheprovider -q tests/test_luo_matrix_reference.py tests/test_primitive_spec_audit.py tests/test_encoding.py tests/test_lattice_core.py
python -B -m pytest -p no:cacheprovider -ra --tb=short tests/test_encoding.py tests/test_lattice_core.py tests/test_prepared_hashing.py tests/test_known_security_gaps.py tests/test_luo_matrix_reference.py --junitxml=test-results/m1-basic.xml
python -B -m experiments.research.luo_matrix_audit --output docs/research/luo-reference/functional-audit.json
wsl --cd /mnt/d/zcode_projects/ibme bash -lc '~/miniconda3/envs/sage/bin/python -B -m pytest -p no:cacheprovider -q tests/test_luo_matrix_reference.py'
wsl --cd /mnt/d/zcode_projects/ibme bash -lc '~/miniconda3/envs/sage/bin/python -B -m experiments.research.luo_matrix_audit --output docs/research/luo-reference/functional-audit-wsl.json'
git diff --check
```

最终 Windows 相关检查 254 passed；同一 M1 的 65 项在 WSL 通过。两个环境审计的公开数据一致：72 条诚实签名、96 项错配拒绝、12 份身份恢复；原始数据和源码指纹见 [核验记录](../../research/luo-reference/verification.json)。CI 普通批次保留三个旧教学 XFAIL；最终运行计数在核验记录单列，不与前述重叠批次相加。

首次本地入口失败是包路径问题，已修复；另用失败测试确认哈希预算耗尽会从验签抛出，已修复为 False。最终无未说明的 M1 失败测试。未执行全 Sage/Lean 套件，未声称引用证明已重新完成。

## 参数、安全和 WIP

采用 R1 小参数 $n=4,m=8,k=4,q=65537,\eta=1,\kappa=2,\gamma_1=128,\gamma_2=2048$；另有 $k=32,\kappa=8,q=2147483647,\gamma_1=4096,\gamma_2=131072$ 的功能配置。身份上限 16 B、消息 0–32 B，均为手选研究参数，`security_claim: none`。

公开枚举在 R1 挑战空间 24 的参数上仅用 11 次 H2 查询生成有效伪造，预期为负面对照。较大挑战配置也未进行 SIS 难度估计，不宣称安全。未注册 IBSBackend、未完成参数/格式准入、HIBE 集成、完整密文认证、生产存储/并发/侧信道防护；旧三个漏洞仍未修复。状态快照包含私钥，仓库只提交公开审计信息。

提交哈希和远端结果在交付回复中提供。下一轮推进 M2，队友的 CHKP/格工具边界不变。
