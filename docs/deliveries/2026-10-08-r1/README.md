# R1 与双方分工交付

日期：2026-10-08。已审阅并直接合并 PR #5，形成 `37e7031`，七份队友文件保留原提交；GitHub 确认 merged，合并后主仓库基础 CI 成功。R1 自有修改单独提交，哈希/推送结果在交付回复中报告。

## 文件范围

- 新增 `experiments/research/primitive_spec_audit.py`、`tests/test_primitive_spec_audit.py`。
- 新增 `docs/research/2026-10-08-r1/README.md`、`两套HIBE实施规格.md`、`Luo2024IBS实施规格.md`、`SRGG2025IBS实施规格与条件.md`、`luo-matrix-research.json`、`parameter-checks.json`、`verification.json`。
- 新增 [主 AI 逐轮工作清单](../../workplans/2026-10-08/主AI任务-IBS集成与优化.md)、[队友 CHKP/格工具任务书](../../workplans/2026-10-08/队友任务-CHKP与格工具.md)。
- 更新 `AGENTS.md`、`IMPLEMENTATION_SPEC.md`、`README.md`、`docs/PROJECT_RESTART.md`，为前轮选型报告增加后续说明。
- 本交付文件。

跨规范、研究、测试和任务书是为了使当前参数限制、实施职责、原文条件和后续接口保持一致。未修改原语/协议生产算法或注册新后端。

## 实跑命令及结果

PR 接收使用 `git fetch origin`、`git merge --no-ff origin/pr-5` 和 `git push origin main`。API 合并先因缺少 workflow scope 被拒绝，改用仓库现有 Git 登录后成功；没有更改凭据权限。

```text
python -B -m pytest -p no:cacheprovider -ra --tb=short tests/test_encoding.py tests/test_lattice_core.py tests/test_prepared_hashing.py tests/test_known_security_gaps.py --junitxml=test-results/pr5-review-basic.xml
python -B -m pytest -p no:cacheprovider --runxfail -ra --tb=short tests/test_known_security_gaps.py --junitxml=test-results/pr5-review-strict.xml
python -B -m pytest -p no:cacheprovider -q tests/test_primitive_spec_audit.py
wsl --cd /mnt/d/zcode_projects/ibme bash -lc '~/miniconda3/envs/sage/bin/python experiments/research/primitive_spec_audit.py --certify-primes-with-sage --output docs/research/2026-10-08-r1/parameter-checks.json'
git diff --check
```

本机 Python 3.14.6 / pytest 9.1.1：基础 182 passed、3 xfailed（39.31 秒）；严格 3 failed（39.15 秒），均为真实目标断言；新算术检查 24 passed（0.04 秒）。首次数学检查有一项 pytest 参数化迭代器弃用警告，改为 tuple 后最终无警告，无最终失败的算术测试。两组旧攻击运行耗时不作为密码性能比较。

指定 WSL Sage 实跑公开整数素性检查；模块内没有密钥、签名或密文执行。JUnit 中三个 XFAIL 与三个真实失败分别核对；文档链接、JSON 与来源指纹见 [verification.json](../../research/2026-10-08-r1/verification.json)。

合并后主仓库 CI：[run 37778417795](https://github.com/youzi258/IB-ME-from-HIBE-IBS/actions/runs/37778417795)，head 为 `37e70316ac03dc86c19feeeb10b4aaf491841f7f`，状态 success；未运行手动 strict_security。此链接不作为随后 R1 提交已完成远端 CI 的证据。

## 参数和安全声明

首套研究选择为 CHKP ROM HIBE + Luo §3 矩阵 IBS；R2 手选参数为 $n=4,m=8,k=4,q=65537,\eta=1,\kappa=2,\gamma_1=128,\gamma_2=2048$，仅用于未来正确性参考，本轮未生成该配置的密码对象。公开计数另用 $m=128$、17 bit 模数长度和作者报告签名容量，不是安全参数。所有新配置 `security_claim: none`，不宣称标准模型、完整 QROM 或 NIST 等级。

## WIP 与风险

正式参数、真实后端和完整性仍未实现；三项旧安全目标依然失败。Luo 缓存是本文采用的原文引用解释，未获得作者确认；模格精确模数与压缩、SRGG 底层强结论/模数映射、Yu 全文和环格完整实例仍待处理。未把已发现条件问题改写为已攻击论文，不把引用核验变成整篇补证任务。

下一轮主 AI执行 M1 矩阵 IBS，队友可独立执行 T1 完整格基与 CHKP 扩展；双方任务书包括逐轮产物、文件范围和交接要求。
