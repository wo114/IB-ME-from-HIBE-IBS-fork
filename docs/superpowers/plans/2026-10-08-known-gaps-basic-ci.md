# 已知漏洞回归与基础 CI 实施计划

基线：`6fd7f42025a55c9082d13599ea4bc88d3b6c7b88`。
范围已获用户授权，目标是自动记录现有教学实例的真实安全失败，并建立基础检查；不改变老师构造、原语或参数。

## 1. 回归

新增 `tests/test_known_security_gaps.py`，仅使用既有公开线性求解器、真实教学 HIBE/IBS 和测试随机源。
分别准备公开签名伪造、未发发送密钥的协议冒名、真实签名密文的单字节低位修改。
安全目标断言分别是 `not verify(...)` 与两个 `result is BOTTOM`，准备阶段检查诚实消息恢复及规范加载。

首先执行无标记测试，确认三个目标断言真实失败，不能因导入或构造错误失败。
随后只对这三个旧教学实例的目标添加 `strict=True, raises=AssertionError` 的 XFAIL，分别注明原因。

验证命令：

```text
python -B -m pytest -p no:cacheprovider -q --tb=short tests/test_known_security_gaps.py
python -B -m pytest -p no:cacheprovider --runxfail -q --tb=short tests/test_known_security_gaps.py
```

普通模式预期 3 xfailed；严格模式预期 3 failed。XPASS(strict) 提醒重新核验并移除标记。

## 2. CI

新增 `.github/workflows/basic-checks.yml`，固定官方 Action 提交、pytest 9.1.1、Windows/Python 3.14。
只读权限；push/PR 自动执行选定基础套件，手动 strict_security 执行 --runxfail，失败不忽略。
始终输出范围说明并上传 JUnit。`.gitignore` 忽略 `test-results/`。

本地基础验证：

```text
python -B -m pytest -p no:cacheprovider -ra --tb=short tests/test_encoding.py tests/test_lattice_core.py tests/test_prepared_hashing.py tests/test_known_security_gaps.py --junitxml=test-results/basic.xml
```

预期 182 passed、3 xfailed。核对 XML 中 3 个 pytest.xfail 项；它们不是通过项。
解析工作流 YAML，检查触发器、只读权限、固定 Action 提交、严格步骤命令及产物路径。

## 3. 文档及交付

新增 `docs/KNOWN_SECURITY_GAPS.md`，说明三项漏洞、普通/严格命令、跳过范围和修复后的标记维护。
README 增加入口。独立审查测试是否吞掉意外错误或夸大安全结论。
执行 `git diff --check`，仅暂存本任务文件，检查暂存差异后提交。
推送 nomo258 fork 的独立分支，向 youzi258 主仓库 main 提 PR，附实际结果和未修复范围。
