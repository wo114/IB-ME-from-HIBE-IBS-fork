# 第二十四步：C64B 已提交交付的终验收与接入清单

日期 2026-10-12。审查者 DeepSeek（独立回核，非第二十二/二十三步证据作者）。
被验收对象：提交 `e5e0b97752f9291ce7621dd830d665baff86aef8`（26 文件、25 项不自哈希清单），fork PR9。

2026-10-12 Codex复核后作事实勘误：原始四份报告及原清单已保存在旁边的`DEEPSEEK-step24-before-codex-corrections-2026-10-12/`。下文保留DeepSeek实跑范围，并单列Codex的新证据，不把两者混计。

## 结论（一句话）

**交付材料与实际范围一致；未发现新的可复现问题。** C64B 是显式研究候选冻结，不是正式安全参数：
`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`approved_security_bits=null`、`NIST_category=null` 全部保持。不制造新门槛，本轮终止。

## 交付物清单

| 文件 | 内容 |
|---|---|
| `第二十四步-报告-C64B终验收.md` | 完整报告：实跑退出码、A/B/C 逐条核对、一页中文结论、未决边界、接入清单 |
| `findings.json` | 机器可读结论：每次运行的退出码、A 节核对、B 节审查、C 节安全措辞、未决边界、环境限制 |
| `运行回执.md` | 原始命令、真实退出码、关键原始输出、未做的事 |
| `MANIFEST.json` | 本目录全部交付物的 SHA-256（不自哈希） |
| `logs/` | 上述命令的原始 stdout/stderr/JSON，含两个可复算的独立校验脚本 |

## 本轮实跑摘要（真实退出码）

| 命令 | 退出码 | 结果 |
|---|---|---|
| `audit_luo_c64b_delivery.py` | 0 | `evidence_consistent`，25 项清单，122/19/28/111/25 分层计数 |
| `python -O audit_luo_c64b_delivery.py` | 0 | 与普通模式逐字段相同 |
| `audit_luo_c64b_selection.py --repo .` | 0 | 28/28 谓词通过，`input_head=e5e0b97`，`repository_writes=0` |
| 同上 + 历史损坏 screen（负控） | 2 | 只拒 `budget_exact_integer_not_js_number` |
| `pytest tests/test_luo_c64b_profile.py` | 0 | **32 passed**（81.05s） |
| 固定 0bf0855 快照上的 `luo_assembly_handoff.py` | 0 | 25 项装配检查，16383 B 签名、20415 B 外载荷 |
| `logs/verify-assembly-source-pin.py` | 0 | 实跑 33 个源哈希与归档**逐项相同** |
| `logs/verify-108-overhead.py` | 0 | 108 = 11+4+4+89，20415 = 16383+108+3924 |
| `pytest tests/test_luo_cross_version_harness.py` | 1 | 9 passed / 10 failed+10 error，**全部为沙箱禁止系统临时区写入所致**，非代码缺陷 |

## 关键澄清

- **检查类型不得相加**：122、19 是两组 pytest 用例；28 是参数谓词；111 是 3 个隔离进程的检查条目（只一次真实签名）；25 是共享装配检查条目；54 是探针签名调用。它们不是密码实验次数。
- **108 字节开销恢复分解**：`DOMAIN_SIGNATURE` 11 字节 + 两处 uint32 长度前缀各 4 字节 + `ENVELOPE_OVERHEAD` 89 字节（17+8+64）= 108。主 Codex 早先的质疑确属误判，已撤回；本轮依据公开常量独立复核后恢复该分解。
- **固定来源在生效**：把旧`--head 0bf0855`用于实际`f98de52`目录时会按预期拒绝。Codex已另在真实`f98de52`上重跑25项通过，见Luo工作树`docs/research/2026-10-12-luo-final-acceptance/evidence/codex-assembly-f98de52.json`；不是DeepSeek旧源码副本的结果，也不覆盖更晚版本。
- **历史HEAD纠错**：归档`parameter-decision.json`和`parameter-decision-optimized.json`均为`886fc12`；本轮新输出`logs/audit-selection.json`才是`e5e0b97`。判定器`freeze_applied=false`表示它只读，不否定e5已完成的显式研究候选选择。
- **责任分开**：CHKP真实后端/整合及适用CLI交付即使不声明安全位数也仍需完成，由另一对话负责。它们不阻塞Luo单体研究级收尾。真实SHAKE始终是需披露的实例化假设；将来具体等级主张须有对应定量依据，但不自动要求QROM。QROM只随QROM主张提出，精确LowBits联合分布仍非当前中止界的必需条件。
- **补跑环境限制**：DeepSeek的工具测试9pass/10fail/10error不是通过记录。Codex在本机同一19项工具测试随51项定向回归全部通过，证据为`codex-targeted-tests.xml`；不改被测代码或ACL。

## 复现

在只读仓库 `C:/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS`（HEAD = e5e0b97）执行：

```text
set PYTHONUTF8=1
set PYTHONDONTWRITEBYTECODE=1
python experiments/research/audit_luo_c64b_delivery.py
python -O experiments/research/audit_luo_c64b_delivery.py
python experiments/research/audit_luo_c64b_selection.py --repo .
python -B -m pytest -p no:cacheprovider -q tests/test_luo_c64b_profile.py
```

装配 smoke 需要把共享框架 `0bf0855464a9902ad95c91ea5bdfb4d12e78f5b9` 还原成只读快照后运行（见报告 §3）。

## 环境限制（如实记录）

本会话文件沙箱不允许 Python 子进程在系统临时区写入或删除（实测：工作区内正常，系统临时区 `WinError 5`）。因此 `tests/test_luo_cross_version_harness.py` 中依赖 `tempfile` 的 10 项测试无法在本会话执行；该文件第二十三步归档为 19 passed。副产品 `.tmp-pytest/` 下 10 个目录被设为拒绝访问，本会话无法读取或删除；曾按 `diagnose-windows-sandbox-acl` 技能发起一次免沙箱修复，因无审批通道被 fail-closed 拒绝后即停止（未改 ACL、未建 junction、未绕过沙箱）。在有审批或完全权限的会话中可删除该目录。
