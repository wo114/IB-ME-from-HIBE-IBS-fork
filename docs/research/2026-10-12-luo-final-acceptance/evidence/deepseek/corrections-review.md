# corrections-review（只读纠错回核，2026-10-12）

范围：读 `CODEX-第二十四步-终验收定向纠错-2026-10-12.md`，对照本目录 findings.json、README.md、运行回执.md、第二十四步-报告-C64B终验收.md 及固定证据。未重跑 pytest/装配/估计器，未提权、未改 ACL、未扫描 `.tmp-pytest/`。

## 逐项核对（7 条）

1. **历史 HEAD**：通过。三份文档均写两份归档 `parameter-decision*.json` 的 `input_head=886fc12`，仅本轮 `logs/audit-selection.json` 为 `e5e0b97`。实测顶层 `input_head=e5e0b97752f9291ce7621dd830d665baff86aef8`，负控同。
2. **freeze 语义**：通过且无误引。`freeze_applied=false` 位于 `candidate_choice` 内，与 `is_formal_security_admission=false` 并列；报告所述"判定器只读、不施加改变，e5 的 profile/helper 已完成显式候选选择"与 JSON 一致，未误写为"未选定"。
3. **责任边界**：通过。CHKP 真实后端/整合与适用 CLI 明列另一对话责任且不阻塞；真实 SHAKE 为持续披露的实例化假设；QROM 仅在声明 QROM 时另论；精确 LowBits 明列可选。此与 `not_required_for_freeze` 五项一致。
4. **Codex 新证据**：通过，未冒称。工作树 `codex-targeted-tests.xml` 实测 51 个 testcase、failures=errors=0；`codex-assembly-f98de52.json` 实测 `target_head=f98de52`、checks=25、32.91s、16383/20415/3924、`private_artifacts_saved=false`；`codex-receipt.json` 记录各退出码、`reviewed_commit=e5e0b97`、25 项清单。报告把 c7d2746 私人快照与 f98de52 实跑分开，未写成本人重跑。
5. **修改范围**：通过。明确"被审查已跟踪文件未改 ≠ 工作树全程干净"，并承认私人目录有 git init/add/commit、原仓库未改、非新算法。
6. **环境失败**：通过。9pass/10fail/10error 与 WinError5 只作缺项/环境限制，不作算法失败或"缺陷必不存在"的推断；Codex 51 项单列。日志实测 `10 failed, 9 passed, 10 errors`，`head_mismatch` 退出 2。
7. **清单范围**：通过。根 MANIFEST 显式列 26 项（4 份主文档 + logs 22 件），排除自身/`logs/MANIFEST.json`/`.tmp-pytest/`/临时快照；`skipped_unreadable=[]`；26 项 SHA-256 只读重算 0 不匹配。logs 实际 22 文件与清单一一对应。

## 新问题

未发现新的实质问题。仅一处陈述习惯：README 与报告分别给出 51、32、19，未显式写成"51=32+19"（findings.json 已给出该等式），属表述细节，不构成事实错误。

## 结论

Codex 定向纠错七项全部落实、证据可复核；交付材料与实际范围一致，未发现新的可复现问题。Luo 研究级收尾到此结束，不生成下一轮任务。私人 `.tmp-pytest/` 残留仍属非交付物，留待有权限会话清理，本次不动。
