# 上游 PR 固定版本审查

审查日期 2026-10-12—13。来源分叉 `nomo258/IB-ME-from-HIBE-IBS` 无 PR；本次审查其上游 `youzi258/IB-ME-from-HIBE-IBS`。两 PR 均仍开放，未进行远端合并或发表 review/comment。

| PR / 固定 head | 结论 | 验证与范围 |
|---|---|---|
| [#14](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/14) / `87deec24f52c1c776a489566cf76f11d0d4a5aff` | 在已审范围接受为 none/false 研究基础 | Windows 定向 146 passed / 15 Sage skip；Sage 定向 161 passed；publication verifier 通过。审公开 backend/params/wire、提升的数学工具、assembly、CLI事务及收据门，没有重跑昂贵历史完整链 |
| [#15](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/15) / 初审 `f6090c9b25245228c4c7bea27d8fc2cb1e6935dd` | 有一项 P2 恢复交付缺陷，原语仍为 WIP | 原固定版本 Sage 56 passed / 1 skip；跳过缺历史私有 witness。审 SampleR/BasisDel、TrapGen、位算法与恢复/攻击脚本 |

PR #15 在工作期间更新为 `0a9e512a204b4e81c844b6998f4e43205cdb2f60`，新增单源矩阵采样工具和真实委派；保留原收据，不将 56 项旧版测试冒称新版全审。新头已拉至 `review/pr15-2026-10-13`；它不进入本批 B 开发基础。

新头增量独立实跑 `test_matrix_finite_sampling.py`：27 passed / 1 skipped（14.93 s）；skip需缺失的旧源码差分快照。审查没有执行昂贵的私有84维委派，不把存档委派收据当本轮重新实跑。

## P2 保存恢复目录缺少根快照

PR #15 的 `experiments/research/abb_rom/root_bits_probe.py:152–155` 在使用 `saved_private_directory` 的路径读取原 `root-private.json` 后，只把新 ciphertexts 写到输出目录，随后标记为 `completed`，没有将验证后的根快照写到新输出目录。

复现的 IO-only 内存 harness 表明：第一次恢复返回 passed；新目录没有 `root-private.json`；用它继续恢复在该文件 90–92 行失败，`public_attack_probe.py:27` 同样无法加载。这个 harness 隔离 IO/控制流并模拟密码调用，不能记为真实密码学试验。新头在该文件上无差异，因此缺陷仍适用。建议在发布 completed 前保存已验证的根快照，使交付目录满足自身恢复契约。

两项 Windows hardlink 测试最初遇到沙箱权限拒绝，在具备文件权限的同工作区域定向复跑均通过；这属于执行环境问题，未当作生产断言失败。发表材料验证器只核历史 Git blob/收据及阶段完整性，明确没有访问秘密状态或重跑原采样。

## P2 矩阵 LLL 入口绕过维度门

新头 `src/ibme/lattice/matrix_sampling/basis.py:195–201` 的 `matrix_checked_lll()` 没有先核 `limits.max_dimension`。独立使用公开2×2完整格，给 `MatrixBasisLimits(max_dimension=1)` 后仍执行并返回dimension=2；应在调用LLL前校验limits类型和输入维度，以免资源限额仅在其它入口生效。这是明确的资源契约缺陷，不是已披露小维参数的安全性反例。

旧教学/小维参数已披露的不安全性与尚未完成的完整 ABB HIBE，不作为意外新增漏洞；本审查也没有将功能通过升级为正式安全准入。
