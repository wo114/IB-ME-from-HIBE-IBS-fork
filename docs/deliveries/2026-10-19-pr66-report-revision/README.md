# PR66 内容修订与未完成的版式复核

接收状态：**WIP，保持开放，待修订版页面核验**。内容修订提交`b34257654684592d446eca59109abe707c5e49a1`，基于PR66旧头`6c0e2d2`及main `6f04f2b`，不改旧作品报告或PPT，不运行新的密码实验。

## 内容已修复

- 表3改为从E13的q=2^127−1、g=16、每个n最小m̄记录直接生成；n1024维度为390160，完整原参数行写入report-facts.json。检查d=m̄+2w、所选行、表格数字及有限网格口径，拒绝空行清单。
- 将“门内穷举否定”改为有限网格预筛，说明15.2/13.8是模型搜索下限；仅陈述当前模型及本批已测点。
- 区分Foo–Li公钥比特打包估计与Sageloli公钥序列化实测，删除同安全口径／路线固有差距推断及缺少对应来源字段的其它大对象尺寸。
- 明确原稿基点与E13后续增补版本；同步Word、Markdown、统计指纹及README，旧25页版式记录不覆盖本修订。

## 实际通过的检查

```text
# Codex捆绑Python；仅读取公开记录和文稿
python docs/reports/2026-10-19-research-draft/check_report.py --record
# 项目规定WSL Sage环境，插件自动加载关闭，OpenBLAS/OMP各1线程
~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_report_fooli_bindings.py \
  --junitxml=test-results/pr66-67-review/pr66-fixed.xml
# 普通Python只读复核本批版本和收据
python -O docs/deliveries/2026-10-19-pr66-report-revision/verify.py
```

**197项文稿检查通过，5项回归通过、0跳过（0.76秒）**。回归包括正确来源、复现旧错误维度、篡改选中行、空选中行和重引“穷举否定”；文件已加入portable framework CI。文稿包含11张Word／Markdown一致的表。新密码运行和新安全估计均为0，声明维持none/false/false。

## 页面渲染受阻

已实际调用所选文档运行时的render_docx.py，返回码1：`FileNotFoundError: LibreOffice soffice.exe was not found on PATH`。[结构化诊断](render.json)绑定当前Word SHA，页面图片为0，逐页检查未完成。

所用[文档技能](C:/Users/youzi/.codex/plugins/cache/openai-primary-runtime/documents/26.1015.12040/skills/documents/SKILL.md)（本机工具路径，不随仓库移交）明确要求：“Run `render_docx.py` to produce `page-<N>.png` images”，并要求检查全部页面。当前缺少渲染器，因此没有把197项结构检查或CI全绿替代为版式通过；这项环境限制不否定已经修复的内容，也不涉及算法可行性判断。

下一步是使用有对应渲染运行时的环境，对此Word产生PNG并逐页检查；如版式需要再改，更新Word与validation后复核。通过后再合并PR66。未要求补安全性证明，不启动三条暂缓路线。
