# PR78 演示改版接收审查

2026-10-20。审查提交头`2ecb7a5`，与PR76／77主线及PR75待接收实现集成。审查覆盖固定A/B/C Suite、前端状态、主线程密码调度、HTTP轮询与同步API、异常分层和公开测量导出；没有更改密码算法或数学参数。

## 已修复的界面问题

1. 执行中刷新后，`renderPresets`生成的新方案按钮没有更新disabled状态，实际B发钥中可以点选另一方案。现于生成按钮后立即统一更新控件，实测B加密中刷新后仍显示“加密消息”，五个方案按钮均锁定，原任务继续完成。
2. 编辑消息后再还原成原文，按钮可继续验证，但旧的“请重新加密”提示没有清除。现按当前文本是否与密文对应消息一致显示提示；66000 B UTF-8输入同时禁用加密与旧密文验证，还原后显示可继续验证。

将状态文档中的Web任务边界限定到本PR：本PR不修改作品报告、不追加后续性能实验或最终发布复现，不将另一个任务中的阶段安排写成全仓库暂停指令。PR77的报告整体重写指导保留。

## 实际验证

在项目规定WSL `~/miniconda3/envs/sage`执行，`PYTHONPATH=src:. PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1`：

```text
python -m pytest -q -p no:cacheprovider tests/test_webui.py tests/test_webui_jobs.py tests/test_webui_http.py tests/test_ci_catalog.py
bash -n experiments/run_web_demo.sh
node --check src/ibme/webui/static/app.js
git diff --check
```

59通过、0失败、0跳过；shell／JavaScript语法通过。Python回归后仅修改前端控件刷新与提示，使用新加载脚本作浏览器复测。JUnit仅去hostname并统一LF，见[evidence/regression.xml](evidence/regression.xml)。快速测试使用的故障注入不计为密码学实跑。

另从集成源码启动独立回环端口8798，在浏览器实际操作。后端Python在`d36b51f`启动，后续修复不改变这部分代码；静态脚本修改后均刷新并核对新页面状态。

| 配置 | 本次独立实际操作 | 结果 |
|---|---|---|
| A：LATTE＋BNN/ML-DSA-44 | 1个新CSPRNG根，1次加密，正确／三类错配／篡改／截断共6次解密 | 全部符合预期；[公开导出](evidence/web-A.json) |
| B：LATTE＋SRGG PARAM-I compact | 同上；发钥和加密执行中刷新，接回任务；UTF-8超限与消息还原 | 全部符合预期；[公开导出](evidence/web-B.json)、[运行记录截图](evidence/web-B-records.png) |
| C：Lai C2＋Sageloli PARAM-I | 核对固定Suite和3924 B容量，独立页面环境预检显示就绪 | 没有新增分钟级Web完整运行 |

A/B都使用64 B以内的示例身份、36 B UTF-8示例消息，三代表完整参数与冻结Suite逐字段相等，当前为`secure/true/true`。两组的1根观察不与作者原A/B收据累计为性能基准，不做跨机器加速分析。导出只有参数、长度、尺寸、计时、结果与密文摘要，不含私钥、身份文本或消息正文；原生桥继续执行已有源码／ABI校验。

当前Web会话仍只驻内存，服务重启会清空；刷新重连不等于磁盘恢复。私有状态持久恢复继续使用CLI。C完整Web流程和最终发布复现仍按实际欠项记录，不能由预检替代。

本次修改：前端`app.js`两处控件／提示、两份当前任务说明及本审查目录。其余文件来自接收PR75和主线的合并。详细源码摘要、公开收据指纹和边界见[review.json](review.json)。合并前须接收PR75，并核对PR78精确头的全部远端检查。
