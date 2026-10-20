# IB-ME 演示 Web

默认入口为报告选定的三组固定方案：

| 入口 | 完整组合 | 配置 |
|---|---|---|
| A | LATTE + BNN / ML-DSA-44 | seed32、64 KiB、reference |
| B | LATTE + SRGG | PARAM-I、128 KiB、compact |
| C | Lai C2 + Sageloli RSIS | C2 / v3 PARAM-I、8 MiB、reference |

三份完整 Suite 随安装包发布，并与[报告选型配置](../../../docs/deliveries/2026-10-19-report-three-selection/suites/)逐字段校验。8 MiB 为 C 的内部载荷预算，应用消息上限为 3924 B。Falcon-512 和 Luo 模格仍可从“补充方案”选择。

## 启动

在规定的 WSL Sage 环境、对应后端及 Hybrid 依赖已安装的条件下运行：

```sh
bash experiments/run_web_demo.sh --build-native --port 8765
```

已有 LATTE／ML-DSA／Falcon 构建时去掉 `--build-native`。C 还需要其已交付的 Sageloli 原生引擎，沿用 `IBME_SAGELOLI_RING_NATIVE` 配置；依赖缺失时页面会显示具体错误，不回退到 mock。B/C 准备时间较长，页面会显示正在执行的实际阶段。

访问 <http://127.0.0.1:8765>。默认仅监听回环地址。

代码在 Windows 盘时，也可以使用已构建 wheel 在 WSL 文件系统中运行：

```sh
python -m pip wheel --no-deps --no-build-isolation --no-index --wheel-dir test-results/demo-wheel .
bash experiments/run_web_demo.sh --wheel "$PWD/test-results/demo-wheel/ibme-0.1.0-py3-none-any.whl" --port 8765
```

运行副本按 wheel 摘要隔离并核对文件，native 来源检查照常执行。修改源码后需重建 wheel 并重新启动服务。

## 操作

选方案、填写身份、开始演示，再加密消息并选择验证情形。正确双方恢复原文；三类身份错配、篡改和截断分别执行实际解密。后端异常显示未完成，与协议拒绝分开。

页面默认显示消息、解密结果和三项测量。密钥尺寸、初始化与发钥耗时位于“参数与更多指标”；实际操作记录和测量 JSON 导出位于“运行记录”。编辑消息后需重新加密，才能继续验证对应的新消息。

刷新会重新连接当前内存任务和会话，不重新初始化根。服务退出或重启会清空会话，持久状态恢复仍由 CLI 提供。会话、私钥和主密钥不写磁盘。导出只包含配置、尺寸、耗时和操作结果，不包含密钥、身份文本或消息正文。

## 调度及 API

HTTP 页面和任务轮询在独立线程响应；所有预检及密码操作都由主解释器线程串行执行，以保留 Sage/cysignals 的线程要求。一次只接受一个操作，重复提交返回 HTTP 409。

- `POST /api/jobs`：`{"operation":"bootstrap","payload":{"preset":"srgg"}}`，返回任务 ID。
- `GET /api/jobs`：查看当前或最近一次任务的真实阶段、状态和结果。轮询记录不包含输入参数，下一项任务替换旧结果。
- 其它操作为 `check`、`encrypt`、`decrypt`、`reset`；`check/bootstrap` 使用固定 `preset` ID。
- 原有同步接口 `/api/check`、`/api/bootstrap`、`/api/encrypt`、`/api/decrypt`、`/api/reset`、`/api/state`、`/api/export` 保留；忙时返回 409。

单次会话的时间与尺寸是交互观测，不能直接当作多根重复性能实验。

## 检查

```sh
python -m pytest -q -p no:cacheprovider tests/test_webui.py tests/test_webui_jobs.py tests/test_webui_http.py
node --check src/ibme/webui/static/app.js
```

这些快速测试检查配置绑定、任务／HTTP 调度、输入与异常、导出边界；真实后端的浏览器检查另记交付记录。
