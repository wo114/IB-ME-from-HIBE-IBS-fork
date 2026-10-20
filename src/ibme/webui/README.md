# IB-ME 交互演示界面

一个只读复用公共装配层的本地 Web 演示：选择 HIBE/IBS 实例，执行真实 Setup、发钥、加密、解密，展示正确匹配、三类身份错配和密文篡改拒绝，并显示尺寸与耗时。

## 运行

必须在能运行所选后端的环境中启动。主演示（LATTE + ML-DSA/falcon）需要 WSL Sage 与已构建的 native 引擎：

```sh
cd <本仓库的WSL路径>
bash experiments/run_web_demo.sh --build-native --port 8765
```

该脚本固定使用 `~/miniconda3/envs/sage/bin/python`，从随包固定源码构建 LATTE、ML-DSA 与 Falcon 到独立本机缓存；已有构建时省略 `--build-native`。也可用已有引擎配置直接运行 `PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m ibme.webui --port 8765`。

然后在 Windows 浏览器打开 <http://127.0.0.1:8765>。服务默认仅绑定回环地址；不会更改 WSL 网络配置。

代码在 Windows 盘、执行在 WSL 时，可把选定本地 wheel 放入 WSL 文件系统的独立运行副本，减少逐次读取并校验源码的跨文件系统开销。在有 setuptools 的 Python 环境构建包，再在本仓库的 WSL 路径启动：

```sh
python -m pip wheel --no-deps --no-build-isolation --no-index --wheel-dir test-results/demo-wheel .
bash experiments/run_web_demo.sh --build-native \
  --wheel "$PWD/test-results/demo-wheel/ibme-0.1.0-py3-none-any.whl" --port 8765
```

已有 native 构建时省略 `--build-native`。运行副本按 wheel 的 SHA-256 隔离，每次启动核对打包文件；不修改全局 Python 环境，不复制密钥状态，原生后端逐次校验照常执行。修改源码后重新构建并指定新 wheel，运行中的服务保持其启动版本。主组合的三路同参数实测见[完整流程部署消融](../../../docs/research/2026-10-19-full-system-placement/README.md)；它测量 warm 公共 API，不代表安装或服务启动时间。

```sh
# 仅检查页面与 API 是否可达
curl -s http://127.0.0.1:8765/api/backends | head
```

## 边界

- 演示会话只存在于服务进程内存中；不写私钥、主密钥、状态目录或密文到磁盘。
- 刷新页面可重连同一服务内的会话，服务重启后会话丢失。持久状态恢复由 CLI 提供，不能把刷新页面称为重启恢复。
- 可导出当前会话的实际参数、尺寸、计时与每次操作结果，JSON 不含密钥、身份文本或消息正文；它不是归档的多次基准实验。
- 密钥尺寸是初始化/发钥后序列化的快照，未在之后每次派生时重新测量缓存增长；密文尺寸为本次完整 wire 的实际字节数。解密计时覆盖协议调用，不含页面通信。
- 不提供 mock 回退；依赖缺失时由预检明确报错。
- 交互界面只开放 LATTE-3 HIBE 与 ML-DSA / Falcon / Luo 三种 IBS。ABB-ROM、CHKP、MP12 等研究 HIBE 及其它研究 IBS 仍通过 CLI 和报告矩阵提供；其中部分 Setup 为分钟级或依赖可选运行时，放进单线程演示服务会阻塞页面。
- 展示预设显式固定为 LATTE `seed32`，以及 `ml-dsa-44`、`falcon-padded-512`、Luo `research`；不继承 registry 的其它默认档。三份完整配置与已交付展示卡逐项比较。
- 已完成的三个展示组合按最新项目决定标记为 `security_claim=project-admitted`、`backend_admitted=true`、`parameters_are_formal=true`。
- 这是项目内部准入，不改变底层来源记录，也不把完整组合表述为外部 NIST 认证对象。
- 后端异常显示“解密未完成”，不计为篡改拒绝；与预期不符的解密结果会明确提示。
