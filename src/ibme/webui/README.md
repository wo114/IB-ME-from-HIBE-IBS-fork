# IB-ME 交互演示界面

一个只读复用公共装配层的本地 Web 演示：选择 HIBE/IBS 实例，执行真实 Setup、发钥、加密、解密，展示正确匹配、三类身份错配和密文篡改拒绝，并显示尺寸与耗时。

## 运行

必须在能运行所选后端的环境中启动。主演示（LATTE + ML-DSA/falcon）需要 WSL Sage 与已构建的 native 引擎：

```sh
cd /mnt/d/zcode_projects/ibme
source /home/youzi/miniconda3/etc/profile.d/conda.sh
conda activate sage
PYTHONPATH=src python -m ibme.webui --port 8765
```

然后在 Windows 浏览器打开 <http://127.0.0.1:8765>。如果 WSL2 localhost 转发不可用，使用 `wsl hostname -I` 返回的地址访问同一端口。

```sh
# 仅检查页面与 API 是否可达
curl -s http://127.0.0.1:8765/api/backends | head
```

## 边界

- 演示会话只存在于服务进程内存中；不写私钥、主密钥、状态目录或密文到磁盘。
- 不提供 mock 回退；依赖缺失时由预检明确报错。
- 交互界面只开放 LATTE-3 HIBE 与 ML-DSA / Falcon / Luo 三种 IBS。ABB-ROM、CHKP、MP12 等研究 HIBE 及其它研究 IBS 仍通过 CLI 和报告矩阵提供；其中部分 Setup 为分钟级或依赖可选运行时，放进单线程演示服务会阻塞页面。
- 所有组合保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。
- 这是功能与交互演示，不是安全证明、生产服务或 NIST 等级声明。
- 服务默认绑定 `0.0.0.0` 以支持 WSL2 localhost 转发；只在可信本地网络使用。
