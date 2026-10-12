# A 第二批：可安装公共入口、默认选择与实际 CLI

基点 `7795719`；实现提交 `887aa5c`，2026-10-12。A 仍进行中。前批 Source HIBE 的数学、参数、对象类和 wire 保持；本批补安装包/公共工具入口、可选后端登记和 native 程序的操作前准入。原 CHKP、忠实 ABB-ROM、正式维度/攻击估计与模型条件未因此完成。

## 1. 交给其他方案使用的入口

- `ibme.lattice.research`：有限 Gaussian/options、GPV、DelTrap、完整基/扩展、计算型根。按需导入 Sage，普通 import 不初始化 Sage 或发钥；公开对象就是原 provider 对象，没有复制第二份算法。
- `ibme.hibe.mp12_chkp`：六方法后端、五类对象/params、registry/spec。安装包包含必要研究支持 namespace；数学唯一实现仍在原文件，本批不改队友 `chkp_*` 或 IBS。
- `default_registry`：加入明确 ID `mp12-chkp-reference`，不是原 CHKP 的别名。无 Sage 时明确 unavailable，无教学/mock回退；Sage 下允许恢复已保存完整密钥。
- 新根和新接收者需要 `IBME_QFALL_PRIVATE_ENGINE` 指向已构建的 native 算术程序。缺少程序时在熵和身份地址写入前拒绝；旧接收者/叶复用、从已保存完整父基派生不调用它。

跨文件修改是为安装和默认入口接入：主集成 owner 的 `pyproject.toml`、`src/ibme/assembly/registry.py`，以及 A 自有模块/测试。冻结协议方法、原 HIBE/IBS 参数和旧 guard 不改变。

## 2. 实际安装验证

从新的 A 独立工作树构建 wheel，经 pip 安装到独立目录。探针都用 Python `-I`，工作目录在仓库外，唯一追加的 Python 路径是安装目录。运行时逐个检查 `ibme/experiments` provider 来源，不能靠仓库 `src/` 或本机旧 editable 安装通过。

| 验证 | 本轮实际结果 |
|---|---|
| Windows 安装入口 | 3检查；34个已载入 provider 全来自安装目录；无 Sage 明确 unavailable |
| 指定 WSL Sage 安装入口 | 10检查；63个 provider 全来自安装目录；实际有限 Gaussian 调用 |
| 安装包加载前批私有实物 | 四种身份匹配、完整主/接收/发送密钥绑定与规范恢复；无 engine/无熵/新增生成0 |
| 没有 native 程序 | Setup 拒绝，已有 receiver 复用成功；新 receiver 拒绝且主状态字节不变 |
| 安装包实际 CLI | 新根、发 Alice/Bob 密钥、加密、首次叶派生解密、第二进程恢复、旧 receiver 复用、篡改拒绝；8步，84.438 s |
| 新 CLI 尺寸 | 41B明文、117505B完整密文；原身份3/5B、内层86B、seed32B；一次实际批次 |
| Sage 源回归 | 新公共入口7项 + 既有真实 HIBE48项，共55 passed，无skip |
| Windows 源回归 | 公共入口及既有装配/CLI/组合：90 passed / 2明确Sage skip；skip不记pass |

测试耗时是诊断总时间，不是公平性能比较或联合优化结论。CPU Intel Core Ultra9 275HX，Sage10.9/Python3.13.14/cryptography49.0.0；Windows Python3.14.6。n2/q549755813911/s_R²16 与前批相同，已知公开隐私攻击仍成立，`none/false/非正式` 保持。

原私有数据按字节一致地复制到**新工作树的被忽略 test-results**供兼容验证，不生成替代 key；新 CLI 私钥/状态也只在忽略目录。Git 归档公共收据/环境/源和 wheel 指纹，不归档秘密。

## 3. 可移交命令

在源码目录构建并安装到指定 Sage；Sage 本身采用 WSL `~/miniconda3/envs/sage`：

```bash
python -m pip wheel --no-deps --no-build-isolation --wheel-dir test-results/a-install/wheels .
~/miniconda3/envs/sage/bin/python -m pip install --no-deps test-results/a-install/wheels/ibme-0.1.0-py3-none-any.whl
export IBME_QFALL_PRIVATE_ENGINE="$(pwd)/test-results/qfall-target/release/ibme-qfall-private-root"

~/miniconda3/envs/sage/bin/python -m ibme.cli setup --state a-reference-state \
  --hibe mp12-chkp-reference --hibe-params n2-reference --ibs luo-module \
  --transport hybrid --signature-format compact
~/miniconda3/envs/sage/bin/python -m ibme.cli issue-sender-key Alice --state a-reference-state
~/miniconda3/envs/sage/bin/python -m ibme.cli issue-receiver-key Bob --state a-reference-state
~/miniconda3/envs/sage/bin/python -m ibme.cli encrypt --state a-reference-state \
  --sender Alice --receiver Bob --in message.bin --out message.ct
unset IBME_QFALL_PRIVATE_ENGINE
~/miniconda3/envs/sage/bin/python -m ibme.cli decrypt --state a-reference-state \
  --sender Alice --receiver Bob --in message.ct --out recovered.bin
```

`*-state/` 是私有运行状态，不提交/发送；上述预设只能调试。原 `chkp` 未交付标记继续保留，不用新 ID 偷换论文原算法。构建 native 程序仍使用既有冻结 qFALL 源；安装包不内置未知平台可执行文件。

两个可重放探针：[公共安装验证](../../../../tests/install_probes/verify_research_api.py)、[CLI 实际链](../../../../tests/install_probes/verify_research_cli.py)。必须在仓库之外、`-I`、新输出/新私有目录执行；确切参数和 receipts 见本目录审计。

## 4. 版本边界与剩余任务

实现期间原共享工作树被切到 `codex/pr-review-integration-2026-10-12` 并合入 PR #9。A 的7份自有改动按 SHA核对后转入 `a-matrix-implementation`，只释放原树中这些已转移并提交的改动，保留整合提交和其它人的状态。最终本批基于7795719，**没有包含 PR #9**；共同工作树那次混合 wheel 不是交付候选。

当前包装直接包含原研究 namespace（130条 wheel 成员、87个支持 Python 模块）。这维护单一算法来源；不是另写一个密码实现，也不把所有打包的研究脚本当已准入后端。后续可分离构建范围，但不把它作为下一轮主编码。

本批实际补齐 A1 的安装/默认入口缺口、A3 的公开工具入口。WIP：原 CHKP/ABB-ROM、目标维度与资源、可引用的 MP12 变体模型、根/密文两角色攻击估计、正式参数仍缺。A2 应使用这些公共工具推进原文算法，不继续仅增加n2样本。

修改清单：`src/ibme/hibe/mp12_chkp/__init__.py`、`src/ibme/lattice/research/__init__.py`、`pyproject.toml`、`src/ibme/assembly/registry.py`、A自有 `hibe_reference.py/hibe_registry.py`、`tests/test_public_research_api.py`、两个安装探针、本目录收据与当前状态/任务登记。准确命令与指纹见[audit.json](audit.json)。
