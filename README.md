# IB-ME from HIBE + IBS

一个共享的身份基匹配加密研究框架：独立实现 HIBE 和 IBS，再通过王老师的两层匿名 HIBE＋IBS 通用构造装配。身份顺序固定为 `(rcv, phi)`，复用 Hybrid、BYTEAUTH、CLI、状态恢复和评测工具。

## 从这里开始

| 你要做什么 | 入口 |
|---|---|
| 看当前完成情况、负责人和剩余工作 | [当前进度](docs/PROJECT_STATUS.md) |
| 找文档、代码、参数和历史证据 | [仓库与文档导航](docs/README.md) |
| 选择后端、预检、使用 CLI | [框架使用指南](docs/FRAMEWORK_USAGE.md) |
| 启动本机演示界面 | [Web 演示说明](src/ibme/webui/README.md) |
| 看报告选定的三组组合及完整配置 | [三代表与冻结 Suite](docs/deliveries/2026-10-19-report-three-selection/README.md) |
| 阅读或修改当前报告 | [报告说明](docs/reports/2026-10-19-research-draft/README.md) · [LaTeX](docs/reports/2026-10-19-research-draft/研究报告初稿.tex) · [PDF](docs/reports/2026-10-19-research-draft/研究报告初稿.pdf) |
| 参与开发或接入原语 | [架构](ARCHITECTURE.md) · [接口与验收](IMPLEMENTATION_SPEC.md) · [协作流程](AI_WORKFLOW.md) · [仓库规则](AGENTS.md) |

## 当前能力与展示范围

公共装配层支持分别选择 HIBE、IBS 和各自参数，发钥前检查版本、能力及容量。LATTE、Lai C2 与多种 IBS 已有真实完整组合记录；ABB-ROM、CHKP 及明确命名的 MP12 变体也保留各自研究后端和实验边界。具体完成情况统一在进度页维护，后端登记和完整组合实跑分别判断。

报告已选定 A＝LATTE＋BNN/ML-DSA-44、B＝LATTE＋SRGG 论文 PARAM-I compact、C＝Lai C2＋Sageloli RSIS v3 PARAM-I。它们用于说明不同实现价值，不能称为三个性能冠军，也不代表三种 HIBE。当前 Web 预设仍是 LATTE＋ML-DSA／Falcon／Luo，和报告三代表是两个集合。

报告采用 LaTeX→PDF；旧 Markdown、Word、作品报告和 PPT 保留为历史材料。接口接入、研究功能、正式参数与安全声明分别记录，当前相关组合的安全字段维持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。已知不安全的小参数和公开反例见[安全回归记录](docs/KNOWN_SECURITY_GAPS.md)。功能测试不替代安全证明。

## 运行入口

在仓库的 WSL 路径下，使用项目指定的 Sage 环境查看后端和兼容性：

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m ibme.cli list-backends
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m ibme.cli check --hibe latte --ibs cert-ml-dsa --transport hybrid
```

本机演示的完整启动、原生依赖构建与运行副本说明见 [Web 演示说明](src/ibme/webui/README.md)。CLI 状态恢复、参数选择和组合测试命令见[框架使用指南](docs/FRAMEWORK_USAGE.md)。

## 目录分工

```text
src/ibme/       公共装配、协议、原语适配器、CLI 与界面
experiments/    运行驱动、研究实现与对照实验
tests/          自动测试与固定向量
ci/             检查分组与执行入口
params/         教学参数样例；实际配置还可能在后端及冻结 Suite 中
docs/           当前进度、契约、报告、交付与历史证据
papers/         论文及来源清单
```

部分公开适配器会调用 `experiments/research/`，安装包也包含其中的候选模块；研究目录中的代码不全是可随意移动的草稿。文档位置和维护约定见[仓库与文档导航](docs/README.md)。
