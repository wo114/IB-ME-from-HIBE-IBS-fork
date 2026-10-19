# Sageloli RSIS v3 公共接入与真实 LATTE 完整组合

2026-10-19，统筹接入交付。原始基线 `798226a` 已包含 PR58/59；实现冻结提交为 `28e5bee9adc095bb68439d3c3b1f743aea4c3e58`。本批复用 PR59 的环原生采样、两档 Appendix E 参数和 v3 编码，不再接收已关闭 PR57 的 v2 小参数登记。

## 已实现内容

- 默认 `sageloli-rsis` 选择器指向 `Sageloli-RSIS-structured-v3`，提供 `PARAM-I`、`PARAM-II` 与明确标为不安全的 `debug-small`；完整数字参数进入 Suite。
- 共同五方法、身份摘要薄包装、固定身份缓存和完整对象恢复已接入。私钥的规范字节不变；恢复校验根和每个用户陷门列的精确关系，并禁止新熵。
- CLI 增加通用 `--hybrid-limits` JSON／文件入口。显式 8 MiB 载荷预算适配 3,227,824／7,553,200 B 签名；不改变默认 64 KiB 或框架硬上限。
- 缺 Sage／显式原生库、v2 状态、错误版本／完整参数、错误陷门、不可容纳的满用户账本及不支持的签名格式均拒绝。
- wheel 包含原生 `native.cpp`，可从安装目录显式构建并独立恢复原状态。

参数、依赖和边界详见[公共接入契约](../../specs/sageloli-ring-ibs.md)；原有两档独立 IBS 的真实数据仍引用[PR59 交付](../team-b-delivery/2026-10-19-sageloli-ring-target/README.md)，不与本批完整组合混计。

## 实测和验证

验收配置为 **LATTE-3 seed32＋Sageloli RSIS v3 PARAM-I＋Hybrid＋BYTEAUTH**。身份各 64 B、应用消息 32 B，另外检查空消息；原始 v3 身份／签名输入限额为 256／4096 B，完整协议的应用消息上限为 3924 B。两档论文预设的标称强度不同，不作等安全性能排名。

论文规模测试使用一个新的系统 CSPRNG 根，不外循环重试。各 CLI 命令均为新解释器；同根组合矩阵复用该原始根与已发用户钥，后续负例与额外签名使用明确标识的固定测试流，不计为另一个全新根。失败、中止和新状态路径保留在本机私有目录。

公开收据和源文件指纹由本目录 `manifest.json` 固定；只读复核运行 `python docs/research/2026-10-19-sageloli-ring-integration/verify.py`，不读取私有状态、不重跑密码实验。测试命令、实际尺寸／时间、安装恢复及最终计数随收据归档。

## 使用方式

在规定 WSL Sage 环境，显式构建原生库（安装版也包含此源码）：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.sageloli.ring.native --directory ~/.cache/ibme-native-tools/sageloli-ring-v3
```

将构建返回的 `path` 设置为 `IBME_SAGELOLI_RING_NATIVE`；LATTE 仍按[原使用说明](../../specs/latte-hibe.md)设置 `IBME_LATTE3_EXECUTABLE`。Suite JSON 不能指定执行路径或导入代码。

```bash
export PYTHONPATH=src:.
~/miniconda3/envs/sage/bin/python -m ibme.cli check --hibe latte --hibe-params seed32 --ibs sageloli-rsis --ibs-params PARAM-I --transport hybrid --hybrid-limits docs/research/2026-10-19-sageloli-ring-integration/hybrid-limits.json --json
~/miniconda3/envs/sage/bin/python -m ibme.cli setup --state /新的私有状态目录 --hibe latte --hibe-params seed32 --ibs sageloli-rsis --ibs-params PARAM-I --transport hybrid --hybrid-limits docs/research/2026-10-19-sageloli-ring-integration/hybrid-limits.json
```

后续发发送者／接收者密钥、加密、解密沿用现有 CLI 命令，预算和唯一后端由状态读取。`PARAM-II` 已提供静态 Suite 和签名容量，但本批没有运行第二档完整组合。

重放同一套研究验收时，使用全新的私有目录和实际源码 SHA：

```bash
PYTHONPATH=src:. OPENBLAS_NUM_THREADS=4 OMP_NUM_THREADS=4 ~/miniconda3/envs/sage/bin/python -m experiments.research.sageloli_ring_integration --profile PARAM-I --source-commit 实际源码SHA --private-directory 新的私有目录
```

完整矩阵的显式选参文件为 [suites.json](suites.json)。`--plan` 只做静态预检；真实执行必须显式选择 `--suite-name latte-sageloli-rsis-v3-PARAM-I-byteauth`，不要把文件中未执行的第二档计入结果。

## 声明与未实现范围

本批是工程接入与一个论文规模完整组合的验收，沿用项目对论文安全性和 HIBE 匿名性的工作前提，不新增基础证明任务。采样器的有限浮点／FFT 总误差和原文模型边界保留；不以功能通过认证安全等级。全部安全字段继续 `none/false/false`。

未完成第二档完整组合、同口径多根性能比较、Web 新预设或新压缩格式；它们不影响第一档公共接入的验收。原 v2 SIS/RSIS 状态不迁移，矩阵 SIS 不由本批完成目标参数。私有状态是原有本地明文机制，无新增认证存储、防回滚或侧信道声明。
