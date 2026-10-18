# PR39 文档复核与候选实现盘点

日期：2026-10-18（Asia/Shanghai）。依据用户此前对全部PR的审查和合并授权，审查[PR39](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/39)固定head `18a493c147b6adeebe2be93c83fe0db861f6cdae`，基线 `44727751b647c98b4c76961c575c667c2ab35d12`，已合入远端 `2b9741b548dd63075b61807a55f5f963e5c3bc19`。本地同时保留用户确认的安全性/匿名性工作前提及继续3m的计划提交，没有覆盖这些新决定。

## 复核范围和结果

PR只修改 `IMPLEMENTATION_SPEC.md` 的LATTE默认登记状态句及 `docs/FRAMEWORK_REUSE_GUIDE.md`，没有算法、参数或运行代码变更。核对注册器、descriptor、预设选择和runner源码，文档描述与实际调用一致，未发现阻止合并的问题。

- 对固定head的两份文档逐个解析并核对69个本地链接，全部存在于相应Git树；复用指南13个编号章节及其顺序不变，README对象未变。
- `git diff --check 44727751b647c98b4c76961c575c667c2ab35d12 18a493c147b6adeebe2be93c83fe0db861f6cdae`：通过。
- 在仓库根为Python进程设置 `PYTHONPATH=src` 与仓库根，使用Windows Python 3.12.14执行 `python -B -m experiments.run_combination_matrix --plan --suite-file ci/c-combinations.json`：`preflight_only`，10项 `unavailable`，`executed_cases=0`、`executed_checks=0`。该结果验证预检示例及缺依赖处理，不是10套实际组合通过。
- 合并前再次读取固定head与远端检查：23项成功、1项预期手动 `strict-security` 未执行；未绕过检查。合并后读取PR状态为 `MERGED`。
- 后续盘点文档的168个本地链接全部存在，`git diff --check`通过；原始证据及用户新确认的工作前提和3m选择均保留。

仅进行文档/源码边界核对及公开配置预检，没有重跑密码学生命周期或生成密钥；沿用现有参数和安全元数据，没有新增安全结论。

## 19条候选的实现口径

“完成”在此指已有完整独立原语研究后端，不要求所有参数可部署，也不等于默认登记、CLI、全部配对和评测都已完成。

| 分类 | 已形成完整独立研究后端 | 尚未完成 |
|---|---|---|
| HIBE：8条 | 3条：CHKP、ABB-ROM、LATTE | 5条：Lai、Zhang、GKR、ABB标准模型、CHKP标准模型 |
| IBS：11条 | 10条：Luo矩阵、Luo模格、SRGG、Yu、Sageloli SIS、Sageloli RSIS、Foo–Li、Wang–PW、BNN-ML-DSA、BNN-Falcon | Xie：有修订研究核，但不是完整共同IBSBackend |

合计13/19。MP12实现变体、同算法参数档和编码不新增候选算法计数。GKR/ABB标准模型/CHKP标准模型继续暂缓；尚未完成的活跃候选为Lai、Zhang、Xie，具体实现问题继续按owner和当前任务处理。Sageloli旧表中的“仅数学探针”已过时，本次只更新该实现状态，不将历史收据改成新一轮实验。

Foo–Li、Yu、Sageloli及SRGG新增路线的公共接入/容量/真实配对仍按各自范围验收；所有就绪池的目标参数、同口径性能比较和作品交付也未因后端存在而自动完成。安全性/匿名性补充证明不作为当前待办，工作前提和3m版本选择以[当前项目状态](../../PROJECT_STATUS.md)为准。
