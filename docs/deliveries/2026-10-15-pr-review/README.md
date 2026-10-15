# 2026-10-15 固定版本 PR 接收

依用户既有“有PR就审核并合并”授权，通过 `gh` 复核固定 head、源码和远端检查后合入。
这是研究代码的工程接收，不是独立人工密码学安全审查；PR29为本任务自审加回归。
没有把小参数功能测试或公开验签方程当成安全证明，全部保持 none/false/false。

| PR | 固定 head | merge | 实际复核结果 |
|---|---|---|---|
| [27 Foo–Li](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/27) | `cf1325053c4dbb1a3632f75cb45d240e83b83bca` | `2ddeeeb8128eab87019b24326bbd8b65c76b4adc` | 指定WSL Sage运行 `python ci/run.py run foo-li`：**294 passed / 0 skipped**；远端20 success、1 strict-security主动任务skip |
| [28 Yu](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/28) | `577c3e4c6c0c7a84d630628df1e9aa774daa5d2f` | `96ea8c223e87b81d19b37f524fce596cbb45d3d5` | 同环境 `python ci/run.py run yu2026`：**550 passed / 0 skipped**；16个既有JUnit警告；远端20 success、1 strict-security skip |
| [29 Lai / Xie](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/29) | `818d899b0b25b0e07c5c98f672759baa80ab11c3` | `e887cff5a20c096f6cf79d37c7181d19feef89f9` | 本地[Lai15项与Xie53项](../../research/team-c-delivery/2026-10-15-xie-study/README.md)无skip；push/PR两组远端共44 success、2 strict-security skip |

PR27/28的独立本地收据为 [foo-li.json](evidence/foo-li.json)、[yu2026.json](evidence/yu2026.json)，
JUnit同目录。收据中的12/13份测试源码指纹逐项与对应Git head比较，结果见
[source-check.json](evidence/source-check.json)。PR27/28原交付MANIFEST另有20/28份文件，
原交付收据不算本轮新生成签名；PR28的 `experiments/research/yu_delivery_check.py` 另核了
110项源码检查以及550单体/57共同检查的一致性。测试集合有交叠，不求和成总算法验收数。
远端原始元数据 [PR27](evidence/pr-27.json)、[PR28](evidence/pr-28.json)、[PR29](evidence/pr-29.json)
保留head、合并时间及完整check结论；两次workflow记录不多算独立用例。

源码审查覆盖PR27的参数/keys/codec/backend/持久服务/descriptor及固定发钥失败语义，
PR28的BPR输入容量扩展64→128、完整对象/codec/backend/issuer/主线程门槛及参数条件，
PR29的Lai精确反例、Xie修订命名/高斯/拒绝/线程限制/严格对象和公开攻击。
在各自研究范围内未发现阻止接收的工程问题，已知数学和参数缺口明确保留：

- Foo–Li：共同五方法、四对象、固定服务完成；q3/n1公开伪造及错身份/消息接受负控存在，默认登记与真实HIBE配对未接入。
- Yu：共同五方法、固定issuer和恢复完成；q3公开 `s=q*e1` 伪造保留，1—4 B消息容量不足Wang帧，descriptor明确阻止该组合；新Sage私有运算需主线程，NC1/Lemma7/正式参数和默认登记仍待。
- Lai：标签单位、Algorithm7/9类型及两层公开参数未澄清，不提供完整HIBE。
- Xie：完成显式修订的NTRU/GPV/拒绝研究核，不冒认原稿或共同IBSBackend；q平移和默认教学参数零挑战公开伪造均保留，不登记组合。

环境为 Core Ultra9 275HX、WSL2、指定 `~/miniconda3/envs/sage` 的Sage10.9/Python3.13.14。
本地单体回归使用各测试声明的固定TEST随机源，实际系统随机批次的身份/消息/次数按各原交付单列；
本轮没有重跑其原性能批次。Foo–Li按经典ROM条件，Yu的原文标准模型条件及PRF假设、
Xie的经典ROM及修订偏差分别列出，不能拼成一个已证明的共同安全模型。
这些教学/研究参数没有正式等级，测试不能替代安全证明。

本批交付仅同步接收事实和公开收据，不修改B的算法，也不升级安全准入。
C后续公共接入和Zhang核验见[本轮C交付](../../research/team-c-delivery/2026-10-15-c-framework/README.md)，
独立原语、真实组合、安装恢复、正式条件分别统计。
