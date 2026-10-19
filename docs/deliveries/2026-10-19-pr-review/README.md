# 2026-10-19 远端 PR 接收记录

按用户要求停止子智能体后，本批由主智能体独立审查 PR50–55；PR50 的版本与 234 passed／29 skipped 回归见[前批接续记录](../2026-10-18-pr49-50-review/README.md)。本批精确原 head、状态和验证见 [validation.json](validation.json)，最终合入提交以各 PR／Git 记录为准。

## PR51

保留演示作者和队友提交，核对 Falcon-512／ML-DSA-44／Luo 预设与已接收展示卡，后端异常不计为拒绝。另发现正常解密得到错误明文仍会报符合预期、`None` 会被当作 BOTTOM 的两项判定问题，已修正为正常模式比较原消息，且只接受明文字节或协议 BOTTOM。

规定 WSL conda Sage 环境原 `tests/test_webui.py tests/test_ci_catalog.py` 为 38 passed；新回归先 3 failed，修复后 **41 passed、0 skipped**。启动脚本 Bash 语法检查通过。三个 JUnit 回执保留在 evidence 中。

原始演示收据、provenance 和 369 项历史校验保持原字节。当前 server／测试与原版本的差异经 `evidence/demo-source-bridge.json` 显式绑定：原源码快照匹配原 provenance，当前文件匹配审查散列，然后才运行原校验器。运行 `python docs/deliveries/2026-10-19-pr-review/evidence/verify_demo.py` 得 **369 checks passed**、2 项明确源码桥接；未重跑历史性能／浏览器实验，也未把历史 38 项当作新版本回归。

## 其它待接收项

PR52 为 Sageloli CI 状态；PR53 为 SRGG 无损编码与资源实测；PR54 为 ABB 条件参数前沿；PR55 为相同 wheel 在 WSL 文件系统的部署。此记录首次提交时它们仍在审查，后续逐项更新验证结果。

安全与运行口径沿用原交付，全部保留 none/false/false；网页是进程内会话，服务重启持久恢复仍由 CLI 处理。

## PR52

两条 Sageloli 路线仅调整为 backend.py／standalone_source，测试选择不变。CI 目录 25 passed、0 skipped；计划保存在 `evidence/pr52-plan.json`。CI 当前字节为12493 B，SRGG 发布桥接同步固定该指纹；246项原清单仍为243直接匹配＋3显式桥接，普通及 `-O` 校验通过，原 validation／快照未改。

## PR53

三份 codec／benchmark／表示盘点专项在规定 Sage 下 **107 passed、0 skipped**（26.21秒）。审查四种对象的原 JSON／context 保留、固定参数头、精确 signed 编码、规范 padding／宽度、缓存状态及先检查容量后分配；未改算法或默认服务。原公开核验器通过：27 workers、495功能检查、76清单文件、122源码。实测为作者归档记录，本轮未重新生成9个根或重跑历史时间／RSS；压缩不被表述为同倍率内存下降或算法加速。

## PR54

前沿、噪声分类、完整基资源、缩放比较及 CI 目录测试 **116 passed、0 skipped**（22.67秒）。另真实重建四行公开几何／有限 CDF，复用原估计结果及其计时再分类，除环境／测量／当前源码指纹外完整数学 payload 相同；未重跑估计器。当前为2个实现研究候选、0个双侧比较候选、0个完整运行候选，资源下界和固定随机 tape成本均显式保留。重放输出为 `evidence/pr54-replay.json`，在仓库根以规定 Sage 运行 `docs/deliveries/2026-10-19-pr-review/evidence/replay_frontier.py --output <new-output.json>` 可复验。

## PR55

核对 WSL wheel 安装的路径限制、文件指纹、额外模块拒绝、缓存独占锁及部署入口；未改变原语或协议。规定 Sage 下部署工具、Web、装配、BYTEAUTH 与 Hybrid 回归 **111 passed、0 skipped**（89.46秒），Bash 语法通过。真实构建当前集成树 wheel（SHA-256 `43c3651c83f06a3b105c7f2ccca7580e5c3d52cbc8fb9971acac058a9448bba5`），在 Linux `/tmp` 独立目录首次安装与再次缓存命中均核验552个文件，全局环境不变。这是当前部署 smoke，未将其当成新的密码学基准。

原性能证据检查 **3449 passed**：541个打包文件与固定原Git字节完全相同，2376项加载provider核对一致，三路每路30次观测的中位数与原数据相符；本轮没有重跑历史计时或15步真实CLI。结论仍限相同wheel在本机文件系统布局的部署开销，不能写为算法或安全等级提高。

PR55 增加 `run_web_demo.sh --wheel`，故原演示证据的显式源码桥接从2项增至3项；原启动脚本快照、原 provenance 和数据保持字节，再运行原369项核验通过。其它文件若有未批准漂移仍会拒绝。

## 验证入口与修改范围

每份 JUnit 和公开重放均在 evidence；具体测试选择见回执中的 testcase，前沿重放脚本支持新输出路径。主要修改范围为原PR源码/材料，以及本目录的审查记录；额外修复只涉及 Web 判定、ABB 行参数绑定及已批准源码/CI的历史校验桥接。原B分支和本地 Foo–Li WIP 未动。各原始PR head保存在 validation.json，最终合入提交和消息可从对应PR/Git查看。
