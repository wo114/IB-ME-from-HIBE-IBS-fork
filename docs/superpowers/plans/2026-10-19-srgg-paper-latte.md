# SRGG论文参数公共接入与LATTE完整组合实施计划

日期2026-10-19，代码基点b92967b。用户已选择执行前一轮提出的SRGG论文参数接入工作；本线程直接实施，不调用子智能体。旧报告及PPT不改。

目标：通过独立ID `srgg2025-paper` 接入现有Table4算法与三组固定参数，支持reference和compact签名，完成真实LATTE组合、CLI持久恢复及PARAM-I重复完整基准。

设计：新增独立适配器，内部复用paper_backend及paper_compact，不改变采样、参数解释、H1/H2、规范JSON对象或既有FixedIssuer。公共参数类只选择固定profile和interpretation，发现/预检不导入Sage算术、不生成密钥。公私钥继续使用原规范JSON；compact只在签名边界应用，拒绝自动跨格式加载。新ID归属同一SRGG论文路线，不新增算法计数。主样本使用table-standard-deviation解释，已有其他解释保留显式选择。

技术环境：公共Python参数/描述符、WSL `~/miniconda3/envs/sage`执行原语、已有LATTE native、Hybrid和BYTEAUTH。源码在Windows挂载目录，计时口径如实记录；不把新组合与旧WSL wheel优化混作同一对照。

文件认领：新增`src/ibme/ibs/srgg/paper_registration.py`、`paper.py`、`tests/test_srgg_paper_registration.py`、`tests/test_srgg_paper_assembly.py`及本批交付目录；仅在公共registry、算法catalog增加明确入口/映射，必要时调整依赖默认数量的测试。CLI、协议、HIBE和冻结采样器不改。

- [x] 先写并运行失败测试：独立ID、三档显式参数、发现零熵且不导入Sage、严格配置、签名容量上界、保留19路线。
- [x] 实现公共参数/懒加载对象解码与后端适配；原JSON公私钥不变，reference/compact不能自动降级，compact仍执行原范数和维度门。
- [x] 使用真实原语测试参数/上下文错配、两种签名格式、规范解析与范数拒绝；原后端/codec/新适配器158项通过，新增上下文检查10项通过。公共框架回归另行收口。
- [x] 生成显式LATTE suite清单：先预检所有配置。共同runner实际执行四种身份匹配、wire及签名修改、恢复；不以mock替代。PARAM-II/III至少compact真实组合验收。
- [x] 将实现形成固定Git提交后，使用既有full_system_benchmark对PARAM-I reference/compact各3独立根、9对warm、9次新进程零熵恢复。身份64 B、消息32 B；单条命令300秒上限，失败保留且不补抽根。
- [x] 用同一已固定源码检查独立CLI建立/发钥/加解密/新进程恢复；打包后验证新适配器可安装，公开证据不含运行秘密。
- [x] 校验公开收据与源码、配置和参数，更新唯一当前进度/目录/使用说明。1824条基准provider、154条安装CLI provider核对通过。
- [x] 实现7573014、材料a8c5f6f已推送队长仓库并创建[PR58](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/58)；未合并。

停止边界：不改旧degree8默认实现，不启动新参数网格、基础证明或其他原语。若保守容量不适配则显式选合法Hybrid载荷预算，不删减签名或截断消息。公开说明分开列原语参数、输入、次数、环境、ROM、采样解释和none/false/false；功能/性能不是安全证明。
