# 首次计时失败记录

本轮首次运行完成 5 组测量后，保存公开参数 metadata 时失败，退出码 1：`TypeError: Object of type bytes is not JSON serializable`，字段为公开的 `hibe_parameters.limits.backend_id`。raw.csv 是部分产物，没有完整环境/源码收据，不用于 README 的正式数值。

已修复：仅对公开参数做显式 bytes→带编码说明的 hex 转换，并在计时前预检 JSON；增加回归测试。此记录保留失败，没有把未完成的归档算作验收通过。
