# V1.1.2 发布前复查（2026-10-11）

结论：对当前工作区候选的 P0/P1 运行路径、异常分支、日志保留、权限、故障恢复与构建重新检查，发现三项问题并完成修复和验证。本轮检查范围内未发现仍未修复的发布阻断问题，可进入发布准备。复查结束时未提交、未部署，VERSION 与前端包版本仍为 1.1.1。随后按用户发布要求统一更新为 1.1.2；正式发布记录与升级说明见 [CHANGELOG](../../../CHANGELOG.md)，本报告保留复查时的测试范围与结果。

## 发现并修复

| 问题 | 实际影响 | 修复和证据 |
|---|---|---|
| Redis 消费者心跳是 JSON null | JSON 解析成功但 map 为 nil，写 stale 字段会 panic；后台 goroutine 无 Recovery，可能导致 API 进程退出 | 增加独立心跳解码，拒绝 null、非对象、缺失/错误时间戳；真实 Redis 连续写 null 和错误类型，监控降级、live 保持 200，正常心跳恢复后 ready 恢复 200 |
| 共享统计查询发起者取消 | singleflight 使用发起者上下文；正常等待者可能收到另一个请求的取消错误 | 等待者自己的上下文仍有效且共享结果为取消/截止错误时，使用自己的查询上下文独立重试一次；保留自身取消响应和普通数据库错误语义。新增取消发起者/独立等待者并发回归，race 通过 |
| 页面刷新失败保留旧正常状态 | 监控接口断连后旧 snapshot 的 age/status 不再更新，页面可能一直声称正常 | 根据服务端样本年龄加本地接收后经过时间计算有效期；超时显示 stale 并撤销页面就绪；实际浏览器仅断开 monitor/status 请求，超过 20 秒显示过期，恢复真实 API 后显示正常 |

对应实现与测试：[监控服务](../../../internal/ser/monitor/service.go)、[异常心跳测试](../../../internal/ser/monitor/p1_test.go)、[真实依赖测试](../../../internal/integration/p1_test.go)、[统计缓存](../../../internal/service/log_cache.go)、[缓存取消测试](../../../internal/service/log_cache_test.go)、[监控页面](../../../web1/src/views/modules/MonitorView.vue)。

缓存独立重试只处理上下文取消/截止错误，不对其他数据库错误重试；仍遵守调用方原有截止时间。该特殊重试不使用共享缓存写入，避免把发起者的失败持续传给其他用户。页面年龄使用本地接收后的经过时间，不依赖浏览器时钟与服务器时间完全一致。

## 本轮执行的验证

| 检查 | 结果 |
|---|---|
| go test ./... -count=1 | 通过；普通入口默认跳过外部依赖/受控浏览器/全语料回放，另行显式执行如下 |
| WAF_INTEGRATION=1 go test ./internal/integration -count=1 -v | 10 项通过，113.633 秒；包含新增异常心跳恢复、P0 隔离/重放原子性、存储故障恢复、权限、禁用自动清理、HTTPS/域名/统计 |
| WAF_ACCURACY=1 + P0 after 目录，真实代理回放 | 6240 个 HTTP 请求通过，判定差异 0，21.722 秒；使用之前同语料评估输出，不是重新生成 89880 次前后评估 |
| 真实浏览器及实际 API 服务 | 启动、正常、监控请求断连、样本过期、恢复通过；后端检查配置为 10240 MiB 且 ready；160.238 秒 |
| Linux race | monitor、service、middleware、telemetry、events、coraza、proxy 七个包通过 |
| go vet ./... | Linux 临时容器中通过 |
| Linux CGO_ENABLED=0 构建 | server 和 log-consumer 两个入口通过，产物在 output/v112-recheck-rwaf、output/v112-recheck-log-consumer |
| npm run build | TypeScript/生产构建通过；已有 ECharts 大 chunk 提示保留 |
| git diff --check | 通过 |

Linux 构建过程中 Windows 模块缓存写入 main module 版本信息出现权限提示，但命令退出为 0、两个可执行文件已生成；测试使用 temp 中的 GOCACHE。镜像构建/正式服务替换未执行。Go vet/race 使用只读仓库挂载的临时容器，不修改业务部署。

容量性能回归继续保留测试数据，在约 30 万行时：前中位数 18.797 ms、后中位数 22.198 ms，前 P95 25.355 ms、后 P95 31.463 ms；容量目录采样 10.780 ms。符合既定本地 P95 ≤500 ms 和中位数增加 ≤25%+2 ms 判据。本轮没有把该波动解释为 SQL 加速；不是长期生产或百万级深分页 SLA。

## 日志与发布边界

- configs/config.yaml 与加载默认仍是 log.retention_days=0；自动清理退出。容量/增长告警不删除或迁移数据库日志。集成环境中的显式保留期函数测试只操作隔离测试数据，未操作业务数据库。
- JSON 处理器接入、128 层语法边界、系统规则不可禁用、毒消息事务隔离、offset 提交顺序和管理员重放保持原设计；新修复没有修改 WAF 检测策略。
- 高 PL 的复杂合法 JSON 误报、编码 Cookie 检测边界仍见 [P0 报告](p0-validation.md)，不能宣称所有业务准确率问题已解决。
- 依赖仍为单 Kafka broker/单 API 聚合模型；容量预算不是数据库物理磁盘余量，需按部署调整。ready 是缓存状态，存在采样延迟；到达严重容量预算会撤销就绪，外部负载均衡使用前须了解该语义。
- 正式发布需统一 VERSION/前端版本与发布记录，并从明确的受审代码范围构建。工作区已有无关子模块变更及 ml-service、.archify 等未跟踪目录，本轮未修改这些内容，不应整目录随意纳入发布。
- 复查过程中未提交、推送或部署；隔离测试服务已停止并保留测试存储。

## 本地证据

原始输出：output/v112-recheck-go.log、output/v112-recheck-integration.log、output/v112-recheck-accuracy-replay.log、output/v112-recheck-browser.log、output/v112-recheck-frontend.log。浏览器截图：output/playwright/v112-monitor-stale.png、v112-monitor-restored.png；已人工检查过期状态和恢复。output 由 Git 忽略，测试入口与报告保留在代码中。

本报告补充 [P0 验证](p0-validation.md) 与 [P1 验证](p1-validation.md)，不替代其中对原样本、权限和容量测量的详细说明。
