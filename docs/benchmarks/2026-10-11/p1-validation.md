# V1.1.2 P1 优化与验证（2026-10-11）

状态：工作区已实现并完成隔离验证，未部署到原服务，VERSION 仍为 1.1.1。保留本轮 P0 修改；日志自动保留策略仍为 `log.retention_days: 0`。本轮不删除、归档或迁移业务数据库日志。测试使用独立 Compose 项目 `rwaf-p0-check`，没有停止业务部署。

## 本轮实现

1. **持续健康检查**：`/health/live` 检查存活；`/health`、`/health/ready` 从缓存快照判断启动、依赖、消费者、日志发送器、满缓冲、严重告警、过期与停机。未就绪返回 HTTP 503，存活仍返回 200。公开响应仅含状态和采样年龄。Compose 增加就绪检查；Nginx 转发三条健康路径。
2. **真实故障展示**：首次采样显示启动中，隐藏零日期；消费者必须为 running；采样年龄超过配置间隔加 15 秒显示 stale。页头改用公开健康接口，不再把审计员没有站点管理权限误报为服务断连。
3. **数据库容量监控**：数据库大小、七类日志/收据表含索引占用、统计估计行数、至少 60 秒窗口的增长估计、日志缓冲所在文件系统剩余空间。容量采样查询 PostgreSQL 系统目录，不对保留日志执行 COUNT(*)。数据库预算默认 10240 MiB，80% 警告、100% 严重；增长默认 1024 MiB/小时；缓冲磁盘剩余空间默认 256 MiB 阈值，均可配置。
4. **日志查询监控与约束**：统计认证后日志 GET 接口调用量、平均耗时、P95 桶、服务端错误和客户端取消；识别 HTTP 200 的业务 5xx。每页最多 100 条、页码最多 100000；5 秒数据库截止时间及请求取消传到 SQL；缓存合并等待者也按自己的上下文退出。
5. **告警正确性**：持续告警更新严重等级，恢复关闭；容量测量失败时保留前次容量/增长异常，避免未知数据被误判为恢复。所有容量告警仅提醒，不启动日志清理。

## 验收标准与结果

| 验收项 | 判据 | 最终结果 |
|---|---|---|
| 依赖故障与恢复 | PostgreSQL、Redis、Kafka 断连分别被识别；ready 503、live 200；恢复后 ready 200、相关告警关闭 | 通过 |
| 启动/过期/停机 | 未采样、过期、消费者未工作、发送器关闭、缓冲满或停止均不能宣告 ready | 单元与实际接口测试通过 |
| 容量告警 | 80%/100% 分级；持续等级升级；未知测量保留告警；恢复自动关闭 | 单元与 PostgreSQL 实测通过 |
| 增长估计 | 59 秒不报告速率；60 秒有效；负增长按零；短窗口不把已有估计清空 | 通过 |
| 日志查询监控 | 并发计数无丢失、P95 桶边界正确、重置无历史残留、业务 5xx 识别、用户取消单列 | 通过 |
| SQL 取消 | 注入 2 秒 pg_sleep，用 100 ms 上下文中断，完成小于 1 秒 | 实测约 100 ms，返回截止时间错误 |
| 缓存等待取消 | 独立 20 ms 截止时间的等待者及时退出，原查询/缓存仍有效 | 通过 |
| 保留数据查询 | 10 万以上保留日志，第一页 100 条、精确总数；本地 P95 ≤500 ms；中位数增加 ≤25%+2 ms | 两轮通过，见下表 |
| 浏览器权限与状态 | 管理员保存阈值并触发/恢复容量告警；非法值拒绝；审计员可读、API 写返回业务 403；390 px 无横向溢出 | 最终代码实测通过 |

真实依赖断连通过测试进程内 TCP 代理断开已有与新连接实现，不停止依赖容器、不修改业务部署。数据库故障时告警写入失败可通过快照观察，恢复后补记并关闭。容量故障使用 1 MiB 人工预算触发，未填满实际磁盘。

## 性能数据

Windows amd64，Go 1.25.5，Intel i7-12700H；依赖使用本机 Docker 的 PostgreSQL 16、Redis 7、Kafka 3.9.1。每轮同一份保留数据、相同 IP 筛选、页码 1/每页 100，先预热 5 次，再采样 30 次。前后对比的是同一查询处理器启用 P1 查询指标与截止时间中间件前后，未含 JWT 认证；没有把短时波动解释成 SQL 加速。

| 数据规模 | 启用前中位数 | 启用后中位数 | 启用前 P95 | 启用后 P95 | 容量采样 |
|---|---:|---:|---:|---:|---:|
| 约 10 万行 | 12.247 ms | 11.852 ms | 13.514 ms | 14.026 ms | 8.404 ms |
| 约 20 万行（最终回归） | 15.622 ms | 16.529 ms | 18.210 ms | 17.440 ms | 9.147 ms |

第一轮 P95 小幅上升，第二轮下降；最终中位数增加约 5.8%，在预设验收范围内。两轮都小于本地 500 ms P95 判据，容量采样没有随日志行数翻倍出现同等增长。本地测试不是生产 SLA，不覆盖百万级深分页、真实大请求体、长期并发压力或多个 API 实例。

健康判断第一次微基准为 205.8 ns/op、288 B/op、1 次分配；继续优化直接读取缓存后为 **108.7 ns/op、0 B/op、0 次分配**。这是判断函数微基准，不包含 HTTP 栈或依赖探测。查询指标首次并发微基准约 62 ns/op、零分配；实际路由耗时以上表为准。

## 验证过程中继续优化的内容

- 消费者有心跳但状态 starting/stopped 不能视为就绪。
- 后台采样停止、旧快照超时后不能永久显示正常；停机前撤销就绪。
- 持续告警从 warning 升到 critical 时同步更新数据库记录。
- 容量采样失败不能用缺失数值关闭尚未恢复的容量告警。
- 用户导航导致 context canceled，不算服务端失败，改为单独取消指标。
- 缓存合并等待者即使共享他人的查询，也响应自己的取消/截止时间。
- 浏览器截图发现审计员页头假报“服务连接异常”，改为公开健康接口，并重新验证管理员/审计员的启动、故障与恢复。
- 健康判断移除每次 Snapshot 复制分配，微基准分配数降为零。

## 已运行检查

- `go test ./...`：最终通过；外部依赖和浏览器测试默认跳过，需要下面的显式入口。
- `WAF_INTEGRATION=1 go test ./internal/integration -count=1 -v`：**10 项真实集成测试通过，约 91.4 秒**；两个浏览器入口在此命令中跳过，P1 单独运行。
- `WAF_INTEGRATION=1 WAF_P1_UI=1 go test ./internal/integration -run '^TestP1BrowserHarness$' -count=1 -v`：两轮真实 API + 浏览器；最终轮通过，约 154.2 秒。最终浏览器覆盖非法配置、审计员 API 权限、健康接口、页头状态和手机布局。测试结束检查 PostgreSQL 配置恢复为 10240 MiB、运行状态 ready。
- Linux 临时容器 `go test -race ./internal/ser/monitor ./internal/middleware ./pkg/telemetry ./pkg/events ./internal/service`：最终通过，随后 `go vet ./...` 通过。
- `npm run build`：TypeScript 和生产构建通过；原 ECharts 大 chunk 提示仍存在。
- `docker compose config --quiet`：通过，使用人工测试环境变量。
- Nginx 健康路径配置执行 `nginx -t`：通过。
- `git diff --check`：通过。

P0 的 PostgreSQL 原始日志隔离、事务原子性、并发修复重放、Kafka poison message 跳过与存储故障恢复、JWT 权限、旧日志保留，以及 HTTPS/域名/日志聚合均纳入这次集成回归。P0 浏览器重放没有再次单独跑，原验证见 [P0 报告](p0-validation.md)。

## 原始证据与复现

测试文件：

- [健康/容量单元测试](../../../internal/ser/monitor/p1_test.go)
- [真实依赖与日志查询集成测试](../../../internal/integration/p1_test.go)
- [真实浏览器服务入口](../../../internal/integration/p1_browser_test.go)
- [查询中间件测试](../../../internal/middleware/log_query_test.go)
- [缓存取消测试](../../../internal/service/log_cache_test.go)
- [并发查询指标测试](../../../pkg/telemetry/log_queries_test.go)

本地原始输出（output 被 Git 忽略）：`output/p1-all-integration.log`、`output/p1-query-cost.log`、`output/p1-final-go-tests.log`、`output/p1-final-unit.log`、`output/p1-final-browser-harness.log`、`output/p1-health-benchmark.log`、`output/p1-frontend-build.log`。摘要保存在 [p1-results.json](p1-results.json)。最终截图在 `output/playwright/p1-final-starting.png`、`p1-final-capacity-alert.png`、`p1-final-auditor-mobile.png`；截图人工检查已完成，最终审计员页头与监控状态一致。

PowerShell 复现普通测试与集成验证：

```powershell
$env:GOCACHE = Join-Path $env:TEMP 'rwaf-config-go-cache'
go test ./...
docker compose -p rwaf-p0-check -f scripts/integration-compose.yml up -d --wait
$env:WAF_INTEGRATION='1'
go test ./internal/integration -count=1 -v
```

浏览器入口以 19080 端口服务 `web1/dist`，写入人工测试账号 fixture；需要先验证启动中，再写 `output/p1-2026-10-11/browser-start` 启动监控，测试完写新的 `browser-done`。标记时间须晚于本次启动；入口最多等待 8 分钟。没有浏览器操作时不要开启 WAF_P1_UI。

## 实际边界与发布注意

- 仍保持单 API 告警聚合模型，多副本需要实例标识或汇总器；此次没有改成集群监控。
- 数据库预算是配置值，必须按部署规模调整；缓冲磁盘余量不能代表远程 PostgreSQL 主机余量，表行数为 ANALYZE 统计估计。
- 后台采样有间隔，默认约 15 秒加探测耗时；健康是最近样本判断，不是每请求同步探测。
- 增长率是数据库物理占用估计，会受索引、VACUUM、页扩展等影响，不能当作精确每日新增日志条数。
- 仍保留原精确计数/偏移分页语义；本轮没有声称百万日志、长年保留或高并发条件下的查询容量已验收。
- 新增配置列由 AutoMigrate 填默认值；旧 API 调用方更新配置时需包含新阈值字段。健康响应及状态码有变化，外部探活应明确使用 live 或 ready。
- 原运行服务未部署、未重启，版本号未提升。测试依赖停止并保留测试存储，未删除业务数据。
