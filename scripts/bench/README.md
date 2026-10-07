# 全系统功能与吞吐量测试

此工具只用于专用测试网络，固定使用测试用户/数据库、Kafka 主题和内部服务名称。应用使用镜像内的规则副本，不挂载项目规则目录。压测驱动和后端在 Linux 镜像内编译，避免宿主机交叉编译差异。

PowerShell，在项目根目录执行：

```powershell
New-Item -ItemType Directory -Force docs/benchmarks/latest | Out-Null
docker compose -p rwaf-bench -f scripts/bench/compose.yml build
docker compose -p rwaf-bench -f scripts/bench/compose.yml up -d api consumer backend web
docker compose -p rwaf-bench -f scripts/bench/compose.yml run --rm driver
docker compose -p rwaf-bench -f scripts/bench/compose.yml exec -T kafka /opt/kafka/bin/kafka-consumer-groups.sh --bootstrap-server localhost:19092 --describe --group waf-log-writer
```

需先构建 web1/dist。依赖使用测试端口 15432、16379、29094，不要同时启动另一份 integration-compose 测试栈。驱动依次测试功能、1/8/32/128 并发 GET、直连后端、SQLi 拦截、约 1 KiB JSON POST，以及关闭规则/CC/爬虫的代理参考值。每轮主要负载持续 10 秒，参考组 5 秒；GET 后端响应固定 1 KiB。连接复用，无外部网络或 TLS。异常状态或功能失败返回非零退出码，原始结果写入 docs/benchmarks/latest/report.json。

测试 CC 拦截时用低限额；测吞吐量时每站点/IP 设为 1,000,000 次/分钟，防止把 429 计入有效吞吐量。自动封禁独立验证，压测期间关闭。正常组保留规则、爬虫检测、CC、名单和日志链路。web1 仅检查页面、SPA 路由、JS 静态资源和 Nginx API 转发，未执行浏览器交互测试。

消费者异步入库，不能只凭 HTTP 200 判断日志完整。等待所有分区 LAG 为零，再比较 processed_events、request_logs、crawler_logs 计数与发布计数；可以在消费期间重启 consumer 验证恢复。不要把短时峰值当作长期稳定容量。

只检查功能可以先设置 `$env:BENCH_SKIP_LOAD='1'`。结束并核对结果后，清理专用测试项目：

```powershell
docker compose -p rwaf-bench -f scripts/bench/compose.yml down -v
```

最终结果见 docs/benchmarks/2026-10-07/final。

## 持续负载与故障恢复验收

先构建前端，然后运行：

```powershell
python scripts/bench/run_readiness.py --build --seconds 600 --concurrency 32
```

默认执行完整 HTTP 回归，再依次测试 GET、JSON POST、登录流量，各持续 200 秒；同时查询管理端统计。随后真实停止 Kafka、停止消费者、暂停 PostgreSQL，并强制终止 API 验证磁盘缓冲恢复。每次恢复核对发布计数、数据库收据、日志总量、重复事件与孤立规则匹配。

该脚本只允许 `rwaf-readiness-*` 测试项目，与上述短时压测使用相同宿主机依赖端口，不能同时运行。`--skip-regression` 可跳过已验证的 HTTP 回归，`--cleanup` 在结束时删除该测试项目及数据卷。结果写入 `docs/benchmarks/latest`；验证通过后应复制至对应日期目录保留，不应把十分钟数据当作全天容量承诺。
