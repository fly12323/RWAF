# RWAF

Go/Gin + Coraza 防火墙，管理界面使用 `web1`（Vue）。当前部署采用 Docker Compose、PostgreSQL 16、Redis 7 和 Kafka 3.9.1；不使用 Kubernetes。未启用的 ML 服务及其旧代码已删除。

## 请求与日志链路

所有站点共用一份防护配置，在 `web1` 的“全局防护”页面管理模式、评分阈值、规则分类、禁用规则、CC、爬虫、黑白名单开关及自动封禁。站点页面管理监听端口、域名、HTTP/HTTPS 证书、后端、负载均衡和站点启停，不再提供独立防护参数。

请求经过黑白名单、Redis CC 限流、爬虫检查和 Coraza，再转发到后端。响应流式转发，日志仅保留请求体和响应体的前 8 KiB。安全配置及名单使用短期缓存，减少请求路径上的数据库查询。

日志先写入有上限的本地磁盘缓冲，分组刷盘确认后由 3 个分片并行批量发送 Kafka，独立 `log-consumer` 内的 3 个消费者组成员按分区批量写入 PostgreSQL。Kafka 故障或进程重启时重放已接收日志；提交日志需要本地刷盘时间，不等待 Kafka 入库。事件去重记录与请求日志、规则匹配在同一事务提交；数据库提交成功后才提交 Kafka offset，重放不会重复入库。

“弱口令检测”页面集中配置认证接口和原始字典，异步匹配明文及预生成的 MD5、SHA-1、SHA-256、Base64、Base64URL 表示，只检测与告警，不阻断业务请求。检测事件本身不保存密码；普通代理日志沿用当前原始报文采集设置，实际行为见 [全量日志说明](docs/request-logs.md)。“运行监控与告警”页面显示依赖健康、Kafka 积压、消费者心跳、代理延迟与错误、日志及检测队列状态，支持告警确认与自动恢复。使用范围和检测边界见 [弱口令与监控说明](docs/detection-and-monitoring.md)。

## 启动

首次获取代码时同时初始化固定版本的 CRS 子模块：

```powershell
git clone --recurse-submodules https://github.com/fly12323/RWAF.git
cd RWAF
# 已经普通克隆的项目运行：git submodule update --init --recursive
```

在项目目录的 PowerShell 中执行：

```powershell
Copy-Item .env.example .env
# 在 .env 中设置 DB_PASSWORD、REDIS_PASSWORD 和至少 32 字符的随机 JWT_SECRET。
# 填写 ADMIN_PASSWORD，至少 12 个字符，不能使用弱口令。
cd web1
npm ci
npm run build
cd ..
docker compose up -d --build
docker compose ps
docker compose logs -f rwaf log-consumer
```

已有 `.env` 时保留原文件并补齐必填项。发布配置不包含数据库、Redis 密码或 JWT 密钥，这些值由 `.env` 提供并传入应用服务。直接启动 Go 服务时也应设置相应环境变量。已有数据库或 Redis 卷须沿用其原密码，避免改动连接密码后无法连接。

管理页面：http://localhost；API：http://localhost:8080。首次启动管理员为 `admin`，密码由 `.env` 的 `ADMIN_PASSWORD` 指定；不再创建默认弱密码。已有管理员的密码不会被环境变量覆盖，旧弱密码账号下次登录必须先改密。站点默认监听 9000；Compose 已映射 443 和 9000–9009，新增其他监听端口需同步调整映射。HTTPS 站点在站点管理导入 PEM 证书链和私钥；同端口按域名/SNI 区分站点。容器后端地址使用可从容器访问的主机名，宿主机服务可使用 `host.docker.internal`。

| 服务 | 宿主机端口 | 用途 |
|---|---|---|
| web | 80 | web1 管理界面 |
| rwaf | 8080、443、9000–9009 | 管理 API、HTTP/HTTPS 站点代理 |
| postgres | 127.0.0.1:5432 | 配置、日志与事件去重 |
| redis | 127.0.0.1:6379 | 会话、CC 限流和攻击计数 |
| kafka | 127.0.0.1:9092 | 日志事件缓冲 |
| log-consumer | 无 | 日志批量入库 |

`kafka-init` 创建 `waf-events`（3 分区、单副本）。应用和消费者等待依赖就绪。生产部署统一使用这一份 `docker-compose.yml`。

## 迁移与边界

这是新的 PostgreSQL 部署配置，**不会自动迁移旧 MySQL 数据**。旧 MySQL 备份已移出项目，不能直接导入 PostgreSQL。切换前需备份并迁移用户、站点、规则等数据；启动时会根据数据库规则重新生成 `configs/rules/custom/custom-rules.conf`，应同时备份规则目录。未对现有正式环境执行切换。

Kafka 当前采用单 broker、3 分区、单副本配置，不提供 broker 节点故障高可用。磁盘缓冲默认 1 GiB；缓冲满、磁盘写入失败或单事件过大会拒绝日志并计数，业务请求继续处理。已确认刷盘的事件在保留卷的进程重启后继续发送。`/health/ready` 表示启动完成，不是持续依赖健康检查；监控页面显示缓冲、依赖和消费状态。

数据库失败时消费者重试并保留 offset，Kafka fetch 错误持续重试；格式错误的事件仍停止消费等待处理。默认每小时分批清理 30 天前的请求、爬虫及弱口令事件，并原子删除关联规则匹配；操作审计、告警和事件去重收据保留。统计使用范围聚合、组合索引与 5 秒缓存。配置、恢复边界和 HTTPS 接入见 [本轮变更说明](docs/https-and-logging.md)。

持续负载/故障验收使用 `scripts/bench/run_readiness.py`，实际数据见 [本轮验收报告](docs/benchmarks/2026-10-07/REPORT.md)。外部告警通知和旧数据迁移尚未处理。

停止服务使用 `docker compose down`，保留数据卷。备份必须包含日志缓冲卷和 TLS 主密钥卷；后者与数据库一起用于恢复证书私钥。

## 验证

```powershell
go test ./...
go vet ./...
docker compose config --quiet
docker compose -p rwaf-upgrade-check -f scripts/integration-compose.yml up -d --wait --wait-timeout 120
docker compose -p rwaf-upgrade-check -f scripts/integration-compose.yml exec -T kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:19092 --create --if-not-exists --topic waf-test-events --partitions 3 --replication-factor 1
$env:WAF_INTEGRATION = '1'
go test ./internal/integration -v -count=1
Remove-Item Env:WAF_INTEGRATION
docker compose -p rwaf-upgrade-check -f scripts/integration-compose.yml down -v
```

集成测试只连接专用测试端口 15432、16379、29094，验证 PostgreSQL/Kafka 去重入库、Redis 限流、站点拦截与监控模式及端口切换。清理命令仅针对该临时测试项目。

文档索引见 [docs](docs/README.md)，测试工具说明见 [scripts](scripts/README.md)。
