# V1.1.2 P0 实现与验证报告

日期：2026-10-11（Asia/Shanghai）。两项 P0 已在工作区实现并验证，尚未部署到原运行服务；VERSION 仍为 1.1.1，本报告不是发布公告。

## 实现范围

### JSON 请求体接入

- 系统内部规则 `1000000002` 在 CRS 检测之前根据 Content-Type 选择 JSON 处理器。覆盖大小写、charset、`application/json`、规范的 `application/*+json` 子类型，并排除 `application/jsonp` 等相似类型。
- 接入独立于分类筛选、策略缓存和热重载；初始化规则不可通过管理端禁用，也不作为攻击命中证据展示。未修改 CRS 原始规则正文。
- 当前固定 Coraza 3.3.3 的 JSON 解析器使用宽松解析，适配器额外校验完整 JSON 语法，并限制嵌套深度为 128。进入正文检测后的异常 JSON、尾随数据或超深嵌套返回 400，block/monitor 均按解析错误处理，记一次审计，不计自动封禁。空正文保持原行为，正文超限仍为 413。
- 保留 CRS 独立的内容类型准入策略。选择 JSON 处理器不代表所有 `+json` 已获准放行；CRS 默认允许类型不包含这些子类型。端到端 `+json` 正向测试通过现有测试策略显式排除 920420，同时单独验证默认内容类型限制仍然有效。实际业务如需开放特定子类型，应显式配置 CRS 内容类型策略，不能用全局关闭协议规则代替调优。

### 异常日志隔离与重放

- 新增 PostgreSQL `quarantined_events` 表，保存原始字节、key、headers、消费者组、topic、partition、offset、时间、大小、SHA-256 和失败原因；二进制消息不截断，重放后也不删除原记录。
- 按消费者组/topic/partition/offset 唯一去重。隔离记录与 `log_quarantine` 告警同事务提交，隔离成功后才提交 Kafka offset。隔离或 offset 提交失败时重试，不提前获取后续消息。
- JSON 格式、事件版本/结构、大小错误直接隔离；批次中的 PostgreSQL 数据/约束错误（SQLSTATE 22/23）回退逐条入库，仅隔离失败事件，保留相邻正常事件。连接、缺表、超时、死锁和事务序列化等故障继续重试。
- 重放将校验后的事件、去重收据、规则证据、重放内容/操作者/原因、操作审计与告警恢复一并提交。行锁串行化并发重放，沿用事件 ID 去重。任一环节失败整笔回滚。
- 管理端“运行监控与告警 → 异常日志隔离”提供列表、详情、原始字节下载、管理员修复重放；管理员/操作员/审计员可读，仅管理员可重放。列表不加载原始报文。
- 默认 `log.retention_days: 0`，日志继续保留在数据库。隔离记录不参与自动清理。监控首次采样前返回空指标对象，修复初始 null 指标导致概览报错的问题。

## 同条件前后规则评估

基线提交：`d3a834d1063ebdecf26d7e097e3f16727a416d5c`；修改前后在同一 Windows amd64 / Go 1.25.5 环境评估，使用同一 Coraza 3.3.3、CRS 4.24.0 原始规则、语料、PL 与阈值组合。名单、CC、爬虫、自动封禁不参与此项测量。

- 160 个普通正常输入、124 个复杂合法输入、184 个核心攻击探针、52 个业务语义探针、3225 个支持的 CRS 正向回归样本，共 3745 个。
- PL1–4 × 阈值 5/10/15，共 12 组策略。修改前后各 44940 个事务，合计 89880 个，均无引擎错误。
- 语料 SHA-256：`161d7fd47aef53ed739d5e9b088689ee01ffa46e04dbc0efd7ebd37267116e76`。
- 原始规则正文 SHA-256：`2173632276ec6cf1e0076064caa009f8e83789c9f89c36e18a00facccee0e8da`。该指纹不包含本次新增的系统接入指令。
- 比较器核对 12 组完整性、样本唯一性、汇总与逐事务结果一致性、相同语料及 CRS 指纹；人工样本判定变化全部发生在 JSON 传输，Query/Form/Cookie 判定未改变。未发现原有预期 CRS 规则命中的丢失。

阈值 5 的主要结果，数字为“修改前 → 修改后”：

| PL | 普通输入误封 / 160 | 复杂合法输入误封 / 124 | 核心攻击探针未阻断 / 184 | CRS 样本全部预期 ID 命中 / 3225 |
| --- | --- | --- | --- | --- |
| PL1 | 6 → 0 | 19 → 19 | 44 → 28 | 1736 → 1743 |
| PL2 | 10 → 4 | 74 → 80 | 34 → 21 | 2685 → 2697 |
| PL3 | 35 → 32 | 86 → 91 | 22 → 12 | 3124 → 3136 |
| PL4 | 108 → 98 | 106 → 106 | 12 → 12 | 3153 → 3170 |

PL1/5 普通样本误封由 3.75% 降至 0%；核心探针未阻断比例由 23.91% 降至 15.22%。这些是确定性样本结果，不能解释为生产误报率、真实漏洞利用成功率或零误报保证。同一字符串的不同传输样本相互关联。

高 PL 的复杂合法 JSON 检测更充分，也会增加误封：PL2/5 增加 6 个、PL3/5 增加 5 个。其余阈值的完整结果见 [对比摘要](p0-comparison.json)。因此不建议仅凭本次修复提高 PL；复杂业务仍需要接口/参数级调优。编码 Cookie 问题和响应检测不在本轮修复范围内。

## 验证结果与边界

| 验证 | 结果 |
| --- | --- |
| 全项目 Go 回归与 go vet | 通过 |
| race 检测 | 日志事件、Coraza、代理三个包通过；临时 Linux Go 1.25.5 容器，源代码/模块只读挂载 |
| 前端 TypeScript 与生产构建 | 通过；已有大 chunk 提示保留 |
| Compose 配置语法 | 使用人工测试环境变量通过，未更新原部署 |
| 实际 Gin 代理回放 | 520 个手工样本 × 12 策略，共 6240 次，和修改后适配器结果零差异；真实本地 HTTP 后端，隔离存储边界 |
| JSON 边界 | Unicode、嵌套数组、转义攻击、Content-Type 选择/限制、异常语法、尾随数据、128/129 深度、空正文、超限、观察模式、单次审计、缓存/热重载通过 |
| 真实 PostgreSQL 隔离/重放 | 原始二进制保留、重投去重、告警同事务、无效重放拒绝、审计失败回滚、并发重放串行、重复事件不重复入库通过 |
| 真实 Kafka 故障恢复 | 专用 3 分区主题/3 worker；先让隔离写入失败，确认后续事件未入库且 lag 未清零；恢复后 4 条坏消息完整隔离、2 条正常唯一日志入库、lag=0；重启后数量一致 |
| API 权限 | 真实 JWT/Redis 会话验证：未认证拒绝、三角色可读、非管理员不可重放；无效/成功/重复重放按既有 HTTP 200 信封返回业务 code 400/0/409 |
| 原有集成回归 | 并发初始化、HTTPS/SNI、证书更新、统计、显式清理、事件去重、Redis CC、站点及观察模式通过 |
| 默认日志留存 | 自动清理 worker 默认退出，一年前的请求与关联规则证据仍在数据库 |
| 真实浏览器 | 管理员登录、隔离详情、无效 JSON 提示、修复重放、原始记录保留、审计员只读通过；浏览器操作后 PostgreSQL 核对只入库一条日志 |

Kafka 存储故障采用专用 PostgreSQL 触发器故障注入，并非停止原运行环境的数据库。本轮没有测量持续吞吐、TLS 性能或生产业务准确率，不能宣称性能提升。隔离链路只保护已经进入 Kafka 的消息；发布端因缓冲满、磁盘失败或事件过大而拒绝的日志，仍受原有发布器边界限制。

浏览器验收另发现首次监控采样前指标为 null 的原有问题，已修复并通过对应回归。浏览器核心重放流程验证使用真实管理 API 与测试 PostgreSQL/Redis，不使用模拟 API。

## 原始产物与复现

本地原始结果在 `output/p0-2026-10-11/`：`before/`、`after/` 的 corpus/outcomes/summary，逐条差异 `changed-verdicts.json`、Go/联调/race/代理回放/前端日志及浏览器 fixture。截图在 `output/playwright/p0-*.png`。本地 fixture 仅包含人工测试账号，不提交。

```powershell
$env:GOCACHE = Join-Path $env:TEMP 'rwaf-config-go-cache'
go test ./...
go vet ./...
go run ./scripts/accuracy -out output/p0-2026-10-11/recheck
$env:WAF_ACCURACY = '1'
$env:WAF_ACCURACY_DIR = 'D:\Project\waf-coraza\output\p0-2026-10-11\recheck'
go test ./pkg/proxy -run 'Test(JSONActualCRSPipeline|AccuracyCorpusMatchesProxy)' -v -count=1
Remove-Item Env:WAF_ACCURACY, Env:WAF_ACCURACY_DIR
python scripts/accuracy/compare.py output/p0-2026-10-11/before output/p0-2026-10-11/recheck --out output/p0-2026-10-11/recheck-comparison.json
docker compose -p rwaf-p0-check -f scripts/integration-compose.yml up -d --wait --wait-timeout 120
docker compose -p rwaf-p0-check -f scripts/integration-compose.yml exec -T kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:19092 --create --if-not-exists --topic waf-test-events --partitions 3 --replication-factor 1
$env:WAF_INTEGRATION = '1'
go test ./internal/integration -v -count=1
Remove-Item Env:WAF_INTEGRATION
docker compose -p rwaf-p0-check -f scripts/integration-compose.yml stop
```

`before/` 是修改前保存的结果；只有实际检出实现回退到上述基线时才能重新生成同义基线。不要用修复后的代码覆盖该目录。已有 CRS 子模块工作树变更未改动。

本轮专用测试依赖容器已停止，保留测试数据库供复核，没有执行删除卷或原运行实例日志清理。

## 升级说明

需同时重新构建/更新 API、消费者与前端，启动迁移新增隔离表；旧请求日志不回填。数据库备份覆盖隔离原始消息与重放证据。API/消费者启动后才应用新的数据库结构和 JSON 接入，现有服务进程尚未更新。

默认不自动删除日志；已有部署显式配置正数 `retention_days` 时仍会清理，升级时需确认实际配置为 0。手动清理接口继续保留，只在明确管理员操作时运行。隔离状态没有“忽略并删除”入口，重放成功仍保留原始证据。
