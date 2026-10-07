# RWAF 辅助工具

此目录不是生产服务源码。生产入口位于 `cmd/server` 和 `cmd/log-consumer`。

| 路径 | 用途 |
|---|---|
| `integration-compose.yml` | Go 集成测试所用 PostgreSQL、Redis、Kafka 临时依赖环境 |
| `bench/` | 完整 HTTP 回归、压测、故障恢复验收及专用测试后端，详见其 README |
| `test/` | SQLi、XSS、CC、爬虫等防护用例；`run_all_tests.py` 运行整组 |
| `demo/` | 创建演示站点、生成流量和检查演示记录；可能修改测试配置或创建用户 |
| `generate_normal_traffic.py` | 可指定目标与速率的正常流量生成器 |

工具应针对专用测试或演示环境运行。测试中的密码、令牌标记和攻击样例是人工测试输入，不应复用为生产凭据。生成结果与本地 `.env` 文件不上传 GitHub。
