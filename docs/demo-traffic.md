# RWAF 本地演示流量

仅对专用演示环境运行以下工具。它们会创建演示站点、配置检测、发送正常与攻击样例流量，并产生请求日志和告警。

先按照根 README 配置并启动 RWAF，然后构建专用演示后端：

```powershell
docker build -t rwaf-bench-driver:local scripts/bench
docker compose -f docker-compose.yml -f scripts/demo/compose.yml up -d demo-backend
python scripts/demo/traffic.py
```

`traffic.py` 默认从本地 `.env` 获取管理员密码，也支持 `DEMO_USERNAME` 与 `DEMO_PASSWORD` 环境变量。管理员登录会替换已有管理员会话；可使用专用演示操作员账号。

`sustained-traffic.py` 针对上述演示站点端口 9008 生成有限时长流量；`generate_normal_traffic.py` 可设置其他目标与速率。`verify-details.py` 校验特定演示记录并可能创建专用用户，只有保留对应演示数据的环境适用。生成报告在忽略的 `output/` 内，本地 `.env.demo` 不上传。
