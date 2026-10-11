# 规则准确性样本评估

该工具读取仓库测试载荷作为数据，调用真实 Coraza/CRS，不执行载荷、不向外部目标发送请求、不访问生产数据库、不改业务策略。

```powershell
python scripts/accuracy/build_corpus.py
go run ./scripts/accuracy
$env:WAF_ACCURACY='1'
go test ./pkg/proxy -run TestAccuracyCorpusMatchesProxy -v -count=1
Remove-Item Env:WAF_ACCURACY
python scripts/accuracy/summarize.py
```

基准比较 PL1–4 与异常分阈值5/10/15。普通输入、复杂合法输入、核心攻击探针、需业务语义的探针、CRS 正向规则回归分别记录。攻击字符串仅在假定易受攻击上下文下标注，未验证后端利用成功；报告中的探针未阻断率不能当作真实生产漏报率。同一字符串四种传输相关，不当作独立抽样估计。

`build_corpus.py` 用 AST 读取常量，不导入攻击脚本。`main.go` 只作规则事务评估。`accuracy_replay_test.go` 在明确设置环境变量后，通过实际 Gin Handler 和本地 HTTP 后端逐一交叉验证；名单、事件持久化边界被隔离，CC/爬虫/自动封禁关闭，以测量规则引擎本身。

工作区已正式接入 JSON 处理器，`-diagnostic-json` 已废弃，使用该参数会明确报错。2026-10-10 的诊断文件属于历史实验。使用 `-out` 可保存独立评估目录，目录内包含代理回放需要的 `input.json`；通过 `WAF_ACCURACY_DIR` 指定该目录。

`python scripts/accuracy/compare.py BEFORE AFTER --out SUMMARY.json --details DETAILS.json` 核对前后同一语料/CRS、12 组完整结果和零引擎错误，再输出逐组对比及可选逐条变化。V1.1.2 P0 的实际结果见 [前后验证报告](../../docs/benchmarks/2026-10-11/p0-validation.md)。

人工样本与逐事务输出保存至 `output/accuracy/`，按项目约定不提交；报告和摘要保存至 `docs/benchmarks/2026-10-10/`。报告描述当前确定性语料，未来更换语料或 CRS 时应同步调整报告中的版本与样本说明。引擎错误、缺失策略组或汇总/明细不一致时，汇总器会停止，避免把错误当作拦截成功。

完整结果：[评估报告](../../docs/benchmarks/2026-10-10/accuracy.md)。
