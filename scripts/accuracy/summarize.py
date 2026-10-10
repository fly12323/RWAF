"""Calculate fixture rates and retain evidence without treating fixture variants as iid traffic."""
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "output/accuracy/2026-10-10"


def main():
    summary = json.loads((OUT / "summary.json").read_text(encoding="utf-8"))
    corpus = {s["id"]: s for s in json.loads((OUT / "corpus.json").read_text(encoding="utf-8"))}
    outcomes = [json.loads(line) for line in (OUT / "outcomes.jsonl").read_text(encoding="utf-8").splitlines()]
    if len(summary['results']) != 12 or len(outcomes) != len(corpus)*12:
        raise ValueError('Incomplete experiment; do not publish rates from a partial run')
    if any(o.get('error') for o in outcomes):
        raise ValueError('Engine errors require separate review before publishing this report')
    for r in summary['results']:
        selected=[o for o in outcomes if o['pl']==r['pl'] and o['threshold']==r['threshold']]
        for ds,c in r['groups'].items():
            observed=[o for o in selected if ds==o['dataset'] or ds==o['dataset']+'/'+o['category']]
            if len(observed)!=c['n'] or sum(o['blocked'] for o in observed)!=c['blocked']:
                raise ValueError(('Summary/outcome disagreement',r['pl'],r['threshold'],ds))
    for r in summary["results"]:
        if r["threshold"] != 5:
            continue
        print(f'\nPL{r["pl"]} threshold=5')
        selected = [o for o in outcomes if o["pl"] == r["pl"] and o["threshold"] == 5]
        for ds in ["benign-basic", "benign-complex", "attack-probe", "context-probe"]:
            bad = [o for o in selected if o["dataset"] == ds and not o.get("error") and o["blocked"] == ds.startswith("benign")]
            print(ds, 'problem-count=',len(bad), 'transport=',dict(Counter(o['id'].rsplit('/',1)[-1] for o in bad)))
            for o in bad[:2]:
                s = corpus[o['id']]
                detection_ids=[i for i in o['rule_ids'] if 913000 <= int(i) < 949000 and int(i)%1000 >= 100]
                print(o['id'], 'score=',o['score'], 'detection-rules=',detection_ids, 'uri=',s['uri'][:100], 'body=',s['body'][:100])
    rows = []
    for r in summary["results"]:
        for ds, c in sorted(r['groups'].items()):
            valid = c['n'] - c['errors']
            blocked_rate = c['blocked']/valid*100 if valid else None
            rows.append({'pl':r['pl'],'threshold':r['threshold'],'dataset':ds,'n':c['n'],'errors':c['errors'],
                         'blocked':c['blocked'],'allowed':valid-c['blocked'],
                         'fpr_pct':round(blocked_rate,4) if ds.startswith('benign') else '',
                         'probe_unblocked_pct':round(100-blocked_rate,4) if ds.startswith(('attack','context')) else '',
                         'expected_rule_matches':c['expected_matched'] if ds.startswith('crs') else ''})
    with (OUT/'rates.csv').open('w',newline='',encoding='utf-8-sig') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    bykey=defaultdict(list)
    for o in outcomes:
        if not o.get('error'):
            bykey[(o['threshold'],o['id'])].append(o)
    reversals=[]
    for (threshold, id), group in bykey.items():
        group.sort(key=lambda o:o['pl'])
        if any(a['blocked'] and not b['blocked'] for a,b in zip(group,group[1:])):
            reversals.append({'threshold':threshold,'id':id,'verdicts':[(o['pl'],o['blocked']) for o in group]})
    print('PL verdict reversals:',len(reversals))
    (OUT/'reversals.json').write_text(json.dumps(reversals,indent=2),encoding='utf-8')
    write_report(summary, corpus, outcomes)


def fraction(blocked, n):
    return f'{blocked}/{n}（{blocked/n*100:.2f}%）' if n else '无样本'


def write_report(summary, corpus, outcomes):
    target=ROOT/'docs/benchmarks/2026-10-10'
    target.mkdir(parents=True,exist_ok=True)
    lines=['# 规则引擎误封与攻击探针未阻断评估（2026-10-10）','',
           '## 结论与范围','',
           '当前规则集提高 PL 会扩大检测，也会明显增加业务误封；当前 JSON 请求体处理器的选用还存在接入缺口。不能仅靠提高 PL 或阈值修复这些问题。', '',
           '这是受控样本评估，不能解释为生产流量误报率或真实攻击利用成功率。CRS 正向回归包含只为触发特定规则的字符串，与人工攻击探针分开。未向外部目标、内网服务、数据库或浏览器执行任何攻击。', '',
           '引擎：Coraza 3.3.3 / CRS 4.24.0 / Go 1.25.5 Windows amd64。CRS 固定提交：`318e529357d6d1ab19bd0d26baf3ffcc5a472c04`。使用当前工作区规则正文，指纹见下文。', '',
           '策略：block；PL1–PL4 × 异常分阈值 5/10/15；全部 CRS 分类，不禁用单条规则，自定义规则目录为空。名单、CC、爬虫、自动封禁不参与此处误封/漏检率。请求体限额 1 MiB，所有人工样本低于上限。实际业务全局策略未读取或修改。', '',
           '## 样本与定义','',
           '| 样本组 | 请求数 | 说明 |','| --- | ---: | --- |',
           '| 普通正常输入 | 160 | 40 个普通搜索/表单值，每个经过 Query/Form/JSON/URL 编码 Cookie 四种传输 |',
           '| 复杂正常输入 | 124 | 31 个允许的消毒富文本、代码存储、高级搜索输入，各四种传输 |',
           '| 核心攻击探针 | 184 | 46 个仓库 SQLi/XSS/LFI/RCE 常见探针，各四种传输 |',
           '| 业务语义探针 | 52 | SSRF、开放跳转与 NoSQL 文本；需业务上下文，单独统计 |',
           '| CRS 正向规则回归 | 3225 | 仅支持的单阶段 HTTP/1.1 请求型正向样本，不等同有效攻击 |','',
           '误封率 FPR = FP/(FP+TN)，即正常请求被规则阻断的比例。本文“样本漏检率”=未阻断核心攻击探针数/有效核心探针数；它是按假定易受攻击上下文标注的探针 FNR，未在真实后端证明利用，不代表真实世界漏报率。匹配了规则但分数低于阈值仍计作未阻断。规则引擎异常单列，不作为成功拦截。所有组本轮引擎异常为 0。', '',
           '同一输入的四种传输相关，样本是确定性场景集而非随机独立业务流量，未提供统计置信区间。不把合并样本构成的比例当作业务流量权重。Cookie 情况假定业务先做 URL 解码再使用值；不同解码约定的业务结论会不同。', '',
           '## 相同阈值 5 下的等级比较','',
           '| PL | 普通输入误封 FP/N | 复杂输入误封 FP/N | 核心攻击探针未阻断 FN/N |','| --- | ---: | ---: | ---: |']
    for r in summary['results']:
        if r['threshold']!=5:continue
        a,b,c=(r['groups'][k] for k in ['benign-basic','benign-complex','attack-probe'])
        lines.append(f"| PL{r['pl']} | {fraction(a['blocked'],a['n'])} | {fraction(b['blocked'],b['n'])} | {fraction(c['n']-c['blocked'],c['n'])} |")
    lines += ['', '## 阈值比较', '', '| PL | 阈值 | 普通输入误封率 | 复杂输入误封率 | 核心探针未阻断率 |','| --- | ---: | ---: | ---: | ---: |']
    for r in summary['results']:
        a,b,c=(r['groups'][k] for k in ['benign-basic','benign-complex','attack-probe'])
        lines.append(f"| PL{r['pl']} | {r['threshold']} | {a['blocked']/a['n']*100:.2f}% | {b['blocked']/b['n']*100:.2f}% | {(c['n']-c['blocked'])/c['n']*100:.2f}% |")
    lines += ['', '## 攻击类型与传输位置（阈值 5）', '', '| PL | SQLi 未阻断 | XSS 未阻断 | LFI 未阻断 | RCE 未阻断 |','| --- | ---: | ---: | ---: | ---: |']
    for r in summary['results']:
        if r['threshold']!=5:continue
        cells=[]
        for category in ['sqli','xss','lfi','rce']:
            c=r['groups']['attack-probe/'+category];cells.append(fraction(c['n']-c['blocked'],c['n']))
        lines.append(f"| PL{r['pl']} | "+' | '.join(cells)+' |')
    lines += ['', '| PL | Query 未阻断 | Form 未阻断 | JSON 未阻断 | URL 编码 Cookie 未阻断 |','| --- | ---: | ---: | ---: | ---: |']
    for pl in range(1,5):
        cells=[]
        for point in ['query','form','json','cookie']:
            selected=[o for o in outcomes if o['pl']==pl and o['threshold']==5 and o['dataset']=='attack-probe' and o['id'].endswith('/'+point)]
            cells.append(fraction(sum(not o['blocked'] for o in selected),len(selected)))
        lines.append(f"| PL{pl} | "+' | '.join(cells)+' |')
    lines += ['', '## 具体问题与诊断', '',
              '1. **JSON 处理器接入缺口**：PL1/阈值5 下，6 个普通 Unicode 转义 JSON 命中 `920540`，21/46 个 JSON 攻击探针未阻断。当前规则文件未按 Content-Type 设置 `ctl:requestBodyProcessor=JSON`；CRS `901340` 只强制正文变量，不能代替选用 JSON 处理器。需修复内容类型到处理器的接入，支持规范 JSON 与 `+json`，并验证嵌套、转义与异常 JSON。', '',
              'Coraza 的[官方 ctl 说明](https://www.coraza.io/docs/seclang/actions/)明确指出 JSON/XML 处理器不会隐式选用，[推荐配置](https://github.com/corazawaf/coraza/blob/main/coraza.conf-recommended)给出了 JSON 和 +json 的选择规则。这里的接入缺口判断同时依据当前代码和临时实验，不依赖文档推测。','',
              '2. **URL 编码 Cookie 的 RCE 漏检**：PL4/阈值5 下仍有12个 RCE Cookie 探针未阻断，原始记录为0分。原始 RCE 规则的变换并不统一做 URL 解码。影响取决于业务是否会解码 Cookie 后进入 shell；需按照业务解码边界验证，不能盲目把所有 Cookie 重复解码。', '',
              '3. **合法业务输入与通用检测重叠**：无事件的图片 HTML 命中 `941160`，普通数学比较表达式可能命中 `942100`；高级 SQL/代码搜索在高 PL 中更多命中注入规则。PL4 还包含 `920273` 的极严格字符集检查。需要按站点/路径/参数制定精确排除及输入约束，不宜全局禁用整类规则。', '',
              '这些结果改变了“仅凭 PL 标签即可认为预设适合上线”的判断：预设只能提供起点，均衡/严格预设尤其需要先做业务调优。未修改任何生产防护逻辑、名单、爬虫算法或 CRS 正文。', '',
              '### 临时 JSON 处理器实验（非当前正式结果）','']
    diagnostic_path=ROOT/'output/accuracy/2026-10-10-json-diagnostic/summary.json'
    diagnostic=json.loads(diagnostic_path.read_text(encoding='utf-8'))
    lines += ['仅在独立临时规则目录增加 JSON Content-Type 选择器，使用同一520个人工样本。临时目录已删除，未写入项目规则目录。JSON 解析会改变检测效果，也可能新增真实规则误封，并非通用“零误报修复”。','',
              '| PL（阈值5） | 普通输入误封 FP/N | 复杂输入误封 FP/N | 核心探针未阻断 FN/N |','| --- | ---: | ---: | ---: |']
    for r in diagnostic['results']:
        if r['threshold']!=5:continue
        a,b,c=(r['groups'][k] for k in ['benign-basic','benign-complex','attack-probe'])
        lines.append(f"| PL{r['pl']} | {fraction(a['blocked'],a['n'])} | {fraction(b['blocked'],b['n'])} | {fraction(c['n']-c['blocked'],c['n'])} |")
    lines += ['', '## CRS 回归与限制','',
              '3225 个官方正向样本按所支持的请求协议、原始标注和适配后的请求头执行。PL1/2/3/4（阈值5）全部预期规则命中的样本数分别为 '+', '.join(str(r['groups']['crs-positive']['expected_matched']) for r in summary['results'] if r['threshold']==5)+'。高 PL 规则本就不会在低 PL 执行，不能把该差值称作真实攻击漏报。不是官方测试框架完整验收，也未自动应用官方 Coraza 覆盖项。','',
              '排除：'+json.dumps(summary['regression_skipped'],ensure_ascii=False)+'。既有缺失的4个回归文件保持原状，其中3个 PHP 文件在本次选择范围；未补造样本。杀毒软件最初拦截了内嵌攻击内容的测试器源码，改为中性测试器读取仓库数据后成功运行，未关闭安全软件。', '',
              '实际 Gin 反向代理 + 本地 HTTP 后端交叉检查520个人工样本 × 12组策略，共6240个请求，与规则适配器的阻断判定零差异。仅存储、名单和事件投递边界被隔离，未使用真实数据库写日志。该结果验证请求编排下的判定一致，未验证特定业务中的漏洞利用成功。', '',
              '基准规则评估共3745 × 12 = 44940个事务；没有错误。等级间未发现原来阻断、提高PL后反而放行的判定逆转。', '',
              '## 复现与原始证据','', '```powershell','python scripts/accuracy/build_corpus.py','go run ./scripts/accuracy',
              "$env:WAF_ACCURACY='1'",'go test ./pkg/proxy -run TestAccuracyCorpusMatchesProxy -v -count=1',
              'Remove-Item Env:WAF_ACCURACY','go run ./scripts/accuracy -diagnostic-json -curated-only -out output/accuracy/2026-10-10-json-diagnostic',
              'python scripts/accuracy/summarize.py','```','',
              '原始样本、逐事务结果与 CSV 在 `output/accuracy/2026-10-10/`；诊断结果在相邻 `2026-10-10-json-diagnostic/`。输出为人工数据，不含业务日志或用户配置，目录按现有约定不提交。测试器和本报告可随代码保留。','',
              '- 样本 SHA256：`'+summary['corpus_sha256']+'`',
              '- 规则正文 SHA256：`'+summary['rules_sha256']+'`',
              '- 基准开始时间（UTC）：`'+summary['generated_at']+'`','',
              '要测线上误报率，需要有代表性的业务流量回放和人工确认的正常/恶意标签；实际漏报率还需要覆盖真实利用上下文、编码链与业务逻辑。当前未获得这些数据。']
    (target/'accuracy.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    (target/'accuracy-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')


if __name__ == '__main__':
    main()
