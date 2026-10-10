"""Build labelled request fixtures as data; never import or execute attack scripts."""
import ast
import json
from pathlib import Path
from urllib.parse import quote, urlencode

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "output/accuracy/2026-10-10"


def constant(file, name):
    tree = ast.parse((ROOT / file).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise ValueError((file, name))


def variants(dataset, category, name, payload, scenario, source):
    for point in ["query", "form", "json", "cookie"]:
        s = dict(id=f"{dataset}/{category}/{name}/{point}", dataset=dataset, category=category,
                 scenario=scenario, source=source, method="GET", uri="/api/input", body="",
                 headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36", "Accept": "application/json,text/html;q=0.9,*/*;q=0.8"})
        if point == "query":
            s["uri"] += "?" + urlencode({"input": payload})
        elif point == "form":
            s.update(method="POST", body=urlencode({"input": payload}))
            s["headers"]["Content-Type"] = "application/x-www-form-urlencoded"
        elif point == "json":
            s.update(method="POST", body=json.dumps({"input": payload}, ensure_ascii=True))
            s["headers"]["Content-Type"] = "application/json"
        else:
            s["headers"]["Cookie"] = "input=" + quote(payload, safe="")
        if s["body"]:
            s["headers"]["Content-Length"] = str(len(s["body"].encode()))
        yield s


def main():
    samples = []
    def add(ds, category, values, scenario, source):
        for i, value in enumerate(values):
            samples.extend(variants(ds, category, str(i + 1), value, scenario, source))
    basic = constant("scripts/generate_normal_traffic.py", "SEARCH_KEYWORDS") + [
        "O'Reilly", "D'Angelo", "John Doe", "Alice Zhang", "john@example.test", "+86 13800138000",
        "2026-10-10T08:30:00+08:00", "SKU-2026-001", "550e8400-e29b-41d4-a716-446655440000",
        "中文搜索：防火墙使用说明", "日本語の検索", "مرحبا بالعالم", "北京 海淀区 中关村",
        "50% discount", "C++ beginner guide", "A & B", "red, green, blue", "a-b_c.d",
        "商品价格 199.00 元", "请联系售后，谢谢！", "Order #12345", "Monday-Friday 09:00-18:00"]
    add("benign-basic", "ordinary", basic, "普通业务文本，作为数据处理", "normal generator + documented synthetic business values")
    complex_groups = {
        "rich-text": ["<p>Hello <strong>world</strong></p>", "<ul><li>one</li><li>two</li></ul>",
                      '<a href="https://docs.example.test">documentation</a>',
                      "<table><tr><td>price</td><td>199</td></tr></table>", '<div class="note">使用指南</div>',
                      '<img src="/images/product.png" alt="product">', "5 < 10 and 20 > 15", "Use union to combine sets"],
        "code-editor": ["SELECT name FROM products WHERE price > 100", "CREATE TABLE examples (id INT, name TEXT)",
                        "a == b && c != d", "const x = (a) => a + 1;", "function add(a,b) { return a+b; }",
                        "print('hello world')", "cat README.md | sort", "git status && git diff",
                        "../images/logo.png", "document.querySelector('.button')"],
        "search-symbols": ["a xor b", "regexp tutorial", "foo || bar", "value != null", "type:book AND year:2026",
                           "[a-z]+\\d{2}", "https://docs.example.test/?a=1&b=2", "price >= 10", "a = a",
                           "not between 0 and 10", "collate nocase", "1+1=2", "emoji 😀 🎉"]
    }
    for category, values in complex_groups.items():
        add("benign-complex", category, values,
            "明确允许该输入的消毒富文本/代码存储/高级搜索场景，不执行用户输入；不代表普通登录接口", "audited synthetic allowed-input scenarios")
    for category, filename, size in [("sqli", "test_sqli.py", 10), ("xss", "test_xss.py", 13),
                                      ("lfi", "test_lfi.py", 10), ("rce", "test_cmdi.py", 13)]:
        source = "scripts/test/" + filename
        for name, value in constant(source, "GET_PAYLOADS")[:size]:
            samples.extend(variants("attack-probe", category, name, value,
                           "假定参数进入对应易受攻击后端上下文，仅测试 WAF 阻断，不执行利用", source))
    for category, filename, size in [("ssrf", "test_ssrf.py", 5), ("open-redirect", "test_openredirect.py", 3),
                                      ("nosqli-text", "test_nosqli.py", 5)]:
        source = "scripts/test/" + filename
        for name, value in constant(source, "GET_PAYLOADS")[:size]:
            samples.extend(variants("context-probe", category, name, value,
                           "需业务语义与漏洞上下文才能认定恶意，单独统计，不混入核心攻击漏报率", source))
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "input.json").write_text(json.dumps(samples, ensure_ascii=True, indent=2), encoding="utf-8")
    print(f"curated samples={len(samples)}")


if __name__ == "__main__":
    main()
