"""
正常流量生成脚本
向 RWAF 代理端口发送正常 HTTP 请求，用于流量与防护验证
用法: python generate_normal_traffic.py --port 8081 --count 500
python scripts/generate_normal_traffic.py --host 127.0.0.1 --port 9000 --count 1000 --delay 0.3 --mix-attacks 0
python scripts/generate_normal_traffic.py --port 9000 --count 1000 --workers 20 --mix-attacks 0
python scripts/generate_normal_traffic.py --port 9000 --count 1000000 --min-delay 0.7 --max-delay 2.2 --workers 10 --mix-attacks 0
"""

import argparse
import random
import string
import time
import urllib.request
import urllib.error
import urllib.parse
import sys

# 常见正常 URL 路径
NORMAL_PATHS = [
    "/",
    "/index.html",
    "/index.php",
    "/login",
    "/logout",
    "/register",
    "/api/user/info",
    "/api/user/profile",
    "/api/product/list",
    "/api/product/detail",
    "/api/product/search",
    "/api/order/list",
    "/api/order/detail",
    "/api/article/list",
    "/api/article/detail",
    "/about",
    "/contact",
    "/help",
    "/faq",
    "/terms",
    "/privacy",
    "/sitemap.xml",
    "/robots.txt",
    "/favicon.ico",
    "/static/css/style.css",
    "/static/js/app.js",
    "/static/js/vendor.js",
    "/static/img/logo.png",
    "/assets/js/main.js",
    "/assets/css/main.css",
    "/images/banner.jpg",
    "/images/avatar.png",
    "/uploads/files/document.pdf",
    "/api/v1/health",
    "/api/v1/status",
    "/api/v1/version",
    "/api/v1/config",
]

# 常见搜索关键词（正常）
SEARCH_KEYWORDS = [
    "hello world", "user guide", "getting started",
    "product", "price", "contact us",
    "about us", "help center", "faq",
    "login help", "reset password",
    "new features", "release notes",
    "api documentation", "tutorial",
    "python", "javascript", "css",
]

# 常见 User-Agent
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "PostmanRuntime/7.36.0",
    "curl/8.4.0",
]

# 常见 Referer
REFERERS = [
    "https://www.google.com/",
    "https://www.baidu.com/",
    "https://www.bing.com/",
    "https://github.com/",
    "",
    "https://www.example.com/",
    "https://www.example.com/products",
    "https://www.example.com/about",
    "https://mail.google.com/",
]

# POST 表单数据（正常）
FORM_DATA = [
    {"username": "admin", "password": "password123"},
    {"username": "user", "password": "pass123456"},
    {"email": "user@example.com", "password": "SecurePass1"},
    {"search": "product"},
    {"name": "John Doe", "email": "john@example.com", "message": "Hello, I have a question about your service."},
    {"name": "Alice", "email": "alice@test.com", "message": "Please send me more information."},
    {"old_password": "oldpass123", "new_password": "newpass456"},
    {"title": "My Article", "content": "This is the content of my article.", "category": "tech"},
    {"page": "1", "limit": "20"},
    {"sort": "desc", "order_by": "created_at"},
]


def random_string(length=8):
    """生成随机字符串"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def random_query_params():
    """生成随机正常查询参数"""
    params = {}
    if random.random() < 0.6:
        params["page"] = str(random.randint(1, 50))
    if random.random() < 0.4:
        params["limit"] = str(random.choice([10, 20, 50]))
    if random.random() < 0.3:
        params["sort"] = random.choice(["asc", "desc"])
    if random.random() < 0.3:
        params["category"] = random.choice(["tech", "news", "product", "help"])
    if random.random() < 0.2:
        params["q"] = random.choice(SEARCH_KEYWORDS)
    if random.random() < 0.15:
        params["id"] = str(random.randint(1, 1000))
    return params


def build_url(base_url, path, params):
    """构建带参数的 URL"""
    url = f"{base_url}{path}"
    if params:
        qs = "&".join(f"{k}={urllib.parse.quote(v)}" for k, v in params.items())
        url += f"?{qs}"
    return url


def send_request(url, method="GET", headers=None, data=None):
    """发送 HTTP 请求并返回状态码"""
    req = urllib.request.Request(url, method=method)

    # 设置请求头
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    # 发送请求体
    if data and method == "POST":
        req.data = urllib.parse.urlencode(data).encode("utf-8")

    try:
        resp = urllib.request.urlopen(req, timeout=3)
        return resp.getcode()
    except urllib.error.HTTPError as e:
        return e.code  # 4xx/5xx 也是正常返回
    except (urllib.error.URLError, ConnectionRefusedError, TimeoutError) as e:
        return None  # 连接失败


def main():
    parser = argparse.ArgumentParser(description="生成正常 WAF 流量用于训练异常检测模型")
    parser.add_argument("--port", type=int, default=8081,
                        help="WAF 代理监听端口（默认 8081）")
    parser.add_argument("--host", type=str, default="127.0.0.1",
                        help="WAF 代理地址（默认 127.0.0.1）")
    parser.add_argument("--count", type=int, default=500,
                        help="请求总数（默认 500）")
    parser.add_argument("--delay", type=float, default=0.05,
                        help="请求间隔秒数（默认 0.05，即每秒约20个请求）")
    parser.add_argument("--mix-attacks", type=float, default=0.05,
                        help="混入攻击请求的比例 0-1，用于产生一些异常日志（默认 0.05）")
    args = parser.parse_args()

    import urllib.parse

    base_url = f"http://{args.host}:{args.port}"
    print(f"目标: {base_url}")
    print(f"请求总数: {args.count}")
    print(f"请求间隔: {args.delay}s")
    print(f"攻击混入比例: {args.mix_attacks*100:.0f}%")
    print("-" * 50)

    success = 0
    failed = 0
    start_time = time.time()

    # 攻击 payload（少量混入，用于产生异常日志验证检测效果）
    ATTACK_PAYLOADS = [
        "/?id=1 AND 1=1",
        "/?q=<script>alert(1)</script>",
        "/?cmd=cat /etc/passwd",
        "/?file=../../../etc/passwd",
        "/?exec=whoami",
    ]

    for i in range(args.count):
        # 决定是否混入攻击请求
        is_attack = random.random() < args.mix_attacks

        if is_attack:
            # 攻击请求
            path = random.choice(ATTACK_PAYLOADS)
            url = f"{base_url}{path}"
            method = "GET"
            headers = {}
            data = None
        else:
            # 正常请求
            path = random.choice(NORMAL_PATHS)
            params = random_query_params()
            url = build_url(base_url, path, params) if params else f"{base_url}{path}"
            method = random.choice(["GET", "GET", "GET", "POST"])  # 75% GET, 25% POST

            # 随机请求头
            headers = {
                "User-Agent": random.choice(USER_AGENTS),
                "Accept": random.choice([
                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "application/json, text/plain, */*",
                    "text/css,*/*;q=0.1",
                    "*/*",
                ]),
                "Accept-Language": random.choice([
                    "zh-CN,zh;q=0.9,en;q=0.8",
                    "en-US,en;q=0.5",
                    "zh-CN,zh;q=0.9",
                ]),
                "Accept-Encoding": "gzip, deflate",
            }
            if random.random() < 0.3:
                headers["Referer"] = random.choice(REFERERS) if random.choice([True, False]) else ""
            if random.random() < 0.1:
                from_email = f"user{random.randint(1,999)}@example.com"
                headers["Cookie"] = f"session_id={random_string(32)}; user_email={from_email}"

            data = random.choice(FORM_DATA) if method == "POST" else None

        # 发送请求
        code = send_request(url, method, headers, data)

        if code is not None:
            success += 1
            tag = "⚠ ATTACK" if is_attack else "✓"
            print(f"[{i+1:4d}/{args.count}] {tag} {method} {url[:80]} -> {code}")
        else:
            failed += 1
            tag = "⚠ ATTACK" if is_attack else "✗"
            print(f"[{i+1:4d}/{args.count}] {tag} {method} {url[:80]} -> 连接失败")

        # 请求间隔
        if args.delay > 0:
            time.sleep(args.delay)

    elapsed = time.time() - start_time
    print("-" * 50)
    print(f"完成! 成功: {success}, 失败: {failed}, 耗时: {elapsed:.1f}s")
    print(f"平均速度: {args.count/elapsed:.0f} 请求/秒")

    if failed > 0:
        print(f"\n⚠ 有 {failed} 个请求连接失败，请检查 WAF 代理端口是否正确")
        sys.exit(1)

    print("\n现在可以去异常检测页面点击「训练模型」了！")


if __name__ == "__main__":
    main()
