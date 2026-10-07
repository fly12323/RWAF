#!/usr/bin/env python3
"""
CRLF 注入攻击测试脚本

覆盖注入点:
  - GET Query / Path
  - POST JSON / Form / Raw
  - Header / Cookie

Payload 来源: HTTP 响应拆分、Set-Cookie 注入、Location 注入、
              缓存投毒、XSS 结合、编码绕过等。
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_base import WAFTestBase, parse_args, Colors


class CRLFTester(WAFTestBase):
    ATTACK_NAME = "CRLF Injection"
    ATTACK_DESC = "CRLF 注入测试 — HTTP 响应拆分、Cookie 注入、缓存投毒"

    GET_PAYLOADS = [
        # 基础 CRLF
        ("basic-crlf", "%0D%0ASet-Cookie:%20evil=true"),
        ("basic-lf", "%0ASet-Cookie:%20evil=true"),
        ("basic-cr", "%0DSet-Cookie:%20evil=true"),
        ("basic-crlf-2", "\r\nSet-Cookie: evil=true"),
        ("basic-lf-2", "\nSet-Cookie: evil=true"),
        ("basic-cr-2", "\rSet-Cookie: evil=true"),

        # Set-Cookie 注入
        ("cookie-inject", "%0D%0ASet-Cookie:%20session=hacked"),
        ("cookie-inject-2", "%0ASet-Cookie:%20admin=true"),
        ("cookie-inject-3", "%0D%0ASet-Cookie:%20role=admin"),
        ("cookie-inject-4", "%0D%0ASet-Cookie:%20PHPSESSID=fake"),
        ("cookie-inject-5", "%0D%0ASet-Cookie:%20JWT=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30."),

        # Location 注入
        ("location-inject", "%0D%0ALocation:%20http://evil.com"),
        ("location-inject-2", "%0ALocation:%20http://evil.com"),

        # Content-Type 注入
        ("content-type", "%0D%0AContent-Type:%20text/html"),
        ("content-type-2", "%0AContent-Type:%20text/html"),

        # Cache-Control 注入
        ("cache-control", "%0D%0ACache-Control:%20no-cache"),
        ("cache-control-2", "%0D%0ACache-Control:%20max-age=0"),
        ("cache-control-3", "%0D%0APragma:%20no-cache"),

        # 缓存投毒
        ("cache-poison", "%0D%0AX-Cache:%20HIT%0D%0AContent-Length:%200"),
        ("cache-poison-2", "%0D%0AX-Cache-Key:%20/%0D%0AContent-Length:%200"),

        # 响应拆分
        ("response-split", "%0D%0A%0D%0A<script>alert(1)</script>"),
        ("response-split-2", "%0A%0A<script>alert(1)</script>"),
        ("response-split-3", "%0D%0AHTTP/1.1%20200%20OK%0D%0AContent-Type:%20text/html%0D%0A%0D%0A<h1>Hacked</h1>"),

        # XSS 结合
        ("crlf-xss", "%0D%0AContent-Length:%200%0D%0A%0D%0A<script>alert(1)</script>"),
        ("crlf-xss-2", "%0D%0AContent-Type:%20text/html%0D%0A%0D%0A<script>alert(1)</script>"),

        # 编码绕过
        ("enc-url", "%250D%250ASet-Cookie:%20evil=true"),
        ("enc-double-url", "%25250D%25250ASet-Cookie:%20evil=true"),
        ("enc-unicode", "\u000d\u000aSet-Cookie: evil=true"),
        ("enc-hex", "\x0d\x0aSet-Cookie: evil=true"),

        # 特殊字符
        ("special-nul", "%00Set-Cookie:%20evil=true"),
        ("special-tab", "%09Set-Cookie:%20evil=true"),
        ("special-space", "%20Set-Cookie:%20evil=true"),
        ("special-vert", "%0BSet-Cookie:%20evil=true"),
        ("special-form", "%0CSet-Cookie:%20evil=true"),

        # 多行注入
        ("multi-line", "%0D%0ASet-Cookie:%20evil=true%0D%0AContent-Type:%20text/html"),
        ("multi-line-2", "%0D%0ASet-Cookie:%20evil=true%0D%0ALocation:%20http://evil.com"),
        ("multi-line-3", "%0D%0ASet-Cookie:%20evil=true%0D%0AX-Frame-Options:%20DENY%0D%0AContent-Security-Policy:%20default-src%20*"),

        # 302 跳转 + CRLF
        ("redirect-crlf", "%0D%0ALocation:%20http://evil.com%0D%0ASet-Cookie:%20evil=true"),
        ("redirect-crlf-2", "%0D%0AHTTP/1.1%20302%20Found%0D%0ALocation:%20http://evil.com"),

        # 结合其他攻击
        ("crlf-ssrf", "%0D%0AX-Custom-IP-Authorization:%20127.0.0.1"),
        ("crlf-csrf", "%0D%0AOrigin:%20http://evil.com"),

        # Header 注入
        ("header-inject", "%0D%0AX-Forwarded-For:%20127.0.0.1"),
        ("header-inject-2", "%0D%0AX-Real-IP:%20127.0.0.1"),
        ("header-inject-3", "%0D%0AX-Remote-IP:%20127.0.0.1"),
        ("header-inject-4", "%0D%0AX-Remote-Addr:%20127.0.0.1"),
        ("header-inject-5", "%0D%0AX-Client-IP:%20127.0.0.1"),
        ("header-inject-6", "%0D%0AX-Originating-IP:%20127.0.0.1"),
    ]

    POST_PAYLOADS = [
        ("json-crlf", "\r\nSet-Cookie: evil=true"),
        ("json-lf", "\nSet-Cookie: evil=true"),
        ("json-cookie", "\r\nSet-Cookie: admin=true"),
        ("json-location", "\r\nLocation: http://evil.com"),
        ("json-xss", "\r\n\r\n<script>alert(1)</script>"),
        ("json-header", "\r\nX-Forwarded-For: 127.0.0.1"),

        ("form-crlf", "\r\nSet-Cookie: evil=true"),
        ("form-cookie", "\r\nSet-Cookie: admin=true"),
        ("form-location", "\r\nLocation: http://evil.com"),
        ("form-xss", "\r\n\r\n<script>alert(1)</script>"),
    ]

    HEADER_PAYLOADS = [
        ("hdr-x-custom", "\r\nSet-Cookie: evil=true"),
        ("hdr-ua-crlf", "Mozilla/5.0\r\nSet-Cookie: evil=true"),
        ("hdr-referer-crlf", "http://evil.com\r\nSet-Cookie: evil=true"),
        ("hdr-xff-crlf", "127.0.0.1\r\nSet-Cookie: evil=true"),
    ]

    COOKIE_PAYLOADS = [
        ("cookie-crlf", "\r\nSet-Cookie: evil=true"),
        ("cookie-cookie", "\r\nSet-Cookie: admin=true"),
        ("cookie-location", "\r\nLocation: http://evil.com"),
    ]

    PATH_PAYLOADS = [
        ("path-crlf", "\r\nSet-Cookie: evil=true"),
        ("path-cookie", "\r\nSet-Cookie: admin=true"),
        ("path-location", "\r\nLocation: http://evil.com"),
    ]

    def run(self):
        print(f"  {Colors.c('正在执行 CRLF 注入测试...', Colors.INFO)}\n")

        print(f"  {Colors.c('[注入点] GET Query', Colors.CYAN)}")
        for name, payload in self.GET_PAYLOADS:
            self.get_query(f"crlf-get-{name}", payload, "/api/redirect", "url")

        print(f"  {Colors.c('[注入点] GET Path', Colors.CYAN)}")
        for name, payload in self.PATH_PAYLOADS:
            self.get_path(f"crlf-path-{name}", payload, "/api/page")

        print(f"  {Colors.c('[注入点] POST JSON', Colors.CYAN)}")
        for name, payload in self.POST_PAYLOADS[:4]:
            self.post_json(f"crlf-json-{name}", payload, "/api/redirect", "url")

        print(f"  {Colors.c('[注入点] POST Form', Colors.CYAN)}")
        for name, payload in self.POST_PAYLOADS[4:]:
            self.post_form(f"crlf-form-{name}", payload, "/api/redirect", "url")

        print(f"  {Colors.c('[注入点] Header', Colors.CYAN)}")
        headers = ["X-Custom-Header", "User-Agent", "Referer", "X-Forwarded-For"]
        for i, (name, payload) in enumerate(self.HEADER_PAYLOADS):
            h = headers[i % len(headers)]
            self.header_inject(f"crlf-hdr-{name}", payload, h, "/api/echo")

        print(f"  {Colors.c('[注入点] Cookie', Colors.CYAN)}")
        for name, payload in self.COOKIE_PAYLOADS:
            self.cookie_inject(f"crlf-cookie-{name}", payload, "/api/echo")


if __name__ == "__main__":
    args = parse_args("CRLF 注入攻击测试")
    tester = CRLFTester(
        target=args.target, domain=args.domain,
        verbose=args.verbose, timeout=args.timeout, delay=args.delay
    )
    tester.execute()
