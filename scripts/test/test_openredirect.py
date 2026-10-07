#!/usr/bin/env python3
"""
开放重定向 (Open Redirect) 攻击测试脚本

覆盖注入点:
  - GET Query / Path
  - POST JSON / Form
  - Header / Cookie
  - PUT / PATCH

Payload 来源: 绝对 URL、协议相对 URL、编码绕过、@ 符号绕过、
              IP 地址、Unicode 域名、302 跳转等。
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_base import WAFTestBase, parse_args, Colors


class OpenRedirectTester(WAFTestBase):
    ATTACK_NAME = "Open Redirect"
    ATTACK_DESC = "开放重定向测试 — URL 跳转、域名绕过、编码绕过"

    GET_PAYLOADS = [
        # 绝对 URL
        ("abs-http", "http://evil.com"),
        ("abs-https", "https://evil.com"),
        ("abs-http-port", "http://evil.com:8080"),
        ("abs-https-port", "https://evil.com:8443"),
        ("abs-path", "http://evil.com/path"),
        ("abs-query", "http://evil.com?data=1"),

        # 协议相对
        ("proto-relative", "//evil.com"),
        ("proto-relative-path", "//evil.com/path"),
        ("proto-relative-port", "//evil.com:8080"),

        # @ 符号绕过
        ("at-sign", "http://@evil.com"),
        ("at-sign-2", "http://user@evil.com"),
        ("at-sign-3", "http://user:pass@evil.com"),
        ("at-sign-4", "http://target.com@evil.com"),
        ("at-sign-5", "http://target.com.evil.com"),
        ("at-sign-6", "http://evil.com#@target.com"),
        ("at-sign-7", "http://target.com?redirect=evil.com"),

        # 双斜杠绕过
        ("double-slash", "http://target.com//evil.com"),
        ("double-slash-2", "http://target.com////evil.com"),

        # 编码绕过
        ("enc-url", "http://evil.com%2Fpath"),
        ("enc-double-url", "http://evil.com%252Fpath"),
        ("enc-unicode", "http://evil\u002ecom"),
        ("enc-hex", "http://6576696c2e636f6d"),
        ("enc-idna", "http://evil.com.xn--target-w5a.com"),

        # IP 地址
        ("ip-decimal", "http://2130706433"),
        ("ip-hex", "http://0x7f000001"),
        ("ip-octal", "http://0177.0000.0000.0001"),
        ("ip-hex-dotted", "http://0x7f.0x00.0x00.0x01"),
        ("ip-ipv6", "http://[::1]"),
        ("ip-ipv6-mapped", "http://[::ffff:127.0.0.1]"),

        # 子域名 / 域名拼接
        ("subdomain", "http://target.com.evil.com"),
        ("subdomain-2", "http://evil.target.com"),
        ("subdomain-3", "http://target.com.redirect.evil.com"),

        # URL 参数嵌套
        ("nested-url", "http://evil.com?redirect=http://target.com"),
        ("nested-url-2", "http://target.com?redirect=http://evil.com"),
        ("nested-url-3", "http://target.com?next=http://evil.com"),
        ("nested-url-4", "http://target.com?url=http://evil.com"),
        ("nested-url-5", "http://target.com?return=http://evil.com"),

        # 相对路径绕过
        ("relative-dot", "/../evil.com"),
        ("relative-double-dot", "../../evil.com"),
        ("relative-protocol", "://evil.com"),
        ("relative-slash", "//evil.com"),

        # 特殊协议
        ("proto-javascript", "javascript:alert(1)"),
        ("proto-data", "data:text/html,<script>alert(1)</script>"),
        ("proto-tel", "tel:+1234567890"),
        ("proto-mailto", "mailto:evil@evil.com"),
        ("proto-file", "file:///etc/passwd"),
        ("proto-ftp", "ftp://evil.com"),

        # 空字节截断
        ("null-trunc", "http://target.com\x00.evil.com"),
        ("null-trunc-2", "http://target.com%00.evil.com"),

        # 参数污染
        ("hpp", "http://evil.com&redirect=http://target.com"),
        ("hpp-2", "http://target.com&redirect=http://evil.com"),

        # 302 跳转载体
        ("carrier-302", "http://httpbin.org/redirect-to?url=http://evil.com"),
        ("carrier-bitly", "https://bit.ly/3xxx"),
        ("carrier-tinyurl", "https://tinyurl.com/xxx"),

        # 中文/Unicode 域名
        ("idna", "http://evil.com.xn--fiq8it87ap2an9bxg5d8b0a0a0a"),
        ("idna-2", "http://evil.com.xn--target-6k4b.com"),

        # 混合
        ("mixed-1", "http://target.com/http://evil.com"),
        ("mixed-2", "http://target.com/?redirect=//evil.com"),
        ("mixed-3", "http://target.com/?next=../../evil.com"),
        ("mixed-4", "http://target.com/?url=javascript:alert(1)"),
        ("mixed-5", "http://target.com?redirect=\u0026#104;\u0026#116;\u0026#116;\u0026#112;\u0026#58;\u0026#47;\u0026#47;evil.com"),
    ]

    POST_PAYLOADS = [
        ("json-abs", "http://evil.com"),
        ("json-protocol-relative", "//evil.com"),
        ("json-at-sign", "http://target.com@evil.com"),
        ("json-ip", "http://2130706433"),
        ("json-javascript", "javascript:alert(1)"),
        ("json-data", "data:text/html,<script>alert(1)</script>"),
        ("json-subdomain", "http://target.com.evil.com"),
        ("json-nested", "http://evil.com?redirect=http://target.com"),

        ("form-abs", "http://evil.com"),
        ("form-protocol", "//evil.com"),
        ("form-at", "http://target.com@evil.com"),
        ("form-javascript", "javascript:alert(1)"),
        ("form-subdomain", "http://target.com.evil.com"),
    ]

    HEADER_PAYLOADS = [
        ("hdr-x-custom", "http://evil.com"),
        ("hdr-ua-redirect", "Mozilla/5.0 http://evil.com"),
        ("hdr-referer-evil", "http://evil.com"),
        ("hdr-xff-evil", "evil.com"),
    ]

    COOKIE_PAYLOADS = [
        ("cookie-abs", "http://evil.com"),
        ("cookie-protocol", "//evil.com"),
        ("cookie-javascript", "javascript:alert(1)"),
    ]

    PATH_PAYLOADS = [
        ("path-abs", "http://evil.com"),
        ("path-protocol", "//evil.com"),
        ("path-at", "http://target.com@evil.com"),
        ("path-javascript", "javascript:alert(1)"),
    ]

    def run(self):
        print(f"  {Colors.c('正在执行开放重定向测试...', Colors.INFO)}\n")

        print(f"  {Colors.c('[注入点] GET Query', Colors.CYAN)}")
        for name, payload in self.GET_PAYLOADS:
            self.get_query(f"redirect-get-{name}", payload, "/api/redirect", "url")

        print(f"  {Colors.c('[注入点] GET Path', Colors.CYAN)}")
        for name, payload in self.PATH_PAYLOADS:
            self.get_path(f"redirect-path-{name}", payload, "/goto")

        print(f"  {Colors.c('[注入点] POST JSON', Colors.CYAN)}")
        for name, payload in self.POST_PAYLOADS[:5]:
            self.post_json(f"redirect-json-{name}", payload, "/api/redirect", "url")

        print(f"  {Colors.c('[注入点] POST Form', Colors.CYAN)}")
        for name, payload in self.POST_PAYLOADS[5:]:
            self.post_form(f"redirect-form-{name}", payload, "/api/redirect", "url")

        print(f"  {Colors.c('[注入点] Header', Colors.CYAN)}")
        headers = ["X-Custom-Header", "User-Agent", "Referer", "X-Forwarded-For"]
        for i, (name, payload) in enumerate(self.HEADER_PAYLOADS):
            h = headers[i % len(headers)]
            self.header_inject(f"redirect-hdr-{name}", payload, h, "/api/echo")

        print(f"  {Colors.c('[注入点] Cookie', Colors.CYAN)}")
        for name, payload in self.COOKIE_PAYLOADS:
            self.cookie_inject(f"redirect-cookie-{name}", payload, "/api/echo")

        print(f"  {Colors.c('[注入点] PUT / PATCH', Colors.CYAN)}")
        for name, payload in [("put-abs", "http://evil.com"),
                               ("put-javascript", "javascript:alert(1)")]:
            self.put_json(f"redirect-put-{name}", payload, "/api/config", "redirect_url")
            self.patch_json(f"redirect-patch-{name}", payload, "/api/config", "redirect_url")


if __name__ == "__main__":
    args = parse_args("开放重定向攻击测试")
    tester = OpenRedirectTester(
        target=args.target, domain=args.domain,
        verbose=args.verbose, timeout=args.timeout, delay=args.delay
    )
    tester.execute()
