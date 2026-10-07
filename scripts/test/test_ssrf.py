#!/usr/bin/env python3
"""
SSRF (服务端请求伪造) 攻击测试脚本

覆盖注入点:
  - GET Query / Path
  - POST JSON / Form
  - Header / Cookie
  - PUT / PATCH

Payload 来源: 内网地址、元数据服务、文件协议、其他协议绕过、
              DNS 重绑定、编码绕过、302 跳转等。
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_base import WAFTestBase, parse_args, Colors


class SSRFTester(WAFTestBase):
    ATTACK_NAME = "Server-Side Request Forgery (SSRF)"
    ATTACK_DESC = "SSRF 攻击测试 — 内网探测、元数据服务、协议绕过、DNS重绑定"

    GET_PAYLOADS = [
        # 本地地址
        ("local-http", "http://127.0.0.1/"),
        ("local-http-port", "http://127.0.0.1:8080/"),
        ("local-http-admin", "http://127.0.0.1:8080/admin"),
        ("local-http-api", "http://127.0.0.1:8080/api/v1/users"),
        ("local-https", "https://127.0.0.1/"),
        ("localhost", "http://localhost/"),
        ("localhost-port", "http://localhost:3306/"),
        ("localhost-redis", "http://localhost:6379/"),
        ("localhost-mysql", "http://localhost:3306/"),
        ("localhost-ssh", "http://localhost:22/"),
        ("localhost-smtp", "http://localhost:25/"),
        ("localhost-ldap", "http://localhost:389/"),
        ("localhost-dns", "http://localhost:53/"),

        # 内网网段
        ("lan-10", "http://10.0.0.1/"),
        ("lan-172", "http://172.16.0.1/"),
        ("lan-192", "http://192.168.1.1/"),
        ("lan-169", "http://169.254.169.254/"),
        ("lan-broadcast", "http://255.255.255.255/"),

        # 元数据服务 (云)
        ("aws-metadata", "http://169.254.169.254/latest/meta-data/"),
        ("aws-metadata-iam", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("aws-metadata-user", "http://169.254.169.254/latest/user-data"),
        ("aws-metadata-hostname", "http://169.254.169.254/latest/meta-data/hostname"),
        ("gcp-metadata", "http://metadata.google.internal/computeMetadata/v1/"),
        ("gcp-metadata-2", "http://169.254.169.254/computeMetadata/v1/"),
        ("azure-metadata", "http://169.254.169.254/metadata/instance?api-version=2017-12-01"),
        ("aliyun-metadata", "http://100.100.100.200/latest/meta-data/"),
        ("tencent-metadata", "http://metadata.tencentyun.com/"),
        ("huawei-metadata", "http://169.254.169.254/openstack/latest/meta_data.json"),
        ("oracle-metadata", "http://169.254.169.254/opc/v1/instance/"),
        ("digitalocean-metadata", "http://169.254.169.254/metadata/v1.json"),

        # 文件协议
        ("file-passwd", "file:///etc/passwd"),
        ("file-shadow", "file:///etc/shadow"),
        ("file-hosts", "file:///etc/hosts"),
        ("file-win", "file:///C:/windows/win.ini"),
        ("file-win-system32", "file:///C:/windows/system32/drivers/etc/hosts"),
        ("file-proc", "file:///proc/self/environ"),
        ("file-dev-null", "file:///dev/null"),

        # 其他协议
        ("ftp-local", "ftp://127.0.0.1/"),
        ("dict-local", "dict://127.0.0.1:11211/"),
        ("gopher-local", "gopher://127.0.0.1:9000/_"),
        ("gopher-redis", "gopher://127.0.0.1:6379/_"),
        ("gopher-mysql", "gopher://127.0.0.1:3306/_"),
        ("ldap-local", "ldap://127.0.0.1:389/"),
        ("tftp-local", "tftp://127.0.0.1:69/"),
        ("sftp-local", "sftp://127.0.0.1/"),
        ("ssh-local", "ssh://127.0.0.1/"),
        ("imap-local", "imap://127.0.0.1:143/"),
        ("smtp-local", "smtp://127.0.0.1:25/"),
        ("pop3-local", "pop3://127.0.0.1:110/"),

        # DNS 重绑定 / 绕过
        ("dns-rebind", "http://7f000001.7f000001.rbndr.us/"),
        ("dns-local", "http://localhost.localdomain"),
        ("dns-loopback", "http://0.0.0.0"),
        ("dns-0", "http://0/"),
        ("dns-0-port", "http://0:8080/"),
        ("dns-127", "http://127.1/"),
        ("dns-127-hex", "http://0x7f000001/"),
        ("dns-127-octal", "http://0177.0.0.1/"),
        ("dns-127-decimal", "http://2130706433/"),

        # 编码绕过
        ("enc-url", "http://127.0.0.1%2Fadmin"),
        ("enc-double-url", "http://127.0.0.1%252Fadmin"),
        ("enc-unicode", "http://\u0031\u0032\u0037.\u0030.\u0030.\u0031/"),
        ("enc-base64", "aHR0cDovLzEyNy4wLjAuMQ=="),

        # 302 跳转（如果后端跟随重定向）
        ("redirect-local", "http://evil.com/redirect?to=http://127.0.0.1"),
        ("redirect-meta", "http://evil.com/redirect?to=file:///etc/passwd"),

        # IP 变形
        ("ip-dotted", "http://127.0.0.1"),
        ("ip-short", "http://127.1"),
        ("ip-decimal", "http://2130706433"),
        ("ip-hex", "http://0x7f000001"),
        ("ip-hex-dotted", "http://0x7f.0x00.0x00.0x01"),
        ("ip-octal", "http://0177.0000.0000.0001"),
        ("ip-octal-mixed", "http://0177.0.0.1"),
        ("ip-binary", "http://01111111000000000000000000000001"),

        # IPv6
        ("ipv6-loopback", "http://[::1]/"),
        ("ipv6-local", "http://[0:0:0:0:0:0:0:1]/"),
        ("ipv6-mapped", "http://[::ffff:127.0.0.1]/"),

        # 域名解析到本地
        ("domain-local", "http://localtest.me/"),
        ("domain-local-2", "http://127.0.0.1.xip.io/"),
        ("domain-local-3", "http://127-0-0-1.nip.io/"),
        ("domain-local-4", "http://127.0.0.1.sslip.io/"),

        # 302 跳转载体
        ("carrier-302", "http://httpbin.org/redirect-to?url=http://127.0.0.1"),
        ("carrier-bitly", "https://bit.ly/3xxx"),

        # 协议混淆
        ("proto-mix", "http://127.0.0.1@evil.com"),
        ("proto-mix-2", "http://evil.com@127.0.0.1"),
        ("proto-mix-3", "http://evil.com#@127.0.0.1"),
        ("proto-question", "http://127.0.0.1?evil.com"),
        ("proto-hash", "http://127.0.0.1#evil.com"),

        # CRLF 注入结合 SSRF
        ("crlf-ssrf", "http://127.0.0.1%0d%0aSet-Cookie:%20evil=true"),
        ("crlf-ssrf-2", "http://127.0.0.1\r\nHost:%20evil.com"),
    ]

    POST_PAYLOADS = [
        ("json-local", "http://127.0.0.1/"),
        ("json-metadata", "http://169.254.169.254/latest/meta-data/"),
        ("json-file", "file:///etc/passwd"),
        ("json-gopher", "gopher://127.0.0.1:6379/_"),
        ("json-dns-rebind", "http://7f000001.7f000001.rbndr.us/"),
        ("json-ipv6", "http://[::1]/"),
        ("json-ip-hex", "http://0x7f000001/"),
        ("json-domain-local", "http://127.0.0.1.nip.io/"),

        ("form-local", "http://127.0.0.1/"),
        ("form-metadata", "http://169.254.169.254/latest/meta-data/"),
        ("form-file", "file:///etc/passwd"),
        ("form-gopher", "gopher://127.0.0.1:3306/_"),
        ("form-dns", "http://127.0.0.1.xip.io/"),
    ]

    HEADER_PAYLOADS = [
        ("hdr-x-custom", "http://127.0.0.1/"),
        ("hdr-ua-local", "Mozilla/5.0 http://127.0.0.1/"),
        ("hdr-referer-local", "http://127.0.0.1/admin"),
        ("hdr-xff-local", "127.0.0.1, http://169.254.169.254/"),
    ]

    COOKIE_PAYLOADS = [
        ("cookie-local", "http://127.0.0.1/"),
        ("cookie-file", "file:///etc/passwd"),
        ("cookie-metadata", "http://169.254.169.254/latest/meta-data/"),
    ]

    PATH_PAYLOADS = [
        ("path-local", "http://127.0.0.1"),
        ("path-file", "file:///etc/passwd"),
        ("path-metadata", "http://169.254.169.254/latest/meta-data"),
        ("path-gopher", "gopher://127.0.0.1:6379"),
    ]

    def run(self):
        print(f"  {Colors.c('正在执行 SSRF 测试...', Colors.INFO)}\n")

        print(f"  {Colors.c('[注入点] GET Query', Colors.CYAN)}")
        for name, payload in self.GET_PAYLOADS:
            self.get_query(f"ssrf-get-{name}", payload, "/api/fetch", "url")

        print(f"  {Colors.c('[注入点] GET Path', Colors.CYAN)}")
        for name, payload in self.PATH_PAYLOADS:
            self.get_path(f"ssrf-path-{name}", payload, "/proxy")

        print(f"  {Colors.c('[注入点] POST JSON', Colors.CYAN)}")
        for name, payload in self.POST_PAYLOADS[:5]:
            self.post_json(f"ssrf-json-{name}", payload, "/api/fetch", "url")

        print(f"  {Colors.c('[注入点] POST Form', Colors.CYAN)}")
        for name, payload in self.POST_PAYLOADS[5:]:
            self.post_form(f"ssrf-form-{name}", payload, "/api/fetch", "url")

        print(f"  {Colors.c('[注入点] Header', Colors.CYAN)}")
        headers = ["X-Custom-Header", "User-Agent", "Referer", "X-Forwarded-For"]
        for i, (name, payload) in enumerate(self.HEADER_PAYLOADS):
            h = headers[i % len(headers)]
            self.header_inject(f"ssrf-hdr-{name}", payload, h, "/api/echo")

        print(f"  {Colors.c('[注入点] Cookie', Colors.CYAN)}")
        for name, payload in self.COOKIE_PAYLOADS:
            self.cookie_inject(f"ssrf-cookie-{name}", payload, "/api/echo")

        print(f"  {Colors.c('[注入点] PUT / PATCH', Colors.CYAN)}")
        for name, payload in [("put-local", "http://127.0.0.1/"),
                               ("put-file", "file:///etc/passwd"),
                               ("put-metadata", "http://169.254.169.254/latest/meta-data/")]:
            self.put_json(f"ssrf-put-{name}", payload, "/api/webhook", "callback")
            self.patch_json(f"ssrf-patch-{name}", payload, "/api/webhook", "callback")


if __name__ == "__main__":
    args = parse_args("SSRF 攻击测试")
    tester = SSRFTester(
        target=args.target, domain=args.domain,
        verbose=args.verbose, timeout=args.timeout, delay=args.delay
    )
    tester.execute()
