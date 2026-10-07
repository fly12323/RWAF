#!/usr/bin/env python3
"""
SQL 注入攻击测试脚本

覆盖注入点:
  - GET Query 参数
  - GET Path 参数
  - POST JSON Body
  - POST Form Data
  - POST Raw Body
  - Header 注入
  - Cookie 注入
  - PUT/PATCH Body

Payload 来源: 经典绕过、注释符变换、编码绕过、时间盲注、联合查询、堆叠查询等。
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_base import WAFTestBase, parse_args, Colors


class SQLiTester(WAFTestBase):
    ATTACK_NAME = "SQL Injection"
    ATTACK_DESC = "SQL 注入攻击测试 — 覆盖经典注入、盲注、联合查询、堆叠查询、绕过技巧"

    # ========== GET Query Payloads ==========
    GET_PAYLOADS = [
        # 经典布尔/报错注入
        ("classic-quote", "1' OR '1'='1"),
        ("classic-quote-dbl", "1\" OR \"1\"=\"1"),
        ("classic-or", "1 OR 1=1"),
        ("classic-and", "1 AND 1=1"),
        ("classic-union", "1 UNION SELECT * FROM users"),
        ("union-columns", "-1 UNION SELECT 1,2,3,4,5--"),
        ("union-db-version", "-1 UNION SELECT 1,@@version,3--"),
        ("union-info", "-1 UNION SELECT null,table_name,null FROM information_schema.tables--"),
        ("union-mysql", "-1 UNION SELECT 1,load_file('/etc/passwd'),3--"),

        # 注释符变换
        ("comment-hash", "1' OR '1'='1'#"),
        ("comment-dash", "1' OR '1'='1'--"),
        ("comment-dash-space", "1' OR '1'='1' -- "),
        ("comment-multiline", "1'/*' OR '1'='1"),
        ("comment-inline", "1'/**/OR/**/'1'='1"),
        ("comment-backtick", "1` OR `1`=`1"),

        # 逻辑绕过
        ("logic-true", "1' AND 1=1--"),
        ("logic-false", "1' AND 1=2--"),
        ("logic-null", "1' AND NULL IS NULL--"),
        ("logic-hex", "1' AND 0x31=0x31--"),
        ("logic-binary", "1' AND BINARY 'a'='a'--"),

        # 字符串拼接绕过
        ("concat-mysql", "1' OR CONCAT('a','b')='ab'--"),
        ("concat-pg", "1' OR 'a'||'b'='ab'--"),
        ("concat-mssql", "1' OR 'a'+'b'='ab'--"),
        ("concat-char", "1' OR CHAR(97)=CHAR(97)--"),

        # 时间盲注
        ("sleep-mysql", "1' AND SLEEP(5)--"),
        ("sleep-pg", "1'; SELECT pg_sleep(5)--"),
        ("sleep-mssql", "1'; WAITFOR DELAY '0:0:5'--"),
        ("sleep-oracle", "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(66),5)--"),
        ("benchmark-mysql", "1' AND BENCHMARK(5000000,MD5(1))--"),

        # 堆叠查询
        ("stacked-drop", "1'; DROP TABLE users;--"),
        ("stacked-delete", "1'; DELETE FROM users WHERE '1'='1"),
        ("stacked-insert", "1'; INSERT INTO logs VALUES('xss');--"),
        ("stacked-update", "1'; UPDATE users SET password='hacked';--"),
        ("stacked-select", "1'; SELECT * FROM password;--"),

        # 编码绕过
        ("url-encoded", "1%27%20OR%20%271%27%3D%271"),
        ("double-url", "1%2527%2520OR%2520%25271%2527%253D%25271"),
        ("unicode-nul", "1%00' OR '1'='1"),
        ("unicode-quote", "%u0027%u0020OR%u0020%u00271%u0027%u003D%u00271"),

        # 空格绕过
        ("space-plus", "1'+OR+'1'='1"),
        ("space-tab", "1'\tOR\t'1'='1"),
        ("space-newline", "1'\nOR\n'1'='1"),
        ("space-comment", "1'/**/OR/**/'1'='1"),

        # 大小写混合
        ("case-mix-1", "1' UnIoN SeLeCt * FrOm users--"),
        ("case-mix-2", "1' aNd '1'='1"),
        ("case-mix-3", "1' Or '1'='1"),

        # 无空格注入
        ("no-space-1", "1'OR'1'='1"),
        ("no-space-2", "1'/**/OR/**/'1'='1"),
        ("no-space-3", "1'%0bOR%0b'1'='1"),

        # 宽字节注入
        ("wide-byte", "%df' OR '1'='1"),
        ("wide-byte-2", "%df%27%20OR%20%271%27%3D%271"),

        # 二次编码 / HPP
        ("hpp-1", "1&id=2' OR '1'='1"),
        ("hpp-2", "1\u0026id=2' OR '1'='1"),

        # 子查询
        ("subquery-1", "1' AND (SELECT COUNT(*) FROM users)>0--"),
        ("subquery-2", "1' AND (SELECT LENGTH(password) FROM admin)=32--"),
        ("subquery-3", "1' AND ASCII(SUBSTRING((SELECT password FROM admin),1,1))>64--"),

        # 报错注入
        ("error-floor", "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"),
        ("error-extract", "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--"),
        ("error-updatexml", "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--"),

        # JSON 注入
        ("json-inject", "1'},{\"$gt\":0},{"),
        ("json-inject-2", "1' UNION SELECT * FROM users--"),

        # 边界/特殊字符
        ("boundary-null", "1\x00' OR '1'='1"),
        ("boundary-backslash", "1\\' OR '1'='1"),
        ("boundary-quote-escape", "1\\\" OR \"1\"=\"1"),
    ]

    # ========== POST Body Payloads ==========
    POST_PAYLOADS = [
        ("json-classic", "1' OR '1'='1"),
        ("json-union", "-1 UNION SELECT 1,2,3--"),
        ("json-sleep", "1' AND SLEEP(5)--"),
        ("json-stacked", "1'; DROP TABLE users;--"),
        ("json-hex", "1' AND 0x31=0x31--"),
        ("json-nosqli", "{\"$ne\": null}"),
        ("json-nosqli-2", "{\"$gt\": \"\"}"),
        ("json-nosqli-regex", "{\"$regex\": \"admin\"}"),

        ("form-classic", "1' OR '1'='1"),
        ("form-union", "-1 UNION SELECT * FROM admin--"),
        ("form-sleep", "1' AND BENCHMARK(1000000,SHA1(1))--"),
        ("form-stacked", "1'; DELETE FROM logs;--"),

        ("raw-classic", "username=admin' OR '1'='1\u0026password=123"),
        ("raw-union", "id=-1 UNION SELECT 1,2,3--"),
    ]

    # ========== Header / Cookie Payloads ==========
    HEADER_PAYLOADS = [
        ("header-x-forwarded", "1' OR '1'='1"),
        ("header-user-agent", "Mozilla/5.0' OR '1'='1"),
        ("header-referer", "http://evil.com' OR '1'='1"),
        ("header-accept", "text/html' UNION SELECT 1,2,3--"),
    ]

    COOKIE_PAYLOADS = [
        ("cookie-classic", "1' OR '1'='1"),
        ("cookie-union", "-1 UNION SELECT * FROM users--"),
        ("cookie-sleep", "1' AND SLEEP(3)--"),
        ("cookie-hex", "1' AND 0x31=0x31--"),
    ]

    # ========== Path Payloads ==========
    PATH_PAYLOADS = [
        ("path-id", "1' OR '1'='1"),
        ("path-union", "-1 UNION SELECT 1,2,3"),
        ("path-quote", "admin'--"),
        ("path-stacked", "1'; DROP TABLE users;--"),
    ]

    def run(self):
        print(f"  {Colors.c('正在执行 SQL 注入测试...', Colors.INFO)}\n")

        # ---- GET Query ----
        print(f"  {Colors.c('[注入点] GET Query 参数', Colors.CYAN)}")
        for name, payload in self.GET_PAYLOADS:
            self.get_query(f"sqli-get-{name}", payload, "/search", "q")

        # ---- GET Path ----
        print(f"  {Colors.c('[注入点] GET Path', Colors.CYAN)}")
        for name, payload in self.PATH_PAYLOADS:
            self.get_path(f"sqli-path-{name}", payload, "/api/item")

        # ---- POST JSON ----
        print(f"  {Colors.c('[注入点] POST JSON Body', Colors.CYAN)}")
        for name, payload in self.POST_PAYLOADS[:8]:
            self.post_json(f"sqli-json-{name}", payload, "/api/login", "username")

        # ---- POST Form ----
        print(f"  {Colors.c('[注入点] POST Form Data', Colors.CYAN)}")
        for name, payload in self.POST_PAYLOADS[8:12]:
            self.post_form(f"sqli-form-{name}", payload, "/api/login", "username")

        # ---- POST Raw ----
        print(f"  {Colors.c('[注入点] POST Raw Body', Colors.CYAN)}")
        for name, payload in self.POST_PAYLOADS[12:]:
            self.post_raw(f"sqli-raw-{name}", payload, "/api/data")

        # ---- Header ----
        print(f"  {Colors.c('[注入点] Header 注入', Colors.CYAN)}")
        headers = ["X-Custom-Header", "X-Forwarded-For", "X-Original-URL", "X-Request-Uri"]
        for i, (name, payload) in enumerate(self.HEADER_PAYLOADS):
            h = headers[i % len(headers)]
            self.header_inject(f"sqli-hdr-{name}", payload, h, "/api/echo")

        # ---- Cookie ----
        print(f"  {Colors.c('[注入点] Cookie 注入', Colors.CYAN)}")
        for name, payload in self.COOKIE_PAYLOADS:
            self.cookie_inject(f"sqli-cookie-{name}", payload, "/api/echo")

        # ---- PUT / PATCH ----
        print(f"  {Colors.c('[注入点] PUT / PATCH Body', Colors.CYAN)}")
        put_payloads = [
            ("put-classic", "1' OR '1'='1"),
            ("put-union", "-1 UNION SELECT 1,2,3--"),
            ("put-sleep", "1' AND SLEEP(2)--"),
        ]
        for name, payload in put_payloads:
            self.put_json(f"sqli-put-{name}", payload, "/api/user/1", "bio")
            self.patch_json(f"sqli-patch-{name}", payload, "/api/user/1", "bio")


if __name__ == "__main__":
    args = parse_args("SQL 注入攻击测试")
    tester = SQLiTester(
        target=args.target, domain=args.domain,
        verbose=args.verbose, timeout=args.timeout, delay=args.delay
    )
    tester.execute()
