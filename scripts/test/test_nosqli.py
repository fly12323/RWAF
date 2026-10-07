#!/usr/bin/env python3
"""
NoSQL 注入攻击测试脚本

覆盖注入点:
  - GET Query / Path
  - POST JSON / Form
  - Header / Cookie
  - PUT / PATCH

Payload 来源: MongoDB、Elasticsearch、CouchDB、Redis 等 NoSQL 注入技巧。
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_base import WAFTestBase, parse_args, Colors


class NoSQLiTester(WAFTestBase):
    ATTACK_NAME = "NoSQL Injection"
    ATTACK_DESC = "NoSQL 注入测试 — MongoDB / Elasticsearch / CouchDB 注入技巧"

    GET_PAYLOADS = [
        # MongoDB 操作符
        ("mongo-ne", '{"$ne": null}'),
        ("mongo-ne-2", '{"$ne": "admin"}'),
        ("mongo-gt", '{"$gt": ""}'),
        ("mongo-gte", '{"$gte": ""}'),
        ("mongo-lt", '{"$lt": ""}'),
        ("mongo-lte", '{"$lte": ""}'),
        ("mongo-regex", '{"$regex": ".*"}'),
        ("mongo-regex-2", '{"$regex": "^a"}'),
        ("mongo-exists", '{"$exists": true}'),
        ("mongo-exists-2", '{"$exists": false}'),
        ("mongo-type", '{"$type": "string"}'),
        ("mongo-where", '{"$where": "this.password.length > 0"}'),
        ("mongo-where-2", '{"$where": "sleep(5000)"}'),
        ("mongo-elemMatch", '{"$elemMatch": {"$gt": ""}}'),
        ("mongo-all", '{"$all": [{"$gt": ""}]}'),
        ("mongo-size", '{"$size": 0}'),
        ("mongo-nin", '{"$nin": ["admin"]}'),
        ("mongo-in", '{"$in": ["admin", "user", "root"]}'),
        ("mongo-mod", '{"$mod": [1, 0]}'),
        ("mongo-not", '{"$not": {"$gt": ""}}'),
        ("mongo-or", '{"$or": [{},{"a":"a"}]}'),
        ("mongo-and", '{"$and": [{},{"a":"a"}]}'),

        # URL 编码形式
        ("url-ne", '%7B%22%24ne%22%3A%20null%7D'),
        ("url-gt", '%7B%22%24gt%22%3A%20%22%22%7D'),
        ("url-regex", '%7B%22%24regex%22%3A%20%22.*%22%7D'),
        ("url-where", '%7B%22%24where%22%3A%20%22this.password.length%20%3E%200%22%7D'),

        # 数组注入
        ("array-inject", '[{"$gt": ""}]'),
        ("array-inject-2", '[{"$ne": null}]'),

        # Elasticsearch
        ("es-match", '{"match": {"password": ".*"}}'),
        ("es-match-all", '{"match_all": {}}'),
        ("es-query-string", '{"query_string": {"query": "*"}}'),
        ("es-script", '{"script": {"source": "doc[\'password\'].value"}}'),
        ("es-script-2", '{"script_fields": {"test": {"script": "java.lang.Math.class.forName(\\"java.lang.Runtime\\").getRuntime().exec(\\"whoami\\")"}}}'),
        ("es-wildcard", '{"wildcard": {"username": "*"}}'),
        ("es-regexp", '{"regexp": {"username": ".*"}}'),
        ("es-fuzzy", '{"fuzzy": {"username": "admin"}}'),

        # CouchDB
        ("couch-selector", '{"selector": {"username": {"$gt": null}}}'),
        ("couch-map", '{"map": "function(doc) { emit(doc._id, doc); }"}'),

        # Redis
        ("redis-eval", 'eval "return redis.call(\'keys\', \'*\')" 0'),
        ("redis-config", 'config set dir /var/www/html'),
        ("redis-flush", 'flushall'),
    ]

    POST_PAYLOADS = [
        ("json-mongo-ne", '{"username": {"$ne": null}}'),
        ("json-mongo-gt", '{"password": {"$gt": ""}}'),
        ("json-mongo-regex", '{"username": {"$regex": "^admin"}}'),
        ("json-mongo-exists", '{"password": {"$exists": true}}'),
        ("json-mongo-where", '{"$where": "this.password.length > 0"}'),
        ("json-mongo-or", '{"$or": [{"username": "admin"}, {"1": "1"}]}'),
        ("json-es-script", '{"script": {"source": "doc[\'password\'].value"}}'),
        ("json-es-match-all", '{"query": {"match_all": {}}}'),
        ("json-couch-selector", '{"selector": {"username": {"$gt": null}}}'),
        ("json-array-inject", '[{"$gt": ""}]'),

        ("form-mongo-ne", '{"$ne": null}'),
        ("form-mongo-gt", '{"$gt": ""}'),
        ("form-mongo-regex", '{"$regex": ".*"}'),
        ("form-es-match", '{"match": {"password": ".*"}}'),
        ("form-couch-selector", '{"selector": {"username": {"$gt": null}}}'),
    ]

    HEADER_PAYLOADS = [
        ("hdr-x-custom", '{"$ne": null}'),
        ("hdr-ua-mongo", 'Mozilla/5.0 {"$gt": ""}'),
        ("hdr-referer-es", 'http://evil.com {"match_all": {}}'),
    ]

    COOKIE_PAYLOADS = [
        ("cookie-mongo-ne", '{"$ne": null}'),
        ("cookie-mongo-gt", '{"$gt": ""}'),
        ("cookie-mongo-regex", '{"$regex": ".*"}'),
    ]

    PATH_PAYLOADS = [
        ("path-mongo-ne", '{"$ne": null}'),
        ("path-mongo-gt", '{"$gt": ""}'),
        ("path-mongo-regex", '{"$regex": ".*"}'),
    ]

    def run(self):
        print(f"  {Colors.c('正在执行 NoSQL 注入测试...', Colors.INFO)}\n")

        print(f"  {Colors.c('[注入点] GET Query', Colors.CYAN)}")
        for name, payload in self.GET_PAYLOADS:
            self.get_query(f"nosqli-get-{name}", payload, "/api/search", "q")

        print(f"  {Colors.c('[注入点] GET Path', Colors.CYAN)}")
        for name, payload in self.PATH_PAYLOADS:
            self.get_path(f"nosqli-path-{name}", payload, "/api/doc")

        print(f"  {Colors.c('[注入点] POST JSON', Colors.CYAN)}")
        for name, payload in self.POST_PAYLOADS[:6]:
            self.post_json(f"nosqli-json-{name}", payload, "/api/login", "query")

        print(f"  {Colors.c('[注入点] POST Form', Colors.CYAN)}")
        for name, payload in self.POST_PAYLOADS[6:]:
            self.post_form(f"nosqli-form-{name}", payload, "/api/login", "query")

        print(f"  {Colors.c('[注入点] Header', Colors.CYAN)}")
        headers = ["X-Custom-Header", "User-Agent", "Referer"]
        for i, (name, payload) in enumerate(self.HEADER_PAYLOADS):
            h = headers[i % len(headers)]
            self.header_inject(f"nosqli-hdr-{name}", payload, h, "/api/echo")

        print(f"  {Colors.c('[注入点] Cookie', Colors.CYAN)}")
        for name, payload in self.COOKIE_PAYLOADS:
            self.cookie_inject(f"nosqli-cookie-{name}", payload, "/api/echo")

        print(f"  {Colors.c('[注入点] PUT / PATCH', Colors.CYAN)}")
        for name, payload in [("put-mongo-ne", '{"$ne": null}'),
                               ("put-mongo-regex", '{"$regex": ".*"}')]:
            self.put_json(f"nosqli-put-{name}", payload, "/api/config", "filter")
            self.patch_json(f"nosqli-patch-{name}", payload, "/api/config", "filter")


if __name__ == "__main__":
    args = parse_args("NoSQL 注入攻击测试")
    tester = NoSQLiTester(
        target=args.target, domain=args.domain,
        verbose=args.verbose, timeout=args.timeout, delay=args.delay
    )
    tester.execute()
