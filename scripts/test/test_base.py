#!/usr/bin/env python3
"""
WAF 攻击测试公共基类与工具模块

所有攻击测试脚本均继承 WAFTestBase，统一输出格式与报告风格。
"""
import argparse
import json
import sys
import time
import urllib.parse
from collections import defaultdict
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests


class Colors:
    OK = "\033[92m"
    FAIL = "\033[91m"
    WARN = "\033[93m"
    INFO = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"

    @classmethod
    def c(cls, text: str, color: str) -> str:
        return f"{color}{text}{cls.END}"


class TestResult:
    def __init__(self, name: str, payload: str, method: str,
                 status_code: int, expected_block: bool,
                 blocked: bool, response_preview: str = "",
                 injection_point: str = "", elapsed_ms: float = 0.0):
        self.name = name
        self.payload = payload
        self.method = method
        self.status_code = status_code
        self.expected_block = expected_block
        self.blocked = blocked
        self.response_preview = response_preview
        self.injection_point = injection_point
        self.elapsed_ms = elapsed_ms
        self.passed = blocked if expected_block else not blocked


class WAFTestBase:
    """WAF 攻击测试基类"""

    ATTACK_NAME = "BaseAttack"
    ATTACK_DESC = "基础攻击测试"

    def __init__(self, target: str, domain: str, verbose: bool = False,
                 timeout: int = 10, delay: float = 0.2):
        self.target = target.rstrip("/")
        self.domain = domain
        self.verbose = verbose
        self.timeout = timeout
        self.delay = delay
        self.results: List[TestResult] = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "WAF-Test-Client/1.0",
            "Accept": "*/*",
        })

    def _req(self, method: str, path: str, **kwargs) -> requests.Response:
        """发送请求并返回响应"""
        url = f"{self.target}{path}"
        headers = kwargs.pop("headers", {})
        headers.setdefault("Host", self.domain)
        try:
            start = time.time()
            resp = self.session.request(
                method, url, headers=headers, timeout=self.timeout, **kwargs
            )
            elapsed = (time.time() - start) * 1000
            return resp
        except requests.Timeout:
            r = requests.Response()
            r.status_code = 0
            r._content = b"TIMEOUT"
            return r
        except requests.ConnectionError:
            r = requests.Response()
            r.status_code = 0
            r._content = b"CONNECTION_ERROR"
            return r
        except Exception as e:
            r = requests.Response()
            r.status_code = 0
            r._content = str(e).encode()
            return r

    def is_blocked(self, resp: requests.Response) -> bool:
        """判断响应是否表示被 WAF 拦截"""
        return resp.status_code in (403, 429, 406, 501, 502, 503)

    def _preview(self, resp: requests.Response, max_len: int = 120) -> str:
        """提取响应预览文本"""
        try:
            text = resp.text[:max_len].replace("\n", " ").replace("\r", "")
            return text
        except Exception:
            return "<binary>"

    def send_and_record(self, name: str, payload: str, method: str,
                        path: str, expected_block: bool = True,
                        injection_point: str = "",
                        **req_kwargs) -> TestResult:
        """发送请求并记录结果"""
        resp = self._req(method, path, **req_kwargs)
        blocked = self.is_blocked(resp)
        preview = self._preview(resp)

        result = TestResult(
            name=name, payload=payload, method=method,
            status_code=resp.status_code, expected_block=expected_block,
            blocked=blocked, response_preview=preview,
            injection_point=injection_point
        )
        self.results.append(result)

        if self.verbose:
            tag = Colors.c("BLOCKED", Colors.OK) if blocked else Colors.c("PASSED", Colors.CYAN)
            print(f"  [{tag}] {method} {path} -> {resp.status_code} ({preview[:60]}...)")

        time.sleep(self.delay)
        return result

    # ========== 便捷封装：不同注入点 ==========

    def get_query(self, name: str, payload: str, path: str = "/search",
                  param: str = "q", expected_block: bool = True) -> TestResult:
        """GET Query 参数注入"""
        encoded = urllib.parse.quote(payload, safe="")
        full_path = f"{path}?{param}={encoded}"
        return self.send_and_record(
            name, payload, "GET", full_path,
            expected_block=expected_block, injection_point="GET-query"
        )

    def get_path(self, name: str, payload: str, base_path: str = "/api/item",
                 expected_block: bool = True) -> TestResult:
        """GET Path 注入"""
        full_path = f"{base_path}/{urllib.parse.quote(payload, safe='')}"
        return self.send_and_record(
            name, payload, "GET", full_path,
            expected_block=expected_block, injection_point="GET-path"
        )

    def post_json(self, name: str, payload: str, path: str = "/api/login",
                  field: str = "username", expected_block: bool = True,
                  extra_fields: Optional[Dict] = None) -> TestResult:
        """POST JSON Body 注入"""
        data = {field: payload}
        if extra_fields:
            data.update(extra_fields)
        return self.send_and_record(
            name, payload, "POST", path,
            expected_block=expected_block, injection_point="POST-json",
            json=data, headers={"Content-Type": "application/json"}
        )

    def post_form(self, name: str, payload: str, path: str = "/api/login",
                  field: str = "username", expected_block: bool = True,
                  extra_fields: Optional[Dict] = None) -> TestResult:
        """POST Form-Data / x-www-form-urlencoded 注入"""
        data = {field: payload}
        if extra_fields:
            data.update(extra_fields)
        return self.send_and_record(
            name, payload, "POST", path,
            expected_block=expected_block, injection_point="POST-form",
            data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

    def post_raw(self, name: str, payload: str, path: str = "/api/data",
                 expected_block: bool = True) -> TestResult:
        """POST Raw Body 注入"""
        return self.send_and_record(
            name, payload, "POST", path,
            expected_block=expected_block, injection_point="POST-raw",
            data=payload, headers={"Content-Type": "text/plain"}
        )

    def header_inject(self, name: str, payload: str, header_name: str = "X-Custom-Header",
                      path: str = "/api/echo", expected_block: bool = True) -> TestResult:
        """Header 注入"""
        return self.send_and_record(
            name, payload, "GET", path,
            expected_block=expected_block, injection_point=f"Header-{header_name}",
            headers={header_name: payload}
        )

    def cookie_inject(self, name: str, payload: str, path: str = "/api/echo",
                      expected_block: bool = True) -> TestResult:
        """Cookie 注入"""
        return self.send_and_record(
            name, payload, "GET", path,
            expected_block=expected_block, injection_point="Cookie",
            headers={"Cookie": f"session={urllib.parse.quote(payload, safe='')}"}
        )

    def put_json(self, name: str, payload: str, path: str = "/api/user/1",
                 field: str = "bio", expected_block: bool = True) -> TestResult:
        """PUT JSON Body 注入"""
        return self.send_and_record(
            name, payload, "PUT", path,
            expected_block=expected_block, injection_point="PUT-json",
            json={field: payload}, headers={"Content-Type": "application/json"}
        )

    def patch_json(self, name: str, payload: str, path: str = "/api/user/1",
                   field: str = "bio", expected_block: bool = True) -> TestResult:
        """PATCH JSON Body 注入"""
        return self.send_and_record(
            name, payload, "PATCH", path,
            expected_block=expected_block, injection_point="PATCH-json",
            json={field: payload}, headers={"Content-Type": "application/json"}
        )

    # ========== 测试执行框架 ==========

    def run(self):
        """子类重写此方法，填充 self.results"""
        raise NotImplementedError("子类必须实现 run() 方法")

    def print_header(self):
        print("\n" + "=" * 70)
        print(f"  {Colors.c(self.ATTACK_NAME, Colors.BOLD)}  —  {self.ATTACK_DESC}")
        print(f"  目标: {self.target}  |  Host: {self.domain}")
        print("=" * 70)

    def print_report(self):
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed
        blocked = sum(1 for r in self.results if r.blocked)
        by_point: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "blocked": 0})
        for r in self.results:
            by_point[r.injection_point]["total"] += 1
            if r.blocked:
                by_point[r.injection_point]["blocked"] += 1

        print("\n" + "-" * 70)
        print(f"  {Colors.c('测试报告', Colors.BOLD)}")
        print("-" * 70)
        print(f"  总用例数: {total}")
        print(f"  被拦截数: {Colors.c(blocked, Colors.OK)}")
        print(f"  通过数:   {Colors.c(passed, Colors.OK)}")
        print(f"  失败数:   {Colors.c(failed, Colors.FAIL) if failed else failed}")
        print()
        print("  按注入点统计:")
        for point, stats in sorted(by_point.items()):
            rate = stats["blocked"] / stats["total"] * 100 if stats["total"] else 0
            color = Colors.OK if rate >= 50 else (Colors.WARN if rate > 0 else Colors.FAIL)
            print(f"    {point:20s}  拦截 {stats['blocked']}/{stats['total']}  ({rate:5.1f}%)")
        print("-" * 70)

        if failed > 0 and not getattr(self, "_silent", False):
            print(f"\n  {Colors.c('失败详情:', Colors.FAIL)}")
            for r in self.results:
                if not r.passed:
                    expect = "应被拦截" if r.expected_block else "应放行"
                    actual = "已拦截" if r.blocked else "未拦截"
                    print(f"    {Colors.c('FAIL', Colors.FAIL)} {r.method} [{r.injection_point}] {r.name}")
                    print(f"      Payload: {r.payload[:80]}")
                    print(f"      期望: {expect} | 实际: {actual} | Status: {r.status_code}")
                    print(f"      响应: {r.response_preview[:80]}")

    def execute(self):
        self.print_header()
        self.run()
        self.print_report()
        return self.results


def parse_args(desc: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("--target", "-t", default="http://localhost:9000",
                        help="WAF 代理目标地址")
    parser.add_argument("--domain", "-d", default="localhost",
                        help="Host 头域名")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="打印每个请求的详细结果")
    parser.add_argument("--timeout", type=int, default=10,
                        help="请求超时秒数")
    parser.add_argument("--delay", type=float, default=0.15,
                        help="请求间隔秒数")
    return parser.parse_args()


if __name__ == "__main__":
    print("这是公共基类模块，请运行具体的攻击测试脚本。")
    print("例如: python scripts/test/test_sqli.py")
