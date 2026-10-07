#!/usr/bin/env python3
"""
WAF 攻击测试汇总运行脚本

用法:
    python scripts/test/run_all_tests.py --target http://localhost:9000

    # 只运行部分测试
    python scripts/test/run_all_tests.py --target http://localhost:9000 --tests sqli,xss,lfi

    # 高并发模式（减少请求间隔）
    python scripts/test/run_all_tests.py --target http://localhost:9000 --delay 0.05

功能:
    - 自动发现并运行 scripts/test/ 目录下所有 test_*.py 脚本
    - 汇总所有测试结果，生成统一报告
    - 支持选择部分测试运行
    - 支持导出 JSON 报告
"""
import argparse
import importlib
import json
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional

# 确保 test_base 在路径中
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_base import Colors


# 所有可用的测试脚本
ALL_TESTS = [
    ("sqli", "SQL 注入", "test_sqli"),
    ("xss", "XSS", "test_xss"),
    ("rce", "RCE", "test_rce"),
    ("lfi", "LFI/路径遍历", "test_lfi"),
    ("ssrf", "SSRF", "test_ssrf"),
    ("cmdi", "命令注入", "test_cmdi"),
    ("upload", "文件上传", "test_upload"),
    ("nosqli", "NoSQL 注入", "test_nosqli"),
    ("xxe", "XXE", "test_xxe"),
    ("openredirect", "开放重定向", "test_openredirect"),
    ("crlf", "CRLF 注入", "test_crlf"),
]


class Colors:
    OK = "\033[92m"
    FAIL = "\033[91m"
    WARN = "\033[93m"
    INFO = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"

    @classmethod
    def c(cls, text, color):
        return f"{color}{text}{cls.END}"


def print_banner():
    print("\n" + "=" * 70)
    print(f"  {Colors.c('WAF-Coraza 攻击测试套件', Colors.BOLD)}")
    print(f"  {Colors.c('All Attack Vectors Test Suite', Colors.CYAN)}")
    print("=" * 70 + "\n")


def run_single_test(module_name: str, target: str, domain: str,
                    verbose: bool, timeout: int, delay: float):
    """运行单个测试脚本"""
    try:
        module = importlib.import_module(module_name)
        # 找到模块中的 Tester 类（以 Tester 结尾）
        tester_class = None
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and attr_name.endswith("Tester"):
                tester_class = attr
                break

        if not tester_class:
            print(f"  {Colors.c('[错误]', Colors.FAIL)} 未找到 Tester 类: {module_name}")
            return None

        tester = tester_class(
            target=target, domain=domain,
            verbose=verbose, timeout=timeout, delay=delay
        )
        results = tester.execute()
        return {
            "name": tester_class.ATTACK_NAME,
            "desc": tester_class.ATTACK_DESC,
            "results": results,
            "passed": sum(1 for r in results if r.passed),
            "failed": sum(1 for r in results if not r.passed),
            "blocked": sum(1 for r in results if r.blocked),
            "total": len(results),
        }
    except Exception as e:
        print(f"  {Colors.c('[错误]', Colors.FAIL)} 运行 {module_name} 失败: {e}")
        import traceback
        traceback.print_exc()
        return None


def print_summary(all_results: List[Dict]):
    """打印汇总报告"""
    print("\n" + "=" * 70)
    print(f"  {Colors.c('全局测试汇总报告', Colors.BOLD)}")
    print("=" * 70)

    total_cases = 0
    total_passed = 0
    total_failed = 0
    total_blocked = 0

    for result in all_results:
        if not result:
            continue
        total_cases += result["total"]
        total_passed += result["passed"]
        total_failed += result["failed"]
        total_blocked += result["blocked"]

        status_color = Colors.OK if result["failed"] == 0 else Colors.FAIL
        status_text = "通过" if result["failed"] == 0 else f"失败 {result['failed']}"

        print(f"\n  {Colors.c(result['name'], Colors.BOLD)}")
        print(f"    描述: {result['desc']}")
        print(f"    用例: {result['total']} | 拦截: {result['blocked']} | "
              f"通过: {Colors.c(result['passed'], Colors.OK)} | "
              f"失败: {Colors.c(result['failed'], status_color)}")
        print(f"    状态: {Colors.c(status_text, status_color)}")

    print("\n" + "-" * 70)
    print(f"  {Colors.c('总计', Colors.BOLD)}")
    print(f"    总用例数: {total_cases}")
    print(f"    总拦截数: {Colors.c(total_blocked, Colors.OK)}")
    print(f"    总通过数: {Colors.c(total_passed, Colors.OK)}")
    print(f"    总失败数: {Colors.c(total_failed, Colors.FAIL) if total_failed else total_failed}")
    print("-" * 70)

    if total_failed == 0:
        print(f"\n  {Colors.c('所有攻击向量测试全部通过！', Colors.OK)}")
    else:
        print(f"\n  {Colors.c(f'共有 {total_failed} 个用例未通过，请检查 WAF 规则配置', Colors.FAIL)}")
    print("=" * 70 + "\n")


def export_json(all_results: List[Dict], output_path: str):
    """导出 JSON 报告"""
    export_data = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_cases": sum(r["total"] for r in all_results if r),
            "total_blocked": sum(r["blocked"] for r in all_results if r),
            "total_passed": sum(r["passed"] for r in all_results if r),
            "total_failed": sum(r["failed"] for r in all_results if r),
        },
        "tests": []
    }

    for result in all_results:
        if not result:
            continue
        test_data = {
            "name": result["name"],
            "desc": result["desc"],
            "total": result["total"],
            "blocked": result["blocked"],
            "passed": result["passed"],
            "failed": result["failed"],
            "details": []
        }
        for r in result["results"]:
            test_data["details"].append({
                "name": r.name,
                "payload": r.payload,
                "method": r.method,
                "status_code": r.status_code,
                "expected_block": r.expected_block,
                "blocked": r.blocked,
                "passed": r.passed,
                "injection_point": r.injection_point,
                "response_preview": r.response_preview,
            })
        export_data["tests"].append(test_data)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(export_data, f, ensure_ascii=False, indent=2)

    print(f"\n  报告已导出到: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="WAF 攻击测试汇总运行脚本")
    parser.add_argument("--target", "-t", default="http://localhost:9000",
                        help="WAF 代理目标地址")
    parser.add_argument("--domain", "-d", default="localhost",
                        help="Host 头域名")
    parser.add_argument("--tests", default="all",
                        help="要运行的测试，逗号分隔，例如: sqli,xss,lfi (默认: all)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="打印每个请求的详细结果")
    parser.add_argument("--timeout", type=int, default=10,
                        help="请求超时秒数")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="请求间隔秒数")
    parser.add_argument("--json", "-j", default="",
                        help="导出 JSON 报告到指定路径")
    args = parser.parse_args()

    print_banner()

    # 确定要运行的测试
    if args.tests == "all":
        selected_tests = ALL_TESTS
    else:
        test_ids = [t.strip().lower() for t in args.tests.split(",")]
        selected_tests = [t for t in ALL_TESTS if t[0] in test_ids]
        if not selected_tests:
            print(f"{Colors.c('[错误]', Colors.FAIL)} 未找到指定的测试: {args.tests}")
            print(f"可用测试: {', '.join(t[0] for t in ALL_TESTS)}")
            sys.exit(1)

    print(f"  目标: {Colors.c(args.target, Colors.CYAN)}")
    print(f"  Host: {Colors.c(args.domain, Colors.CYAN)}")
    print(f"  测试项: {Colors.c(', '.join(t[1] for t in selected_tests), Colors.CYAN)}")
    print(f"  请求间隔: {args.delay}s")
    print()

    all_results = []
    start_time = time.time()

    for test_id, test_name, module_name in selected_tests:
        print(f"\n{'='*70}")
        print(f"  [{Colors.c(test_name, Colors.BOLD)}] 开始测试...")
        print(f"{'='*70}")

        result = run_single_test(
            module_name, args.target, args.domain,
            args.verbose, args.timeout, args.delay
        )
        all_results.append(result)

    elapsed = time.time() - start_time

    print_summary(all_results)
    print(f"  总耗时: {elapsed:.1f} 秒\n")

    if args.json:
        export_json(all_results, args.json)


if __name__ == "__main__":
    main()
