#!/usr/bin/env python3
"""
CC 防护测试脚本 — 简洁版

核心功能:
    - 控制请求次数
    - 显示每个请求是否被拦截（429/403）
    - 显示每个请求的响应延迟（毫秒）

用法:
    # 基本测试（20个请求）
    python scripts/test/test_cc.py -t http://127.0.0.1:9000 -n 20

    # 高并发（200个请求，50并发）
    python scripts/test/test_cc.py -t http://127.0.0.1:9000 -n 200 -c 50

    # 观察延迟模式（站点配置了 delay_ms）
    python scripts/test/test_cc.py -t http://127.0.0.1:9000 -n 100 -c 20

    # 详细模式（打印每个请求）
    python scripts/test/test_cc.py -t http://127.0.0.1:9000 -n 30 -v
"""
import argparse
import asyncio
import time
import sys
from collections import defaultdict
from datetime import datetime

import aiohttp


class Colors:
    OK = "\033[92m"
    FAIL = "\033[91m"
    WARN = "\033[93m"
    INFO = "\033[94m"
    CYAN = "\033[96m"
    END = "\033[0m"

    @staticmethod
    def c(text, color):
        return f"{color}{text}{Colors.END}"


async def send_request(session: aiohttp.ClientSession, url: str, headers: dict,
                       timeout: int, verbose: bool, req_id: int) -> dict:
    """发送单个请求，返回字典包含 status、延迟(ms)、是否被拦截"""
    start = time.time()
    try:
        async with session.get(url, headers=headers,
                               timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            elapsed_ms = (time.time() - start) * 1000
            blocked = resp.status in (429, 403)
            result = {
                "id": req_id,
                "status": resp.status,
                "elapsed_ms": round(elapsed_ms, 1),
                "blocked": blocked,
                "blocked_reason": "",
            }
            if blocked:
                result["blocked_reason"] = f"[{resp.status}] CC拦截"
            elif resp.status != 200:
                result["blocked_reason"] = f"[{resp.status}] 其他错误"
            return result
    except asyncio.TimeoutError:
        elapsed_ms = (time.time() - start) * 1000
        return {
            "id": req_id,
            "status": 0,
            "elapsed_ms": round(elapsed_ms, 1),
            "blocked": False,
            "blocked_reason": "[超时]",
        }
    except Exception as e:
        elapsed_ms = (time.time() - start) * 1000
        return {
            "id": req_id,
            "status": 0,
            "elapsed_ms": round(elapsed_ms, 1),
            "blocked": False,
            "blocked_reason": f"[异常: {e}]",
        }


async def run_test(target: str, domain: str, total: int, concurrent: int,
                   timeout: int, verbose: bool):
    """运行测试并打印结果"""
    url = target.rstrip("/") + "/api/test"
    headers = {"Host": domain}

    print(f"\n{Colors.c('='*60, Colors.CYAN)}")
    print(f"  CC 防护测试")
    print(f"  目标: {target}")
    print(f"  请求数: {total}  |  并发: {concurrent}")
    print(f"  开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{Colors.c('='*60, Colors.CYAN)}")

    sem = asyncio.Semaphore(concurrent)
    results = []

    async with aiohttp.ClientSession() as session:
        async def bounded_send(req_id):
            async with sem:
                return await send_request(session, url, headers, timeout, verbose, req_id)

        print(f"\n  正在发送 {total} 个请求，并发数 {concurrent}...\n")

        tasks = [bounded_send(i) for i in range(total)]
        results = await asyncio.gather(*tasks)

    # 打印每个请求结果
    if verbose:
        print(f"  {'─'*55}")
        print(f"  {'编号':>4}  {'状态':>6}  {'延迟(ms)':>10}  {'结果'}")
        print(f"  {'─'*55}")

    blocked_count = 0
    success_count = 0
    error_count = 0
    delay_times = []

    for r in results:
        if r["blocked"]:
            blocked_count += 1
            symbol = Colors.c("✗ 拦截", Colors.FAIL)
        elif r["status"] == 200:
            success_count += 1
            symbol = Colors.c("✓ 成功", Colors.OK)
            delay_times.append(r["elapsed_ms"])
        else:
            error_count += 1
            symbol = Colors.c(r["blocked_reason"], Colors.WARN)

        if verbose:
            print(f"  {r['id']:>4d}  {r['status']:>6d}  {r['elapsed_ms']:>10.1f}  {symbol}")

    # 统计汇总
    print(f"\n{Colors.c('='*60, Colors.CYAN)}")
    print(f"  汇总报告")
    print(f"{Colors.c('='*60, Colors.CYAN)}")

    print(f"  总请求数:  {total}")
    print(f"  成功(200): {Colors.c(f'{success_count}', Colors.OK)}  ({success_count/total*100:.1f}%)")
    print(f"  被拦截:    {Colors.c(f'{blocked_count}', Colors.FAIL if blocked_count else Colors.OK)}  ({blocked_count/total*100:.1f}%)")
    print(f"  其他错误:  {Colors.c(f'{error_count}', Colors.WARN if error_count else Colors.OK)}")

    # 延迟统计（仅成功请求）
    if delay_times:
        delay_times.sort()
        avg = sum(delay_times) / len(delay_times)
        p50 = delay_times[len(delay_times) // 2]
        p90 = delay_times[int(len(delay_times) * 0.9)]
        p99 = delay_times[int(len(delay_times) * 0.99)]
        mn = min(delay_times)
        mx = max(delay_times)

        print(f"\n  响应延迟（成功请求，单位: ms）:")
        print(f"    平均: {avg:.1f}ms")
        print(f"    P50:  {p50:.1f}ms")
        print(f"    P90:  {p90:.1f}ms")
        print(f"    P99:  {p99:.1f}ms")
        print(f"    最小: {mn:.1f}ms")
        print(f"    最大: {mx:.1f}ms")
    else:
        print(f"\n  响应延迟: 无成功请求")

    # 判断结论
    print(f"\n  {'─'*50}")
    if blocked_count > 0:
        rate = blocked_count / total * 100
        print(f"  {Colors.c('结论: CC 防护已生效!', Colors.OK)} 拦截率 {rate:.1f}%")
        if delay_times and avg > 300:
            print(f"  {Colors.c('注意: 响应延迟偏高，可能触发了 delay 模式', Colors.WARN)}")
    else:
        print(f"  {Colors.c('结论: 无拦截记录', Colors.WARN)}")
        print(f"  可能原因: CC 未启用 / 阈值高于 {total} / 间隔过大")
    print(f"  {'─'*50}\n")

    # 打印被拦截的详情
    if blocked_count > 0 and not verbose:
        print(f"  被拦截请求详情 ({blocked_count} 条):")
        print(f"  {'─'*55}")
        print(f"  {'编号':>4}  {'状态':>6}  {'延迟(ms)':>10}")
        print(f"  {'─'*55}")
        for r in results:
            if r["blocked"]:
                print(f"  {r['id']:>4d}  {r['status']:>6d}  {r['elapsed_ms']:>10.1f}")
        print()


async def main():
    parser = argparse.ArgumentParser(description="CC 防护测试脚本")
    parser.add_argument("-t", "--target", default="http://localhost:9000",
                        help="WAF 代理地址")
    parser.add_argument("-d", "--domain", default="localhost",
                        help="Host 头")
    parser.add_argument("-n", "--requests", type=int, default=30,
                        help="总请求数")
    parser.add_argument("-c", "--concurrent", type=int, default=10,
                        help="并发数")
    parser.add_argument("--timeout", type=int, default=10,
                        help="请求超时秒数")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="打印每个请求的详细结果")
    args = parser.parse_args()

    await run_test(args.target, args.domain, args.requests,
                   args.concurrent, args.timeout, args.verbose)


if __name__ == "__main__":
    asyncio.run(main())