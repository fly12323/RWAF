#!/usr/bin/env python3
"""
爬虫检测测试脚本

测试 WAF 对各类爬虫、扫描器、搜索引擎、Bot 的识别能力。

用法:
    # 默认测试（展示所有检测结果）
    python scripts/test/test_crawler.py -t http://127.0.0.1:9000

    # 详细模式（打印每个请求的完整信息）
    python scripts/test/test_crawler.py -t http://127.0.0.1:9000 -v

    # 仅显示拦截结果（需站点配置了 block 动作）
    python scripts/test/test_crawler.py -t http://127.0.0.1:9000 --block-only

    # 测试指定类别
    python scripts/test/test_crawler.py -t http://127.0.0.1:9000 --category scanner

站点配置:
    默认所有爬虫动作均为 "log"（仅记录，不拦截）。
    如需测试拦截功能，请配置站点安全设置：
      - 爬虫检测: 开启
      - 扫描器动作: block
      - Bot 动作: block
      - 爬虫动作: block
"""
import argparse
import sys
import time
from collections import defaultdict
from datetime import datetime
from typing import List, Optional, Tuple

import requests

# ========== 颜色输出 ==========

class Colors:
    OK = "\033[92m"
    FAIL = "\033[91m"
    WARN = "\033[93m"
    INFO = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    END = "\033[0m"

    @classmethod
    def c(cls, text: str, color: str) -> str:
        return f"{color}{text}{cls.END}"


# ========== 测试用例定义 ==========

# (name, user_agent, expected_type, expected_name, path, description)
TestCase = Tuple[str, str, str, str, str, str]

SCANNER_CASES: List[TestCase] = [
    ("SQLmap",        "sqlmap/1.5.2 stable",                          "scanner", "SQLmap",          "/api/test", "SQL 注入扫描器"),
    ("Nikto",         "Nikto/2.5.0 (https://cirt.net/nikto)",         "scanner", "Nikto",           "/api/test", "Web 服务器扫描器"),
    ("Nmap",          "nmap/7.92 (https://nmap.org)",                  "scanner", "Nmap",            "/api/test", "端口扫描器"),
    ("Burp Suite",    "BurpSuite/2023.1",                              "scanner", "Burp Suite",      "/api/test", "Burp Suite 代理"),
    ("OWASP ZAP",     "OWASP ZAP/2.12.0 (https://www.zaproxy.org)",    "scanner", "OWASP ZAP",      "/api/test", "ZAP 安全扫描器"),
    ("DirBuster",     "dirb/2.22",                                     "scanner", "DirBuster",       "/api/test", "目录扫描器"),
    ("FFUF",          "ffuf/1.5.0 (https://github.com/ffuf/ffuf)",    "scanner", "FFUF",            "/api/test", "模糊测试工具"),
    ("Gobuster",      "gobuster/3.3.0",                                "scanner", "Gobuster",        "/api/test", "目录/文件扫描器"),
    ("Acunetix",      "Mozilla/5.0 (Windows NT 6.1; rv:1.0) Acunetix", "scanner","Acunetix",       "/api/test", "Acunetix Web 漏洞扫描器"),
    ("Nessus",        "Nessus/8.15.0 (https://www.tenable.com/nessus)","scanner", "Nessus",          "/api/test", "Nessus 漏洞扫描器"),
    ("WPScan",        "WPScan v3.8.20 (https://wpscan.com)",          "scanner", "WPScan",          "/api/test", "WordPress 扫描器"),
    ("Masscan",       "masscan/1.3.2",                                 "scanner", "Masscan",         "/api/test", "大规模端口扫描器"),
    ("Amass",         "amass/3.23.0 (https://owasp.org/amass)",       "scanner", "Amass",           "/api/test", "子域名枚举工具"),
    ("Dirsearch",     "dirsearch/0.4.3",                               "scanner", "Dirsearch",       "/api/test", "目录扫描器"),
]

CRAWLER_CASES: List[TestCase] = [
    ("Googlebot",     "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",   "crawler", "Google Bot",     "/api/test", "Google 搜索引擎爬虫"),
    ("Bingbot",       "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",     "crawler", "Bing Bot",       "/api/test", "Bing 搜索引擎爬虫"),
    ("Baidu Spider",  "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.htm)", "crawler", "Baidu Spider", "/api/test", "百度搜索引擎爬虫"),
    ("Yandex Bot",    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",           "crawler", "Yandex Bot",     "/api/test", "Yandex 搜索引擎爬虫"),
    ("Sogou Spider",  "Sogou web spider/4.0 (+http://www.sogou.com/docs/help/webmasters.htm)",      "crawler", "Sogou Spider",   "/api/test", "搜狗搜索引擎爬虫"),
    ("DuckDuckBot",   "Mozilla/5.0 (compatible; DuckDuckBot-Https/1.1; https://duckduckgo.com/duckduckbot)", "crawler", "DuckDuckGo Bot", "/api/test", "DuckDuckGo 搜索爬虫"),
    ("Facebook",      "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",  "crawler", "Facebook Crawler", "/api/test", "Facebook 链接预览爬虫"),
    ("Twitterbot",    "Twitterbot/1.0 (https://developer.twitter.com/en/docs/twitter-for-websites)", "crawler", "Twitter Bot",    "/api/test", "Twitter 卡片爬虫"),
    ("LinkedIn Bot",  "Mozilla/5.0 (compatible; LinkedInBot/1.0; https://www.linkedin.com/help/linkedin)", "crawler", "LinkedIn Bot", "/api/test", "LinkedIn 爬虫"),
    ("Yahoo Slurp",   "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)", "crawler", "Yahoo Slurp", "/api/test", "Yahoo 搜索爬虫"),
]

BOT_CASES: List[TestCase] = [
    ("cURL",          "curl/7.68.0",                                  "bot",    "cURL",            "/api/test", "curl 命令行工具"),
    ("Wget",          "Wget/1.21.2 (linux-gnu)",                      "bot",    "Wget",            "/api/test", "wget 下载工具"),
    ("Python Requests","python-requests/2.28.1",                      "bot",    "Python Requests", "/api/test", "Python Requests 库"),
    ("Java HttpClient","Java/17.0.2",                                 "bot",    "Java HttpClient", "/api/test", "Java HTTP 客户端"),
    ("Scrapy",        "Scrapy/2.8.0 (+https://scrapy.org)",           "bot",    "Scrapy",          "/api/test", "Scrapy 爬虫框架"),
    ("Selenium",      "Mozilla/5.0 Selenium/3.141.0",                "bot",    "Selenium",        "/api/test", "Selenium 自动化测试"),
    ("PhantomJS",     "Mozilla/5.0 (Unknown; Linux) PhantomJS/2.1.1","bot",   "PhantomJS",       "/api/test", "PhantomJS 无头浏览器"),
    ("Headless Chrome","Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/90.0", "bot", "Headless Browser", "/api/test", "Chrome 无头模式"),
    ("Ruby HTTP",     "Ruby/3.0.0 (ruby-x86_64-linux) Net::HTTP",    "bot",    "Ruby Net::HTTP",  "/api/test", "Ruby HTTP 客户端"),
    ("Perl LWP",      "LWP/6.58 libwww-perl/6.58",                   "bot",    "Perl LWP",        "/api/test", "Perl WWW 库"),
    ("PHP cURL",      "PHP/8.1.0 (cURL)",                             "bot",    "PHP cURL",        "/api/test", "PHP cURL"),
    ("Node.js",       "Node.js/18.0.0 (node-fetch)",                  "bot",    "Node.js",         "/api/test", "Node.js HTTP 客户端"),
    ("Go HTTP",       "Go-http-client/2.0",                           "bot",    "Go HTTP Client",  "/api/test", "Go HTTP 客户端"),
]

BEHAVIOR_CASES: List[TestCase] = [
    ("robots.txt",    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "bot", "Suspicious Bot", "/robots.txt", "正常浏览器访问 robots.txt"),
    ("sitemap.xml",   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "bot", "Suspicious Bot", "/sitemap.xml", "正常浏览器访问 sitemap.xml"),
    ("Swagger 文档",  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "bot", "Suspicious Bot", "/swagger-ui/", "正常浏览器访问 Swagger 文档"),
    ("GraphQL 路径",  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "bot", "Suspicious Bot", "/graphql", "正常浏览器访问 GraphQL"),
    ("API 文档",      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "bot", "Suspicious Bot", "/openapi.json", "正常浏览器访问 OpenAPI 文档"),
    ("RSS Feed",      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "bot", "Suspicious Bot", "/feed", "正常浏览器访问 Feed 路径"),
]

ABNORMAL_CASES: List[TestCase] = [
    ("SQLi 特征",     "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36",   "scanner","Suspicious Scanner", "/search?q=union+select+*+from+users", "URI 包含 SQL 注入特征"),
    ("XSS 特征",      "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36",   "scanner","Suspicious Scanner", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "URI 包含 XSS 特征"),
    ("LFI 特征",      "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36",   "scanner","Suspicious Scanner", "/file?path=../../../etc/passwd", "URI 包含路径遍历特征"),
    ("命令注入特征",  "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36",   "scanner","Suspicious Scanner", "/ping?host=127.0.0.1%20whoami", "URI 包含命令注入特征"),
    ("敏感文件访问",  "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36",   "scanner","Suspicious Scanner", "/.env", "访问敏感文件"),
    ("/etc/passwd",   "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36",   "scanner","Suspicious Scanner", "/file/../../../etc/passwd", "访问 /etc/passwd"),
]

HUMAN_CASES: List[TestCase] = [
    ("Chrome 浏览器",  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "human", "Human", "/index.html", "正常 Chrome 浏览器"),
    ("Firefox 浏览器", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0", "human", "Human", "/index.html", "正常 Firefox 浏览器"),
    ("Safari 浏览器",  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15", "human", "Human", "/index.html", "正常 Safari 浏览器"),
    ("Edge 浏览器",    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0", "human", "Human", "/index.html", "正常 Edge 浏览器"),
]

# ========== 类别分组 ==========

ALL_CATEGORIES = {
    "scanner":   ("扫描器",    SCANNER_CASES,   Colors.FAIL),
    "crawler":   ("搜索引擎",  CRAWLER_CASES,   Colors.INFO),
    "bot":       ("通用 Bot",  BOT_CASES,       Colors.WARN),
    "behavior":  ("行为检测",  BEHAVIOR_CASES,   Colors.MAGENTA),
    "abnormal":  ("异常模式",  ABNORMAL_CASES,  Colors.CYAN),
    "human":     ("正常用户",  HUMAN_CASES,     Colors.OK),
}


# ========== 测试执行 ==========

def send_request(session: requests.Session, target: str, path: str,
                 user_agent: str, timeout: int) -> Tuple[int, str, float]:
    """发送请求并返回 (status_code, response_preview, elapsed_ms)"""
    url = f"{target.rstrip('/')}{path}"
    headers = {
        "User-Agent": user_agent,
        "Accept": "*/*",
    }
    start = time.time()
    try:
        resp = session.get(url, headers=headers, timeout=timeout)
        elapsed = (time.time() - start) * 1000
        preview = resp.text[:100].replace("\n", " ").replace("\r", "")
        return resp.status_code, preview, round(elapsed, 1)
    except requests.Timeout:
        elapsed = (time.time() - start) * 1000
        return 0, "TIMEOUT", round(elapsed, 1)
    except requests.ConnectionError:
        elapsed = (time.time() - start) * 1000
        return 0, "CONNECTION_ERROR", round(elapsed, 1)
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        return 0, f"ERROR: {e}", round(elapsed, 1)


def run_category(session: requests.Session, target: str, timeout: int,
                 verbose: bool, show_block_only: bool,
                 cat_key: str, cat_label: str, cat_color: str,
                 cases: List[TestCase]) -> List[dict]:
    """运行一个类别的所有测试用例"""
    results = []

    print(f"\n  {Colors.c('>> ' + cat_label, cat_color)} ({len(cases)} 个用例)")

    for name, ua, exp_type, exp_name, path, desc in cases:
        status, preview, elapsed = send_request(session, target, path, ua, timeout)
        is_blocked = status in (403, 429, 406, 501)

        # 检测是否匹配预期
        type_match = "[OK]" if exp_type != "human" else "[--]"
        if not show_block_only or is_blocked:
            result = {
                "name": name,
                "ua": ua[:70],
                "expected_type": exp_type,
                "expected_name": exp_name,
                "path": path,
                "description": desc,
                "status": status,
                "elapsed_ms": elapsed,
                "blocked": is_blocked,
                "type_match": type_match,
            }
            results.append(result)

            # 打印单行结果
            if not show_block_only:
                if is_blocked:
                    status_str = Colors.c(f"{status} 拦截", Colors.OK)
                elif status == 200:
                    status_str = Colors.c(f"{status} 放行", Colors.DIM)
                else:
                    status_str = Colors.c(f"{status}", Colors.WARN)

                label = f"{name:16s}"
                exp = f"{exp_type:7s}"
                print(f"    {label}  {status_str}  期望={exp}  用时={elapsed:>7.1f}ms  {preview[:50]}")

    return results


def print_category_summary(all_results: dict):
    """打印各类别统计汇总"""
    print(f"\n  {'='*60}")
    print(f"  {Colors.c('各类别统计', Colors.BOLD)}")
    print(f"  {'='*60}")
    print(f"  {'类别':12s} {'用例数':>6s} {'拦截':>6s} {'拦截率':>8s}")
    print(f"  {'—'*35}")

    grand_total = 0
    grand_blocked = 0

    for cat_key in ["scanner", "crawler", "bot", "behavior", "abnormal", "human"]:
        cat_label, _, _ = ALL_CATEGORIES[cat_key]
        results = all_results.get(cat_key, [])
        total = len(results)
        blocked = sum(1 for r in results if r["blocked"])
        rate = blocked / total * 100 if total else 0
        grand_total += total
        grand_blocked += blocked

        # 颜色标记拦截率
        if cat_key == "human":
            color = Colors.OK if rate == 0 else Colors.FAIL  # human 不应拦截
        elif cat_key == "scanner":
            color = Colors.OK if rate > 50 else Colors.WARN   # scanner 应拦截
        else:
            color = Colors.DIM

        print(f"  {cat_label:12s} {total:>6d} {blocked:>6d} {Colors.c(f'{rate:>7.1f}%', color)}")

    print(f"  {'—'*35}")
    print(f"  {'合计':12s} {grand_total:>6d} {grand_blocked:>6d}")


def print_failed_blocked(all_results: dict):
    """打印应拦截但未拦截 / 不应拦截但拦截的异常"""
    anomalies = []

    for cat_key, results in all_results.items():
        for r in results:
            if cat_key == "human" and r["blocked"]:
                anomalies.append((f"误拦截: {r['name']}", r))
            elif cat_key in ("scanner",) and not r["blocked"]:
                # 仅当站点配置了 block 才提示
                pass  # 默认是 log，不报异常

    if anomalies:
        print(f"\n  {Colors.c('注意:', Colors.WARN)}")
        for reason, r in anomalies:
            print(f"    {reason} (status={r['status']}, path={r['path']})")


# ========== 主流程 ==========

def main():
    parser = argparse.ArgumentParser(
        description="WAF 爬虫检测测试脚本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python scripts/test/test_crawler.py
  python scripts/test/test_crawler.py -t http://127.0.0.1:9000 -v
  python scripts/test/test_crawler.py -t http://127.0.0.1:9000 --category scanner
  python scripts/test/test_crawler.py -t http://127.0.0.1:9000 --block-only
        """
    )
    parser.add_argument("-t", "--target", default="http://127.0.0.1:9000",
                        help="WAF 代理地址")
    parser.add_argument("--timeout", type=int, default=10,
                        help="请求超时秒数")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="打印每个请求的详细信息")
    parser.add_argument("--block-only", action="store_true",
                        help="仅显示被拦截的请求")
    parser.add_argument("--category", choices=list(ALL_CATEGORIES.keys()) + ["all"],
                        default="all", help="测试指定类别 (默认 all)")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="请求间隔秒数")
    args = parser.parse_args()

    target = args.target.rstrip("/")
    timeout = args.timeout
    verbose = args.verbose
    show_block_only = args.block_only
    delay = args.delay

    # 标题
    print(f"\n{Colors.c('='*70, Colors.CYAN)}")
    print(f"  {Colors.c('WAF 爬虫检测测试', Colors.BOLD)}")
    print(f"  目标: {target}")
    print(f"  时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{Colors.c('='*70, Colors.CYAN)}")
    print(f"\n  默认所有爬虫动作均为 {Colors.c('log', Colors.WARN)}（仅记录，不拦截）")
    print(f"  如需测试拦截，请在站点配置中将动作设为 {Colors.c('block', Colors.FAIL)}")
    print(f"{Colors.c('='*70, Colors.CYAN)}")

    # 确定要运行的类别
    categories_to_run = [args.category] if args.category != "all" else list(ALL_CATEGORIES.keys())

    session = requests.Session()
    all_results = {}

    for cat_key in categories_to_run:
        cat_label, cases, cat_color = ALL_CATEGORIES[cat_key]
        results = run_category(
            session, target, timeout, verbose, show_block_only,
            cat_key, cat_label, cat_color, cases
        )
        all_results[cat_key] = results
        if delay > 0:
            time.sleep(delay)

    # 汇总
    print(f"\n{Colors.c('='*70, Colors.CYAN)}")
    print(f"  {Colors.c('测试汇总', Colors.BOLD)}")
    print(f"{Colors.c('='*70, Colors.CYAN)}")

    # 按类别统计
    print_category_summary(all_results)
    print_failed_blocked(all_results)

    # 期望检测结果表（不依赖拦截状态）
    print(f"\n  {'='*60}")
    print(f"  {Colors.c('期望检测矩阵', Colors.BOLD)}")
    print(f"  {'='*60}")
    print(f"  {'类型':10s}  {'期望检测':10s}  {'优先级':8s}  {'置信度':8s}  {'说明'}")
    print(f"  {'—'*60}")
    rows = [
        ("scanner",  "[V] 扫描器",    "最高", "0.95", "扫描器 UA 特征"),
        ("crawler",  "[V] 搜索引擎",  "高",   "0.90", "搜索引擎 UA 特征"),
        ("bot",      "[V] 通用 Bot",  "中",   "0.85", "Bot UA 特征"),
        ("behavior", "[V] 行为模式",  "低",   "0.70", "爬虫行为路径"),
        ("abnormal", "[V] 异常模式",  "最低", "0.65", "URI 攻击特征"),
        ("human",    "[–] 不检测",    "–",    "0.00", "正常浏览器"),
    ]
    for t, det, pri, conf, desc in rows:
        color = Colors.OK if "[V]" in det else Colors.DIM
        print(f"  {t:10s}  {Colors.c(det, color):10s}  {pri:8s}  {conf:8s}  {desc}")

    # 检测优先级说明
    print(f"\n  {Colors.c('检测优先级: scanner > crawler > bot > behavior > abnormal > human', Colors.INFO)}")
    print(f"  即: 同时匹配多个规则时，优先级最高的类型生效（如 sqlmap UA 不会被识别为 bot）")

    # 最终结论
    print(f"\n  {'='*60}")

    # 统计各类别检测结果
    detection_stats = {}
    for cat_key in categories_to_run:
        results = all_results.get(cat_key, [])
        total = len(results)
        if total == 0:
            continue
        blocked = sum(1 for r in results if r["blocked"])
        detection_stats[cat_key] = (total, blocked)

    if detection_stats:
        success = True
        # 检查 normal 是否被误拦截
        if "human" in detection_stats:
            _, h_blocked = detection_stats["human"]
            if h_blocked > 0:
                print(f"  {Colors.c('[!] 正常用户请求被拦截 - 请检查爬虫配置是否过严', Colors.WARN)}")
                success = False

        if all(blocked == 0 for _, blocked in detection_stats.values()):
            print(f"  {Colors.c('[i] 未触发任何拦截 - 默认动作为 log，如需测试拦截请配置 block', Colors.INFO)}")
        else:
            print(f"  {Colors.c('[OK] 爬虫检测功能运行正常', Colors.OK)}")

    print(f"  {'='*60}\n")

    session.close()


if __name__ == "__main__":
    main()
