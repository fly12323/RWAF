"""Generate bounded demonstration traffic through the local WAF; retain all data."""
import base64
import collections
import hashlib
import json
import os
from pathlib import Path
import time
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

ROOT = Path(__file__).resolve().parents[2]
sys.stdout.reconfigure(encoding='utf-8')
RUN = datetime.now().strftime('%Y%m%d-%H%M%S')
OUT = ROOT / 'output' / 'demo' / RUN
OUT.mkdir(parents=True, exist_ok=True)
http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
username = os.environ.get('DEMO_USERNAME', 'admin')
password = os.environ.get('DEMO_PASSWORD')
if not password:
    if username != 'admin':
        raise RuntimeError('Set DEMO_PASSWORD for the dedicated demo account')
    password = next(line.split('=', 1)[1] for line in (ROOT / '.env').read_text(encoding='utf-8-sig').splitlines() if line.startswith('ADMIN_PASSWORD='))
token = ''


def api(path, method='GET', data=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request('http://localhost/api/v1' + path, data=None if data is None else json.dumps(data).encode(), headers=headers, method=method)
    with http.open(req, timeout=15) as response:
        result = json.load(response)
    if result['code'] != 0:
        raise RuntimeError(result.get('message', 'API failed'))
    return result['data']


if username == 'admin':
    print('Admin login replaces the current admin session. Use DEMO_USERNAME/DEMO_PASSWORD for a separate admin or operator account.', flush=True)
token = api('/auth/login', 'POST', {'username': username, 'password': password})['token']
policy = api('/waf/protection')
weak = api('/weak-password/config')
sites = api('/sites?page_size=100')['list'] or []
name = '本地演示站点（模拟流量）'
site = next((item for item in sites if item['name'] == name), None)
if not site:
    occupied = {item['listen_port'] for item in sites}
    port = next((port for port in range(9008, 8999, -1) if port not in occupied), None)
    if port is None:
        raise RuntimeError('No free published demo port')
    site = api('/sites', 'POST', {'name': name, 'domains': ['demo.waf.test'], 'listen_port': port, 'upstream_mode': 'ip', 'upstream_targets': [{'host': 'demo-backend', 'port': 8081, 'weight': 1}]})
base = 'http://localhost:' + str(site['listen_port'])
print(json.dumps({'run': RUN, 'site_id': site['id'], 'site': name, 'address': base}, ensure_ascii=False), flush=True)
records = []
browser = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36'


def send(kind, path, data=None, agent=browser, pause=.4):
    headers = {'Host': 'demo.waf.test', 'User-Agent': agent, 'X-Demo-Run': RUN}
    if data is not None:
        headers['Content-Type'] = 'application/json'
    url = base + path + ('&' if '?' in path else '?') + urllib.parse.urlencode({'demo_run': RUN})
    req = urllib.request.Request(url, data=None if data is None else json.dumps(data).encode(), headers=headers)
    started = time.perf_counter()
    try:
        response = http.open(req, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        response.read()
        records.append({'kind': kind, 'status': response.status, 'request_id': response.headers.get('X-Request-ID'), 'duration_ms': round((time.perf_counter() - started) * 1000, 2)})
    if pause:
        time.sleep(pause)


print('Stage 1: normal browsing', flush=True)
for i in range(60):
    send('normal', ['/products?category=books', '/search?q=notebook', '/news', '/help', '/'][i % 5])

print('Stage 2: passive weak-password detection', flush=True)
if weak['enabled'] and '123456' in weak['dictionary']:
    paths = {rule['kind']: rule['path'] for rule in weak['endpoints'] if rule['method'] == 'POST' and rule['path'] in ['/login', '/register', '/password'] and rule['host'] in ['', 'demo.waf.test'] and 'password' in rule['password_fields']}
    representations = {'plain': '123456', 'md5': hashlib.md5(b'123456').hexdigest(), 'sha1': hashlib.sha1(b'123456').hexdigest(), 'sha256': hashlib.sha256(b'123456').hexdigest(), 'base64': base64.b64encode(b'123456').decode(), 'base64url': base64.urlsafe_b64encode(b'123456').decode().rstrip('=')}
    # Some representations overlap (e.g. base64 and base64url for numeric plaintext).
    for kind, path in paths.items():
        for representation, encoded in representations.items():
            if representation in weak['representations']:
                send('weak_' + kind + '_' + representation, path, {'username': 'demo-user', 'password': encoded}, pause=.6)
else:
    print('Weak detection demo skipped: current configuration is disabled or dictionary changed.', flush=True)

print('Stage 3: scanner and attack payloads', flush=True)
send('scanner', '/catalog', agent='sqlmap/1.7', pause=.5)
send('crawler', '/catalog', agent='Scrapy/2.11 (+https://scrapy.org)', pause=.5)
payloads = [('sqli', '1 UNION SELECT username FROM users'), ('xss', '<script>alert(1)</script>'), ('lfi', '../../../../etc/passwd'), ('command_injection', ';cat /etc/passwd')]
# Stay below the automatic IP-ban threshold for this first burst, so the demo remains browsable.
attack_count = min(8, max(0, policy['auto_block_threshold'] - 1)) if policy['auto_block_enabled'] else 8
for i in range(attack_count):
    kind, payload = payloads[i % len(payloads)]
    send(kind, '/search?' + urllib.parse.urlencode({'q': payload}), pause=.5)

print('Stage 4: brief high-frequency requests (CC may return 429)', flush=True)
for i in range(40):
    send('burst', '/products?category=demo', pause=.025)

print('Waiting for Kafka persistence', flush=True)
deadline = time.monotonic() + 20
while time.monotonic() < deadline:
    logs = api('/logs?' + urllib.parse.urlencode({'site_id': site['id'], 'page_size': 100}))
    if logs['total'] >= len(records):
        break
    time.sleep(1)
events = api('/weak-password/events?page=1')
alerts = api('/monitor/alerts?page=1')
monitor = api('/monitor/status')
report = {'run': RUN, 'site_id': site['id'], 'site': name, 'address': base, 'requests': len(records), 'statuses': dict(collections.Counter(str(row['status']) for row in records)), 'by_kind': {kind: dict(collections.Counter(str(row['status']) for row in records if row['kind'] == kind)) for kind in sorted({row['kind'] for row in records})}, 'persisted_site_logs_total': logs['total'], 'weak_events_total': events['total'], 'alerts_total': alerts['total'], 'log_pipeline': monitor['log_pipeline'], 'weak_stats': events['stats'], 'records': records}
(OUT / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps({key: value for key, value in report.items() if key != 'records'}, ensure_ascii=False, indent=2), flush=True)
print('Report: ' + str(OUT / 'report.json'), flush=True)
