"""Verify the retained demo records and read-only catalog without changing policy."""
import base64
import json
from pathlib import Path
import secrets
import sys
import urllib.request
import urllib.error

sys.stdout.reconfigure(encoding='utf-8')
root = Path(__file__).resolve().parents[2]
http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
token = ''

def call(path, method='GET', data=None, expected=0):
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token}
    request = urllib.request.Request('http://localhost/api/v1' + path, headers=headers, method=method,
        data=None if data is None else json.dumps(data).encode())
    try:
        response = http.open(request, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        result = json.load(response)
    assert result['code'] == expected, (path, result.get('message'), result['code'])
    return result.get('data')

credentials = root / '.env.demo'
if not credentials.exists():
    admin_password = next(line.split('=', 1)[1] for line in (root / '.env').read_text(encoding='utf-8-sig').splitlines() if line.startswith('ADMIN_PASSWORD='))
    token = call('/auth/login', 'POST', {'username': 'admin', 'password': admin_password})['token']
    username, password = 'waf-demo-operator', 'Verify!' + secrets.token_urlsafe(24)
    call('/users', 'POST', {'username': username, 'password': password, 'role': 'operator', 'nickname': '独立演示测试账号'})
    credentials.write_text('DEMO_USERNAME=' + username + '\nDEMO_PASSWORD=' + password + '\n', encoding='utf-8')
env = dict(line.split('=', 1) for line in credentials.read_text().splitlines() if '=' in line)
session = call('/auth/login', 'POST', {'username': env['DEMO_USERNAME'], 'password': env['DEMO_PASSWORD']})
token = session['token']
rules = call('/rules?page_size=100&category=SQL%20Injection')
assert rules['total'] == 68 and all(rule['category'] == 'SQL Injection' for rule in rules['list'])
rule = rules['list'][0]
assert not rule['is_custom'] and rule['rule_content'] and rule['rule_file']
before = call('/rules/' + str(rule['id']))
for method, suffix, data in [('PUT', '', {'description': 'Must not change'}), ('PUT', '/status', {'enabled': False}), ('DELETE', '', None)]:
    call('/rules/' + str(rule['id']) + suffix, method, data, expected=403)
assert call('/rules/' + str(rule['id'])) == before
events = call('/weak-password/events?page_size=100')
assert events['total'] >= 18
detail = call('/weak-password/events/' + str(events['list'][0]['id']))
log = detail['request']['log']
assert log['request_id'] == detail['event']['request_id']
stored = call('/logs/' + str(log['id']))
assert log['body'] == stored['log']['body'] and log['uri'] == stored['log']['uri']
call('/weak-password/events/bad', expected=400)
call('/weak-password/events/999999999', expected=404)
logs = call('/logs?site_id=1&page_size=100')
cc = [item for item in logs['list'] if item['action'] == 'block' and item['response_code'] == 429]
assert cc and all(item['decision_source'] == 'cc' and not item['rule_evaluated'] for item in cc)
summary = {'builtin_rules': call('/rules?page_size=1')['total'], 'categories': len(call('/rules/categories')), 'sql_rules': rules['total'], 'readonly_operations_denied': 3, 'weak_events_retained': events['total'], 'weak_request_original_content': True, 'cc_unscored_records': len(cc)}
out = root / 'output/demo/details-verification.json'
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
state = {'cookies': [], 'origins': [{'origin': 'http://localhost', 'localStorage': [{'name': 'waf_console_auth', 'value': json.dumps(session)}]}]}
if '--browser' in sys.argv:
    (root / 'output/demo/browser-state.json').write_text(json.dumps(state), encoding='utf-8')
print(json.dumps(summary, ensure_ascii=False))

