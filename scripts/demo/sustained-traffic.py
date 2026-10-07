"""Bounded three-minute traffic against the retained local demonstration site."""
import collections
import concurrent.futures
import json
from pathlib import Path
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime

duration, rate = 180, 100
run = datetime.now().strftime('%Y%m%d-%H%M%S')
counts = collections.Counter()
lock = threading.Lock()
slots = threading.BoundedSemaphore(128)
started = time.monotonic()

def request(index):
    try:
        path = '/products?bulk_run=' + run + '&item=' + str(index)
        req = urllib.request.Request('http://localhost:9008' + path, headers={
            'Host': 'demo.waf.test', 'User-Agent': 'Mozilla/5.0 Chrome/131.0', 'X-Demo-Run': run})
        http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            response = http.open(req, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            response.read()
            status = str(response.status)
    except Exception:
        status = 'network_error'
    finally:
        with lock:
            counts[status] += 1
        slots.release()

print(json.dumps({'run': run, 'duration_seconds': duration, 'target_rps': rate}), flush=True)
submitted, skipped, next_report = 0, 0, 30
with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
    for index in range(duration * rate):
        remaining = started + index / rate - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
        if time.monotonic() - started >= duration:
            break
        if slots.acquire(blocking=False):
            pool.submit(request, index)
            submitted += 1
        else:
            skipped += 1
        elapsed = time.monotonic() - started
        if elapsed >= next_report:
            with lock:
                print(json.dumps({'elapsed_seconds': round(elapsed), 'submitted': submitted, 'completed': sum(counts.values()), 'statuses': dict(counts)}), flush=True)
            next_report += 30
report = {'run': run, 'elapsed_seconds': round(time.monotonic() - started, 2), 'submitted': submitted, 'client_capacity_skips': skipped, 'statuses': dict(counts)}
out = Path(__file__).resolve().parents[2] / 'output/demo' / run
out.mkdir(parents=True, exist_ok=True)
(out / 'sustained-report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
print(json.dumps(report), flush=True)
