"""Run isolated sustained-load and real recovery acceptance; never deploy production.

python scripts/bench/run_readiness.py --seconds 600
Build rwaf:readiness and rwaf-bench-driver:readiness first, or add --build.
Raw reports are mounted at docs/benchmarks/latest. Leaves the test stack for inspection
unless --cleanup is specified. Requires Python 3.10+ and Docker Compose.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs" / "benchmarks" / "latest"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=600)
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--project", default="rwaf-readiness-bench")
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--skip-regression", action="store_true")
    parser.add_argument("--cleanup", action="store_true")
    args = parser.parse_args()
    if not args.project.startswith("rwaf-readiness-"):
        parser.error("only isolated rwaf-readiness-* projects are allowed")
    if args.seconds < 30 or args.concurrency < 1 or args.concurrency > 128:
        parser.error("seconds >= 30 and concurrency in 1..128 required")
    OUT.mkdir(parents=True, exist_ok=True)
    compose = ["docker", "compose", "-p", args.project, "-f", "scripts/bench/compose.yml", "-f", "scripts/bench/readiness-compose.yml"]
    checks = []
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

    def run(arguments, **kwargs):
        result = subprocess.run(compose + arguments, cwd=ROOT, text=True, encoding="utf-8", errors="replace", creationflags=creationflags, **kwargs)
        result.check_returncode()
        return result.stdout

    def save(name, value):
        (OUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")

    def check(name, passed, detail=None):
        checks.append({"name": name, "pass": bool(passed), "detail": detail})
        print(f"CHECK {name}: {passed} {detail}", flush=True)
        save("recovery.json", checks)
        if not passed:
            raise RuntimeError(name)

    def pipeline():
        return json.loads(run(["exec", "-T", "api", "wget", "-qO-", "http://127.0.0.1:8080/health/ready"], capture_output=True))["events"]

    def database():
        sql = """SELECT json_build_object(
          'processed',(SELECT count(*) FROM processed_events),
          'requests',(SELECT count(*) FROM request_logs),
          'crawlers',(SELECT count(*) FROM crawler_logs),
          'weak',(SELECT count(*) FROM weak_password_events),
          'duplicate_requests',(SELECT count(*) FROM (SELECT request_id FROM request_logs GROUP BY request_id HAVING count(*)>1) d),
          'duplicate_crawlers',(SELECT count(*) FROM (SELECT request_id FROM crawler_logs GROUP BY request_id HAVING count(*)>1) d),
          'orphan_matches',(SELECT count(*) FROM rule_matches m LEFT JOIN request_logs r ON r.id=m.request_log_id WHERE r.id IS NULL));"""
        return json.loads(run(["exec", "-T", "postgres", "psql", "-U", "waf_test", "-d", "waf_test", "-At", "-c", sql], capture_output=True).strip())

    def wait_delivery(expected=None, timeout=180):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state, db = pipeline(), database()
            target = expected if expected is not None else state["accepted"] + state.get("recovered", 0)
            if state["queued"] == 0 and db["processed"] == target:
                check("delivered event counts match database", True, {"expected": target, "pipeline": state, "database": db})
                check("no duplicates or orphan matches", not any(db[k] for k in ("duplicate_requests", "duplicate_crawlers", "orphan_matches")), db)
                check("all receipts have one event row", db["processed"] == db["requests"] + db["crawlers"] + db["weak"], db)
                return state, db
            time.sleep(1)
        check("delivery timeout", False, {"expected": target, "pipeline": state, "database": db})

    def start_driver(mode, name, seconds, skip_drain=False):
        env = os.environ.copy()
        env.update(BENCH_REPORT=name + ".json", BENCH_SOAK_SECONDS=str(seconds), BENCH_CONCURRENCY=str(args.concurrency))
        arguments = compose + ["run", "--rm", "--no-deps"]
        if skip_drain:
            arguments += ["-e", "BENCH_SKIP_DRAIN=1"]
        arguments += ["driver", mode]
        log = (OUT / (name + ".log")).open("w", encoding="utf-8")
        process = subprocess.Popen(arguments, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, creationflags=creationflags)
        return process, log

    def wait_driver(process, log, name):
        while process.poll() is None:
            # Sample every five seconds; the caller remains free to inject faults.
            names = [args.project + "-" + item + "-1" for item in ("api", "consumer", "postgres", "kafka")]
            result = subprocess.run(["docker", "stats", "--no-stream", "--format", "{{json .}}"] + names, cwd=ROOT, capture_output=True, text=True, creationflags=creationflags)
            with (OUT / "resources.jsonl").open("a", encoding="utf-8") as resource:
                resource.write(json.dumps({"time": time.time(), "phase": name, "stats": result.stdout.strip()}) + "\n")
            time.sleep(5)
        log.close()
        check(name + " driver passed", process.returncode == 0, process.returncode)

    try:
        if args.build:
            run(["build"])
        run(["up", "-d", "--no-build", "api", "consumer", "backend", "web"])
        if not args.skip_regression:
            env = os.environ.copy()
            env.update(BENCH_SKIP_LOAD="1", BENCH_REPORT="regression.json")
            with (OUT / "regression.log").open("w", encoding="utf-8") as log:
                run(["run", "--rm", "--no-deps", "driver"], env=env, stdout=log, stderr=subprocess.STDOUT)
        save("db-before-soak.json", database())
        process, log = start_driver("readiness-load", "soak", args.seconds)
        wait_driver(process, log, "sustained load")
        _, db = wait_delivery()
        save("db-after-soak.json", db)

        # Real Kafka outage during forwarding: disk backlog must grow and replay.
        process, log = start_driver("readiness-fault", "kafka-outage", 60)
        time.sleep(8)
        run(["stop", "-t", "2", "kafka"])
        time.sleep(12)
        state = pipeline()
        check("Kafka outage buffers logs on disk", state["queued"] > 0 and state["spool_bytes"] > 0 and state["dropped"] == 0, state)
        run(["start", "kafka"])
        wait_driver(process, log, "Kafka outage")
        wait_delivery()

        # Consumers paused independently: Kafka retains events until restart.
        run(["stop", "-t", "5", "consumer"])
        process, log = start_driver("readiness-fault", "consumer-outage", 45)
        time.sleep(15)
        state, db = pipeline(), database()
        check("consumer outage retains unconsumed events", state["accepted"] > db["processed"] and state["dropped"] == 0, {"pipeline": state, "database": db})
        run(["start", "consumer"])
        wait_driver(process, log, "consumer outage")
        wait_delivery()

        # Database unavailable to consumer, with offset preservation. No load
        # during pause: WAF policy refresh behavior is a separate fail-closed contract.
        run(["stop", "-t", "5", "consumer"])
        process, log = start_driver("readiness-fault", "database-buffer", 6, skip_drain=True)
        wait_driver(process, log, "database buffer")
        state, before = pipeline(), database()
        run(["start", "consumer"])
        time.sleep(2)
        run(["pause", "postgres"])
        time.sleep(30)
        heartbeat = json.loads(run(["exec", "-T", "redis", "redis-cli", "--raw", "GET", "waf:consumer:heartbeat:waf-log-writer"], capture_output=True))
        check("database outage causes consumer retry", heartbeat.get("retrying_workers", 0) > 0, heartbeat)
        run(["unpause", "postgres"])
        wait_delivery()

        # Kill the publisher after durable acknowledgment while Kafka is down.
        run(["stop", "-t", "2", "kafka"])
        process, log = start_driver("readiness-fault", "crash-buffer", 6, skip_drain=True)
        wait_driver(process, log, "crash buffer")
        before = pipeline()
        expected = before["accepted"] + before.get("recovered", 0)
        check("durable pending events before SIGKILL", before["queued"] > 0, before)
        run(["kill", "-s", "SIGKILL", "api"])
        run(["start", "kafka", "api"])
        deadline = time.monotonic() + 90
        while True:
            try:
                state = pipeline()
                break
            except (subprocess.CalledProcessError, json.JSONDecodeError):
                if time.monotonic() > deadline:
                    raise
                time.sleep(1)
        check("publisher restart recovered durable backlog", state["recovered"] >= before["queued"], {"before": before, "after": state})
        _, final = wait_delivery(expected)
        save("db-final.json", final)
        print("Acceptance complete. Reports: " + str(OUT), flush=True)
    finally:
        # Restore paused dependencies even on failure; never leave a frozen DB.
        subprocess.run(compose + ["unpause", "postgres"], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creationflags)
        if args.cleanup:
            run(["down", "-v"])


if __name__ == "__main__":
    main()
