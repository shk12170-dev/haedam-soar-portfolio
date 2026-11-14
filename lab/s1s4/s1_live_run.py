"""S1 입력 실행기(1인 재구성에서 새로 작성) — 로그인 무차별 대입 탐지.

tools/s1_input_probe.py는 B 개인 Kali의 b_scenario_probe.py(해시 고정)에 의존해 이 저장소만으로는
실행할 수 없다. 이 스크립트는 그 의존 없이 s4_session_check.py와 같은 http.client 패턴으로
S1 하나만 수행한다. 합성 계정(zz_ 접두)만 쓰고, 실제 사용자 계정을 공격하지 않는다.

탐지 조건(infra/graylog/bootstrap.py, lab/s1s4/graylog/s1-login-bruteforce.json):
  query: source:haedam-portal AND rule:"login-bruteforce" AND status:401
  group_by: username, src_ip / 30분 안에 9회 초과(>8) → 알림
포털 레이트리밋(LOGIN_RATE_LIMIT=20/5분/출발지)에 걸리지 않도록 9회·60초 간격(9분)으로 편다.

사용(Kali에서, 실제 네트워크 호출):
  python3 lab/s1s4/s1_live_run.py --run-id S1-20261114-01 --execute
계획만 보려면 --execute를 뺀다(네트워크 호출 없음).
"""
import argparse
import http.client
import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from pathlib import Path

HOST, PORT = "10.250.0.2", 5000
SOURCE = "203.0.113.11"
ATTEMPTS = 9
INTERVAL = 60


def stamp():
    return datetime.now(timezone(timedelta(hours=9))).isoformat()


class Evidence:
    def __init__(self, out, run_id):
        self.out = out
        self.data = {"run_id": run_id, "scope": "S1_login_bruteforce_synthetic_account",
                     "source": SOURCE, "attempts_planned": ATTEMPTS, "interval_seconds": INTERVAL,
                     "started_kst": stamp(), "steps": [], "completed_failures": 0, "complete": False}
        with out.open("x", encoding="utf-8") as f:
            json.dump(self.data, f)

    def save(self):
        tmp = self.out.with_name(self.out.name + ".writing")
        tmp.write_text(json.dumps(self.data, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, self.out)


def call(evidence, cookie_box, method, path, expected, payload=None):
    step = {"method": method, "path": path, "expected_status": expected, "started_kst": stamp()}
    evidence.data["steps"].append(step)
    evidence.save()
    conn = http.client.HTTPConnection(HOST, PORT, timeout=8, source_address=(SOURCE, 0))
    try:
        headers = {"Connection": "close", "Content-Type": "application/json"}
        if cookie_box.get("cookie"):
            headers["Cookie"] = "haedam_session=" + cookie_box["cookie"]
        if method == "POST":
            if not cookie_box.get("csrf"):
                raise ValueError("missing_csrf")
            headers["X-CSRF-Token"] = cookie_box["csrf"]
        conn.connect()
        step["source_actual"] = conn.sock.getsockname()[0]
        if step["source_actual"] != SOURCE:
            raise ValueError("source_mismatch")
        conn.request(method, path, json.dumps(payload or {}) if method == "POST" else None, headers)
        resp = conn.getresponse()
        step["status"] = resp.status
        raw = resp.read(1048577)
        if len(raw) > 1048576:
            raise ValueError("response_too_large")
        for key, value in resp.getheaders():
            if key.lower() == "set-cookie":
                jar = SimpleCookie()
                jar.load(value)
                if "haedam_session" in jar:
                    cookie_box["cookie"] = jar["haedam_session"].value
        if resp.status != expected:
            raise ValueError(f"unexpected_status:{resp.status}")
        body = json.loads(raw)
        data = body.get("data") or {}
        if "csrf_token" in data:
            cookie_box["csrf"] = data["csrf_token"]
        return data
    finally:
        conn.close()
        step["finished_kst"] = stamp()
        evidence.save()


def run(run_id, out):
    username = f"zz_s1_{run_id}".lower()
    evidence = Evidence(out, run_id)
    cookie_box = {}
    call(evidence, cookie_box, "GET", "/api/v1/auth/me", 200)
    wrong = "wrong_test_" + secrets.token_urlsafe(24)
    first = time.monotonic()
    for index in range(ATTEMPTS):
        if index:
            time.sleep(max(0, INTERVAL - (time.monotonic() - previous)))
        previous = time.monotonic()
        call(evidence, cookie_box, "POST", "/api/v1/auth/login", 401,
             {"username": username, "password": wrong})
        evidence.data["completed_failures"] += 1
        evidence.save()
    evidence.data["complete"] = True
    evidence.data["finished_kst"] = stamp()
    evidence.save()
    print(f"[s1] {run_id}: {evidence.data['completed_failures']}/{ATTEMPTS} 401 완료, 계정={username}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    out = Path(a.out or f"{a.run_id}-s1-client.json")
    if out.exists():
        raise SystemExit(f"[s1] 증적 파일이 이미 있습니다: {out}")
    if not a.execute:
        print(json.dumps({"mode": "plan_only_no_traffic", "run_id": a.run_id, "source": SOURCE,
                          "attempts": ATTEMPTS, "interval_seconds": INTERVAL,
                          "account": f"zz_s1_{a.run_id}".lower()}, ensure_ascii=False))
        return
    run(a.run_id, out)


if __name__ == "__main__":
    main()
