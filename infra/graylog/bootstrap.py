"""Graylog 탐지 설정 자동 반입 (1인 재구성에서 새로 작성).

팀은 D PC Graylog에 입력·스트림·파이프라인·이벤트 정의·알림을 화면과 API로 하나씩 넣었다.
이 스크립트는 같은 설정을 저장소 파일에서 읽어 한 번에 넣는다. 이름이 이미 있으면 건너뛰므로
여러 번 실행해도 안전하다.

사용법(저장소 루트에서):
    python infra/graylog/bootstrap.py [--url http://127.0.0.1:9000] [--disable-events]

자격 증명: 환경 변수 GRAYLOG_ADMIN_PASSWORD, 없으면 infra/graylog/.env의 같은 이름 값.
반입 원본(출처는 CREDITS.md):
    infra/graylog/pipelines/*.txt      파이프라인 규칙(pfSense·Wazuh·S7)
    infra/graylog/notifications/*.json  n8n 알림(S1·S12)
    lab/s8s10/graylog/s8-s10-n8n-notification.json
    lab/{s1s4,s8s10,s12}/graylog/*.json 이벤트 정의
    infra/graylog/lookup/s7_baseline_hashes.csv (컨테이너 안 /usr/share/graylog/data/lookup)
"""
from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent

DEFAULT_EVENTS_STREAM = "000000000000000000000002"
N8N_BASE = "http://host.docker.internal:5678/webhook/"

# ── 입력 (팀 D PC와 같은 포트. 호스트 게시는 docker-compose.yml) ──────────────
INPUTS = [
    ("Portal GELF UDP", "org.graylog2.inputs.gelf.udp.GELFUDPInput", 12201),
    ("Portal GELF TCP", "org.graylog2.inputs.gelf.tcp.GELFTCPInput", 12201),
    ("pfSense Syslog UDP", "org.graylog2.inputs.syslog.udp.SyslogUDPInput", 1514),
    ("pfSense Syslog TCP", "org.graylog2.inputs.syslog.tcp.SyslogTCPInput", 1514),
    ("Wazuh Raw TCP", "org.graylog2.inputs.raw.tcp.RawTCPInput", 5514),
]

# ── 스트림 ────────────────────────────────────────────────────────────────
# rules: ("field", 값) = 정확히 일치(StreamRuleType EXACT=1), ("input", 입력 제목) = 입력 일치(MATCH_INPUT=8)
STREAMS = {
    "haedam-portal": {"desc": "민원 포털 GELF (source=haedam-portal)", "match": "AND",
                      "rules": [("field", "source", "haedam-portal")]},
    "pfsense": {"desc": "pfSense filterlog syslog", "match": "OR",
                "rules": [("input", "pfSense Syslog UDP"), ("input", "pfSense Syslog TCP")]},
    "wazuh-alerts": {"desc": "Wazuh 경보(Raw TCP 5514)", "match": "AND",
                     "rules": [("input", "Wazuh Raw TCP")]},
}

# ── 파이프라인: (이름, 연결 스트림, [(규칙 파일, 단계 지정)]) ───────────────────
# 단계 지정 None이면 파일 머리말의 "// stage N match either rule ..." 줄을 따른다.
# 머리말이 없으면 dict로 직접 준다(S7 규칙 머리말의 "연결(반입 뒤)" 지시를 옮긴 것).
PIPELINES = [
    ("pfsense-parse", "pfsense", [("pfsense-parse.txt", None)]),
    ("wazuh-parse", "wazuh-alerts", [
        ("wazuh-parse.txt", {0: ["wazuh: parse alert json"], 1: ["wazuh: fim path safe"]}),
        ("s7-parse.txt", {2: ["S7: FIM file_key"], 3: ["S7: FIM signal (not baseline)"]}),
    ]),
    ("s7-web-parse", "haedam-portal", [("s7-parse.txt", {0: ["S7: web access 2xx"]})]),
]

# ── 알림: (제목, 원본 JSON, 웹훅 경로) ─────────────────────────────────────────
NOTIFICATIONS = [
    ("n8n haedam-s1 (S1 → haedam-30)", "infra/graylog/notifications/s1-n8n-haedam-s1.json", None),
    ("n8n haedam-s4 (S4 → haedam-31)", "infra/graylog/notifications/s1-n8n-haedam-s1.json", "haedam-s4"),
    ("n8n haedam-s8-s10 (S8·S10 → haedam-32)", "lab/s8s10/graylog/s8-s10-n8n-notification.json", None),
    ("n8n haedam-s12 (S12 → haedam-20)", "infra/graylog/notifications/s12-n8n-haedam-s12.json", None),
    ("n8n haedam-s7 (S7 → haedam-33)", "lab/s7/graylog/s7-n8n-notification.json", None),
]

# ── 이벤트 정의: (원본 JSON, 붙일 알림 제목) ────────────────────────────────────
EVENTS = [
    ("lab/s1s4/graylog/s1-login-bruteforce.json", "n8n haedam-s1 (S1 → haedam-30)"),
    ("lab/s1s4/graylog/s4-fail-then-success.json", "n8n haedam-s4 (S4 → haedam-31)"),
    ("lab/s8s10/graylog/s8-scan-then-login.json", "n8n haedam-s8-s10 (S8·S10 → haedam-32)"),
    ("lab/s8s10/graylog/s10-three-layer.json", "n8n haedam-s8-s10 (S8·S10 → haedam-32)"),
    ("lab/s12/graylog/s12-request-flood.json", "n8n haedam-s12 (S12 → haedam-20)"),
    ("lab/s7/graylog/s7-tamper-file-key.json", "n8n haedam-s7 (S7 → haedam-33)"),
]

LOOKUP = {
    "name": "s7_baseline_hashes",
    "path": "/usr/share/graylog/data/lookup/s7_baseline_hashes.csv",
    "key": "sha256",
    "value": "file_key",
}


# ═══ 순수 함수 (tests/test_graylog_bootstrap.py) ══════════════════════════════

def replace_stream_ids(defn: dict, ids: dict[str, str]) -> dict:
    """정의의 검색 대상 스트림을 이 Graylog의 스트림 ID로 바꾼다.

    - `REPLACE_<이름>_stream_id` 자리표시 → ids[이름]
    - 팀 Graylog의 실제 ID가 박혀 있는 경우(S12) → 포털 스트림
    - 저장 대상 기본 이벤트 스트림(000…002)은 그대로 둔다.
    """
    out = copy.deepcopy(defn)
    new = []
    for sid in out["config"]["streams"]:
        m = re.fullmatch(r"REPLACE_(.+)_stream_id", sid)
        if m:
            new.append(ids[m.group(1)])
        elif sid in ids.values() or sid == DEFAULT_EVENTS_STREAM:
            new.append(sid)
        else:
            new.append(ids["haedam-portal"])
    out["config"]["streams"] = new
    return out


def parse_pipeline_file(text: str) -> tuple[list[tuple[str, str]], dict[int, list[str]]]:
    """규칙 파일에서 (제목, 원문) 목록과 머리말의 단계 지정을 읽는다."""
    rules = []
    for m in re.finditer(r'^rule "([^"]+)".*?^end\s*$', text, re.S | re.M):
        rules.append((m.group(1), m.group(0).strip()))
    stages: dict[int, list[str]] = {}
    for m in re.finditer(r"^//\s*stage\s+(\d+)\s+match\s+\w+\s+(.+)$", text, re.M):
        stages[int(m.group(1))] = re.findall(r'"([^"]+)"', m.group(2))
    return rules, stages


def pipeline_source(name: str, stages: dict[int, list[str]]) -> str:
    lines = [f'pipeline "{name}"']
    for n in sorted(stages):
        lines.append(f"stage {n} match either")
        lines.extend(f'rule "{r}";' for r in stages[n])
    lines.append("end")
    return "\n".join(lines) + "\n"


def notification_with_url(raw: dict, url: str, title: str) -> dict:
    out = copy.deepcopy(raw)
    out["config"]["url"] = url
    out["title"] = title
    return out


# ═══ Graylog API ═════════════════════════════════════════════════════════════

class Graylog:
    def __init__(self, url: str, password: str):
        self.url = url.rstrip("/")
        token = base64.b64encode(f"admin:{password}".encode()).decode()
        self.headers = {"Authorization": f"Basic {token}", "X-Requested-By": "bootstrap",
                        "Content-Type": "application/json", "Accept": "application/json"}

    def call(self, method: str, path: str, body=None, missing_ok: bool = False):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method, headers=self.headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            if missing_ok and e.code == 404:
                return None
            detail = e.read().decode(errors="replace")[:400]
            raise SystemExit(f"[bootstrap] {method} {path} → {e.code}: {detail}") from None


def read_password() -> str:
    pw = os.environ.get("GRAYLOG_ADMIN_PASSWORD")
    env = HERE / ".env"
    if not pw and env.is_file():
        for line in env.read_text(encoding="utf-8").splitlines():
            if line.startswith("GRAYLOG_ADMIN_PASSWORD="):
                pw = line.split("=", 1)[1].strip()
    if not pw:
        raise SystemExit("GRAYLOG_ADMIN_PASSWORD가 없습니다(환경 변수 또는 infra/graylog/.env)")
    return pw


def ensure_inputs(g: Graylog, made: list) -> dict[str, str]:
    have = {i["title"]: i["id"] for i in g.call("GET", "/api/system/inputs")["inputs"]}
    for title, typ, port in INPUTS:
        if title in have:
            continue
        cfg = {"bind_address": "0.0.0.0", "port": port, "recv_buffer_size": 1048576,
               "number_worker_threads": 2, "override_source": None, "charset_name": "UTF-8"}
        if "syslog" in typ:
            cfg.update({"store_full_message": True, "allow_override_date": True, "expand_structured_data": False,
                        "force_rdns": False})
        if "gelf" in typ or "tcp" in typ.lower():
            cfg.update({"decompress_size_limit": 8388608, "max_message_size": 2097152, "tcp_keepalive": False,
                        "use_null_delimiter": "gelf.tcp" in typ, "tls_enable": False})
        have[title] = g.call("POST", "/api/system/inputs",
                             {"title": title, "type": typ, "global": True, "configuration": cfg})["id"]
        made.append(f"input {title}")
    return have


def ensure_streams(g: Graylog, inputs: dict[str, str], made: list) -> dict[str, str]:
    listed = g.call("GET", "/api/streams")["streams"]
    have = {s["title"]: s["id"] for s in listed}
    rule_count = {s["title"]: len(s.get("rules", [])) for s in listed}
    index_sets = g.call("GET", "/api/system/indices/index_sets?skip=0&limit=0&stats=false")["index_sets"]
    default_set = next(s["id"] for s in index_sets if s.get("default"))
    for title, spec in STREAMS.items():
        rules = []
        for r in spec["rules"]:
            if r[0] == "field":
                rules.append({"field": r[1], "type": 1, "value": r[2], "inverted": False, "description": ""})
            else:
                rules.append({"field": "gl2_source_input", "type": 8, "value": inputs[r[1]], "inverted": False,
                              "description": r[1]})
        if title in have:
            # 규칙이 빠진 채 남은 스트림(이전 실행이 중간에 실패한 경우)은 규칙만 채운다
            if rule_count[title] == 0:
                for rule in rules:
                    g.call("POST", f"/api/streams/{have[title]}/rules", rule)
                g.call("POST", f"/api/streams/{have[title]}/resume")
                made.append(f"stream rules {title}")
            continue
        sid = g.call("POST", "/api/streams", {
            "title": title, "description": spec["desc"], "rules": rules, "matching_type": spec["match"],
            "remove_matches_from_default_stream": True, "index_set_id": default_set})["stream_id"]
        g.call("POST", f"/api/streams/{sid}/resume")
        have[title] = sid
        made.append(f"stream {title}")
    return have


def ensure_lookup(g: Graylog, made: list) -> None:
    name = LOOKUP["name"]
    tables = g.call("GET", "/api/system/lookup/tables?per_page=100")["lookup_tables"]
    if any(t["name"] == name for t in tables):
        return
    adapters = {a["name"]: a["id"] for a in g.call("GET", "/api/system/lookup/adapters?per_page=100")["data_adapters"]}
    if name not in adapters:
        adapters[name] = g.call("POST", "/api/system/lookup/adapters", {
            "name": name, "title": "S7 기준본 해시 CSV", "description": "infra/graylog/lookup",
            "config": {"type": "csvfile", "path": LOOKUP["path"], "separator": ",", "quotechar": '"',
                       "key_column": LOOKUP["key"], "value_column": LOOKUP["value"], "check_interval": 60,
                       "case_insensitive_lookup": False}})["id"]
    caches = {c["name"]: c["id"] for c in g.call("GET", "/api/system/lookup/caches?per_page=100")["caches"]}
    if name not in caches:
        caches[name] = g.call("POST", "/api/system/lookup/caches", {
            "name": name, "title": "S7 기준본(캐시 없음)", "description": "", "config": {"type": "none"}})["id"]
    g.call("POST", "/api/system/lookup/tables", {
        "name": name, "title": "S7 기준본 해시", "description": "키 sha256 → 값 file_key",
        "cache_id": caches[name], "data_adapter_id": adapters[name],
        "default_single_value": "", "default_single_value_type": "NULL",
        "default_multi_value": "", "default_multi_value_type": "NULL"})
    made.append(f"lookup {name}")


def ensure_pipelines(g: Graylog, streams: dict[str, str], made: list) -> None:
    rules_have = {r["title"] for r in g.call("GET", "/api/system/pipelines/rule")}
    pipes_have = {p["title"]: p["id"] for p in g.call("GET", "/api/system/pipelines/pipeline")}
    by_stream: dict[str, list[str]] = {}
    for name, stream, parts in PIPELINES:
        stages: dict[int, list[str]] = {}
        for fname, stage_map in parts:
            rules, header = parse_pipeline_file((HERE / "pipelines" / fname).read_text(encoding="utf-8"))
            wanted = stage_map if stage_map is not None else header
            wanted_titles = {t for ts in wanted.values() for t in ts}
            for title, src in rules:
                if title in wanted_titles and title not in rules_have:
                    g.call("POST", "/api/system/pipelines/rule", {"title": title, "description": fname, "source": src})
                    rules_have.add(title)
                    made.append(f"rule {title}")
            for n, ts in wanted.items():
                stages.setdefault(n, []).extend(ts)
        if name not in pipes_have:
            pipes_have[name] = g.call("POST", "/api/system/pipelines/pipeline", {
                "title": name, "description": "bootstrap", "source": pipeline_source(name, stages)})["id"]
            made.append(f"pipeline {name}")
        by_stream.setdefault(streams[stream], []).append(pipes_have[name])
    for sid, pids in by_stream.items():
        current = g.call("GET", f"/api/system/pipelines/connections/{sid}", missing_ok=True)
        have_ids = set(current.get("pipeline_ids", [])) if current else set()
        if not set(pids) <= have_ids:
            g.call("POST", "/api/system/pipelines/connections/to_stream",
                   {"stream_id": sid, "pipeline_ids": sorted(have_ids | set(pids))})
            made.append(f"connect {sid}")


def ensure_processor_order(g: Graylog, made: list) -> None:
    """파이프라인 프로세서가 Message Filter Chain(스트림 배정) 뒤에 오도록 한다."""
    cfg = g.call("GET", "/api/system/messageprocessors/config")
    order = cfg["processor_order"]
    names = [p["class_name"] for p in order]
    chain = "org.graylog2.messageprocessors.MessageFilterChainProcessor"
    pipe = "org.graylog.plugins.pipelineprocessor.processors.PipelineInterpreter"
    if chain in names and pipe in names and names.index(pipe) < names.index(chain):
        order.insert(names.index(chain), order.pop(names.index(pipe)))
        cfg["processor_order"] = order
        g.call("PUT", "/api/system/messageprocessors/config", cfg)
        made.append("processor order")


def webhook_header() -> str:
    """n8n 웹훅 호출자 인증 헤더(팀 11/03: 헤더 이름 X-Haedam-Key). 값은 infra/n8n/.env의 N8N_WEBHOOK_KEY."""
    env = ROOT / "infra" / "n8n" / ".env"
    if env.is_file():
        for line in env.read_text(encoding="utf-8").splitlines():
            if line.startswith("N8N_WEBHOOK_KEY="):
                return "X-Haedam-Key:" + line.split("=", 1)[1].strip()
    return ""


def ensure_notifications(g: Graylog, made: list) -> dict[str, str]:
    listed = g.call("GET", "/api/events/notifications?per_page=200")["notifications"]
    have = {n["title"]: n["id"] for n in listed}
    header = webhook_header()
    for n in listed:
        if n["title"] in {t for t, _, _ in NOTIFICATIONS} and header and n["config"].get("headers") != header:
            n["config"]["headers"] = header
            for secret in ("basic_auth", "api_secret"):  # 암호화 필드는 GET 모양 그대로 되돌려 보낼 수 없다
                v = n["config"].get(secret)
                if isinstance(v, dict):
                    n["config"][secret] = {"keep_value": True} if v.get("is_set") else None
            g.call("PUT", f"/api/events/notifications/{n['id']}", n)
            made.append(f"notification header {n['title']}")
    allow = g.call("GET", "/api/system/urlwhitelist")
    allowed = {e["value"] for e in allow["entries"]}
    for title, rel, hook in NOTIFICATIONS:
        raw = json.loads((ROOT / rel).read_text(encoding="utf-8"))
        url = N8N_BASE + hook if hook else raw["config"]["url"]
        if url not in allowed:
            allow["entries"].append({"id": re.sub(r"\W", "-", url)[-36:], "title": title, "type": "literal", "value": url})
            allowed.add(url)
            g.call("PUT", "/api/system/urlwhitelist", allow)
            made.append(f"allowlist {url}")
        if title not in have:
            body = notification_with_url(raw, url, title)
            if header:
                body["config"]["headers"] = header
            have[title] = g.call("POST", "/api/events/notifications", body)["id"]
            made.append(f"notification {title}")
    return have


def ensure_events(g: Graylog, streams: dict[str, str], notifs: dict[str, str], enable: bool, made: list) -> None:
    have = {d["title"] for d in g.call("GET", "/api/events/definitions?per_page=200")["event_definitions"]}
    for rel, notif_title in EVENTS:
        defn = replace_stream_ids(json.loads((ROOT / rel).read_text(encoding="utf-8")), streams)
        if defn["title"] in have:
            continue
        defn["notifications"] = [{"notification_id": notifs[notif_title], "notification_parameters": None}]
        defn.pop("id", None)
        g.call("POST", f"/api/events/definitions?schedule={'true' if enable else 'false'}", defn)
        made.append(f"event {defn['title']}")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--url", default="http://127.0.0.1:9000")
    ap.add_argument("--disable-events", action="store_true", help="이벤트 정의를 만들되 일정은 꺼 둔다")
    args = ap.parse_args(argv)
    g = Graylog(args.url, read_password())
    made: list[str] = []
    inputs = ensure_inputs(g, made)
    streams = ensure_streams(g, inputs, made)
    ensure_lookup(g, made)
    ensure_pipelines(g, streams, made)
    ensure_processor_order(g, made)
    notifs = ensure_notifications(g, made)
    ensure_events(g, streams, notifs, not args.disable_events, made)
    for m in made:
        print(f"  + {m}")
    print(f"[bootstrap] 생성 {len(made)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
