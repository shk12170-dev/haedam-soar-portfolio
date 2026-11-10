"""infra/graylog/bootstrap.py의 순수 함수 시험(Graylog 서버 없이)."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("bootstrap", ROOT / "infra" / "graylog" / "bootstrap.py")
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


def load(rel: str) -> dict:
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def test_replace_stream_ids_s10():
    ids = {"haedam-portal": "aaa", "pfsense": "bbb"}
    out = bootstrap.replace_stream_ids(load("lab/s8s10/graylog/s10-three-layer.json"), ids)
    assert out["config"]["streams"] == ["aaa", "bbb"]
    assert "REPLACE_" not in json.dumps(out)


def test_replace_stream_ids_maps_team_hardcoded_portal_id():
    """S12 정의는 팀 Graylog의 실제 스트림 ID를 그대로 갖고 있다 → 이 PC의 포털 스트림으로 바꾼다."""
    out = bootstrap.replace_stream_ids(load("lab/s12/graylog/s12-request-flood.json"), {"haedam-portal": "aaa"})
    assert out["config"]["streams"] == ["aaa"]


def test_replace_stream_ids_keeps_default_events_stream():
    out = bootstrap.replace_stream_ids(load("lab/s1s4/graylog/s1-login-bruteforce.json"), {"haedam-portal": "aaa"})
    assert out["storage"][0]["streams"] == ["000000000000000000000002"]


def test_parse_pipeline_rules_and_stages():
    text = (ROOT / "infra/graylog/pipelines/pfsense-parse.txt").read_text(encoding="utf-8")
    rules, stages = bootstrap.parse_pipeline_file(text)
    titles = [t for t, _ in rules]
    assert titles[0] == "pfsense: filterlog header"
    assert "pfsense: cleanup" in titles
    assert all(src.lstrip().startswith("rule \"") and src.rstrip().endswith("end") for _, src in rules)
    assert stages[0] == ["pfsense: filterlog header"]
    assert stages[2] == ["pfsense: filterlog ports", "pfsense: common fields", "pfsense: tag fragment"]


def test_pipeline_source_has_every_stage():
    src = bootstrap.pipeline_source("pfsense-parse", {0: ["a"], 1: ["b", "c"]})
    assert src.startswith('pipeline "pfsense-parse"')
    assert 'stage 1 match either\nrule "b";\nrule "c";' in src
    assert src.rstrip().endswith("end")


def test_notification_for_other_webhook():
    raw = load("infra/graylog/notifications/s1-n8n-haedam-s1.json")
    out = bootstrap.notification_with_url(raw, "http://host.docker.internal:5678/webhook/haedam-s4", "n8n haedam-s4")
    assert out["config"]["url"].endswith("/haedam-s4")
    assert out["title"] == "n8n haedam-s4"
    assert raw["config"]["url"].endswith("/haedam-s1")  # 원본은 그대로
