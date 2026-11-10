"""infra/n8n/make_credentials.py 시험(n8n 없이)."""
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("mc", ROOT / "infra" / "n8n" / "make_credentials.py")
mc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mc)


@pytest.fixture
def env(tmp_path):
    key = tmp_path / "pf_key"
    key.write_text("dummy-test-key\n", encoding="utf-8")
    return {"N8N_WEBHOOK_KEY": "test-hook", "PORTAL_RESPONSE_KEY": "test-portal", "TICKET_STORE_KEY": "test-ticket",
            "WAZUH_API_PASSWORD": "test-wazuh", "PF_SSH_PRIVATE_KEY_FILE": str(key)}


def workflows():
    for f in sorted((ROOT / "infra/n8n/workflows").glob("haedam-*.json")):
        data = json.loads(f.read_text(encoding="utf-8"))
        for wf in (data if isinstance(data, list) else [data]):
            yield f.name[:9], wf


def test_all_referenced_credentials_built(env):
    names = {c["name"] for c in mc.build_credentials(env)}
    for prefix, wf in workflows():
        wf = mc.link_workflow(wf, prefix)
        for node in wf["nodes"]:
            for ref in (node.get("credentials") or {}).values():
                assert ref["name"] in names, (prefix, node["name"], ref["name"])


def test_generic_auth_nodes_get_linked(env):
    for prefix, wf in workflows():
        wf = mc.link_workflow(wf, prefix)
        for node in wf["nodes"]:
            if node.get("parameters", {}).get("authentication") == "genericCredentialType":
                assert node.get("credentials"), (prefix, node["name"])
                assert all(r["id"] for r in node["credentials"].values())


def test_missing_env_raises(env):
    env.pop("PORTAL_RESPONSE_KEY")
    with pytest.raises(KeyError, match="PORTAL_RESPONSE_KEY"):
        mc.build_credentials(env)


def test_caller_header_name_matches_graylog():
    creds = mc.build_credentials({"N8N_WEBHOOK_KEY": "x", "PORTAL_RESPONSE_KEY": "x", "TICKET_STORE_KEY": "x",
                                  "WAZUH_API_PASSWORD": "x", "PF_SSH_PRIVATE_KEY_FILE": __file__})
    callers = [c for c in creds if c["name"].endswith("caller")]
    assert callers and all(c["data"]["name"] == "X-Haedam-Key" for c in callers)
