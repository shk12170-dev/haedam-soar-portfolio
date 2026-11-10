"""n8n 자격 증명 JSON 생성 + 워크플로에 자격 증명 연결(1인 재구성에서 새로 작성).

팀은 n8n 화면에서 자격 증명을 손으로 만들고 노드마다 연결했다. 반입 JSON에는 연결이 비어 있어
(팀 문서 f5a4b6a "반입 뒤 자격 증명 연결이 지워지는 문제") 그대로 가져오면 게시할 수 없다.
이 스크립트는 .env 값으로 자격 증명을 만들고, 워크플로 사본의 해당 노드에 고정 ID로 연결한다.

    python infra/n8n/make_credentials.py --out <임시 폴더>
      → <임시 폴더>/credentials.json (비밀값 포함, 반입 직후 삭제)
      → <임시 폴더>/workflows/*.json  (자격 증명이 연결된 사본)
값은 infra/n8n/.env(커밋 안 함)에서 읽는다. 필수 값이 없으면 변수 이름을 말하고 멈춘다.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent

# (자격 증명 이름, n8n 형식, 고정 ID, data를 만드는 함수)
CALLERS = ["haedam-s1 caller", "haedam-s4 caller", "haedam-s8-s10 caller", "haedam-s12 caller",
           "haedam-s7 caller", "haedam-s7-live caller"]
PORTAL = "haedam-portal response key"
TICKET = "haedam-ticket-store key"
WAZUH = "haedam-wazuh api"
PF_SSH = "haedam-pf-response D"

# 워크플로 파일 접두 → 일반 자격 증명(genericAuthType) 노드에 붙일 이름
GENERIC = {"haedam-10": TICKET, "haedam-12": PORTAL, "haedam-13": PORTAL, "haedam-17": WAZUH}


def cred_id(name: str) -> str:
    return "hd" + "".join(c for c in name.lower() if c.isalnum())[:14].ljust(14, "0")


def read_env(path: Path) -> dict[str, str]:
    env = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


def need(env: dict[str, str], key: str) -> str:
    if not env.get(key):
        raise KeyError(f"infra/n8n/.env에 {key} 값이 없습니다")
    return env[key]


def build_credentials(env: dict[str, str]) -> list[dict]:
    hook = need(env, "N8N_WEBHOOK_KEY")
    creds = [{"name": n, "type": "httpHeaderAuth", "data": {"name": "X-Haedam-Key", "value": hook}} for n in CALLERS]
    creds.append({"name": PORTAL, "type": "httpHeaderAuth",
                  "data": {"name": "X-Response-Key", "value": need(env, "PORTAL_RESPONSE_KEY")}})
    creds.append({"name": TICKET, "type": "httpHeaderAuth",
                  "data": {"name": "X-Response-Key", "value": need(env, "TICKET_STORE_KEY")}})
    creds.append({"name": WAZUH, "type": "httpBasicAuth",
                  "data": {"user": env.get("WAZUH_API_USER", "wazuh-wui"), "password": need(env, "WAZUH_API_PASSWORD")}})
    key_file = Path(need(env, "PF_SSH_PRIVATE_KEY_FILE"))
    creds.append({"name": PF_SSH, "type": "sshPrivateKey",
                  "data": {"host": env.get("PF_SSH_HOST", "10.250.0.1"), "port": 22, "username": "haedam-pf",
                           "privateKey": key_file.read_text(encoding="utf-8"), "passphrase": ""}})
    for c in creds:
        c["id"] = cred_id(c["name"])
    return creds


def link_workflow(wf: dict, prefix: str) -> dict:
    """노드의 자격 증명 참조를 이름 → 고정 ID로 채운다."""
    for node in wf["nodes"]:
        p = node.get("parameters", {})
        for typ, ref in (node.get("credentials") or {}).items():
            ref["id"] = cred_id(ref["name"])
        if p.get("authentication") == "genericCredentialType" and prefix in GENERIC:
            typ = p.get("genericAuthType")
            name = GENERIC[prefix]
            node.setdefault("credentials", {})[typ] = {"id": cred_id(name), "name": name}
    return wf


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    out = Path(a.out)
    (out / "workflows").mkdir(parents=True, exist_ok=True)
    env = read_env(HERE / ".env")
    (out / "credentials.json").write_text(json.dumps(build_credentials(env), ensure_ascii=False), encoding="utf-8")
    for f in sorted((HERE / "workflows").glob("haedam-*.json")):
        data = json.loads(f.read_text(encoding="utf-8"))
        wfs = data if isinstance(data, list) else [data]
        # n8n import:workflow --separate는 파일 하나에 워크플로 객체 하나를 기대한다(팀 내보내기는 배열)
        for i, w in enumerate(wfs):
            name = f.name if i == 0 else f"{f.stem}-{i}.json"
            (out / "workflows" / name).write_text(json.dumps(link_workflow(w, f.name[:9]), ensure_ascii=False),
                                                  encoding="utf-8")
    print(f"credentials {len(build_credentials(env))}, workflows → {out / 'workflows'}")


if __name__ == "__main__":
    main()
