#!/bin/sh
# 포털 VM(Ubuntu 24.04, 팀 A 자리) 배포 스크립트 — 1인 재구성에서 새로 작성.
# 팀 A는 VMware Ubuntu VM에 포털을 Waitress systemd 서비스(0.0.0.0:5000)로 올리고 팀 VPN(team-a 10.250.0.2)으로
# B의 DB·D의 Graylog·C의 Wazuh에 붙었다(team_docs/2026-10-22-D-인수인계.md). 같은 배치를 한 번에 만든다.
#
# 호스트에서:  tar로 묶은 /tmp/portal.tgz(backend/, dist/)와 /tmp/portal.env를 올린 뒤
#             ssh haedam@10.10.30.20 'sudo sh /tmp/install_portal.sh'
# 다시 실행해도 된다(코드·dist 교체, 마이그레이션, 서비스 재시작).
set -eu
APP=/opt/haedam-portal
[ -f /tmp/portal.tgz ] || { echo "/tmp/portal.tgz 없음"; exit 1; }

id portal >/dev/null 2>&1 || useradd --system --home "$APP" --shell /usr/sbin/nologin portal
mkdir -p "$APP"
rm -rf "$APP/backend" "$APP/dist"
tar -xzf /tmp/portal.tgz -C "$APP"
# 웹 루트는 팀 A VM과 같은 경로에 둔다(S7 FIM·탐지 규칙·복원 스크립트가 이 경로를 전제로 함)
WEB=/home/haedam/haedam-portal-frontend/dist
mkdir -p "$(dirname "$WEB")" && rm -rf "$WEB" && mv "$APP/dist" "$WEB"
chmod o+x /home/haedam /home/haedam/haedam-portal-frontend && chmod -R o+rX "$WEB"
mkdir -p "$APP/backend/instance"
chown -R portal:portal "$APP"

if [ -f /tmp/portal.env ]; then
  install -m 600 -o root -g root /tmp/portal.env /etc/haedam-portal.env
  rm -f /tmp/portal.env
fi

[ -x "$APP/venv/bin/python" ] || python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --upgrade pip
# 편집 모드로 설치한다: 앱이 패키지 위치 기준으로 backend/migrations를 찾기 때문(일반 설치면 site-packages를 가리킴)
"$APP/venv/bin/pip" install -q -e "$APP/backend"
chown -R portal:portal "$APP"

cat > /etc/systemd/system/haedam-portal.service <<'EOF'
[Unit]
Description=Haedam civil petition portal (Waitress)
After=network-online.target openvpn-client@team-a.service
Wants=network-online.target

[Service]
User=portal
WorkingDirectory=/opt/haedam-portal/backend
EnvironmentFile=/etc/haedam-portal.env
ExecStartPre=/opt/haedam-portal/venv/bin/flask --app haedam_portal:create_app db upgrade
ExecStart=/opt/haedam-portal/venv/bin/waitress-serve --host=0.0.0.0 --port=5000 --call haedam_portal:create_app
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable haedam-portal >/dev/null 2>&1
systemctl restart haedam-portal
sleep 4
systemctl --no-pager --lines=5 status haedam-portal | head -8
curl -s -o /dev/null -w "health %{http_code}\n" http://127.0.0.1:5000/api/v1/health
