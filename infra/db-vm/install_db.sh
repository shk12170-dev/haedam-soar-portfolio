#!/bin/sh
# DB VM(Ubuntu 24.04, 팀 B 업무망 10.10.20.10) MySQL 8.4 LTS 설치 — 1인 재구성에서 새로 작성.
# 팀 B DB VM은 MySQL 8.4.11을 10.10.20.10에서 돌렸고, pfSense 규칙 HAEDAM_TEAM_VPN_A_DB로
# 포털 A(10.250.0.2)만 3306에 들어오게 했다(team_docs/2026-10-21-A-C-작업계획.md).
#
# 실행: ssh haedam@<DB NAT 주소> 'sudo sh /tmp/install_db.sh <앱 계정 비밀번호>'
# 다시 실행해도 된다(이미 설치돼 있으면 계정·권한만 맞춘다).
set -eu
APP_PW="${1:?앱 계정 비밀번호를 인자로 주세요}"
WANT="8.4.11"

if ! command -v mysqld >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  curl -fsSL https://repo.mysql.com/RPM-GPG-KEY-mysql-2025 | gpg --dearmor --yes -o /usr/share/keyrings/mysql.gpg
  echo "deb [signed-by=/usr/share/keyrings/mysql.gpg] http://repo.mysql.com/apt/ubuntu noble mysql-8.4-lts" \
    > /etc/apt/sources.list.d/mysql.list
  apt-get update -qq
  # 팀과 같은 8.4.11이 저장소에 있으면 그 버전으로, 없으면 8.4 LTS 최신으로 설치한다.
  VER=$(apt-cache madison mysql-server | awk -v w="$WANT" '$3 ~ "^"w {print $3; exit}')
  if [ -n "$VER" ]; then
    apt-get install -y -qq mysql-server="$VER" mysql-client="$VER" mysql-community-server="$VER" \
      mysql-community-client="$VER" mysql-common="$VER" mysql-community-client-core="$VER" \
      mysql-community-server-core="$VER" mysql-community-client-plugins="$VER" >/dev/null
  else
    apt-get install -y -qq mysql-server >/dev/null
  fi
fi

CNF=/etc/mysql/mysql.conf.d/haedam.cnf
cat > "$CNF" <<'EOF'
[mysqld]
bind-address = 10.10.20.10
character-set-server = utf8mb4
collation-server = utf8mb4_0900_ai_ci
default-time-zone = '+09:00'
EOF
systemctl restart mysql

mysql -uroot <<SQL
CREATE DATABASE IF NOT EXISTS haedam CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
CREATE USER IF NOT EXISTS 'haedam'@'10.250.0.2' IDENTIFIED BY '${APP_PW}';
ALTER USER 'haedam'@'10.250.0.2' IDENTIFIED BY '${APP_PW}';
GRANT ALL PRIVILEGES ON haedam.* TO 'haedam'@'10.250.0.2';
FLUSH PRIVILEGES;
SQL
mysql -uroot -N -e "SELECT VERSION(); SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user='haedam';"
ss -ltn | grep 3306
