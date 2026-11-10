<?php
/*
 * pfSense CE 2.7.2 실습 구성 (1인 재구성에서 새로 작성).
 * 팀 B PC pfSense의 주소·VPN·규칙 기록(team_docs/2026-10-22-B-마감-내일인수인계.md,
 * 2026-10-23-D-VPN-질문-답변-B.md, docs/DISTRIBUTED-LAB-PLAN.md)을 한 PC에서 같은 값으로 재현한다.
 *
 * 실행(설치 직후, 콘솔에서 SSH 키를 넣은 뒤):
 *   scp configure_lab.php admin@10.10.30.1:/tmp/  &&  ssh admin@10.10.30.1 'php /tmp/configure_lab.php <새 admin 비밀번호>'
 * 여러 번 실행해도 같은 결과가 되도록 이름(descr)·CN으로 찾아 덮어쓴다.
 * 비밀값(비밀번호·키)은 이 파일에 없다. 인자로 받거나 pfSense 안에서 생성한다.
 */
require_once("config.inc");
require_once("auth.inc");
require_once("certs.inc");
require_once("openvpn.inc");
require_once("filter.inc");
require_once("interfaces.inc");
require_once("system.inc");
require_once("util.inc");

$admin_pw = $argv[1] ?? "";
$TUN = "10.250.0.0/24";
$VPN_PORT = "1195";
$A = "10.250.0.2";   // 포털 VM (team-a)
$C = "10.250.0.3";   // Wazuh·티켓 저장소 (team-c, 호스트)
$D = "10.250.0.100"; // Graylog·n8n (team-d, 호스트)
$DB = "10.10.20.10";

function out($m) { echo "[lab] $m\n"; }

/* 1. admin 비밀번호(기본값 pfsense 제거)와 SSH 키 전용 */
if ($admin_pw !== "") {
	$users = config_get_path("system/user", []);
	foreach ($users as $i => $u) {
		if ($u["name"] === "admin") {
			local_user_set_password($users[$i], $admin_pw);
			local_user_set($users[$i]);
			config_set_path("system/user/$i", $users[$i]);
			out("admin password changed");
		}
	}
}
config_set_path("system/ssh/enable", "enabled");
config_set_path("system/ssh/sshdkeyonly", "enabled");

/* 2. 인터페이스: OPT1=DMZ em2, OPT2=WORK em3 (WAN em0·LAN em1은 콘솔에서 설정) */
config_set_path("interfaces/opt1", ["enable" => "", "if" => "em2", "descr" => "DMZ",
	"ipaddr" => "10.10.10.1", "subnet" => "24", "spoofmac" => ""]);
config_set_path("interfaces/opt2", ["enable" => "", "if" => "em3", "descr" => "WORK",
	"ipaddr" => "10.10.20.1", "subnet" => "24", "spoofmac" => ""]);
/* WAN 203.0.113.0/24는 TEST-NET(bogon)이므로 bogon·사설 차단을 끈다(팀 Kali가 WAN:80에 닿았던 조건) */
config_del_path("interfaces/wan/blockbogons");
config_del_path("interfaces/wan/blockpriv");
out("interfaces DMZ/WORK, WAN bogon off");

/* 3. 원격 syslog → D Graylog (filter 로그, BSD 형식) */
config_set_path("syslog/enable", true);
config_set_path("syslog/remoteserver", "$D:514");
config_set_path("syslog/filter", true);
config_set_path("syslog/ipproto", "ipv4");
config_set_path("syslog/logfilter", true);
out("remote syslog $D:514");

/* 4. OpenVPN: CA·서버 인증서·클라이언트 인증서(team-a/c/d) */
function find_by_descr($path, $descr) {
	foreach (config_get_path($path, []) as $i => $x) { if (($x["descr"] ?? "") === $descr) return $i; }
	return null;
}
function ensure_ca($descr) {
	$i = find_by_descr("ca", $descr);
	if ($i !== null) return config_get_path("ca/$i");
	$ca = ["refid" => uniqid(), "descr" => $descr];
	ca_create($ca, 2048, 3650, ["commonName" => "haedam-lab-ca", "countryName" => "KR",
		"organizationName" => "haedam-lab"], "sha256");
	$all = config_get_path("ca", []); $all[] = $ca; config_set_path("ca", $all);
	return $ca;
}
function ensure_cert($descr, $caref, $cn, $type) {
	$i = find_by_descr("cert", $descr);
	if ($i !== null) return config_get_path("cert/$i");
	$c = ["refid" => uniqid(), "descr" => $descr];
	cert_create($c, $caref, 2048, 3650, ["commonName" => $cn, "countryName" => "KR",
		"organizationName" => "haedam-lab"], $type, "sha256");
	$all = config_get_path("cert", []); $all[] = $c; config_set_path("cert", $all);
	return $c;
}
$ca = ensure_ca("HAEDAM_LAB_CA");
$srv = ensure_cert("HAEDAM_TEAM_TRANSIT server", $ca["refid"], "haedam-vpn-server", "server");
foreach (["team-a", "team-c", "team-d"] as $cn) { ensure_cert("vpn $cn", $ca["refid"], $cn, "user"); }

$servers = config_get_path("openvpn/openvpn-server", []);
$idx = null; $vpnid = 2;
foreach ($servers as $i => $s) { if ($s["description"] === "HAEDAM_TEAM_TRANSIT") { $idx = $i; $vpnid = $s["vpnid"]; } }
$server = $idx !== null ? $servers[$idx] : ["vpnid" => $vpnid, "tls" => base64_encode(openvpn_create_key())];
$server = array_merge($server, [
	"mode" => "server_tls", "protocol" => "UDP4", "dev_mode" => "tun", "interface" => "lan",
	"ipaddr" => "", "local_port" => $VPN_PORT, "description" => "HAEDAM_TEAM_TRANSIT",
	"tls_type" => "auth", "tlsauth_keydir" => "default", "caref" => $ca["refid"], "certref" => $srv["refid"],
	"dh_length" => "none", "ecdh_curve" => "none", "cert_depth" => "1", "strictusercn" => "",
	"data_ciphers" => "AES-256-GCM,AES-128-GCM,CHACHA20-POLY1305", "data_ciphers_fallback" => "AES-256-CBC",
	"digest" => "SHA256", "tunnel_network" => $TUN, "topology" => "subnet",
	"local_network" => "203.0.113.0/24,10.10.20.0/24", "maxclients" => "", "dynamic_ip" => "",
	"verbosity_level" => "1", "create_gw" => "both", "ping_method" => "keepalive",
	"keepalive_interval" => "10", "keepalive_timeout" => "60", "inactive_seconds" => "0",
	"custom_options" => "", "disable" => null,
]);
$server = array_filter($server, fn($v) => $v !== null);
if ($idx === null) { $servers[] = $server; } else { $servers[$idx] = $server; }
config_set_path("openvpn/openvpn-server", array_values($servers));
out("openvpn server HAEDAM_TEAM_TRANSIT udp4/$VPN_PORT $TUN (vpnid $vpnid)");

/* 고정 주소(CSC): A .2, C .3, D .100 */
$csc = [];
foreach (config_get_path("openvpn/openvpn-csc", []) as $x) {
	if (!in_array($x["common_name"], ["team-a", "team-c", "team-d"])) $csc[] = $x;
}
foreach (["team-a" => $A, "team-c" => $C, "team-d" => $D] as $cn => $ip) {
	$csc[] = ["server_list" => (string)$vpnid, "common_name" => $cn, "description" => "fixed $ip",
		"tunnel_network" => "$ip/24", "push_reset" => "", "gwredir" => ""];
}
config_set_path("openvpn/openvpn-csc", $csc);
out("csc team-a/c/d");

/* 5. NAT: WAN 203.0.113.1:80 → 포털 A 10.250.0.2:5000 (출발지 보존, 연결된 pass) */
$nat = array_values(array_filter(config_get_path("nat/rule", []), fn($r) => ($r["descr"] ?? "") !== "HAEDAM_WAN_PORTAL"));
$nat[] = ["interface" => "wan", "protocol" => "tcp", "ipprotocol" => "inet",
	"source" => ["any" => ""], "destination" => ["network" => "wanip", "port" => "80"],
	"target" => $A, "local-port" => "5000", "descr" => "HAEDAM_WAN_PORTAL",
	"associated-rule-id" => "pass", "natreflection" => "disable"];
config_set_path("nat/rule", $nat);
out("nat WAN:80 -> $A:5000");

/* 6. OpenVPN 탭 규칙: 필요한 경로만 허용하고 나머지는 기록하며 차단 */
$mk = function($descr, $proto, $src, $dst, $port) {
	$r = ["type" => "pass", "interface" => "openvpn", "ipprotocol" => "inet", "descr" => $descr, "log" => "",
		"source" => ["address" => $src], "destination" => ["address" => $dst],
		"tracker" => (string)(1792000000 + abs(crc32($descr)) % 1000000)];
	if ($proto !== "any") { $r["protocol"] = $proto; }
	if ($port !== "") { $r["destination"]["port"] = $port; }
	return $r;
};
$wanted = [
	$mk("HAEDAM_TEAM_VPN_PING_TEST", "icmp", $TUN, "10.250.0.1", ""),
	$mk("HAEDAM_A_TO_D_GELF_TCP", "tcp", $A, $D, "12201"),
	$mk("HAEDAM_A_TO_D_GELF_UDP", "udp", $A, $D, "12201"),
	$mk("HAEDAM_A_TO_C_WAZUH", "tcp", $A, $C, "1514-1515"),
	$mk("HAEDAM_TEAM_VPN_A_DB", "tcp", $A, $DB, "3306"),
	$mk("HAEDAM_D_TO_A_RESPONSE_API", "tcp", $D, $A, "5000"),
	$mk("HAEDAM_D_TO_PF_SSH", "tcp", $D, "10.250.0.1", "22"),
	$mk("HAEDAM_C_TO_A_WAZUH_AR", "tcp", $C, $A, "22"),
];
$wanted[] = ["type" => "block", "interface" => "openvpn", "ipprotocol" => "inet", "descr" => "HAEDAM_TEAM_VPN_DEFAULT_BLOCK",
	"log" => "", "source" => ["network" => "openvpn"], "destination" => ["any" => ""], "tracker" => "1792488292"];
$names = array_map(fn($r) => $r["descr"], $wanted);
$rules = array_values(array_filter(config_get_path("filter/rule", []), fn($r) => !in_array($r["descr"] ?? "", $names)));
config_set_path("filter/rule", array_merge($wanted, $rules));
out("openvpn rules " . count($wanted));

write_config("haedam lab configure");
interface_configure("opt1"); interface_configure("opt2");
openvpn_resync_all();
system_syslogd_start();
mwexec("/etc/rc.filter_configure_sync");
out("applied");
