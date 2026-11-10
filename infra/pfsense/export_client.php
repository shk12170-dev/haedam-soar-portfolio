<?php
/*
 * 팀 VPN 클라이언트 설정(.ovpn)을 표준 출력으로 내보낸다(1인 재구성에서 새로 작성).
 * pfSense 패키지(openvpn-client-export)는 인터넷이 없는 실습망에서 설치할 수 없어 대신 쓴다.
 * 사용: ssh admin@10.10.30.1 'php /tmp/export_client.php team-c' > team-c.ovpn
 * 출력에는 클라이언트 개인키가 들어 있으므로 저장소에 넣지 않는다(.gitignore *.ovpn).
 */
require_once("config.inc");
require_once("certs.inc");

$cn = $argv[1] ?? "";
$server = null;
foreach (config_get_path("openvpn/openvpn-server", []) as $s) {
	if ($s["description"] === "HAEDAM_TEAM_TRANSIT") $server = $s;
}
$cert = null;
foreach (config_get_path("cert", []) as $c) {
	if ($c["descr"] === "vpn $cn") $cert = $c;
}
if (!$server || !$cert) { fwrite(STDERR, "server or cert for '$cn' not found\n"); exit(1); }
$ca = lookup_ca($server["caref"]);
$ca = $ca["item"] ?? $ca;
$remote = get_interface_ip($server["interface"]);
echo "# HAEDAM_TEAM_TRANSIT client $cn\n";
echo "client\ndev tun\nproto udp4\nremote $remote {$server["local_port"]}\nnobind\npersist-key\npersist-tun\n";
echo "remote-cert-tls server\nauth SHA256\ndata-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\n";
echo "verb 3\nkey-direction 1\n";
echo "<ca>\n" . base64_decode($ca["crt"]) . "</ca>\n";
echo "<cert>\n" . base64_decode($cert["crt"]) . "</cert>\n";
echo "<key>\n" . base64_decode($cert["prv"]) . "</key>\n";
echo "<tls-auth>\n" . base64_decode($server["tls"]) . "</tls-auth>\n";
