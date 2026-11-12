# 실습망 → 이 PC(팀 C·D 자리)로 들어오는 연결을 허용한다. 관리자 PowerShell에서 사용자가 직접 실행한다.
# 팀 4대 분산에서는 C·D가 각자 PC의 Windows 방화벽을 열었다(team_docs/2026-10-23-D-VPN-질문-답변-B.md "D Windows 방화벽").
# 한 PC 재구성에서는 OpenVPN 어댑터 두 개(10.250.0.3 = C, 10.250.0.100 = D)가 "공용 네트워크"로 잡혀
# pfSense·포털 VM에서 오는 syslog·GELF·Wazuh·API 연결이 모두 막힌다.
# 범위: 출발지는 팀 VPN 대역(10.250.0.0/24)과 pfSense 관리망(10.10.30.0/24)만, 목적지는 VPN 주소 두 개만.
# 되돌리기: Get-NetFirewallRule -Group "haedam-lab" | Remove-NetFirewallRule
#Requires -RunAsAdministrator
$group = "haedam-lab"
$remote = @("10.250.0.0/24", "10.10.30.0/24")
Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule

$rules = @(
  @{ Name = "D Graylog GELF/syslog/Wazuh TCP"; Local = "10.250.0.100"; Proto = "TCP"; Ports = @("12201", "514", "5514") },
  @{ Name = "D Graylog GELF/syslog UDP";       Local = "10.250.0.100"; Proto = "UDP"; Ports = @("12201", "514") },
  @{ Name = "C Wazuh agent/API, ticket store"; Local = "10.250.0.3";   Proto = "TCP"; Ports = @("1514", "1515", "55000", "8088") }
)
foreach ($r in $rules) {
  New-NetFirewallRule -Group $group -DisplayName "haedam-lab $($r.Name)" -Direction Inbound -Action Allow `
    -Protocol $r.Proto -LocalAddress $r.Local -LocalPort $r.Ports -RemoteAddress $remote -Profile Any | Out-Null
}
New-NetFirewallRule -Group $group -DisplayName "haedam-lab ICMP echo" -Direction Inbound -Action Allow `
  -Protocol ICMPv4 -IcmpType 8 -LocalAddress @("10.250.0.3", "10.250.0.100") -RemoteAddress $remote -Profile Any | Out-Null
# Docker Desktop 첫 실행 때 생긴 "Docker Desktop Backend" 공용(Public) 차단 규칙은 위 허용보다 우선한다(차단 > 허용).
# 공용 프로필의 기본 동작이 "들어오는 연결 차단"이므로, 이 차단 규칙을 꺼도 열리는 것은 위 실습망 허용뿐이다.
# 되돌리기: Get-NetFirewallRule -DisplayName "Docker Desktop Backend" | ? Action -eq Block | Enable-NetFirewallRule
$dockerBlock = Get-NetFirewallApplicationFilter | Where-Object Program -match 'com\.docker\.backend\.exe$' |
  Get-NetFirewallRule | Where-Object { $_.Action -eq 'Block' -and $_.Direction -eq 'Inbound' }
$dockerBlock | Disable-NetFirewallRule
"Docker Desktop Backend 차단 규칙 끔: $(@($dockerBlock).Count)개"
Get-NetFirewallRule -Group $group | Select-Object DisplayName, Enabled | Format-Table -AutoSize
