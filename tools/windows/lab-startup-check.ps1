# 기동 체크리스트 점검 — README "매번 켤 때 순서"와 2026-11-19 일지의 재발 주의 항목을 한 번에 확인한다.
# 기본은 읽기 전용(점검만). 고치는 동작은 스위치를 줄 때만 한다.
#   -FixClock          pfSense 시계를 호스트 시각으로 맞춘다(OpenVPN 올리기 전에 쓸 것)
#   -StartContainers   멈춘 Docker 컨테이너를 시작한다
#   -RestartPortal     포털 GELF 연결이 막혀 있으면 haedam-portal.service를 재시작한다
# 예) powershell -ExecutionPolicy Bypass -File tools\windows\lab-startup-check.ps1
#     powershell -ExecutionPolicy Bypass -File tools\windows\lab-startup-check.ps1 -FixClock -StartContainers -RestartPortal
param(
  [switch]$FixClock,
  [switch]$StartContainers,
  [switch]$RestartPortal,
  [string]$PfSsh = "admin@10.10.30.1",
  [string]$PortalSsh = "haedam@10.10.30.20",
  [string]$ExpectedAgentId = "001",
  [int]$MaxClockDriftSec = 60
)

$script:fail = 0
function Ok($m)   { Write-Host "[ OK ] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[WARN] $m" -ForegroundColor Yellow; $script:fail++ }
function Info($m) { Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Http($url) {
  try {
    $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5 -MaximumRedirection 0 -ErrorAction Stop
    return [int]$r.StatusCode
  } catch {
    if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
    return 0
  }
}
$ssh = @("-o", "BatchMode=yes", "-o", "ConnectTimeout=5")

Write-Host "== 1. pfSense 시계 (틀리면 S10 경계 탐지가 창 밖으로 빠짐)"
$pfEpoch = (& ssh @ssh $PfSsh "date +%s" 2>$null)
if (-not $pfEpoch) {
  Warn "pfSense SSH 응답 없음 ($PfSsh). VM이 켜졌는지 확인"
} else {
  $hostEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $drift = [int64]$pfEpoch - $hostEpoch
  if ([math]::Abs($drift) -le $MaxClockDriftSec) { Ok "pfSense 시계 차이 ${drift}초" }
  elseif ($FixClock) {
    $now = (Get-Date).ToString("yyyyMMddHHmm.ss")
    & ssh @ssh $PfSsh "date $now" | Out-Null
    Info "pfSense 시계 교정함(차이 ${drift}초 → $now). OpenVPN을 이미 올렸다면 재시작하고 -RestartPortal로 GELF도 다시 붙일 것"
  } else { Warn "pfSense 시계 차이 ${drift}초. -FixClock으로 교정(OpenVPN 올리기 전에)" }
}

Write-Host "== 2. OpenVPN 주소 (없으면 Docker 컨테이너가 bind 실패로 멈춤)"
foreach ($ip in @("10.250.0.100", "10.250.0.3")) {
  if (Get-NetIPAddress -IPAddress $ip -ErrorAction SilentlyContinue) { Ok "VPN 주소 $ip 붙음" }
  else { Warn "VPN 주소 $ip 없음. pfSense가 뜬 뒤 OpenVPNService 재시작(300초 재시도 대기 해소)" }
}
if (Test-Connection -ComputerName 10.250.0.1 -Count 1 -Quiet) { Ok "VPN 서버 10.250.0.1 응답" }
else { Warn "VPN 서버 10.250.0.1 무응답" }

Write-Host "== 3. Docker 컨테이너"
$want = @("soc-mongo", "soc-opensearch", "soc-graylog", "ticket-store", "n8n",
          "haedam-wazuh-wazuh.manager-1", "haedam-wazuh-wazuh.indexer-1", "haedam-wazuh-wazuh.dashboard-1", "haedam-wazuh-wazuh-relay-1")
$running = @(docker ps --format "{{.Names}}" 2>$null)
if ($LASTEXITCODE -ne 0) { Warn "Docker에 연결 안 됨. Docker Desktop을 켤 것" }
else {
  foreach ($c in $want) {
    if ($running -contains $c) { Ok "$c 실행 중" }
    elseif ($StartContainers) { docker start $c | Out-Null; Info "$c 시작 요청" }
    else { Warn "$c 멈춤. -StartContainers로 시작" }
  }
}

Write-Host "== 4. 서비스 응답"
$checks = @(
  @{ Name = "Graylog lbstatus";      Url = "http://127.0.0.1:9000/api/system/lbstatus"; Ok = @(200) },
  @{ Name = "n8n healthz";           Url = "http://127.0.0.1:5678/healthz";             Ok = @(200) },
  @{ Name = "보안 대시보드";         Url = "http://127.0.0.1:8089/";                    Ok = @(200) },
  @{ Name = "포털 health(VPN)";      Url = "http://10.250.0.2:5000/api/v1/health";      Ok = @(200) }
)
foreach ($c in $checks) {
  $code = Http $c.Url
  if ($c.Ok -contains $code) { Ok "$($c.Name) $code" } else { Warn "$($c.Name) 응답 $code ($($c.Url))" }
}

Write-Host "== 5. 포털 GELF 연결 (터널 재연결 뒤 Send-Q가 쌓이면 이벤트가 Graylog에 안 감)"
$ss = (& ssh @ssh $PortalSsh "ss -tnH dst 10.250.0.100:12201" 2>$null)
if (-not $ss) { Warn "포털 GELF 연결 없음 또는 SSH 실패 ($PortalSsh)" }
else {
  $stuck = @($ss | Where-Object { ($_ -split "\s+")[2] -as [int] -gt 0 })
  if ($stuck.Count -eq 0) { Ok "GELF 연결 정상(Send-Q 0)" }
  elseif ($RestartPortal) {
    & ssh @ssh $PortalSsh "sudo -n systemctl restart haedam-portal.service" | Out-Null
    Info "Send-Q 적체 → haedam-portal.service 재시작함"
  } else { Warn "GELF Send-Q 적체: $($stuck -join ' | '). -RestartPortal로 재시작" }
}

Write-Host "== 6. Wazuh 포털 에이전트 ID (n8n haedam-15·17은 $ExpectedAgentId 고정)"
$agents = (docker exec haedam-wazuh-wazuh.manager-1 /var/ossec/bin/agent_control -l 2>$null)
$line = @($agents | Where-Object { $_ -match "haedam-portal" }) | Select-Object -First 1
if (-not $line) { Warn "포털 에이전트를 찾지 못함(매니저 미기동 또는 미등록)" }
elseif ($line -match "ID:\s*0*$([int]$ExpectedAgentId)\b" -and $line -match "Active") { Ok "포털 에이전트 ID $ExpectedAgentId Active" }
else { Warn "포털 에이전트 상태 확인 필요: $line (ID가 바뀌었으면 haedam-15·17의 agent 값도 바꿀 것)" }

Write-Host ""
if ($script:fail -eq 0) { Write-Host "모든 항목 정상. 회차 시작 가능." -ForegroundColor Green; exit 0 }
else { Write-Host "경고 $($script:fail)건. 위 안내대로 조치 후 다시 실행." -ForegroundColor Yellow; exit 1 }
