# 인수인계 — 서버 구축 PC에서 이어서 할 작업

작성: 2026-11-20 · 기준 커밋: `cfb39cd` 이후 · 작성 환경: 실습 환경이 없는 다른 PC(VMware·OpenVPN 없음)

이 문서는 서버(실습 환경)가 구축된 PC에서 Claude가 이어서 작업할 수 있도록 남긴 메모입니다. 끝난 항목은 체크하고 일지(`docs/journal/`)에 결과를 남깁니다.

## 0. 먼저 할 일 (저장소 동기화)

```powershell
cd <기존 저장소 폴더>      # 서버 PC의 haedam-soar-portfolio 복제본
git status                 # 서버 PC에만 있는 수정이 있으면 먼저 커밋하거나 따로 보관
git pull --ff-only origin main
```

`.env`, 인증서, SSH 키는 Git에 없습니다. pull로 지워지지 않지만, 혹시 몰라 작업 전에 저장소 밖으로 백업해 둡니다(11-14 일지 교훈).

## 1. 다른 PC에서 바꾼 것 중 서버 PC에서 반영·확인이 필요한 것

| # | 변경 | 서버 PC에서 할 일 | 완료 기준 |
| --- | --- | --- | --- |
| 1 | `infra/wazuh/docker-compose.yml`이 비밀번호를 `.env`에서 읽음 | `infra/wazuh/.env`에 `WAZUH_INDEXER_PASSWORD`, `WAZUH_DASHBOARD_PASSWORD`, `WAZUH_API_PASSWORD` 3줄 추가(현재 쓰는 값 그대로). `docker compose -f infra/wazuh/docker-compose.yml config -q` 통과 확인 | 오류 없이 통과 |
| 2 | 대시보드 `wazuh.yml` 마운트 제거(이미지가 환경변수로 생성) | `docker compose -f infra/wazuh/docker-compose.yml up -d` 뒤 `https://127.0.0.1:5601` 로그인 → Wazuh 앱에서 API 연결 정상 확인 | API 연결 초록. **실패하면** 마운트를 되돌리되 비밀번호는 파일에 적지 말고 방법을 다시 찾는다 |
| 3 | n8n `haedam-15`·`17`의 Wazuh 에이전트 ID `010` → `001` | `agent_control -l`로 실제 ID 확인 → 같으면 두 워크플로를 n8n에 다시 반입(README 설치 8단계) | n8n 화면에서 두 워크플로의 `agent: '001'` 확인 |
| 4 | `tools/windows/lab-startup-check.ps1` 신규 | 기동 후 실행: `powershell -ExecutionPolicy Bypass -File tools\windows\lab-startup-check.ps1` | 경고 0건. 경고가 오탐이면 스크립트 수정 |
| 5 | `infra/n8n/.env.example` 신규 | 기존 `infra/n8n/.env`와 키 이름이 같은지 대조 | 키 이름 일치(값은 비교하지 않음) |
| 6 | PPT 수치를 11-16 일지 기준으로 수정(S1 3.7초, 오차단 0건), Suricata 표기 제거 | PowerPoint로 열어 11·14장 글자 넘침 확인. 11-19 재검증에서 36.8ms·0.1초를 실제로 쟀다면 그 기록을 일지에 넣고 숫자 복원 | 레이아웃 정상, 모든 수치에 일지 근거 |

## 2. 제출 요구사항 중 남은 것 (서버 PC에서만 가능)

- [ ] **케이스별 캡처** → `docs/captures/<케이스>/` (예: `docs/captures/S1/01-graylog-event.png`). 장면: 정상 상태 · 탐지(Graylog) · 대응(n8n 실행) · 티켓(대시보드) · 효과·원복. **키·쿠키·비밀번호·웹훅 주소가 보이지 않게** 찍는다. README 실측 결과 표에서 링크.
- [ ] **시나리오 재현 1~2개 리허설** — README "시나리오 재현" 표의 명령 그대로(S1·S7 권장). 명령이 틀리면 README를 고친다.
- [ ] **새 PC 설치 리허설(가능하면)** — 최소한 README 설치 순서를 처음부터 읽으며 서버 PC 실제 설정과 다른 곳을 찾아 고친다.
- [ ] 캡처를 PPT 케이스 슬라이드(7~9장)에 넣는다.

## 3. 사람(본인)이 채울 것

- [ ] `docs/RETROSPECTIVE.md` 2절 — 리허설·본발표 피드백과 반영 내용(지금 있는 한 줄은 예시)
- [ ] `docs/RETROSPECTIVE.md` 4절 "느낀 점" — Claude가 일지를 바탕으로 쓴 초안. 본인 말로 다듬기
- [ ] 이력서 프로젝트 항목·자기소개서 기본본(저장소 밖)

## 4. 제출 직전 점검

```powershell
python -X utf8 tools/secret_scan.py          # 종료 코드 0
python -X utf8 -m pytest -q tests            # 28 passed
git status                                   # .env·키·인증서가 스테이징되지 않았는지
```

제출 댓글: 저장소 주소 · PPT(PDF) · 이력서·자기소개서 · "README대로 설치 → 동작 확인 → 담당 작업·개선점 정리 완료"

## 5. Claude에게 줄 시작 문장 (복사해서 사용)

> 이 저장소(haedam-soar-portfolio)에서 이어서 작업할 거야. `git pull` 후 `docs/HANDOFF.md`를 읽고, 1번 표의 반영·확인 항목부터 차례로 진행해 줘. 실습 환경(pfSense·포털·DB·Kali VM, Docker)은 이 PC에 구축돼 있어.
