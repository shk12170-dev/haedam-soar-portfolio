# 출처 (CREDITS)

이 저장소는 팀 프로젝트 **NoBugs · 해담시청 민원포털 보안 관제·자동 대응**(2026-10~11)의 결과물을, PC 한 대에서 혼자 설치·실행·실측할 수 있도록 다시 구성한 개인 포트폴리오다. 팀 git 이력은 가져오지 않았고(fork 아님), 필요한 파일만 아래 커밋에서 반입했다.

## 팀 원본 저장소

| 저장소 | 반입 기준 커밋 |
| --- | --- |
| `NoBugs-Aleph/aleph-soar-capstone` | `main` `3ac60e8` |
| 같은 저장소, pfSense 도구 브랜치 `codex/pfsense-response-1026` | `bcaa586` |
| `NoBugs-Aleph/haedam-portal-backend` | `main` `98e549c` |
| `NoBugs-Aleph/haedam-portal-frontend` | `main` `994fc45` |

## 팀원

| 이름 | GitHub | 팀 자리 |
| --- | --- | --- |
| 반소람 | whiteclover0542 | A · 포털 서비스·대응 API, S1·S4 |
| 김명준 | myeongjundev | B · 망·pfSense·VPN, S8·S10, 포털 구현 |
| 김상혁 | shk12170-dev | C · Wazuh·S7, 티켓 저장소·보안 대시보드 |
| 김대훈 | chacha1650a | D · Graylog·n8n, S12 |

## 반입 경로별 원작자

"커밋 작성자"는 반입 기준 커밋까지의 `git shortlog` 결과(커밋 수 순)다. 설계·검토 기여는 팀 문서 기준으로 따로 적었다.

| 이 저장소 경로 | 원본 경로 | 커밋 작성자 | 비고 |
| --- | --- | --- | --- |
| `services/portal/backend/` | backend 저장소 전체 | 김명준, 반소람 | Flask 포털·대응 API. AI 지침 파일(`AGENTS.md`·`CLAUDE.md`·`CODEX.md`) 제외 |
| `services/portal/frontend/` | frontend 저장소 전체 | 김명준, 반소람 | React(Vite) 포털 화면. AI 지침 파일 제외 |
| `services/ticket-store/` | `services/ticket-store/` | 김상혁, 김명준, 김대훈, 반소람 | 티켓 저장소·보안 대시보드 |
| `infra/graylog/` | `infra/graylog/` | 김대훈 | compose, 파이프라인(pfSense·Suricata·Wazuh·S7), 알림, 조회 테이블. `wazuh-parse` 원문은 김상혁 인수인계 |
| `infra/n8n/` | `infra/n8n/` | 김대훈, 김명준, 김상혁 | compose, 워크플로 haedam-00~50, 티켓 판정 가드 |
| `lab/s1s4/` | `lab/s1s4/` | 반소람, 김명준 | S1·S4 탐지 정의·점검 스크립트 |
| `lab/s7/` | `lab/s7/` | 김상혁 | S7 변조 입력·복원 AR·Wazuh UDP→TCP 중계기·규칙 명세 |
| `lab/s8s10/` | `lab/s8s10/` | 김대훈(반입), 김명준(규칙 설계) | S8·S10 탐지 정의·알림 |
| `lab/s12/` | `lab/s12/` | 김대훈 | S12 탐지 정의 |
| `lab/pfsense/` | 브랜치 `bcaa586`의 `lab/pfsense/` | 김명준 | pfSense 차단 도구·설치 번들 |
| `lab/INPUT-TOOLS.md`, `lab/input-tools-provenance.json` | 같은 경로 | 팀 | 입력 도구 출처·해시 |
| `tools/s1_input_probe.py`, `tools/s8s10_input.py` | 같은 경로 | 김명준 | S1·S8·S10 공격 입력 |
| `tools/s12_*.py` | 같은 경로 | 김대훈 | S12 부하·health 측정 |
| `contracts/` | `contracts/` | 김명준, 김상혁, 반소람, 김대훈 | API·이벤트·티켓 계약 스키마와 예시 |

## 이 저장소에서 새로 만든 것

반입 이후에 작성한 파일은 각 파일 머리말과 git 이력으로 구분한다. 첫 반입 커밋에서 새로 만든 것은 `tools/secret_scan.py`, `tests/test_secret_scan.py`, `.gitignore`, `.secretscanignore`, 이 파일이다.

## 반입하지 않은 것

팀 협업용 자료(`.claude/`, `.codex/`, `.agents/`, `prompts/`, `orchestration/`, `work-log/`, `team_docs/`, 회의·논의 문서), 로컬 산출물(`.venv` 등), n8n 워크플로 생성기 체인(`tools/gen_n8n_*.py`, 생성된 JSON을 원본으로 사용), Suricata 관련 실행 구성.
