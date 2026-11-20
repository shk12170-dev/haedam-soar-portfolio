# 개인 작업 내역 — 팀 공통 vs 본인 직접 작업·검증

> 팀 공통 결과물과, **본인(김상혁, C)이 직접 작업·검증한 내용**을 구분한다.
> 팀원 코드·자료의 파일별 원작자는 [CREDITS.md](../CREDITS.md)에, 날짜별 근거는 [docs/journal](journal/)에 있다.

## 1. 팀 역할 분담 (공통)

| 자리 | 팀원 | 담당 |
| --- | --- | --- |
| A | 반소람 | 포털·대응 API, S1·S4 |
| B | 김명준 | 망·pfSense·VPN, S8·S10, 포털 구현 |
| **C** | **김상혁 (본인)** | **Wazuh 서버·agent·FIM, S7 홈페이지 변조 탐지·복원, 티켓 저장소·보안 대시보드** |
| D | 김대훈 | Graylog·n8n, S12 |

- 팀 원본 저장소: [NoBugs-Aleph/aleph-soar-capstone](https://github.com/NoBugs-Aleph/aleph-soar-capstone) 외 포털 backend/frontend.
- 팀은 PC 4대를 OpenVPN(10.250.0.0/24)으로 묶어 운영했다.

## 2. 본인 팀 담당 (C 자리, 원 프로젝트)

- **Wazuh**: 매니저·에이전트·FIM(실시간 파일 무결성) 구성.
- **S7 홈페이지 변조**: FIM 탐지 + 원본 복원/격리 설계.
- **티켓 저장소**: 멱등·생명주기(open→responding→verified→restored→closed) 기반 대응 기록 API.
- **보안 대시보드**: 티켓·조치 가시화.

## 3. 이 저장소에서 본인이 직접 한 일 (1인 재구현)

팀 4대(A·B·C·D) 구성을 **PC 한 대**에 재배치하고, 6개 시나리오를 공격→탐지→자동대응→복구까지 **실측**했다.

| 구분 | 본인 직접 작업·검증 | 근거 |
| --- | --- | --- |
| 환경 재배치 | pfSense VM(4-NIC·OpenVPN 서버), 포털·DB VM **무인 설치**(`infra/vm/make_vm.py` cloud-init), Docker 9개 컨테이너 단일 PC화 | [journal 11-11](journal/2026-11-11.md), [11-13](journal/2026-11-13.md) |
| 설정 반입 | Graylog 이벤트 정의·알림, n8n 워크플로(19개) 자동 반입, Wazuh 설정 | `infra/graylog`, `infra/n8n/workflows`, `infra/wazuh` |
| S7 자동 복구 완성 | 팀에서도 미완이던 **Wazuh Active Response 자동 호출**을 `location:local`로 완성 (변조 0.1초 내 복구) | [journal 11-19 §1-3](RETROSPECTIVE.md), `infra/wazuh/config/wazuh_cluster/wazuh_manager.conf` |
| 6개 시나리오 실측 | S1·S4·S8·S10 티켓 종료, S7 자동복구 검증, S12 no_action 확인 | [journal 11-16](journal/2026-11-16.md), [11-19](journal/2026-11-19.md) |
| 환경 버그 수정 | pfSense 시계 지연, 포털 GELF 좀비 소켓 추적·해결 | [RETROSPECTIVE.md](RETROSPECTIVE.md), [journal 11-19](journal/2026-11-19.md) |
| 민감정보 관리 | 시크릿 스캔 도구, `.env.example` 대체, 실제 자격은 저장소 밖(`vms/keys`) | `tests/test_secret_scan.py`, `*/.env.example` |

## 4. 팀 공통 vs 본인 구분 요약

- **팀 공통(원 설계):** 6개 시나리오의 탐지 규칙 개념, 포털·대응 API, 망 구조, n8n 워크플로 골격, S12 판정 개념 등 — 원작자는 CREDITS.md.
- **본인 직접:** 위 설계를 **PC 한 대에 처음부터 설치·기동**하고, **실 트래픽으로 전 과정을 재현·실측**하고, **팀 미완(S7 AR)·환경 버그(시계·소켓)를 해결**한 부분.

## 5. 팀원 자료 출처 표기
- 팀원이 작성한 코드는 원본 커밋 그대로 반입했고, 수정한 곳은 파일 머리말과 git 이력에 남겼다.
- 파일별 원작자 매핑: [CREDITS.md](../CREDITS.md).

## 6. 날짜별 근거
- 설치·기동: [2026-11-10](journal/2026-11-10.md) ~ [11-14](journal/2026-11-14.md)
- 첫 실측·전체 케이스: [2026-11-16](journal/2026-11-16.md)
- 재검증·환경 버그 수정: [2026-11-19](journal/2026-11-19.md)
- 커밋 이력: `git log`(저장소) — 시크릿 스캔·검증·문서화 커밋 포함.
