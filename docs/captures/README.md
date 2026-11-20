# 시나리오 실측 캡처

2026-11-19 재검증(라이브) 결과가 저장소에 기록된 상태를 보안 대시보드에서 캡처한 것이다.
각 티켓은 공격 → 로그 수집 → 탐지 → n8n 자동 대응 → 복구 → 종료의 전 과정을 타임스탬프로 남긴다.

| 파일 | 내용 | 무엇을 증명하나 |
| --- | --- | --- |
| [01-dashboard-overview.jpg](01-dashboard-overview.jpg) | 보안 대시보드 전체 현황 (종료 8건) + 최근 7일 사건 추이 (11-16·11-19 실측) | 저장소에 실제 사건이 쌓여 있음 |
| [02-case-board.jpg](02-case-board.jpg) | 케이스 보드 — A(S1·S4)·B(S8·S10)·C(S7)·D(S12) 자리별 티켓 | 6개 시나리오가 팀 자리별로 매핑·종료됨 |
| [03-ticket-detail.jpg](03-ticket-detail.jpg) | 티켓 T-20261119-0001(S1) 사건 개요 | 공격 출발지·대상·상태(종료) |
| [04-ticket-timeline.jpg](04-ticket-timeline.jpg) | 같은 티켓의 대응 흐름(KST) + 대응 기록 | 조건충족→판정→n8n수신→티켓생성→조치(MTTR 1분33초)→효과확인→원복→종료, block/unblock 기록 |
| [05-graylog-event-definitions.jpg](05-graylog-event-definitions.jpg) | Graylog 이벤트 정의 — S1·S4·S7·S8·S10·S12 전부 `enabled` | 6개 시나리오의 **탐지 규칙**이 실제로 활성화돼 주기적으로 평가됨 |
| [06-n8n-workflows.jpg](06-n8n-workflows.jpg) | n8n 워크플로 목록 — 19개 전부 Published, Prod. executions 28 | **자동 대응** 워크플로가 설치·게시돼 실제 실행됨 |
| [07-n8n-workflow-canvas.jpg](07-n8n-workflow-canvas.jpg) | haedam-15 Wazuh 복구 워크플로 노드 그래프 (트리거→요청준비→외부호출?→Wazuh호출→응답해석→결과정리) | 워크플로를 **UI로 보고·편집·실행 가능**(유지보수 가능 상태) |

> Wazuh FIM/AR(S7)은 `infra/wazuh/`와 복구 로그(변조 0.1초 내 `run=ar`)로 증명된다. n8n UI는 n8n 2.39.5에서 소유자 계정 설정이 필수라, 새 PC 설치 시 최초 1회 로컬 소유자 계정(예: `admin@haedam.local`)을 만든 뒤 접속한다(비밀번호는 각자 설정, 저장소에 커밋하지 않음).

## 재현 방법 (직접 캡처하려면)
1. 환경 기동 후 보안 대시보드 접속: `http://127.0.0.1:8089/`
2. 케이스 보드 → 자리별 티켓 확인, 티켓 클릭 → 대응 흐름 타임라인 확인.
3. 탐지 근거(Graylog 이벤트 정의): `http://127.0.0.1:9000` → Alerts/Event Definitions.
4. 자동 대응(n8n 워크플로): `http://localhost:5678` → Workflows.
5. 무결성(Wazuh FIM/AR): Wazuh 대시보드 → Integrity monitoring.

> 티켓 상세의 "대응 흐름"은 탐지~복구 각 단계의 실측 시각을 담고 있어, 별도 공격 재현 없이도 전 과정을 확인할 수 있다.
