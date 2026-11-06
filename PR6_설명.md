# CloudGuard v3 PR6: Complete Multi-Cloud Security Policies and Integration

브랜치: `feature/v3-pr6-integration`

이번 PR로 **CG-NET-01 · CG-STO-01 두 정책이 AWS · Azure · GCP 세 클라우드 모두에 적용**되고, 세 클라우드가 함께 있는
Terraform 구성 7개(A~G)로 "정상은 배포, 위험·판정 불가·문법 오류는 배포 전 차단"을 GitHub Actions 안에서 검증한다.
설계: PR 6 통합 설계 검토서 + GPT 교차 검토(2026-11-06) 반영본 (설계서 0-1장이 최종 기준).

## 한눈에

| 항목 | PR 5 | PR 6 |
|---|---|---|
| 정책 × 클라우드 | 5칸 (GCP 저장소 없음) | **6칸 모두 지원** |
| 규칙 | 24 | 29 (GCP Storage 5) |
| 단위 테스트 | 271 | **386** |
| 자가 점검 | 37 | **47** (기존 37개 정답 변경 없음) |
| 통합 시나리오 | — | **7** (A~G) |
| 고장 주입 | 31 | PR 6 신규 32 + PR 5의 31 재주입 = **63가지 모두 탐지** |
| 필수 검사 | 2개 작업 | 2개 + `3. 멀티클라우드 통합 검증` (등록은 사람이) |

## 1. Phase A — GCP Cloud Storage (CG-STO-01)

**정책:** 공개 주체(`allUsers`·`allAuthenticatedUsers`)에게 버킷·Managed Folder·객체 권한을 부여하는 **선언 자체**를 금지한다.
판정은 정책 위반, 실제 노출 가능성은 `exposure` 에 따로 (Azure 모델 C와 같음).

| 규칙 ID | 판정 | 조건 |
|---|---|---|
| GCP_STORAGE_PUBLIC_IAM | BLOCK | 버킷·Managed Folder IAM(member·binding·policy)이 공개 주체에게 역할 부여 — **역할과 무관** (역할이 사용자 정의·변수면 exposure `undetermined`) |
| GCP_STORAGE_PUBLIC_ACL | BLOCK | 버킷·기본 객체·객체 ACL 이 공개 주체에게 권한, 또는 `publicRead`·`publicReadWrite`·`authenticatedRead` |
| GCP_STORAGE_PAP_NOT_ENFORCED | REVIEW | 버킷 `public_access_prevention` 이 `inherited` 또는 생략 (조직 정책에 달려 확인 불가) |
| GCP_STORAGE_PUBLIC_UNRESOLVED | REVIEW | 구성원·entity·policy_data·PAP 가 변수·표현식 |
| GCP_STORAGE_UNSUPPORTED | REVIEW | 다른 폴더의 data 소스, 읽을 수 없는 파일, 처음 보는 구성원·entity 형식 |

| exposure | 뜻 |
|---|---|
| public_access_possible | allUsers 에게 권한, 연결 버킷 PAP 가 inherited 이거나 버킷을 못 찾음 |
| authenticated_users_access_possible | allAuthenticatedUsers (익명은 아니지만 전 세계 Google 계정) |
| blocked_by_public_access_prevention | 연결 버킷 PAP 가 enforced (Google 은 공개 주체 추가를 412 로 거부) |
| acl_disabled_by_uniform_access | ACL 이고 연결 버킷 UBLA 가 true (ACL 요청 400) |
| undetermined | 역할·값 불명, 또는 PAP REVIEW |

- 검사 대상 13종(버킷 1, IAM 6, ACL 6)은 위반이 없어도 checks 에 PASS 로 기록된다. 범위 밖 자원은 `GCP_STORAGE_OUT_OF_SCOPE` 에 명시하고, provider 8.10.0 의 storage 자원이 모두 둘 중 하나로 분류됐는지 테스트한다.
- 버킷 연결(참조 우선, 리터럴은 같은 폴더에서 유일할 때만)은 exposure 에만 쓴다 → **연결이 판정을 완화하지 않는다.**
- 관계없는 변수(`labels`, `lifecycle_rule` 등)는 판정에 영향 없음. `website` 블록은 권한을 주지 않으므로 사유에만 표시.

**S3 모듈 격리 (교차 검토 필수 1번):** S3 버킷 ↔ 공개 차단 연결을 폴더(모듈) 단위로 바꿨다.

| 상황 | PR 5 | PR 6 |
|---|---|---|
| 두 루트 모듈의 같은 로컬 이름, 차단 설정은 한쪽만 | 다른 쪽도 PASS (미탐) | REVIEW |
| 다른 폴더의 같은 리터럴 버킷 이름 | PASS (미탐) | REVIEW (다른 루트 = 별도 배포 단위) |
| 같은 폴더의 파일 분리 | PASS | PASS |
| 기존 예시 37개·`samples/` 폴더 결과 | — | **변화 0건** |

## 2. Phase B — 멀티클라우드 통합 검증

- `scenarios/A_all_pass` ~ `G_syntax_error`: 폴더마다 `aws.tf`·`azure.tf`·`gcp.tf` (루트 모듈 하나), 정답은 `scenarios/expected.json`.
- Summary 기존 표 뒤에 **정책 × 클라우드 행렬** 추가: PASS / BLOCK / REVIEW / N/A / 미지원 / 확인 불가(ERROR), 검사한 자원 수, 규칙 ID, 대상 자원 종류, 한계.
- 워크플로:

| 작업 (체크 이름) | 내용 |
|---|---|
| `1. 보안 정책 검사` | 변경 없음 (액션 버전만 C1) |
| `2. 모의 배포` | 변경 없음 |
| `통합 시나리오 (A_all_pass)` … 7개 | 게이트 단계(`continue-on-error`, 종료 코드 파일 저장) → 모의 배포 단계(`if: steps.gate.outcome == 'success'`) → `tools/check_scenario.py verify` 가 판정·규칙·checks·게이트 결과·배포 실행 여부 확인 → 결과 파일 업로드 |
| `3. 멀티클라우드 통합 검증` | `needs: scenario` + `if: always()`. 매트릭스 결과가 success 이고 7개 시나리오 결과가 **각각 정확히 하나씩** 있고 모두 기대대로일 때만 성공 |

- `pull_request` 의 `paths` 필터를 제거 → README 만 바꾼 PR 에서도 필수 검사가 생성됨. `push` 는 필터 유지(+ `scenarios/**`, `tools/**`).
- 워크플로 문법은 actionlint 1.7.7 로 확인(오류 0), 구조는 `tests/test_workflow.py` 로 확인.

## 3. Phase C — 정리

- Node 24: checkout v5, setup-python v6, upload-artifact v6, download-artifact v7 (각 태그 action.yml 확인, 별도 커밋).
- `README.md` 전면 갱신, `docs/TEST_REPORT.md`(단계별 결과 보존), `docs/DEMO_GUIDE.md`(브라우저 시연 5장면).
- 시연 점검 중 발견: 회귀 테스트가 `infra/` 까지 비교해, 시연대로 위험 파일을 넣으면 보안 검사보다 앞의 단위 테스트에서 실패했다 → `infra/` 를 회귀 비교에서 제외.

## 4. 변경 파일

| 구분 | 파일 |
|---|---|
| 수정 (5) | `policy_gate.py`, `summary.py`, `samples/expected.json`(10줄 추가), `.github/workflows/policy-gate.yml`, `README.md` |
| 새 예시 (10) | `samples/safe/41·42`, `samples/risky/43·44·45·46·49`, `samples/review/47·48·50` |
| 시나리오 (22) | `scenarios/expected.json`, `scenarios/{A~G}/{aws,azure,gcp}.tf` |
| 테스트 (8 + fixture 3) | `tests/test_regression_baseline.py`, `test_s3_module_isolation.py`, `test_gcp_storage.py`, `test_gcp_storage_folder.py`, `test_resource_catalog.py`, `test_summary_matrix.py`, `test_integration_scenarios.py`, `test_workflow.py` + fixture 3개(`pr5_regression_baseline.json`, `summary_input.json`, `pr5_summary_expected.md`) |
| 도구 (2) | `tools/check_scenario.py`, `tools/make_regression_baseline.py` |
| 문서 (3) | `docs/TEST_REPORT.md`, `docs/DEMO_GUIDE.md`, 이 문서 |

바꾸지 않은 것: `self_test.py`, `requirements.txt`(python-hcl2==7.3.1), `infra/`, 기존 테스트 9개 파일, 기존 예시 37개와 정답, 기존 규칙 ID·결과 JSON 구조·종료 코드.

## 5. 커밋 (단계별)

| 커밋 | 내용 | 그 시점 테스트 |
|---|---|---|
| A1 | PR 5 결과를 회귀 기준으로 고정 (코드 수정 전) | 275 · 37/37 |
| A2 | S3 연결 모듈 격리 + 이름 충돌 테스트 | 281 · 37/37 |
| A3 | GCP Cloud Storage + 테스트·예시 10개 | 356 · 47/47 |
| B1 | 정책 × 클라우드 행렬 | 364 · 47/47 |
| B2 | 통합 시나리오 A~G + 판정 도구 + 통합 테스트 | 375 · 47/47 |
| B3 | Actions 매트릭스 + 최종 집계, paths 수정 | 383 · 47/47 |
| C1 | Node 24 액션 버전 | 384 · 47/47 |
| C2 | README·시연 가이드·보고서, infra/ 회귀 제외 | 384 · 47/47 |
| C3 | 교차 검토: 집계가 같은 시나리오 결과 중복을 실패로 처리 | 386 · 47/47 |

ZIP 에는 최종 파일과 함께 `PR6_commits.patch`(위 커밋 순서의 git 패치)를 따로 제공한다. 브라우저로 올릴 때는 최종 파일만 올리면 된다.

## 6. 업로드 후 GitHub 에서 확인할 것 (미검증)

1. PR 화면에 체크 10개(작업 1·2, 시나리오 7, 작업 3)가 생기고 모두 초록색
2. 시나리오 A 만 모의 배포 `success`, B~G 는 `skipped` (각 작업 Summary)
3. `3. 멀티클라우드 통합 검증` Summary 7행 모두 ✅
4. Node 20 경고 없음
5. 병합 후 Settings → Branches 에서 필수 검사에 `3. 멀티클라우드 통합 검증` 추가 → 시연 가이드 장면 2로 병합 차단 확인
6. README 만 고친 PR 에서도 필수 검사가 생성되는지

## 7. 알려진 한계

README "기술적 한계"와 `docs/TEST_REPORT.md` 참고. 핵심: 지원 범위 안에서만 검사, 실제 클라우드 상태·조직 정책·Terraform 밖 변경·원격 모듈은 보지 않음, 동적 구성과 PAP `inherited` 는 보수적으로 REVIEW, 모의 배포는 실제 배포가 아님.
