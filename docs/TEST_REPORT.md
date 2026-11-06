# CloudGuard v3 PR 6 테스트 보고서

> 이 문서는 단계별로 채운다. 각 절은 그 단계가 끝난 시점의 실제 실행 결과이며, 뒤 단계에서 고치지 않는다.
> 실행 환경: Python 3.13 / 3.12, python-hcl2 7.3.1 (v7.3.1 태그 소스 설치). GitHub Actions 실행 결과는 별도 표시.

## Phase A — GCP Storage + S3 모듈 격리 (커밋 A1~A3)

**결과:** 단위 테스트 356개 통과 (PR 5 271 + 85), 자가 점검 47/47, 고장 주입 19가지 모두 탐지. Python 3.13·3.12 동일.

| 확인 | 결과 |
|---|---|
| 회귀 기준 (A1, 코드 수정 전 고정) | 예시 37개 파일별 + 폴더 6개 통째 검사 결과 = PR 5와 동일. 허용한 차이는 `safe/06` 의 GCP checks 1줄 추가뿐 |
| S3 모듈 격리 (A2) | 기존 예시·폴더 결과 변화 0건. 새 테스트 6개 중 2개(다른 루트의 같은 로컬 이름, 다른 폴더의 같은 리터럴 이름)는 PR 5 코드에서 실패함을 확인 = 수정 전 미탐 재현 |
| A2 커밋 단독 | 그 커밋 상태로 단위 테스트·자가 점검 37/37 통과 (git worktree로 확인) |
| GCP 판정표 | 설계서 0-1장 확정표의 모든 행을 `tests/test_gcp_storage.py` 66개가 실제 HCL로 확인 |
| 새 예시 10개 | safe 41·42 PASS, risky 43·44·45·46·49 BLOCK, review 47·48·50 REVIEW (기존 37개 정답 변경 없음) |

| 새 테스트 파일 | 개수 |
|---|---|
| tests/test_regression_baseline.py | 4 |
| tests/test_s3_module_isolation.py | 6 |
| tests/test_gcp_storage.py | 66 |
| tests/test_gcp_storage_folder.py | 7 |
| tests/test_resource_catalog.py | 2 |

### Phase A 고장 주입

| # | 주입한 고장 | 자가 점검 | 단위 테스트 |
|---|---|---|---|
| G-1 | 공개 IAM 구성원을 검사하지 않음 | 43/47 | failures=28, errors=14 |
| G-2 | allAuthenticatedUsers 를 일반 사용자로 판단 | 46/47 | failures=4 |
| G-3 | PAP inherited 를 enforced 로 판단 | 46/47 | failures=26 |
| G-4 | UBLA true 면 공개 IAM 도 안전하다고 판단 | 42/47 | failures=1 |
| G-5 | 공개 객체 ACL 을 놓침 | 46/47 | failures=1 |
| G-6 | 다른 버킷의 IAM 과 잘못 연결 (항상 첫 버킷) | 47/47 | failures=1 |
| G-7 | Managed Folder 공개 권한을 놓침 | 47/47 | failures=2 |
| G-8 | policy_data·jsonencode 를 잘못 파싱 (빈 목록) | 47/47 | failures=6 |
| G-9 | 변수·동적 표현식을 무조건 PASS | 45/47 | failures=17 |
| G-10 | Storage 자원(bucket_acl)을 checks 에서 생략 | 47/47 | failures=2 |
| G-13 | REVIEW 를 배포 가능(종료 코드 0)으로 처리 | 47/47 | failures=2 |
| G-14a | 기존 AWS 기능 손상 (S3 와일드카드 무시) | 45/47 | failures=10 |
| G-14b | 기존 Azure 기능 손상 (v4 기본값 false) | 46/47 | failures=17 |
| G-16 | 사용자 정의 역할을 안전하다고 가정 | 46/47 | errors=5 |
| G-17 | 무관한 변수(labels)로 버킷 전체를 REVIEW (PR 3 오탐 재발) | 47/47 | failures=1 |
| G-18 | 연결 결과로 BLOCK 완화 (PAP enforced 면 PASS) | 43/47 | failures=19, errors=1 |
| G-20 | predefined_acl 만 보고 role_entity 누락 | 46/47 | failures=5 |
| G-21 | S3 연결을 다시 전체 폴더로 합침 | 47/47 | failures=2 |
| G-25 | ACL 공개 entity + 역할 불명을 PASS | 47/47 | failures=1 |

자가 점검(파일 단위)이 놓친 고장(47/47로 통과)은 모두 단위 테스트가 잡았다. 두 검사 모두 GitHub Actions 배포 전에 실행된다.

## Phase B — 멀티클라우드 통합 검증 (커밋 B1~B3)

**결과:** 단위 테스트 383개 통과 (Phase A 356 + 27), 자가 점검 47/47, 시나리오 7/7 기대대로, 고장 주입 12가지 모두 탐지. Python 3.13·3.12 동일.

| 확인 | 결과 |
|---|---|
| 시나리오 A~G (로컬, Actions 와 같은 순서 흉내) | 아래 표. 정상 A 만 모의 배포 실행, 나머지 6개는 건너뜀 |
| 폴더 격리 | `scenarios/` 를 한 번에 검사해도 시나리오별 결과와 같음 |
| Summary 호환 | PR 5 summary.py 출력(고정 파일)이 새 출력의 앞부분과 글자 단위로 같음, 행렬은 그 뒤에만 추가 |
| 워크플로 문법 | actionlint 1.7.7 (GitHub 소스로 빌드)로 오류 0건. PR 5 워크플로도 0건 |
| 워크플로 구조 | `pull_request` 에 paths 없음, 기존 작업 이름 2개 유지, 집계 작업 `needs: scenario` + `if: always()` (tests/test_workflow.py) |
| **GitHub 에서의 실제 실행** | **미검증** — 업로드 후 확인 필요 (아래 "GitHub 에서 확인할 것") |

| 시나리오 | 판정 | 종료 코드 | 게이트 단계 | 모의 배포 단계 | 기대대로 |
|---|---|---|---|---|---|
| A_all_pass | PASS | 0 | success | success | ✅ |
| B_aws_risk | BLOCK | 1 | failure | skipped | ✅ |
| C_azure_risk | BLOCK | 1 | failure | skipped | ✅ |
| D_gcp_risk | BLOCK | 1 | failure | skipped | ✅ |
| E_all_risk | BLOCK | 1 | failure | skipped | ✅ |
| F_review | REVIEW | 1 | failure | skipped | ✅ |
| G_syntax_error | ERROR | 2 | failure | skipped | ✅ |

| 새 테스트 파일 | 개수 |
|---|---|
| tests/test_summary_matrix.py | 8 |
| tests/test_integration_scenarios.py | 11 |
| tests/test_workflow.py | 8 |

### Phase B 고장 주입

| # | 주입한 고장 | 자가 점검 | 단위 테스트 |
|---|---|---|---|
| G-11 | Summary 행렬에서 한 클라우드 누락 | 47/47 | failures=3, errors=4 |
| G-12 | 하나의 BLOCK 을 PASS 로 집계 (행렬) | 47/47 | failures=2 |
| G-12b | 시나리오 판정에서 첫 파일 상태만 사용 | 47/47 | failures=3 |
| G-15 | Actions 매트릭스에서 시나리오 G 누락 | 47/47 | failures=1 |
| G-15b | Actions 에서 단위 테스트 단계 삭제 | 47/47 | failures=1 |
| G-19 | 모든 폴더를 한 모듈로 합침 (격리 해제) | 47/47 | failures=9 |
| G-22 | 집계 작업에서 always() 제거 | 47/47 | failures=1 |
| G-23 | pull_request 에 paths 필터 되살림 | 47/47 | failures=1 |
| G-24 | 집계가 매트릭스 실패를 무시 | 47/47 | failures=1 |
| G-26 | 필수 작업 이름 변경 (2. 모의 배포) | 47/47 | failures=1 |
| G-27 | 시나리오 모의 배포 조건 제거 (위험해도 배포) | 47/47 | failures=1 |
| G-28 | 시나리오 검증이 배포 실행 여부를 보지 않음 | 47/47 | failures=1 |

### GitHub 에서 확인할 것 (여기서는 실행할 수 없음)

1. PR 화면에 `1. 보안 정책 검사`, `2. 모의 배포`, `통합 시나리오 (A_all_pass)` … `(G_syntax_error)` 7개, `3. 멀티클라우드 통합 검증` 이 모두 생기는지
2. 시나리오 작업 7개가 모두 초록색이고, 각 작업의 Summary 에서 A 만 모의 배포 `success`, 나머지는 `skipped` 인지
3. `3. 멀티클라우드 통합 검증` Summary 에 7행이 모두 ✅ 인지
4. README 만 고친 PR 에서도 위 검사들이 생성되는지 (paths 필터 제거 확인)
5. 필수 검사에 `3. 멀티클라우드 통합 검증` 을 등록한 뒤, 일부러 시나리오 정답을 틀리게 바꾼 PR 에서 병합 버튼이 막히는지

## Phase C — Node 24·문서 (커밋 C1~C2)

**결과:** 단위 테스트 384개 통과, 자가 점검 47/47, 시나리오 7/7. Python 3.13·3.12 동일.

| 확인 | 결과 |
|---|---|
| C1 Node 24 | 액션 9줄만 변경: checkout v4→v5, setup-python v5→v6, upload-artifact v4→v6, download-artifact v4→v7. 각 태그의 action.yml 이 `node24` 인 것을 GitHub 저장소에서 확인 (upload-artifact v5, download-artifact v5·v6 은 node20 이라 건너뜀). 사용하는 입력값(`python-version`, `name`, `path`, `if-no-files-found`, `pattern`, `merge-multiple`)이 새 버전에 있음을 확인. actionlint 오류 0건. `tests/test_workflow.py` 가 node24 버전만 쓰는지 확인 |
| C2 회귀 테스트 수정 | 시연 가이드대로 `infra/` 에 위험 파일을 넣으면, 회귀 테스트가 `infra/` 결과도 비교해서 **보안 검사보다 앞의 단위 테스트 단계에서 실패**하는 문제를 발견. `infra/` 는 사용자 배포 폴더라 회귀 비교에서 제외 (기준 파일에는 남김). 수정 후 위험 파일을 넣으면 단위 테스트·자가 점검은 통과하고 `보안 검사 실행` 단계에서 차단됨 (종료 코드 1) |
| 워크플로 단계 흉내 (Python 3.12, git 기록 없는 복사본) | 단위 테스트 → 자가 점검 → `infra/` PASS(종료 코드 0) → Summary → 시나리오 7개 verify(실제 명령 그대로) → aggregate 통과. 일부러 `needs-result failure`, 결과 파일 누락, 결과 폴더 없음, 위험 시나리오에 배포 success 를 넣으면 모두 실패 |
| 커밋별 상태 | A1~C2 모든 커밋에서 그 시점의 단위 테스트·자가 점검이 통과 (git worktree 로 하나씩 확인) |

## 종합

| 항목 | PR 5 | PR 6 |
|---|---|---|
| 단위 테스트 | 271 | **386** (회귀 4, S3 격리 6, GCP 66, GCP 폴더 7, 분류표 2, 행렬 8, 통합 13, 워크플로 9, 기존 271) |
| 자가 점검 예시 | 37 | **47** (GCP 10개 추가, 기존 37개 정답 변경 없음) |
| 통합 시나리오 | — | **7** (A~G) |
| 규칙 | 24 | **29** (GCP Storage 5) |
| 고장 주입 | 31 | **PR 6 신규 32가지 32/32 탐지 + PR 5의 31가지를 PR 6 코드에 다시 주입해 31/31 탐지** |

### 회귀 (기존 기능)

- 예시 37개를 파일 하나씩, `samples/` 와 하위 폴더 5개를 통째로 검사한 결과(판정·findings·exposure·error)와 종료 코드가 PR 5 와 같다 (`tests/test_regression_baseline.py`, A1 커밋에서 코드 수정 전 고정).
- 허용한 차이는 `safe/06_gcp_storage_private.tf` 의 checks 에 `google_storage_bucket.backup` PASS 1줄 추가뿐 (교차 검토에서 허용).
- `infra/` 는 각 단계에서 PASS·종료 코드 0 을 직접 확인했다.
- 기존 Summary 출력은 PR 5 summary.py 의 출력(고정 파일)과 앞부분이 글자 단위로 같다.

### 미탐·오탐 수정 내역 (PR 3~6)

| PR | 발견 | 종류 | 처리 |
|---|---|---|---|
| 3 | 인라인 규칙 목록 안의 무관한 변수로 NSG 전체 REVIEW | 오탐 | 값 단위 판단으로 수정 |
| 4 | GCP 방화벽 정책 `*_with_rules` 미검사 | 미탐 | REVIEW 처리 |
| 5 | Azure 저장소 `min_tls_version = "TLS1_0"` 이 PASS | 미탐 | BLOCK |
| 5 | 공개 컨테이너를 항상 첫 계정에 연결 (F-4) | 연결 오류 | 참조·유일 리터럴만 연결 |
| 5 최종 | azapi blobServices 정적 웹사이트·templateLink·azapi TLS 가 PASS | 미탐 | REVIEW·BLOCK |
| 5 최종 | 버전 제약을 표본으로 계산해 `>= 4.121.0` 오판, `= 4`·`<= 4` 해석 오류 | Terraform 동작과 다름 | 정확한 구간 계산 |
| 6 | S3 공개 차단 연결이 다른 루트 모듈의 같은 이름 버킷에 붙음 | 미탐 (PASS) | 폴더(모듈) 단위 격리 |
| 6 | 회귀 테스트가 사용자 배포 폴더까지 비교 | 게이트 동작 왜곡 | `infra/` 제외 |

### 지원 범위와 미지원 범위

지원 범위는 README 의 정책 표와 Summary 행렬, 범위 밖은 `policy_gate.py` 의 `GCP_STORAGE_OUT_OF_SCOPE`(GCP Storage)와 README "기술적 한계" 참고.

### 미검증 (사용자가 GitHub 에서 확인해야 함)

1. GitHub Actions 에서의 실제 실행 (Phase B "GitHub 에서 확인할 것" 1~5)
2. Node 24 버전 액션으로 실행했을 때 Node 20 경고가 사라졌는지
3. `pip install -r requirements.txt` 로 PyPI 에서 새로 설치 — 이 작업 환경은 PyPI 에 연결되지 않아 python-hcl2 v7.3.1 태그 소스를 설치해 실행했다 (그래서 로컬 자가 점검 Summary 에는 버전이 `0.0.0` 으로 보임)
4. Windows PC(`py`)에서의 실행

## 교차 검토 후 수정 — 집계 중복 결과 (2026-11-06)

GPT 교차 검토에서 `tools/check_scenario.py` 의 `aggregate()` 가 시나리오 이름을 `set` 으로 비교해,
**정상 7개 + 같은 시나리오 결과 1개 더**를 잘못 통과시키는 것을 재현했다 (여기서도 같은 결과 재현).

| 확인 | 결과 |
|---|---|
| 수정 | 시나리오별 결과 개수를 세어 정확히 하나씩인지 확인. 누락·정답표 밖·**2개 이상** 모두 실패 |
| 새 테스트 2개 (`tests/test_integration_scenarios.py`) | 정상 7 + A 중복 → 실패, 정상 7 + G 중복 → 실패, B 누락 + A 중복(개수는 7로 같음) → 누락·중복 둘 다 보고하고 실패 |
| 정상 7/7 | 그대로 통과 (`--local-all`, verify·aggregate 실제 명령) |
| 고장 주입 G-29 (중복 검사 제거) | 단위 테스트 3개 실패로 탐지 |
| 전체 고장 주입 | PR 6 신규 32/32 + PR 5의 31/31 = **63가지 모두 탐지** |
| 단위 테스트 / 자가 점검 | **386** 통과 / 47/47 (Python 3.13, 3.12 + python-hcl2 7.3.1) |
| 변경 범위 | `tools/check_scenario.py`, `tests/test_integration_scenarios.py` (+ 이 보고서·설명서 숫자) |
