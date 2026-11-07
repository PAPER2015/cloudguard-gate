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

## v3.1 — CG-NET-01 AWS 표현 방식 + `.tf.json` 차단 (2026-11-07)

v4 설계 검토 중 실제 코드로 확인한 **탐지 누락(조용한 PASS) 3가지**를 고쳤다. 새 기능은 없고, 기존 판정 4종·종료 코드·결과 JSON 구조·규칙 29개는 그대로다.

| # | 수정 전 | 수정 후 |
|---|---|---|
| 1 | `aws_security_group_rule`(type = ingress)로 SSH 22 를 0.0.0.0/0 에 공개 → **PASS** (검사 대상이 아니었음) | 다른 표현 방식과 같은 판정 (BLOCK/REVIEW/PASS) |
| 2 | `aws_security_group` 의 `ingress = var.rules`, `ingress = [for ...]`, `dynamic "ingress"` → **PASS** (규칙이 없는 것처럼 처리) | REVIEW (`AWS_ADMIN_PORT_UNRESOLVED`) — Azure NSG 의 같은 경우와 같은 방식 |
| 3 | `.tf` 와 `.tf.json` 이 섞인 폴더 → `.tf.json` 을 **조용히 무시** (Terraform 은 배포함) | `.tf.json` 마다 ERROR 결과, 종료 코드 2 |

### 표현 방식 동등성 (CG-NET-01, AWS)

같은 인바운드 규칙을 4가지 방법(인라인 `ingress` 블록, 인라인 `ingress = [{...}]`, `aws_vpc_security_group_ingress_rule`, `aws_security_group_rule`)으로 쓰고 22가지 경우를 모두 검사한다 (`tests/test_aws_net01_equivalence.py`). 판정과 규칙 ID 가 4가지 모두 같아야 통과.

| 경우 | 기대 |
|---|---|
| IPv4·IPv6 공개 + 22 / 3389 (4가지) | BLOCK |
| 공개 + 포트 범위 20-30, 3000-4000(IPv6), 0-65535 | BLOCK |
| 공개 + 전체 프로토콜 `-1` (IPv4·IPv6) | BLOCK |
| 회사 대역(IPv4·IPv6) + 22, 회사 대역 + `-1`, 공개 + 443(IPv4·IPv6), 공개 + 23-3388 | PASS |
| 출발지 변수 + 443, 회사 대역 + 포트 변수 | PASS (어떤 값이어도 위반 불가) |
| 출발지 변수 + 22 (IPv4·IPv6), 공개 + 포트 변수, 공개 + 프로토콜 변수, 출발지 변수 + `-1` | REVIEW |

- **수정 전에도** 인라인 블록·인라인 속성·`ingress_rule` 3가지는 22가지 모두 기대대로였다. `aws_security_group_rule` 만 BLOCK·REVIEW 14가지가 모두 PASS 로 나왔다.
- 나가는 방향(인라인 `egress`, `egress = [{...}]`, `aws_vpc_security_group_egress_rule`, `aws_security_group_rule` type = egress)은 CG-NET-01 범위 밖 → 22가지 모두 PASS (수정 전후 같음).
- `aws_security_group_rule` 의 type 이 변수·생략·처음 보는 값이면 방향을 알 수 없으므로, 위반 가능성이 있을 때 REVIEW (회사 대역처럼 어느 방향이든 안전하면 PASS). 대문자 `INGRESS` 는 ingress 로 본다 (Terraform 은 이 값을 거부하므로 배포되지 않음 — 보수적 처리).
- checks 와 Summary 지원 행렬에 `aws_security_group_rule` 이 추가됐다 (그래서 이 자원만 있는 폴더가 'N/A' 로 보이지 않는다).

### `.tf.json` 처리 (`tests/test_tf_json_files.py`, 명령줄 게이트 경로로 실행)

| 폴더 | 수정 전 | 수정 후 |
|---|---|---|
| 비어 있음 | ERROR(2) | ERROR(2) — 같은 안내 문구 |
| `.tf.json` 만 | ERROR(2) | ERROR(2) — 같은 안내 문구 + `.tf.json` 파일 이름 줄 추가 |
| 경로 없음 / `.tf.json` 파일 하나를 직접 지정 | ERROR(2) | ERROR(2) |
| `.tf` + `.tf.json` (하위 폴더·`override.tf.json` 포함) | `.tf` 결과만, `.tf.json` 무시 | `.tf.json` 은 ERROR, `.tf` 는 평소대로 검사, 종료 코드 2 |
| BLOCK `.tf` + `.tf.json` | 1 | 2 (ERROR 우선, BLOCK 기록은 남음) |
| `.tf` + `policy.json`·`terraform.tfvars.json`·`*.tf.json.bak` | 0 | 0 (오탐 없음) |
| `.tf.json` 이 없는 폴더 | — | 결과 JSON 이 수정 전과 바이트 단위로 같음 (`samples/`, `scenarios/`, `infra/`) |

`.tf.json` 결과는 기존 분석 오류와 같은 5개 필드(`file, status, findings, checks, error`)이고, `summary.py` 가 그대로 표시한다.

### 수정 전 실패 → 수정 후 통과

| 실행 | 결과 |
|---|---|
| 새 테스트 2개 파일(18개)을 **PR 6 코드**에 넣어 실행 | 28개 실패 (`aws_security_group_rule` 동등성 14, 방향 4, 불투명 인라인 3, checks 1, 행렬 1, `.tf.json` 5) |
| 같은 테스트를 v3.1 코드에서 실행 | 18개 모두 통과 |

`.tf.json` 만 있는 폴더 테스트는 수정 전에도 ERROR(2) 였고, 실패 원인은 새로 추가한 파일 이름 안내 줄이다.

### 고장 주입

| 묶음 | 결과 |
|---|---|
| v3.1 신규 15가지 (N-1~N-15: 수정 되돌리기, IPv6 무시, egress 오판, 방향 불명 오판, dynamic 무시·과잉, `.tf.json` 무시·하위 폴더 누락·`*.json` 과잉·REVIEW 로 기록 등) | **15/15 탐지** — 모두 신규 테스트가 잡았고, **기존 386개 테스트만으로는 15가지 모두 못 잡음** (신규 테스트가 꼭 필요함을 확인) |
| PR 6 의 32가지를 v3.1 코드에 다시 주입 | 32/32 탐지 |
| PR 5 의 31가지를 v3.1 코드에 다시 주입 | 31/31 탐지 |

고장 주입은 다른 테스트 실행과 **겹치지 않게 순서대로** 실행했다 (아래 "알려진 한계" 6 참고).

### 회귀

| 항목 | 결과 |
|---|---|
| 단위 테스트 | **404** 통과 (PR 6 386 + 신규 18), Python 3.13·3.12, 연속 3회 |
| 자가 점검 | 47/47 (예시·정답표 변경 없음) |
| 통합 시나리오 | 7/7 기대대로 (정답표 변경 없음) |
| 결과 JSON | `samples/`·`scenarios/`·`infra/` 전체 결과가 PR 6 과 바이트 단위로 같음 |
| Summary | 지원 행렬의 CG-NET-01 × AWS 한 줄만 바뀜 (검사 대상 자원 목록·한계 문구). 결과표는 같음 |
| 워크플로 | 변경 없음 (필수 검사 3개 이름·구조 그대로) |

### 알려진 한계 (이번에 고치지 않음)

1. `.tf.json` 은 **해석하지 않고 차단**만 한다. Terraform JSON 파서는 범위 밖.
2. 인터넷 전체는 `0.0.0.0/0`·`::/0` 문자열만 알아본다. `0::/0` 같은 다른 표기(AWS 가 받아들이는지는 확인하지 않음), 대역을 쪼갠 전체 공개(`0.0.0.0/1` + `128.0.0.0/1`), 접두사 목록 안의 대역은 확인하지 않는다 (v3 부터 있던 한계, 이번에 문서화).
3. 포트만 보고 프로토콜 종류(tcp/udp)는 구분하지 않는다. 예: udp 22 공개도 BLOCK (v3 와 같음, 보수적).
4. 나가는 규칙(egress)은 CG-NET-01 대상이 아니다.
5. `dynamic "ingress"` 는 펼치지 않고 REVIEW 한다.
6. **테스트 실행 환경 주의 (v3 PR 6 부터 있던 문제, 이번에 발견):** `tests/test_integration_scenarios.py` 와 `tools/check_scenario.py` 가 `/tmp/cg-test-*.json`, `/tmp/cg-scenario-*.json` 고정 경로를 쓴다. 같은 PC 에서 테스트를 **두 개 동시에** 돌리면 파일이 겹쳐 가짜 실패가 날 수 있다. GitHub Actions 는 작업마다 다른 컴퓨터라 영향이 없다. 이번 PR 범위(탐지 누락)를 넘으므로 고치지 않고 기록만 한다.

## v3.2 — 인터넷 전체 출발지 판단 정확도 + 테스트 동시 실행 안전 (2026-11-07)

v3.1 보고서 "알려진 한계" 2·6 과 GPT 교차 검토 A·B 를 고쳤다. 판정 4종·종료 코드·결과 JSON 구조·규칙 ID 29개·워크플로는 그대로다.

### 1. 같은 대역의 다른 표기 (AWS·Azure·GCP, `tests/test_cidr_public_notation.py`)

v3.1 은 출발지가 정확히 `"0.0.0.0/0"`·`"::/0"` 문자열일 때만 인터넷 전체로 봤다. v3.2 는 표준 라이브러리 `ipaddress` 로 정규화한다.

AWS provider 가 실제로 받아들이는 값은 terraform-provider-aws(main `e25511f`, 2026-11-06)의 CIDR 검증 함수(`internal/types/cidr_block.go`)를 그대로 옮긴 Go 프로그램(검토 자료 `review/aws_cidr_oracle`)으로 확인했다. **AWS EC2 API 가 받아들이는지는 확인하지 않았다** (클라우드 계정 없음).

| 입력 | provider (IPv4 칸) | provider (IPv6 칸) | Python `ipaddress` | v3.1 | v3.2 |
|---|---|---|---|---|---|
| `0.0.0.0/0`, `::/0` | 수용 / — | — / 수용 | 전체 | BLOCK | BLOCK |
| `0::/0`, `0:0::/0`, `0000::/0`, `::0/0`, `0:0:0:0:0:0:0:0/0` | 거부 | **수용** | `::/0` | **PASS** | BLOCK |
| `0.0.0.0/00` | **수용** | 거부 | `0.0.0.0/0` | **PASS** | BLOCK |
| `::ffff:0:0/96`, `::ffff:0.0.0.0/96` (IPv4-mapped) | **수용** (provider 는 IPv4 `0.0.0.0/0` 으로 해석) | 거부 | IPv6 `/96` (그대로는 전체 아님) | **PASS** | BLOCK — mapped 대역을 IPv4 로 바꿔 판단 |
| `10.0.0.1/0` (호스트 비트) | 거부 | 거부 | `0.0.0.0/0` | PASS | BLOCK — 배포는 안 되지만 보수적으로 |
| 앞뒤 공백 `" 0.0.0.0/0"` | 거부 | 거부 | 공백 제거 시 전체 | PASS | BLOCK — 보수적 |
| `0.0.0.0/1`, `::/1`, `::ffff:10.0.0.0/104` | 수용 | 수용 | 일부 | PASS | PASS |
| `00.0.0.0/0`, `0/0`, `0.0.0.0/33` | 거부 | 거부 | 오류 | PASS | PASS (배포 불가 값) |

27개 입력 기준으로 **provider 가 받아들이면서 인터넷 전체인데 검사기가 놓치는 값은 0개**다. 검사기가 더 넓게 잡는 값(provider 거부)은 배포되지 않으므로 BLOCK 해도 배포 결과에 영향이 없다.

### 2. 쪼갠 대역

| 범위 | 합치는 조건 | 판정 |
|---|---|---|
| **규칙 하나의 출발지 목록** (AWS `cidr_blocks`·`ipv6_cidr_blocks`, Azure `source_address_prefixes`, GCP `source_ranges`·`src_ip_ranges`) | 한 규칙이라 대상·방향·포트·프로토콜이 같음. IPv4·IPv6 는 따로 | 전체면 BLOCK, 확정 조각만으로 전체가 아니고 변수가 섞이면 REVIEW (v3.1 과 같은 규칙) |
| **AWS 같은 보안그룹의 여러 규칙** (인라인 블록, `aws_vpc_security_group_ingress_rule`, `aws_security_group_rule`) | 같은 대상(같은 `aws_security_group.<이름>` — 인라인 또는 `.id` 참조 — 또는 같은 리터럴 sg ID) · 인바운드 · 같은 관리자 포트를 확실히 포함 · 같은 프로토콜(`-1` 은 모든 프로토콜과) · 같은 IP 종류 · 같은 폴더 | BLOCK (`AWS_PUBLIC_ADMIN_PORT`, 사유에 보안그룹·포트·각 규칙의 대역 표시) |
| 위 조건 중 대상·방향·포트·프로토콜을 알 수 없는 규칙이 있어야만 전체 | — | REVIEW (`AWS_ADMIN_PORT_UNRESOLVED`) |
| 다른 폴더(루트 모듈)가 같은 리터럴 sg ID 에 나눠 단 규칙 | 같은 계정·리전인지 정적으로 알 수 없음 | REVIEW |

AWS 보안그룹 규칙은 허용만 있고 거부가 없어서 합산이 실제 공개 범위와 같다. Azure NSG·GCP 방화벽은 거부 규칙·우선순위가 있어 **규칙끼리는 합치지 않는다** (한계).

**표시 범위 (오탐 방지):** 꼭 필요한 규칙만 BLOCK 한다. 다른 규칙만으로도 전체가 되는 규칙(예: 같은 그룹의 `10.0.0.0/8`)은 표시하지 않고, 같은 대역을 가진 중복 규칙은 함께 표시한다. 혼자 이미 `0.0.0.0/0` 인 규칙이 있으면 그 규칙만 기존대로 BLOCK 하고 합산 사유를 덧붙이지 않는다.

`tests/test_aws_sg_union.py` (36개): 합쳐서 전체 BLOCK 10 (vpc 규칙 2개, security_group_rule 2개, 인라인 2블록, 인라인 + 별도 규칙, 같은 리터럴 ID, RDP, IPv6, 겹치는 포트 범위, `-1` + tcp, 세 조각) · 합치면 안 되는 PASS 10 (다른 그룹, 다른 리터럴 ID, 22 와 3389, 관리자 포트 아닌 쪽, tcp 와 udp, IPv4 절반 + IPv6 절반, 인라인 egress, security_group_rule egress, 빈틈, 리터럴 ID 와 참조) · 표시 범위 4 · 불명 값 8 (대상·포트·방향·프로토콜 불명 → REVIEW 5, 불명이어도 전체가 안 되면 PASS 2, 확정 BLOCK 이 불명보다 우선 1) · 폴더 경계 4 (같은 폴더 다른 파일 BLOCK, 다른 폴더 같은 이름 PASS, 다른 폴더 같은 리터럴 ID REVIEW, 다른 폴더 다른 ID PASS).

### 3. 테스트·도구 동시 실행 안전

| 파일 | 수정 전 | 수정 후 |
|---|---|---|
| `tools/check_scenario.py` (`run_local`) | `/tmp/cg-scenario-<시나리오>.json` 고정 | 실행마다 새 `TemporaryDirectory` |
| `tests/test_integration_scenarios.py` (`summary_of`) | `/tmp/cg-test-<시나리오>.json` 고정 | 실행마다 새 `TemporaryDirectory` |

GitHub Actions 가 쓰는 `verify`·`aggregate` 경로는 바뀌지 않았다. `tests/test_parallel_safety.py`: ① 저장소의 파이썬 파일에 고정 `/tmp` 경로가 없는지 정적 검사 (결정적) ② 시나리오 흉내 실행 4개를 동시에 돌려 모두 성공·같은 출력인지 (확률적 — v3.1 코드에서 4개 중 1개 실패를 재현함).

고장 주입 도구도 절대 경로 없이 다시 만들었다 (검토 자료 `review/fault_injection/fault_inject.py` — 저장소를 고장마다 새 임시 폴더로 복사, 고장 목록은 JSON, `--jobs` 로 동시 실행, 먼저 고장 없는 복사본이 통과하는지 확인 후 시작). 제품 저장소에는 넣지 않았다.

### 수정 전 실패 → 수정 후 통과

| 실행 | 결과 |
|---|---|
| 새 테스트 3개 파일(44개)을 **v3.1 코드**에 넣어 실행 | **80개 실패** (표기 36, 한 규칙 분할 12, Azure 4, GCP 5, 같은 그룹 합산 19, 폴더 경계 2, 고정 경로 1, 동시 실행 1) |
| v3.2 코드 | 44개 모두 통과 |

### 고장 주입 (새 실행기, `--jobs 2` 동시 실행)

| 묶음 | 결과 |
|---|---|
| v3.2 신규 25가지 (M-1~M-25: 정규화 제거, mapped 미변환, IPv6 무시, /1 을 전체로(오탐), strict 파싱, Azure·GCP 미적용, 합산 제거, 대상·포트·프로토콜 무시(오탐), egress 합산(오탐), 불명을 확정으로, 불명 REVIEW 제거, 필요 규칙 선택 제거(오탐), 중복 사유, 다른 폴더 리터럴 REVIEW 제거, 모듈 경계 무시(오탐), RDP 미합산, 파일·폴더 문맥 누락, `/tmp` 고정 경로 되돌리기 2) | **25/25 탐지**. 신규 테스트를 지우면 23가지를 못 잡음 (잡는 2가지: IPv6 무시·중복 사유 — 기존 회귀 테스트가 잡음) |
| v3.1 15 + PR 6 32 + PR 5 31 을 v3.2 코드에 다시 주입 | **78/78 탐지** |

### 회귀

| 항목 | 결과 |
|---|---|
| 단위 테스트 | **448** 통과 (v3.1 404 + 신규 44), Python 3.13·3.12, 연속 3회 |
| 동시 실행 | 단위 테스트 2개 + 시나리오 흉내 1개를 동시에 3회 — 모두 통과 |
| 자가 점검 / 시나리오 | 47/47 / 7/7 (예시·정답표 변경 없음) |
| 결과 JSON | `samples/`·`scenarios/`·`infra/` 전체 결과가 v3.1 과 바이트 단위로 같음 |
| Summary | 결과표 같음. 지원 행렬의 CG-NET-01 AWS·Azure·GCP 한계 문구만 바뀜 |
| 커밋별 | N1(410)·N2(446)·N3(448) 각 시점에서 단위·자가 점검·시나리오 통과 |

### 알려진 한계 (v3.2 이후)

1. Azure NSG·GCP 방화벽은 서로 다른 규칙의 출발지를 합치지 않는다 (거부 규칙·우선순위 때문에 단순 합산이 틀릴 수 있음). 한 규칙 안의 목록만 합친다.
2. AWS 에서 리터럴 sg ID 와 Terraform 리소스 참조는 같은 보안그룹이어도 합치지 않는다. 모듈 출력·data 소스·`count` 인덱스로 연결된 규칙은 대상 불명으로 보고, 합쳐서 전체일 때 REVIEW.
3. 접두사 목록(prefix list), 다른 보안그룹을 출발지로 쓰는 규칙, Azure 서비스 태그의 실제 IP 범위는 해석하지 않는다.
4. 프로토콜 번호·이름 중 tcp(6)·udp(17)·icmp(1)·icmpv6(58)·전체(-1) 만 같은 것으로 묶는다. 그 밖의 프로토콜은 이름이 같을 때만 합친다.
5. provider 수용 여부는 AWS provider 검증 함수 기준이다. AWS EC2 API, Azure·GCP provider/API 의 수용 여부는 확인하지 않았다.
6. `0.0.0.0/1` 같은 매우 넓은 대역 하나는 "인터넷 전체"가 아니므로 PASS 다 (정책 정의 그대로).

## v3.2.1 — v3.2 교차 검토 지적 A·B·C 수정 (2026-11-07)

| 지적 | v3.2 | v3.2.1 |
|---|---|---|
| **A. UDP·ICMP 오탐** | AWS 만 프로토콜과 상관없이 포트 숫자 범위로 판단 → `udp 22` 공개, ICMP `from_port = 0`·`to_port = 255`(ICMP type·code) 공개를 BLOCK. Azure·GCP 는 같은 설정을 PASS (기존 테스트 `test_udp`·`test_udp_22_is_not_ssh`·`test_icmp_only`) | AWS 도 **TCP(6)와 전체 프로토콜(-1/all)만** 관리자 포트로 판단. 개별 판정과 같은 보안그룹 합산 모두. (v3.1 보고서 한계 3 "udp 22 공개도 BLOCK" 은 이 수정으로 바뀜) |
| **B. 무관한 사설 규칙 BLOCK** | 합산에서 혼자 꼭 필요한 규칙이 없을 때(겹치는 덮개) 그룹 전체를 표시하면서 `10.0.0.0/8` 같은 사설 규칙도 BLOCK. 사설 규칙이 `0.0.0.0/0` 의 빈틈을 메우는 경우에도 BLOCK | 사설·내부 전용 대역(10/8, 172.16/12, 192.168/16, 100.64/10, 127/8, 169.254/16, fc00::/7, fe80::/10, ::1)만 가진 규칙은 **표시하지 않음**. 합산 계산에는 그대로 포함 |
| **C. 중복 REVIEW** | 한 규칙이 22·3389 두 포트, 여러 대상 그룹, IPv4·IPv6 에서 같은 규칙 ID 를 여러 번 받음 (예: 대상 불명 규칙 2개 → REVIEW 4건) | 자원 하나에 합산 판정은 **한 번** (사유를 합침). BLOCK·REVIEW 가 함께면 BLOCK. 개별 판정이 이미 같은 규칙 ID·BLOCK 이면 덧붙이지 않음 |

명령줄 수정 전후 (검토 자료 `logs/00_before_after.log`):

| 경우 | v3.2 | v3.2.1 |
|---|---|---|
| `aws_security_group_rule` udp 22 공개 | BLOCK (1) | PASS (0) |
| `aws_vpc_security_group_ingress_rule` icmp 0~255 공개 | BLOCK (1) | PASS (0) |
| 겹치는 덮개 3개 + 사설 `10.0.0.0/8` 규칙 | BLOCK 4건 (사설 포함) | BLOCK 3건 (사설 제외) |
| 22~4000 범위 절반 + 대상 불명 절반 | REVIEW 4건 (규칙마다 2건) | REVIEW 2건 |

**테스트** (`tests/test_v32_review_fixes.py`, 15개): 프로토콜 3 (개별 14가지 × 3가지 표현, 합산 5가지, 세 클라우드 같은 판정 2가지) · 사설 규칙 5 (IPv4 겹치는 덮개, 빈틈 메우기, 다른 내부 대역 5가지, IPv6 겹치는 덮개 + ULA, 사설이 아닌 중복은 v3.2 기준 유지) · 중복 7 (두 포트 REVIEW·BLOCK, 여러 대상 그룹, 개별 REVIEW + 합산 REVIEW, 혼자 공개인 규칙의 합산 건너뛰기, IPv4 + IPv6, 22번 BLOCK + 3389번 REVIEW).
v3.2 코드에서 **41개 하위 확인 실패** → v3.2.1 에서 15개 모두 통과.

**정리:** 프로토콜 판단이 포트 판단(`aws_port_state`: TCP·전체 프로토콜만 포함)에 들어가 있으므로, 합산에서 프로토콜별로 나누던 반복을 없앴다 (동작 같음).

**고장 주입:** 처음 돌린 v3.2.1 신규 10가지 중 **2가지를 못 잡았다** (P-7 IPv6 내부 대역 누락, P-9 BLOCK·REVIEW 함께일 때 REVIEW 선택). 테스트가 그 경우를 실제로 만들지 못하고 있었으므로 테스트를 고쳤다 (로그 `08a_…first_run_8of10.log`). 이전 묶음을 다시 돌렸을 때는 v3.2 의 M-12(프로토콜 무시)·M-18(혼자 공개인 규칙 건너뛰기)이 v3.2.1 변경 뒤 겉으로 드러나지 않았다 (`09a_…101of103.log`). M-12 는 위 정리로 코드에서 사라진 조건이라 목록에서 뺐고, M-18 은 합산 문맥을 직접 확인하는 테스트를 추가했다.

| 묶음 | 결과 |
|---|---|
| v3.2.1 신규 10가지 (P-1~P-10, 테스트 보강 뒤) | **10/10 탐지**. `test_v32_review_fixes.py` 를 지우면 P-4~P-10 7가지를 못 잡음 (P-1·P-2·P-3 은 기존 테스트도 일부 잡음) |
| 이전 102가지 (v3.2 24 + v3.1 15 + PR 6 32 + PR 5 31) | **102/102 탐지** |
| 합계 | **112/112** |

**회귀:** 단위 테스트 **463** (v3.2 448 + 15), 자가 점검 47/47, 시나리오 7/7. `samples/`·`scenarios/`·`infra/` 결과 JSON 은 v3.1·v3.2 와 바이트 단위로 같음 (예시 47개에 AWS udp·icmp 규칙이 없음).

## v3.2.2 — GPT 재검토(v3.2.1) 지적 D·B·C 수정 (2026-11-07)

GPT 가 보낸 독립 테스트 2개 파일(기존 8개 + 신규 4개)을 **고치지 않고** `tests/independent/` 에 넣었고, SHA-256 을 테스트로 고정했다 (`tests/test_gpt_independent_review.py`).

| 지적 | v3.2.1 | v3.2.2 |
|---|---|---|
| **D. 확정 BLOCK → REVIEW (가장 심각)** | 같은 그룹에 확정 규칙 `0.0.0.0/1`·`128.0.0.0/1`(TCP 22) + 포트가 변수인 `0.0.0.0/0` 규칙 → 불확정 규칙이 혼자 전체라는 이유로 합산을 건너뛰어 **REVIEW 1건만** 남음 | **확정 규칙만의 합산을 먼저** 판단 → BLOCK 2건 + 불확정 규칙 REVIEW. 규칙을 더 넣어서 BLOCK 이 내려가는 경로 제거 |
| **B. 원인 규칙 표시** | 사설 대역 목록으로 제외 → 사설이 아닌 군더더기(`8.8.8.0/24`)는 BLOCK, `/1`+`/1`+`/2`+`/2` 에서는 `0.0.0.0/1` 하나만 표시하고 "규칙 1개를 합치면 전체"라고 설명 | 목록 대신 계산: **인터넷 전체를 덮는 군더더기 없는 묶음(최소 덮개)에 하나라도 들어가는 규칙**만 표시. 표시한 규칙을 합치면 항상 전체. 사유에 개수를 쓰지 않음 |
| **C. 교차 폴더 REVIEW 문맥** | 폴더 A 가 혼자 BLOCK 인데 폴더 B 의 같은 sg ID `10.0.0.0/8` 때문에 A 문맥에 REVIEW 가 생김 (최종 출력은 BLOCK 우선 병합으로 가려짐) | 한 폴더 안에서 이미 전체인 폴더는 교차 폴더 합산에서 뺌. 실제 교차 폴더 절반 두 개(`/1` + `/1`)는 계속 REVIEW |
| A. UDP·ICMP | v3.2.1 수정 | 그대로 (GPT 의 UDP·ICMP 4개 + TCP 양성 대조 1개 통과) |

**기대값을 바꾼 기존 테스트 1개:** v3.2.1 의 `test_private_rule_filling_the_gap_is_not_blocked` 는 `0.0.0.0/1` 의 빈틈을 메우는 사설 규칙 `10.0.0.0/8` 을 표시하지 않는 것을 확인했다. 그러나 그 규칙이 없으면 나머지가 전체가 되지 않으므로, 빼면 "표시된 규칙을 고치면 해결된다"가 거짓이 된다 (GPT 지적 B 의 조건). v3.2.2 에서는 표시하는 것이 맞아 `test_private_rule_filling_the_gap_is_part_of_the_witness` 로 바꿨다.

**명령줄 수정 전후** (검토 자료 `logs/00_before_after_cli.log`, 사례 `cases/`):

| 사례 | v3.2.1 | v3.2.2 |
|---|---|---|
| D 확정 `/1`+`/1` + 포트 변수 `0.0.0.0/0` | REVIEW 1건 | **BLOCK** 2건 + REVIEW 1건 |
| B1 `/1`×2 + `/2`×4 + `8.8.8.0/24` | BLOCK 7건 (`8.8.8.0/24` 포함) | BLOCK 6건 |
| B2 `0/1`+`128/1`+`128/2`+`192/2` | BLOCK 1건 ("규칙 1개를 합치면") | BLOCK 4건 (두 덮개 모두) |
| B3 빈틈 메우는 사설 `10/8` | BLOCK 8건 (사설 제외 — 나머지만으론 전체 아님) | BLOCK 9건 |
| C 교차 폴더 사설 / 교차 폴더 절반 | BLOCK 2 / REVIEW 2 | 같음 (바뀐 것은 내부 문맥) |
| A udp 22 공개 | PASS | PASS |

**새 테스트** (`tests/test_v322_witness_monotonic.py`, 12개, hcl2 없이 실행):
- 단조성 4: BLOCK 기본 5가지에 추가 규칙 15가지 / 격자 216가지(CIDR 6 × 대상 3 × 포트 3 × 프로토콜 4) / 2개 동시 추가 / 무작위 300회 — 파일 판정이 내려가면 실패, 확정 BLOCK 규칙이 사라지면 실패
- 원인 규칙 3: 무작위 150 덮개에서 브루트포스(모든 부분집합)로 구한 최소 덮개 소속과 비교, GPT 예시, 사유에 개수 없음
- 교차 폴더 5: 사설·`8.8.8.0/24` 다른 폴더 → REVIEW 없음, 절반 두 폴더 → REVIEW, 한 폴더가 혼자 전체여도 다른 두 폴더의 절반은 REVIEW, 필요한 규칙만 표시

**숨기지 않는 것:** 무작위 단조성 테스트(300회, 3000회로 늘려도)는 v3.2.1 의 D 를 **잡지 못했다** — 무작위로 "포트 변수 + `0.0.0.0/0`" 조합이 거의 안 나온다. D 는 격자·고정 테스트가 잡는다.

**수정 전 재현 (v3.2.1 `6cd8bcf`):**
- GPT 12개: **8 통과 / 4 실패** (기존 8개 중 C 1개, 신규 4개 중 D·B·B 3개) — GPT 보고와 같음 → v3.2.2 **12/12** (Python 3.13·3.12, hcl2 있음·없음 모두)
- 새 테스트 25개(GPT 13 + 위 12): 하위 확인 **158개 실패 + 1 오류**(`_relevant_entries` 없음) → v3.2.2 모두 통과

**고장 주입** (`fault_inject.py --jobs 4`, 고장마다 단위·자가 점검·시나리오):

| 묶음 | 결과 |
|---|---|
| v3.2.2 신규 8가지 (Q-1~Q-8) | **8/8**. 새 테스트 2파일을 지우면 **6/8** — Q-1(D 되돌림)·Q-7(C 되돌림)을 못 잡음 → 새 테스트가 꼭 필요 |
| v3.2.1 6 + v3.2 22 + v3.1 15 + PR 6 32 + PR 5 31 | **106/106** |
| 합계 | **114/114** |

은퇴시킨 고장 6가지: v3.2 M-17·M-18, v3.2.1 P-4~P-7. 바꿀 코드(사설 대역 목록, `_essential_entries`, 혼자 공개 건너뛰기)가 v3.2.2 에서 없어졌다. 같은 성격의 고장은 Q-3·Q-4·Q-5(원인 규칙)·Q-6(혼자 공개 재기록)·Q-1(건너뛰기)로 대신한다. 원본은 `retired_*.json` 으로 남김.

**회귀:** 단위 **488** (v3.2.1 463 + 25) — Python 3.13.18·3.12.3 각 3회 OK, **skip 0**. hcl2 를 import 못 하게 하면 488 중 **384 skip**, 104 실행 OK (v3.2.1 은 463 중 384 skip — GPT 환경 "463 발견, 384 skip, 79 통과"와 같은 수). 자가 점검 47/47, 시나리오 7/7, infra exit 0, 동시 실행 3회 통과. `samples/`·`scenarios/`·`infra/` 결과 JSON 은 v3.1·v3.2·v3.2.1 과 같음.

**한계 (v3.2.2 에서 생긴 것):** 원인 규칙 계산은 같은 그룹·포트의 규칙 수 n 에 대해 대략 n² × 주소 조각 수. 무작위 대역 200개 0.5초, 500개 4.2초, 1,000개 10초 (AWS 보안그룹 인바운드 규칙은 기본 60개, IPv4·IPv6 따로이며 한도를 늘려도 인터페이스당 1,000개를 넘을 수 없음. Terraform 파일에는 그보다 많이 쓸 수 있으므로 비정상적으로 큰 파일은 느려질 수 있음). 그 밖의 한계는 v3.2.1 과 같다 — GitHub Actions·Windows 는 이번에도 실행하지 않았다.
