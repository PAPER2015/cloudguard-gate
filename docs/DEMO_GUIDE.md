# CloudGuard 시연 가이드 (GitHub 브라우저만 사용)

클라우드 계정·자격 증명·Git 명령어가 필요 없습니다. 실제 클라우드에는 아무것도 만들어지지 않습니다.
시연에 쓴 PR 은 **병합하지 않고 닫습니다.**

## 준비 (한 번만)

1. 저장소 **Settings → Branches**(또는 **Rules → Rulesets**) → `main` 규칙 편집
2. **Require status checks to pass before merging** 을 켜고, 검색창에서 아래 세 개를 추가 → 저장
   - `1. 보안 정책 검사`
   - `2. 모의 배포`
   - `3. 멀티클라우드 통합 검증`
   > 검색에 안 나오면 아직 한 번도 실행되지 않은 것입니다. PR 을 하나 올려 실행시킨 뒤 다시 추가하세요.

## 장면 1. 정상 설정 → PASS → 모의 배포 성공 ✅

1. 저장소에서 `infra/01_aws_s3_private.tf` 열기 → 연필(✏️) 아이콘
2. 첫 줄 주석 끝에 ` (시연)` 정도만 덧붙이기
3. **Commit changes…** → **Create a new branch** 선택(예: `demo-pass`) → **Propose changes** → **Create pull request**
4. PR 아래 **Checks** 가 모두 초록색이 될 때까지 기다리기 (1~3분)
   - `1. 보안 정책 검사` ✅ → `2. 모의 배포` ✅
5. **Details → Summary** 에서 확인할 것
   - "✅ 정책 게이트 통과"
   - **정책 × 클라우드 지원 행렬**: AWS 두 칸은 `PASS`, Azure·GCP 칸은 `N/A`
     → "N/A 는 안전하다는 뜻이 아니라 이번에 검사할 대상이 없었다는 뜻"이라고 설명

## 장면 2. 위험한 설정 → BLOCK → 배포 중단 ⛔

1. 내 PC 로 `samples/risky/43_gcp_storage_public_iam.tf` 를 받아 둡니다 (GitHub 에서 파일 열기 → Download raw file)
2. 저장소 `infra` 폴더 → **Add file → Upload files** → 그 파일 올리기
3. **Create a new branch**(예: `demo-block`) → **Propose changes** → **Create pull request**
4. 확인할 것
   - `1. 보안 정책 검사` ❌ 빨간 X — 단계 `보안 검사 실행` 에서 실패
   - `2. 모의 배포` **Skipped** (배포 단계로 못 넘어감)
   - **Merge pull request 버튼이 막혀 있음** (필수 검사 실패)
   - Summary: `GCP_STORAGE_PUBLIC_IAM`(BLOCK) + `GCP_STORAGE_PAP_NOT_ENFORCED`(REVIEW),
     행렬의 GCP CG-STO-01 칸이 `⛔ BLOCK`
5. PR 아래 **Close pull request** → 브랜치 삭제

## 장면 3. 변수 때문에 판정 불가 → REVIEW → 배포 중단 🔍

1. 장면 2와 같은 방법으로 `samples/review/48_gcp_iam_member_variable.tf` 를 `infra/` 에 올리는 PR 만들기
2. 확인할 것
   - `1. 보안 정책 검사` ❌, `2. 모의 배포` Skipped
   - Summary: "🔍 REVIEW = 값이 변수·표현식이거나 설정이 없어 안전한지 확인할 수 없음. 안전하다고 가정하지 않고 배포를 막습니다."
   - 규칙 `GCP_STORAGE_PUBLIC_UNRESOLVED` — 권한을 받을 구성원이 `var.reader` 라서 allUsers 인지 알 수 없음
3. PR 닫기 → 브랜치 삭제

## 장면 4. 세 클라우드 통합 시나리오 확인 🌐

어느 PR 에서든 Checks 목록에 아래가 함께 있습니다.

| 작업 | 기대 |
|---|---|
| `통합 시나리오 (A_all_pass)` | ✅ — Summary 에서 게이트 `success`, 모의 배포 `success` |
| `통합 시나리오 (B_aws_risk)` ~ `(F_review)` | ✅ — 게이트 `failure`, 모의 배포 `skipped` (**막혔기 때문에 성공**) |
| `통합 시나리오 (G_syntax_error)` | ✅ — 종료 코드 2(ERROR), 모의 배포 `skipped` |
| `3. 멀티클라우드 통합 검증` | ✅ — 7행 모두 ✅ |

설명 포인트: "위험 시나리오의 작업이 초록색인 것은 **위험을 제대로 막았다**는 뜻입니다.
만약 위험한데 배포 단계가 실행되면 그 작업이 빨간색이 되고, 최종 검사도 실패해 병합이 막힙니다."

## 장면 5. 결과를 클라우드·정책별로 읽기 📊

장면 2의 Summary 행렬에서 한 칸을 골라 읽습니다.

- **결과**: 그 칸의 가장 나쁜 판정 (하나라도 BLOCK 이면 BLOCK)
- **검사한 자원**: 몇 개를 실제로 검사했는지 (PASS·REVIEW·BLOCK 개수)
- **규칙 ID / 검사 대상 자원 종류**: 이 칸이 무엇을 보는지
- **알려진 한계**: 이 칸이 보지 않는 것

## 끝난 뒤 정리

- 시연용 PR 을 모두 닫고 브랜치를 삭제했는지 확인 (`main` 의 `infra/` 는 안전한 파일 2개 그대로)

## 문제가 생기면

| 증상 | 원인·해결 |
|---|---|
| Checks 가 "Expected — Waiting for status" 에서 멈춤 | 필수 검사 이름이 작업 이름과 다름. 위 세 이름을 정확히 등록 |
| 필수 검사 검색에 `3. 멀티클라우드 통합 검증` 이 없음 | 아직 한 번도 실행되지 않음. PR 을 하나 올린 뒤 다시 검색 |
| `검사기 자가 점검` 단계가 실패 | 검사기 고장 신호. `requirements.txt` 가 `python-hcl2==7.3.1` 인지 확인 |
