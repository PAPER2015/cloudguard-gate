# CloudGuard 정책 게이트 (GitHub Actions)

Terraform 파일을 GitHub에 올리면 파이썬 보안 검사가 **자동으로** 실행되고,
위험한 설정(BLOCK)이 있으면 **배포 단계로 넘어가지 못하게 막는** 시스템입니다.
실제 클라우드에는 아무것도 배포하지 않습니다 (모의 배포).

```
GitHub에 infra/*.tf 업로드
        ↓
1. 보안 정책 검사 (policy_gate.py)
     ↙            ↘
   PASS          BLOCK / ERROR
     ↓              ↓
2. 모의 배포      빨간 X, 배포 단계 건너뜀
```

## 폴더 구성

| 경로 | 역할 |
|---|---|
| `.github/workflows/policy-gate.yml` | GitHub Actions 설정 (언제, 무엇을 실행할지) |
| `policy_gate.py` | 보안 검사기 (python-hcl2 사용) |
| `summary.py` | 검사 결과를 표로 만들어 Actions 화면에 표시 |
| `requirements.txt` | 설치할 라이브러리 목록 |
| `infra/` | **"배포할" Terraform 파일** — 게이트가 검사하는 폴더 |
| `samples/safe`, `samples/risky` | 시연용 예시 10개 (게이트 검사 대상 아님) |

처음에는 `infra/`에 안전한 파일 2개만 들어 있어서 검사가 통과(초록색)합니다.

> 중요: `requirements.txt`에서 `python-hcl2==7.3.1`로 버전을 고정했습니다. 최신 8.x에서 검사 결과가 전부 PASS로 잘못 나왔던 사례가 있어, 이 프로젝트에서 정상 작동을 확인한 버전을 사용합니다.

---

## 따라 하기 (Git 명령어 없이 웹 브라우저로만)

### 1단계. 저장소 만들기
1. github.com 로그인 → 오른쪽 위 `+` → **New repository**
2. 이름: `cloudguard-gate` / **Public** 선택 / Create repository

### 2단계. 파일 올리기
1. 새 저장소 화면의 **uploading an existing file** 링크 클릭
2. 이 폴더 안의 `policy_gate.py`, `summary.py`, `requirements.txt`, `README.md`,
   `infra` 폴더, `samples` 폴더를 끌어다 놓기 → 아래 **Commit changes**

### 3단계. 자동 검사 설정 파일 만들기
`.github`처럼 점(.)으로 시작하는 폴더는 끌어다 놓기로 잘 안 올라갈 수 있어서 직접 만듭니다.
1. 저장소 화면 → **Add file → Create new file**
2. 파일 이름 칸에 정확히 입력: `.github/workflows/policy-gate.yml`
   (`/`를 입력하면 폴더가 자동으로 만들어집니다)
3. 이 폴더의 `.github/workflows/policy-gate.yml` 내용을 전부 복사해서 붙여넣기
4. **Commit changes**
5. (선택) 같은 방법으로 `.gitignore`도 만들기

### 4단계. 통과 확인 ✅
1. 저장소 위쪽 **Actions** 탭 클릭
2. `CloudGuard Policy Gate` 실행이 보이고, 1~2분 뒤 **초록색 체크**가 되면 성공
3. 실행 항목을 누르면 `1. 보안 정책 검사` → `2. 모의 배포` 순서로 둘 다 성공한 그림과
   아래쪽 **Summary**에 결과 표가 보입니다.
   (실행이 안 보이면: Actions 탭 → 왼쪽 `CloudGuard Policy Gate` → **Run workflow**)

### 5단계. 차단 시연 ⛔ (발표 핵심 장면)
1. `infra` 폴더로 이동 → **Add file → Upload files**
2. 내 PC의 `samples/risky/07_aws_sg_ssh_open.tf`를 올리고 Commit
3. Actions 탭에서 **빨간 X** 확인
   - `1. 보안 정책 검사` 실패 (AWS_PUBLIC_ADMIN_PORT)
   - `2. 모의 배포`는 **건너뜀(skipped)** → 위험한 코드는 배포 단계로 못 넘어감
4. 원상복구: `infra/07_aws_sg_ssh_open.tf` 파일 열기 → 오른쪽 위 `...` → **Delete file** → Commit
   → 다시 초록색으로 돌아옴

## 내 PC에서 먼저 확인하기 (선택)
```
py -m pip install -r requirements.txt
py policy_gate.py infra --json results.json
py summary.py results.json
```

## 다음 확장 아이디어
- **Pull Request 차단**: Settings → Branches → 규칙 추가 → "Require status checks to pass"에서
  `1. 보안 정책 검사` 선택 → 검사 실패한 PR은 main에 합칠 수 없게 됨 (실무형 게이트)
- 변수로 지정한 포트 등 "판단 불가" 상황을 WARN으로 표시
- Streamlit 대시보드로 results.json 시각화
- Checkov(실무용 IaC 검사 도구)와 결과 비교
