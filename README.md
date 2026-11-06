# CloudGuard — 멀티클라우드 IaC 배포 위험 예방 DevSecOps 정책 게이트

> CloudGuard는 AWS·Azure·GCP의 **지원 대상** Terraform 설정에 공통 보안 정책을 적용하고,
> 위험하거나 판정할 수 없는 설정의 배포 진행을 GitHub Actions 단계에서 차단하는
> 멀티클라우드 DevSecOps 정책 게이트의 **프로토타입**입니다.

Terraform 파일을 GitHub에 올리면 파이썬 검사기(`policy_gate.py`)가 자동으로 실행되고,
위험(BLOCK)·판정 불가(REVIEW)·분석 오류(ERROR)가 하나라도 있으면 **배포 단계로 넘어가지 못합니다.**
실제 클라우드에는 아무것도 배포하지 않습니다 (모의 배포). 클라우드 계정·자격 증명도 필요 없습니다.

## 구조

```
PR 또는 push
   │
   ├─ 1. 보안 정책 검사 ─ 단위 테스트 → 검사기 자가 점검 → infra/ 검사 → Summary(결과표 + 정책 행렬)
   │        │ 성공했을 때만
   │        └─ 2. 모의 배포 (실제 배포 없음)
   │
   └─ 통합 시나리오 (A~G) 7개 ─ 각 시나리오를 게이트에 넣고 "정상은 배포, 위험은 차단"이 맞는지 확인
            └─ 3. 멀티클라우드 통합 검증 (7개 결과를 모아 최종 판정, 하나라도 다르면 실패)
```

필수 검사(브랜치 보호)에 등록할 이름: `1. 보안 정책 검사`, `2. 모의 배포`, `3. 멀티클라우드 통합 검증`

## 지원 정책 × 클라우드

| 정책 | AWS | Azure | GCP |
|---|---|---|---|
| **CG-NET-01** 관리자 포트(22·3389) 인터넷 공개 금지 | 보안 그룹 인바운드 규칙 3가지 표현 (인라인 `ingress`, `aws_vpc_security_group_ingress_rule`, `aws_security_group_rule`) | NSG·NSG 규칙 | VPC 방화벽, 방화벽 정책 규칙 3종 |
| **CG-STO-01** 저장소 공개 금지 | S3 버킷·공개 차단·버킷 정책 | Storage 계정·컨테이너·정적 웹사이트·azapi·ARM 템플릿(REVIEW) | 버킷 PAP·IAM 6종·ACL 6종·Managed Folder |

각 칸의 규칙 ID·검사 대상 자원 전체·알려진 한계는 Actions **Summary의 "정책 × 클라우드 지원 행렬"** 에 매번 표시됩니다
(코드: `policy_gate.py` 의 `POLICY_SUPPORT`, `policy_support_resources()`).

## 판정의 뜻

| 판정 | 뜻 | 종료 코드 | 배포 |
|---|---|---|---|
| ✅ PASS | 검사한 지원 대상에서 정책 위반을 찾지 못함 | 0 | 진행 |
| ⛔ BLOCK | 정책 위반이 확실함 (예: SSH 0.0.0.0/0, allUsers 에게 권한) | 1 | 차단 |
| 🔍 REVIEW | 변수·표현식·외부 정책 때문에 안전한지 확인할 수 없음 — 안전하다고 가정하지 않음 | 1 | 차단 |
| ⚠️ ERROR | 검사기가 파일을 읽지 못함 (문법 오류, 해석하지 않는 `.tf.json` 구성 파일 등) | 2 | 차단 |

정책 행렬에서는 다음도 구분합니다.

- **PASS** = 그 칸의 대상 자원을 실제로 검사했고 위반이 없음 (클라우드 전체가 안전하다는 **보증이 아님**)
- **N/A** = 지원하지만 이번 검사에 대상 자원이 없음
- **미지원** = 구현이 없음
- **확인 불가(ERROR)** = 읽지 못한 파일이 있어 대상 유무를 알 수 없음

Azure·GCP 저장소 결과에는 `exposure`(실제 노출 가능성, Terraform 정적 구성 기준)가 따로 붙습니다.
판정은 "설정의 정책 위반", exposure 는 "실제로 열릴 가능성"입니다. 예: GCP 버킷에 PAP `enforced` 가 있어도
allUsers 에게 권한을 주는 선언은 BLOCK 이고, exposure 는 `blocked_by_public_access_prevention` 입니다.

## 폴더 구성

| 경로 | 역할 |
|---|---|
| `policy_gate.py` | 보안 검사기 (python-hcl2 7.3.1 고정) |
| `self_test.py` | 검사기 자가 점검 — 정답을 아는 예시 47개를 파일 하나씩 검사해 `samples/expected.json` 과 비교 |
| `summary.py` | 결과를 Actions Summary 표로 (결과표 + 정책 행렬) |
| `infra/` | **배포할** Terraform — 게이트가 검사하는 폴더 (지금은 안전한 AWS 파일 2개) |
| `samples/safe·risky·review·error` | 자가 점검용 예시 (배포 대상 아님) |
| `scenarios/A~G` | 세 클라우드가 함께 있는 통합 시나리오 (폴더 하나 = 루트 모듈 하나) + `expected.json` |
| `tests/` | 단위·회귀·통합·워크플로 테스트 (실제 `.tf` 문장을 python-hcl2 로 파싱) |
| `tools/check_scenario.py` | 시나리오 기대 동작 판정 (Actions 와 로컬 테스트가 함께 사용) |
| `tools/terraform_version_oracle/` | Terraform 버전 제약 정답표를 만드는 Go 프로그램 (CI 에서는 실행 안 함) |
| `docs/TEST_REPORT.md`, `docs/DEMO_GUIDE.md` | 테스트 보고서, 브라우저만으로 하는 시연 가이드 |

## 실행 방법 (내 PC)

```
# Windows 는 py, Mac·Linux 는 python3
py -m pip install -r requirements.txt
py -m unittest discover -s tests          # 단위·회귀·통합 테스트
py self_test.py                           # 검사기 자가 점검 (47/47 이어야 정상)
py policy_gate.py infra --json results.json
py summary.py results.json                # 결과표 + 정책 행렬 (Markdown)
py tools/check_scenario.py --local-all    # 시나리오 A~G 를 Actions 순서대로 흉내
```

한 폴더는 하나의 Terraform 모듈로 봅니다. 같은 폴더의 여러 `.tf` 파일은 서로 연결해서 보지만,
**다른 폴더(다른 루트 모듈)의 같은 이름 자원은 연결하지 않습니다** (v3 PR 6 부터 S3 도 동일).

## GitHub Actions 동작과 "모의 배포"

- `pull_request` 는 **모든 PR 에서** 실행됩니다 (README 만 바꿔도 필수 검사가 생성되도록 paths 필터 없음).
  `push` 는 검사 대상 파일이 바뀔 때만 실행됩니다.
- `2. 모의 배포` 는 `1. 보안 정책 검사` 가 성공해야만 실행되고, 실제로는 메시지만 출력합니다.
  실무라면 이 자리에서 `terraform apply` 를 실행합니다. "배포 성공" = "게이트 통과"라는 뜻입니다.
- 통합 시나리오 작업은 위험 시나리오에서 게이트 단계가 **실패하고 모의 배포 단계가 건너뛰어지는 것**을
  GitHub 이 기록한 단계 결과(`steps.<id>.outcome`)로 확인합니다. 기대대로 막혔으면 초록색입니다.
- 브라우저만으로 PASS·BLOCK·REVIEW 를 시연하는 방법: [docs/DEMO_GUIDE.md](docs/DEMO_GUIDE.md)

## 검사기 자가 점검 (Self-Test)

python-hcl2 8.x 에서 위험 파일이 오류 없이 전부 PASS 로 나온 적이 있습니다. 검사기가 고장 나도 "통과"로
보이는 것(fail-open)이 보안 게이트에서 가장 위험하므로, 실제 검사 전에 정답을 아는 예시로 검사기부터 점검합니다.
파일별 판정과 걸린 규칙 목록이 정답표와 정확히 같아야 통과하고, 하나라도 다르면 배포까지 멈춥니다.
새 규칙을 만들면 예시 파일과 정답을 함께 추가합니다.

## 기술적 한계 (발표 때 과장하지 말 것)

- 모든 AWS·Azure·GCP 자원을 검사하지 않습니다. CG-NET-01·CG-STO-01 의 **지원 범위 안에서만** 검사합니다.
- 실제 클라우드에 배포된 접근 상태는 확인하지 않습니다. exposure 도 Terraform 정적 구성 기준입니다.
- 조직 정책(GCP `storage.publicAccessPrevention`, 공개 주체 제한 등)·일부 provider 기본값·환경 변수는 해석하지 못하므로
  보수적으로 REVIEW 가 나올 수 있습니다 (예: GCP 버킷 PAP `inherited`).
- 원격 모듈(레지스트리·Git) 내부, Terraform 밖의 변경(콘솔·CLI·업로드 시 객체 ACL), 서명된 URL 은 보지 않습니다.
- IAM Condition, `for_each`·`dynamic` 같은 복잡한 동적 구성은 펼치지 않고 REVIEW 합니다.
- Terraform JSON 구성 파일(`.tf.json`)은 해석하지 않습니다. 검사 폴더에 하나라도 있으면 (`.tf` 와 섞여 있어도) ERROR 로 차단합니다 (v3.1).
- CG-NET-01 은 **들어오는(인바운드) 규칙**만 봅니다. 나가는 규칙(`egress`, `aws_vpc_security_group_egress_rule`)은 범위 밖입니다.
- 인터넷 전체는 `0.0.0.0/0`·`::/0` 표기만 알아봅니다. 다른 표기(예: `0::/0`)나 여러 대역으로 쪼갠 전체 공개(예: `0.0.0.0/1` + `128.0.0.0/1`), 접두사 목록 안의 대역은 확인하지 않습니다.
- 의도된 공개(정적 웹사이트 등)를 승인하는 예외 기능은 없습니다.
- 모의 배포는 실제 인프라 배포가 아닙니다.

자세한 한계와 검증 결과: [docs/TEST_REPORT.md](docs/TEST_REPORT.md)
