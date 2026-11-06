# Terraform 버전 제약 기준값(oracle) 만들기

`tests/fixtures/terraform_version_constraints.json`은 이 폴더의 Go 프로그램으로 만든 **정답표**다.
Terraform이 provider 버전 제약을 평가할 때 쓰는 것과 같은 라이브러리·함수를 쓴다.

- Terraform `internal/getproviders/providerreqs/version.go`
  - `ParseVersionConstraints` → `constraints.ParseRubyStyleMulti`
  - `MeetingConstraints` → `versions.MeetingConstraints`
- 라이브러리: `github.com/apparentlymart/go-versions` **v1.0.2** (Terraform `go.mod`에 적힌 버전)

`policy_gate.py`의 `possible_major_versions()`가 이 정답표와 모두 같은지
`tests/test_terraform_version.py`가 확인한다 (GitHub Actions에서 자동 실행, Go 불필요).

## 다시 만드는 방법 (Go 1.24 필요)

```
cd tools/terraform_version_oracle
git clone --depth 1 -b v1.0.2 https://github.com/apparentlymart/go-versions
GOFLAGS=-mod=mod GOPROXY=off go build -o oracle .
./oracle < cases.txt > ../../tests/fixtures/terraform_version_constraints.json
```

출력 (JSON 객체 두 개):

- `majors`: 제약 문자열마다 "그 제약을 만족하는 버전이 하나라도 있는 메이저 목록"(1~7), 문법 오류면 `"error"`
- `members`: `제약 @@ 정확한버전` 줄마다 그 버전이 제약을 만족하는지 (`true`/`false`) — 잠금 파일 판정용

`cases.txt`에서 `#`으로 시작하는 줄은 구역 설명이다. 구역: ① PR 5 첫 제출본의 258개,
② 경계 사례(표본 범위 밖 큰 숫자, `!=`로 비는 구간, 부분 버전, 사전 공개 버전),
③ 문법 경계(공백·탭·쉼표·`v` 접두사), ④ 무작위 400개, ⑤ 정확한 버전 220개.

### 후보 버전을 만드는 방법 (PR 5 최종에서 바뀜)

처음에는 메이저 1~7 × 부 버전 0~120 × 수 버전 {0,1,2,5,9,10,99} 를 촘촘히 찍어 보았다.
그러면 `>= 4.121.0, <= 5.0.0` 처럼 표본 밖 숫자를 쓰는 제약에서 4.x 를 놓친다 (GPT 교차 검토 지적).

지금은 **제약에 적힌 경계값**에서 후보를 만든다. 정식 버전만 보면 제약을 만족하는 집합은
"경계값으로 정해지는 구간 하나 − `!=`로 뺀 점 몇 개"이므로, 비어 있지 않다면 다음 중 하나가 반드시 들어 있다.

- 구간의 가장 작은 값 후보: 각 메이저 시작 (M.0.0), 적힌 버전 z, 그 바로 다음 (z의 수 버전 + 1)
- 그 값에서 수 버전을 +0~+5 한 것 (`!=`로 몇 개를 빼도 남는 값을 찾기 위해)
- 수 버전을 아주 크게(999999999) 한 것, 부 버전 + 1, 부·수 버전을 아주 크게 한 것

사전 공개 버전(`4.0.0-beta1`)은 라이브러리 규칙상 `= 4.0.0-beta1` 처럼 정확히 지목해야만 후보가 되므로,
제약에 적힌 사전 공개 버전을 그대로 후보에 넣는다.

이 변경으로 기존 258개 중 2개의 정답이 바뀌었다: `4.0.0-beta1`, `= 4.0.0-beta1` → `[]` 에서 `[4]`.
예전 표본에 사전 공개 버전이 없어서 생긴 오답이었고, 실제 라이브러리는 4.0.0-beta1 을 허용한다.

### 무작위 사례를 다시 만들 때

`cases.txt` ④ 구역은 Python `random.seed(20261106)` 으로 만든 400개다. 숫자는
{0,1,2,3,4,5,9,10,99,100,120,121,150,999,1000}, 사전 공개 표시는 {beta1, rc.1, alpha, 1, alpha.1, beta.2},
연산자 11종(공백 없는 형태 포함), 조건 1~4개, 일부는 연산자 뒤 공백 2칸(문법 오류)이다.
정답은 언제나 위 Go 프로그램 출력이 기준이고, 사례 문자열 자체는 `cases.txt` 에 그대로 들어 있으므로
다시 만들 필요는 없다.

### 알려진 차이 (보수적인 방향만)

Terraform 라이브러리는 받아들이지만 `policy_gate.py` 는 문법 오류로 보는 표기:
끝에 쉼표 (`~> 4.0,`), 빌드 메타데이터 (`4.0.0+abc`), 빈 사전 공개 표시 (`>= 4.0.0-`).
문법 오류이면 저장소 기본값을 정할 수 없으므로 REVIEW 가 되어, 위험을 통과시키는 방향의 차이는 아니다.
(`tests/test_terraform_version.py` 의 `test_conservative_where_terraform_is_lenient`)
