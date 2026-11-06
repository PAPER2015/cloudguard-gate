## ⛔ 정책 게이트 차단 — 배포 중단

총 3개 | PASS 1 | REVIEW 0 | BLOCK 1 | ERROR 1

| 파일 | 결과 | 위반 규칙 | 이유 |
|---|---|---|---|
| infra/a.tf | ⛔ BLOCK | AWS_PUBLIC_ADMIN_PORT | a \| b<br>c |
| infra/a.tf | 🔍 REVIEW | GCP_STORAGE_PAP_NOT_ENFORCED | r |
| infra/b.tf | ✅ PASS | - | - |
| infra/c.tf | ⚠️ ERROR | - | UnexpectedToken: x<br>y |
