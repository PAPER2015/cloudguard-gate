# [오류] Terraform 문법 오류 - 마지막 중괄호 } 가 없음
# 예상 결과: ERROR → 읽을 수 없는 파일은 절대 PASS가 아님 (종료 코드 2)
resource "aws_s3_bucket" "broken" {
  bucket = "cloudguard-demo-broken"
