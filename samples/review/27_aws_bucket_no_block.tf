# [판단 불가] AWS S3 버킷만 있고, 연결된 공개 차단 설정(aws_s3_bucket_public_access_block)이 없음
# 공개 여부를 확인할 근거가 없으므로 PASS로 넘기지 않음
# 예상 결과: REVIEW (AWS_S3_NO_PUBLIC_BLOCK) → 배포 차단
resource "aws_s3_bucket" "logs" {
  bucket = "cloudguard-demo-logs"
}
