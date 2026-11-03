# [위험] AWS S3 저장소 완전 공개
# - 공개 접근 차단 옵션을 모두 끔
# - 접근 정책에서 모든 사람("*")에게 읽기 허용
# 예상 결과: BLOCK (AWS_S3_PUBLIC_BLOCK_OFF, AWS_S3_WILDCARD_PRINCIPAL)
resource "aws_s3_bucket_public_access_block" "open" {
  bucket                  = "cloudguard-demo-public"
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "open" {
  bucket = "cloudguard-demo-public"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::cloudguard-demo-public/*"
    }
  ]
}
EOF
}
