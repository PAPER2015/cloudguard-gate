# [안전] AWS S3 저장소 - 공개 접근 차단 4개 옵션 모두 켬
resource "aws_s3_bucket" "reports" {
  bucket = "cloudguard-demo-reports"
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = "cloudguard-demo-reports"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
