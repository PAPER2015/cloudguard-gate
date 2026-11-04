# 알 수 없는 공개 차단 값은 안전하다고 판정하지 않는다.
resource "aws_s3_bucket_public_access_block" "variable" {
  bucket                  = "cloudguard-demo-variable"
  block_public_acls       = var.block_public_acls
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
