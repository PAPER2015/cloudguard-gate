# HCL 문법은 맞지만 정책 문자열이 JSON이 아님 → REVIEW.
resource "aws_s3_bucket_policy" "invalid_json" {
  bucket = "cloudguard-demo-json"
  policy = "not-valid-json"
}
