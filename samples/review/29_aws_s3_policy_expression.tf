# jsonencode 표현식은 이번 기초 버전의 정적 해석 대상이 아님.
resource "aws_s3_bucket_policy" "generated" {
  bucket = "cloudguard-demo-generated"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Deny"
      Principal = "*"
      Action = "s3:*"
      Resource = "arn:aws:s3:::cloudguard-demo-generated/*"
    }]
  })
}
