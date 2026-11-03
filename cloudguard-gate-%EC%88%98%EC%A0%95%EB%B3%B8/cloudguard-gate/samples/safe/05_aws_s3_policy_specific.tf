# [안전] AWS S3 접근 정책 - 특정 역할(앱 서버)에게만 읽기 허용
resource "aws_s3_bucket_policy" "app_read" {
  bucket = "cloudguard-demo-app-data"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:role/app-server" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::cloudguard-demo-app-data/*"
    }
  ]
}
EOF
}
