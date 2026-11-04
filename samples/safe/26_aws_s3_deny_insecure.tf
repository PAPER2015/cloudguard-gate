# HTTPS 강제 정책: Effect=Deny, Principal=*는 익명 읽기 허용이 아님.
resource "aws_s3_bucket_policy" "deny_insecure" {
  bucket = "cloudguard-demo-private"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": "arn:aws:s3:::cloudguard-demo-private/*",
    "Condition": {"Bool": {"aws:SecureTransport": "false"}}
  }]
}
EOF
}
