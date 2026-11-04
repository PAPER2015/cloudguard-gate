# Principal.AWS 리스트에 *가 하나라도 있으면 공개 허용 정책 위반.
resource "aws_s3_bucket_policy" "allow_list_wildcard" {
  bucket = "cloudguard-demo-list"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": ["arn:aws:iam::123456789012:role/app", "*"]},
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::cloudguard-demo-list/*"
  }]
}
EOF
}
