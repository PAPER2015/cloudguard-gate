# AWS — 관리자 포트(CG-NET-01) + S3 저장소(CG-STO-01)
resource "aws_security_group" "admin" {
  name        = "cg-scn-c-admin-sg"
  description = "admin access"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"]
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "cg-scn-c-logs"
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
