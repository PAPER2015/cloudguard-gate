# [안전] AWS 방화벽(보안 그룹)
# - SSH(22)는 회사 IP 대역에서만 허용
# - 웹(443)은 누구나 접속해야 하므로 전체 공개 (관리자 포트가 아니라서 OK)
resource "aws_security_group" "web" {
  name        = "cloudguard-web-sg"
  description = "web server security group"

  ingress {
    description = "SSH from office only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"]
  }

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
