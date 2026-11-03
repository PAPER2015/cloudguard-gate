# [위험] AWS 방화벽 - SSH(22)를 인터넷 전체(0.0.0.0/0)에 공개
# 예상 결과: BLOCK (AWS_PUBLIC_ADMIN_PORT)
resource "aws_security_group" "bastion" {
  name        = "cloudguard-bastion-sg"
  description = "bastion security group"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
