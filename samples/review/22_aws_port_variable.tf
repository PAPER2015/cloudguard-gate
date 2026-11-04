# [판단 불가] AWS 방화벽 - 인터넷 전체(0.0.0.0/0)에 열려 있지만 포트가 변수
# 변수 기본값은 22(SSH)지만, 실제 배포 때 어떤 값이 들어갈지 검사기는 알 수 없음
# 예상 결과: REVIEW (AWS_ADMIN_PORT_UNRESOLVED) → 안전하다고 가정하지 않고 배포 차단
variable "ssh_port" {
  type    = number
  default = 22
}

resource "aws_security_group" "admin" {
  name        = "cloudguard-admin-sg"
  description = "admin access security group"

  ingress {
    description = "admin port from variable"
    from_port   = var.ssh_port
    to_port     = var.ssh_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
