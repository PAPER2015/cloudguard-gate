# [위험] GCP 방화벽 - 인터넷 전체에 TCP 모든 포트 공개
# allow 블록에 ports를 쓰지 않으면 해당 프로토콜의 "모든 포트"를 허용 → SSH(22), RDP(3389) 포함
# 예상 결과: BLOCK (GCP_PUBLIC_ADMIN_PORT)
resource "google_compute_firewall" "all_tcp_open" {
  name          = "cloudguard-allow-all-tcp"
  network       = "default"
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
  }
}
