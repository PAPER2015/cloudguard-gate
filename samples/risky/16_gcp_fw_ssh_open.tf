# [위험] GCP 방화벽 - SSH(22)를 인터넷 전체(0.0.0.0/0)에 공개
# direction을 생략했으므로 기본값 INGRESS(들어오는 연결)로 적용됨
# 예상 결과: BLOCK (GCP_PUBLIC_ADMIN_PORT)
resource "google_compute_firewall" "ssh_open" {
  name          = "cloudguard-allow-ssh-anywhere"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
