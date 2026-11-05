# [안전] GCP 방화벽 - SSH(22)는 회사 IP 대역에서만 허용
# 예상 결과: PASS
resource "google_compute_firewall" "ssh_office" {
  name          = "cloudguard-allow-ssh-office"
  network       = "default"
  direction     = "INGRESS"
  source_ranges = ["203.0.113.0/24"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
