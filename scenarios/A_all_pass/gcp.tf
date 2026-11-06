# GCP — 방화벽 관리자 포트(CG-NET-01) + Cloud Storage(CG-STO-01)
resource "google_compute_firewall" "ssh" {
  name          = "cg-scn-a-ssh"
  network       = "default"
  direction     = "INGRESS"
  source_ranges = ["203.0.113.0/24"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_storage_bucket" "reports" {
  name                        = "cg-scn-a-reports"
  location                    = "ASIA-NORTHEAST3"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}

resource "google_storage_bucket_iam_member" "reader" {
  bucket = google_storage_bucket.reports.name
  role   = "roles/storage.objectViewer"
  member = "user:analyst@example.com"
}
