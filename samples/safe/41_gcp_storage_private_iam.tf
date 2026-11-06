# [안전] GCP Cloud Storage - 공개 접근 방지(PAP) 강제 + 특정 사용자에게만 읽기 권한
# 예상 결과: PASS
resource "google_storage_bucket" "reports" {
  name                        = "cloudguard-demo-gcp-reports"
  location                    = "ASIA-NORTHEAST3"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}

resource "google_storage_bucket_iam_member" "analyst" {
  bucket = google_storage_bucket.reports.name
  role   = "roles/storage.objectViewer"
  member = "user:analyst@example.com"
}
