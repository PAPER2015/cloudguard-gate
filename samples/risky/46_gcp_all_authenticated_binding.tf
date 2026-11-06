# [위험] GCP Cloud Storage - "로그인한 사용자 모두"(allAuthenticatedUsers)에게 관리 권한
# 개인 Gmail 을 포함한 전 세계 Google 계정이라 사실상 공개
# 예상 결과: BLOCK (GCP_STORAGE_PUBLIC_IAM)
resource "google_storage_bucket" "uploads" {
  name                        = "cloudguard-demo-gcp-uploads"
  location                    = "ASIA-NORTHEAST3"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}

resource "google_storage_bucket_iam_binding" "admins" {
  bucket  = google_storage_bucket.uploads.name
  role    = "roles/storage.objectAdmin"
  members = ["group:ops@example.com", "allAuthenticatedUsers"]
}
