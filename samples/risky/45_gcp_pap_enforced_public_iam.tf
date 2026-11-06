# [위험] GCP Cloud Storage - PAP enforced 인데 allUsers 에게 권한을 선언 (설계서의 핵심 사례)
# 실제로는 PAP 가 무력화하고 Google 이 412 로 거부하지만, 공개 선언 자체가 정책 위반
# 예상 결과: BLOCK (GCP_STORAGE_PUBLIC_IAM), exposure: blocked_by_public_access_prevention
resource "google_storage_bucket" "backup" {
  name                        = "cloudguard-demo-gcp-backup"
  location                    = "ASIA-NORTHEAST3"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}

resource "google_storage_bucket_iam_member" "oops" {
  bucket = google_storage_bucket.backup.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
