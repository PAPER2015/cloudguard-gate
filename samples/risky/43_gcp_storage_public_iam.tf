# [위험] GCP Cloud Storage - 버킷 전체를 인터넷의 누구나(allUsers) 읽을 수 있게 함
# PAP 를 enforced 로 하지 않아(생략 = inherited) 조직 정책이 없으면 실제로 공개된다
# 예상 결과: BLOCK (GCP_STORAGE_PUBLIC_IAM) + REVIEW (GCP_STORAGE_PAP_NOT_ENFORCED)
resource "google_storage_bucket" "assets" {
  name                        = "cloudguard-demo-gcp-assets"
  location                    = "ASIA-NORTHEAST3"
  uniform_bucket_level_access = true
}

resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.assets.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
