# [위험] GCP Cloud Storage - 사용자 정의 역할을 allUsers 에게 부여
# 역할의 권한 목록은 알 수 없지만, 공개 주체에게 권한을 주는 선언 자체가 정책 위반 (교차 검토 결정)
# 예상 결과: BLOCK (GCP_STORAGE_PUBLIC_IAM), exposure: blocked_by_public_access_prevention
resource "google_storage_bucket" "media" {
  name                        = "cloudguard-demo-gcp-media"
  location                    = "ASIA-NORTHEAST3"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}

resource "google_storage_bucket_iam_member" "custom" {
  bucket = google_storage_bucket.media.name
  role   = "projects/cloudguard-demo-project/roles/mediaReader"
  member = "allUsers"
}
