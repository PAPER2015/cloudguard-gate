# [검토] GCP Cloud Storage - 권한을 받을 구성원이 변수라 공개 주체(allUsers)인지 알 수 없음
# 예상 결과: REVIEW (GCP_STORAGE_PUBLIC_UNRESOLVED)
variable "reader" {
  type = string
}

resource "google_storage_bucket" "exports" {
  name                        = "cloudguard-demo-gcp-exports"
  location                    = "ASIA-NORTHEAST3"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}

resource "google_storage_bucket_iam_member" "reader" {
  bucket = google_storage_bucket.exports.name
  role   = "roles/storage.objectViewer"
  member = var.reader
}
