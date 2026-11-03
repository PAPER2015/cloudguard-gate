# [안전] GCP 저장소(Cloud Storage) - 공개 접근 방지 강제
resource "google_storage_bucket" "backup" {
  name                        = "cloudguard-demo-backup"
  location                    = "ASIA-NORTHEAST3"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}
