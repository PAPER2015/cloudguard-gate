# [안전] GCP Cloud Storage - Managed Folder 에 팀 그룹만 쓰기 권한 (공개 주체 없음)
# 예상 결과: PASS
resource "google_storage_bucket" "shared" {
  name                        = "cloudguard-demo-gcp-shared"
  location                    = "ASIA-NORTHEAST3"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}

resource "google_storage_managed_folder" "team" {
  bucket = google_storage_bucket.shared.name
  name   = "team/"
}

resource "google_storage_managed_folder_iam_member" "team_writer" {
  bucket         = google_storage_bucket.shared.name
  managed_folder = google_storage_managed_folder.team.name
  role           = "roles/storage.objectUser"
  member         = "group:data-team@example.com"
}
