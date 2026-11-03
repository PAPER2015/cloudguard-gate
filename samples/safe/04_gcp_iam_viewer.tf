# [안전] GCP 권한 - 보기 전용(Viewer) 권한만 부여 (최소 권한 원칙)
resource "google_project_iam_member" "analyst" {
  project = "cloudguard-demo-project"
  role    = "roles/viewer"
  member  = "user:analyst@example.com"
}
