# [위험] GCP 권한
# - 외부 개발자 계정에 프로젝트 전체 관리자(Owner) 권한 부여
# - 오래 쓰는 서비스 계정 키(장기 키) 생성
# 예상 결과: BLOCK (GCP_PROJECT_OWNER, GCP_SERVICE_ACCOUNT_KEY)
resource "google_project_iam_member" "contractor" {
  project = "cloudguard-demo-project"
  role    = "roles/owner"
  member  = "user:contractor@example.com"
}

resource "google_service_account_key" "ci_key" {
  service_account_id = "ci-bot@cloudguard-demo-project.iam.gserviceaccount.com"
}
