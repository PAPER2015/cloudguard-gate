# [검토] GCP Cloud Storage - 공개 부여는 없지만 PAP 가 inherited (조직 정책에 맡김)
# 조직 정책은 Terraform 에 보이지 않아 Terraform 밖의 공개를 막는지 확인할 수 없음
# 예상 결과: REVIEW (GCP_STORAGE_PAP_NOT_ENFORCED)
resource "google_storage_bucket" "logs" {
  name                        = "cloudguard-demo-gcp-logs"
  location                    = "ASIA-NORTHEAST3"
  uniform_bucket_level_access = true
  public_access_prevention    = "inherited"
}
