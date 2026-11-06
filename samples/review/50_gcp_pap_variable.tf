# [검토] GCP Cloud Storage - PAP 값이 변수라 공개 차단 여부를 확인할 수 없음
# 예상 결과: REVIEW (GCP_STORAGE_PUBLIC_UNRESOLVED)
variable "pap" {
  type    = string
  default = "enforced"
}

resource "google_storage_bucket" "archive" {
  name                        = "cloudguard-demo-gcp-archive"
  location                    = "ASIA-NORTHEAST3"
  uniform_bucket_level_access = true
  public_access_prevention    = var.pap
}
