# [위험] GCP Cloud Storage - 객체 ACL 로 파일 하나를 누구나 읽게 함 (IAM 과 별개인 ACL 경로)
# 버킷은 PAP enforced 라 실제로는 막히지만, 공개 선언 자체가 정책 위반
# 예상 결과: BLOCK (GCP_STORAGE_PUBLIC_ACL), exposure: blocked_by_public_access_prevention
resource "google_storage_bucket" "files" {
  name                     = "cloudguard-demo-gcp-files"
  location                 = "ASIA-NORTHEAST3"
  public_access_prevention = "enforced"
}

resource "google_storage_object_acl" "report" {
  bucket      = google_storage_bucket.files.name
  object      = "report.pdf"
  role_entity = ["OWNER:user-owner@example.com", "READER:allUsers"]
}
