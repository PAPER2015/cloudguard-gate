# [판단 불가] Azure Storage - 익명 공개 허용 설정 생략, AzureRM 버전 정보 없음
# 버전에 따라 기본값이 true(v3·v4) 또는 false(v2·v5)라서 최신 기본값을 가정하지 않음
# 예상 결과: REVIEW (AZURE_STORAGE_PUBLIC_UNRESOLVED) → 배포 차단
resource "azurerm_storage_account" "unknown" {
  name                     = "cgdemounknown"
  resource_group_name      = "cloudguard-rg"
  location                 = "koreacentral"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}
