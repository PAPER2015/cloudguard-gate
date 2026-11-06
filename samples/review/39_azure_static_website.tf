# [판단 불가] Azure Storage - 계정은 익명 접근 차단(false)이지만 정적 웹사이트를 켬
# 정적 웹사이트의 $web 컨테이너는 계정 설정과 무관하게 공개됨 (Microsoft 문서)
# → 의도된 공개인지 사람이 확인해야 함
# 예상 결과: REVIEW (AZURE_STORAGE_STATIC_WEBSITE)
resource "azurerm_storage_account" "site" {
  name                            = "cgdemosite"
  resource_group_name             = "cloudguard-rg"
  location                        = "koreacentral"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  account_kind                    = "StorageV2"
  allow_nested_items_to_be_public = false
}

resource "azurerm_storage_account_static_website" "site" {
  storage_account_id = azurerm_storage_account.site.id
  index_document     = "index.html"
}
