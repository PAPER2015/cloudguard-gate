# [위험] Azure Storage - 계정이 익명 공개를 허용하고, 그 계정의 컨테이너를 blob 공개로 설정
# 예상 결과: BLOCK (AZURE_STORAGE_PUBLIC_ALLOWED, AZURE_STORAGE_CONTAINER_PUBLIC)
#   exposure: anonymous_access_configured (정적 구성 기준. 실제 클라우드 접근을 확인한 것은 아님)
resource "azurerm_storage_account" "public" {
  name                            = "cgdemopublic"
  resource_group_name             = "cloudguard-rg"
  location                        = "koreacentral"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true
}

resource "azurerm_storage_container" "images" {
  name                  = "images"
  storage_account_id    = azurerm_storage_account.public.id
  container_access_type = "blob"
}
