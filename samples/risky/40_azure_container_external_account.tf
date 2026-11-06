# [위험] Azure Storage - 이 코드 밖에 있는 계정(data 소스)에 공개 컨테이너를 만듦
# 계정 설정은 알 수 없지만, 컨테이너가 익명 읽기를 선언한 것 자체가 정책 위반
# 예상 결과: BLOCK (AZURE_STORAGE_CONTAINER_PUBLIC), exposure: public_access_possible
data "azurerm_storage_account" "shared" {
  name                = "cgsharedaccount"
  resource_group_name = "shared-rg"
}

resource "azurerm_storage_container" "downloads" {
  name                  = "downloads"
  storage_account_id    = data.azurerm_storage_account.shared.id
  container_access_type = "container"
}
