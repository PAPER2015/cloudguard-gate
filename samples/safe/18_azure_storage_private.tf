# [안전] Azure Storage - 계정이 익명 접근을 명시적으로 차단, 컨테이너는 비공개
# 예상 결과: PASS
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

resource "azurerm_storage_account" "private" {
  name                            = "cgdemoprivate"
  resource_group_name             = "cloudguard-rg"
  location                        = "koreacentral"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = false
}

resource "azurerm_storage_container" "reports" {
  name                  = "reports"
  storage_account_id    = azurerm_storage_account.private.id
  container_access_type = "private"
}
