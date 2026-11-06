# [안전] Azure Storage - AzureRM v5 사용, 익명 공개 허용 설정을 생략
# v5의 allow_nested_items_to_be_public 기본값은 false → 계정이 익명 접근을 막음
# 예상 결과: PASS
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.0"
    }
  }
}

resource "azurerm_storage_account" "archive" {
  name                     = "cgdemoarchive"
  resource_group_name      = "cloudguard-rg"
  location                 = "koreacentral"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_storage_container" "backup" {
  name               = "backup"
  storage_account_id = azurerm_storage_account.archive.id
}
