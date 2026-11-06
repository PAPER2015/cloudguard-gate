# [위험] Azure Storage - AzureRM v4 사용, 익명 공개 허용 설정을 생략
# v3·v4의 allow_nested_items_to_be_public 기본값은 true → 계정이 익명 공개를 허용함
# 예상 결과: BLOCK (AZURE_STORAGE_PUBLIC_ALLOWED)
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

resource "azurerm_storage_account" "logs" {
  name                     = "cgdemologs"
  resource_group_name      = "cloudguard-rg"
  location                 = "koreacentral"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}
