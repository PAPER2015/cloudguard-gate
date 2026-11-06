# Azure — NSG 관리자 포트(CG-NET-01) + Storage 계정·컨테이너(CG-STO-01)
# 공개 허용 값을 명시해 provider 버전 판단이 결과에 끼어들지 않게 한다.
resource "azurerm_network_security_rule" "ssh" {
  name                        = "cg-scn-e-ssh"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "203.0.113.0/24"
  destination_address_prefix  = "*"
  resource_group_name         = "cg-scn-rg"
  network_security_group_name = "cg-scn-e-nsg"
}

resource "azurerm_storage_account" "data" {
  name                            = "cgscnedata"
  resource_group_name             = "cg-scn-rg"
  location                        = "koreacentral"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true
}

resource "azurerm_storage_container" "reports" {
  name                  = "reports"
  storage_account_id    = azurerm_storage_account.data.id
  container_access_type = "private"
}
