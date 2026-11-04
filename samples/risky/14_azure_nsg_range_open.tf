# [위험] Azure NSG 내부 규칙 - 인터넷(Internet)에 포트 범위 20-30 공개 → SSH(22) 포함
# 예상 결과: BLOCK (AZURE_PUBLIC_ADMIN_PORT)
resource "azurerm_network_security_group" "range_open" {
  name                = "cloudguard-range-nsg"
  location            = "koreacentral"
  resource_group_name = "cloudguard-rg"

  security_rule {
    name                       = "allow-low-ports"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["20-30"]
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
}
