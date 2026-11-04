# [안전] Azure NSG 내부 규칙 - 인터넷에는 웹(443)만 공개, 관리자 포트는 거부
# 예상 결과: PASS
resource "azurerm_network_security_group" "web" {
  name                = "cloudguard-web-nsg"
  location            = "koreacentral"
  resource_group_name = "cloudguard-rg"

  security_rule {
    name                       = "allow-https"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "deny-admin"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_ranges    = ["22", "3389"]
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
