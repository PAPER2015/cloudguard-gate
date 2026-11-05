# [안전] Azure NSG 규칙(별도 자원) - SSH(22)는 회사 IP 대역에서만 허용
# 예상 결과: PASS
resource "azurerm_network_security_group" "office" {
  name                = "cloudguard-office-nsg"
  location            = "koreacentral"
  resource_group_name = "cloudguard-rg"
}

resource "azurerm_network_security_rule" "ssh_office" {
  name                        = "allow-ssh-office"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "203.0.113.0/24"
  destination_address_prefix  = "*"
  resource_group_name         = "cloudguard-rg"
  network_security_group_name = "cloudguard-office-nsg"
}
