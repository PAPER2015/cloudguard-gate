# [위험] Azure NSG 규칙(별도 자원) - RDP(3389)를 인터넷 전체(*)에 공개
# 예상 결과: BLOCK (AZURE_PUBLIC_ADMIN_PORT)
resource "azurerm_network_security_rule" "rdp_open" {
  name                        = "allow-rdp-anywhere"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "cloudguard-rg"
  network_security_group_name = "cloudguard-legacy-nsg"
}
