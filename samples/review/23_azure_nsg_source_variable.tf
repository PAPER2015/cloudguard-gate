# [판단 불가] Azure NSG 규칙 - SSH(22) 허용인데 출발지가 변수
# 실제 배포 때 "*"가 들어갈 수도 있으므로 안전하다고 가정하지 않음
# 예상 결과: REVIEW (AZURE_ADMIN_PORT_UNRESOLVED) → 배포 차단
variable "admin_source" {
  type = string
}

resource "azurerm_network_security_rule" "ssh_variable" {
  name                        = "allow-ssh-variable-source"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = var.admin_source
  destination_address_prefix  = "*"
  resource_group_name         = "cloudguard-rg"
  network_security_group_name = "cloudguard-office-nsg"
}
