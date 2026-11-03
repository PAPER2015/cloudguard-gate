# [안전] Azure SQL 서버
# - 비밀번호는 파일에 직접 쓰지 않고 변수(var.)로 받음
# - TLS 1.2 이상만 허용
# - DB 방화벽은 회사 IP 1개만 허용
variable "sql_admin_password" {
  type      = string
  sensitive = true
}

resource "azurerm_mssql_server" "main" {
  name                         = "cloudguard-sql-safe"
  resource_group_name          = "cloudguard-rg"
  location                     = "koreacentral"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_admin_password
  minimum_tls_version          = "1.2"
}

resource "azurerm_mssql_firewall_rule" "office" {
  name             = "office-ip"
  server_id        = "demo-server-id"
  start_ip_address = "203.0.113.10"
  end_ip_address   = "203.0.113.10"
}
