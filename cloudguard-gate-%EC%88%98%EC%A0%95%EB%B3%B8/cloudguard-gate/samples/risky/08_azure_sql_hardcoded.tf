# [위험] Azure SQL 서버
# - 비밀번호를 파일에 직접 적음 (가짜 예시 값)
# - 오래된 TLS 1.0 허용
# - DB 방화벽이 모든 IP(0.0.0.0 ~ 255.255.255.255) 허용
# 예상 결과: BLOCK (AZURE_HARDCODED_PASSWORD, AZURE_OLD_TLS, AZURE_WIDE_FIREWALL)
resource "azurerm_mssql_server" "legacy" {
  name                         = "cloudguard-sql-risky"
  resource_group_name          = "cloudguard-rg"
  location                     = "koreacentral"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "FakePassw0rd-ForDemoOnly"
  minimum_tls_version          = "1.0"
}

resource "azurerm_mssql_firewall_rule" "allow_all" {
  name             = "allow-all"
  server_id        = "demo-server-id"
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}
