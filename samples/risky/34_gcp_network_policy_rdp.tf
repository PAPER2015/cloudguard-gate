# Global network firewall policy allows Internet TCP RDP (BLOCK).
resource "google_compute_network_firewall_policy_rule" "open_rdp" {
  firewall_policy = "network-policy"
  priority        = 2000
  action          = "allow"
  direction       = "INGRESS"
  match {
    src_ip_ranges = ["::/0"]
    layer4_configs {
      ip_protocol = "tcp"
      ports       = ["3389"]
    }
  }
}
