# Hierarchical firewall policy allows Internet TCP SSH (BLOCK).
resource "google_compute_firewall_policy_rule" "open_ssh" {
  firewall_policy = "org-policy"
  priority        = 1000
  action          = "allow"
  direction       = "INGRESS"
  match {
    src_ip_ranges = ["0.0.0.0/0"]
    layer4_configs {
      ip_protocol = "tcp"
      ports       = ["22"]
    }
  }
}
