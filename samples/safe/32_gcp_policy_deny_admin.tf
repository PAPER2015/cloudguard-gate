# Hierarchical firewall policy: explicit Deny is not an Allow violation (PASS).
resource "google_compute_firewall_policy_rule" "deny_admin" {
  firewall_policy = "org-policy"
  priority        = 1000
  action          = "deny"
  direction       = "INGRESS"
  match {
    src_ip_ranges = ["0.0.0.0/0"]
    layer4_configs {
      ip_protocol = "tcp"
      ports       = ["22"]
    }
  }
}
