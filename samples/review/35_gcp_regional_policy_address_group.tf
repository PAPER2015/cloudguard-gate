# Regional network firewall policy uses a source address group, which this
# simple static checker cannot evaluate: REVIEW, not PASS.
resource "google_compute_region_network_firewall_policy_rule" "complex_source" {
  firewall_policy = "regional-policy"
  region          = "asia-northeast3"
  priority        = 1500
  action          = "allow"
  direction       = "INGRESS"
  match {
    src_address_groups = ["projects/demo/locations/asia-northeast3/addressGroups/office"]
    layer4_configs {
      ip_protocol = "tcp"
      ports       = ["22"]
    }
  }
}
