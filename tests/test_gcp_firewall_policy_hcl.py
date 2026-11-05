"""GCP 방화벽 정책 규칙 — 실제 .tf 문장(python-hcl2) 기반 단위 테스트 (v3 PR 4 교차 검토).

test_gcp_firewall_policy.py(딕셔너리 기반)를 보완한다:
  - 실제 Terraform 문장을 python-hcl2 7.3.1로 읽었을 때도 같은 판정이 나오는지
  - 교차 검토에서 찾은 놓침 2가지가 다시 생기지 않는지
      1) action = "apply_security_profile_group" 은 검사 후 통과(기본 동작도 allow) → 허용으로 판정
      2) *_firewall_policy_with_rules 자원 → 결과에서 빠지지 않고 REVIEW
  - 규칙이 아닌 자원(정책 자체, 연결)은 과잉 차단하지 않는지
실행: python -m unittest discover -s tests -v
"""
import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from policy_gate import build_checks, file_status, scan_configuration  # noqa: E402

try:
    import hcl2
except ImportError:  # pragma: no cover
    hcl2 = None


def scan(src):
    data = hcl2.load(io.StringIO(src))
    findings = scan_configuration(data)
    return file_status(findings), sorted({f["rule"] for f in findings}), findings, data


def policy_rule(typ="google_compute_network_firewall_policy_rule", action='"allow"',
                src='["0.0.0.0/0"]', l4='ip_protocol = "tcp"\n      ports = ["22"]',
                match_extra="", top_extra=""):
    return f'''resource "{typ}" "r" {{
  firewall_policy = "p"
  priority        = 1000
  direction       = "INGRESS"
  action          = {action}
  {top_extra}
  match {{
    src_ip_ranges = {src}
    {match_extra}
    layer4_configs {{
      {l4}
    }}
  }}
}}
'''


BLOCK = ("BLOCK", ["GCP_FIREWALL_POLICY_PUBLIC_ADMIN_PORT"])
REVIEW = ("REVIEW", ["GCP_FIREWALL_POLICY_UNRESOLVED"])
PASS = ("PASS", [])
RULE_TYPES = ("google_compute_firewall_policy_rule",
              "google_compute_network_firewall_policy_rule",
              "google_compute_region_network_firewall_policy_rule")


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class PolicyRuleFromTfTest(unittest.TestCase):
    def check(self, src, expected):
        self.assertEqual(scan(src)[:2], expected)

    def test_all_three_rule_types_block_public_ssh(self):
        for typ in RULE_TYPES:
            with self.subTest(typ):
                self.check(policy_rule(typ=typ), BLOCK)

    def test_rdp(self):
        self.check(policy_rule(l4='ip_protocol = "tcp"\n      ports = ["3389"]'), BLOCK)

    def test_tcp_ports_omitted(self):
        self.check(policy_rule(l4='ip_protocol = "tcp"'), BLOCK)

    def test_protocol_all(self):
        self.check(policy_rule(l4='ip_protocol = "all"'), BLOCK)

    def test_https_only(self):
        self.check(policy_rule(l4='ip_protocol = "tcp"\n      ports = ["443"]'), PASS)

    def test_office_source(self):
        self.check(policy_rule(src='["203.0.113.0/24"]'), PASS)

    def test_deny(self):
        self.check(policy_rule(action='"deny"'), PASS)

    def test_goto_next(self):
        self.check(policy_rule(action='"goto_next"'), PASS)

    def test_disabled(self):
        self.check(policy_rule(top_extra="disabled = true"), PASS)

    def test_variable_source(self):
        self.check(policy_rule(src="var.ranges"), REVIEW)

    def test_variable_action(self):
        self.check(policy_rule(action="var.action"), REVIEW)

    def test_secure_tag_selector(self):
        self.check(policy_rule(match_extra='src_secure_tags {\n      name = "tagValues/1"\n    }'), REVIEW)

    def test_missing_layer4_configs_is_review(self):
        # layer4_configs는 필수 항목. 없으면 허용 포트를 알 수 없으므로 PASS가 아니라 REVIEW
        src = policy_rule().replace('    layer4_configs {\n      ip_protocol = "tcp"\n      ports = ["22"]\n    }\n', "")
        self.assertNotIn("layer4_configs", src)
        self.check(src, REVIEW)

    def test_unrelated_variables_do_not_change_result(self):
        # PR 3 Azure 오탐 유형 재발 방지
        self.check(policy_rule(src='["203.0.113.0/24"]', top_extra="description = var.description"), PASS)
        self.check(policy_rule(top_extra="description = var.description"), BLOCK)


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class CrossReviewFixTest(unittest.TestCase):
    def test_apply_security_profile_group_is_allow(self):
        # 검사 장비를 거쳐 통과(기본 동작도 allow)하므로 공개 SSH 노출로 본다
        self.assertEqual(scan(policy_rule(action='"apply_security_profile_group"'))[:2], BLOCK)

    def test_apply_security_profile_group_office_source_is_pass(self):
        self.assertEqual(scan(policy_rule(action='"apply_security_profile_group"',
                                          src='["203.0.113.0/24"]'))[:2], PASS)

    def test_with_rules_resources_are_review_not_silent(self):
        for typ in ("google_compute_firewall_policy_with_rules",
                    "google_compute_network_firewall_policy_with_rules",
                    "google_compute_region_network_firewall_policy_with_rules"):
            with self.subTest(typ):
                src = f'''resource "{typ}" "p" {{
  name = "p"
  rule {{
    priority  = 1000
    direction = "INGRESS"
    action    = "allow"
    match {{
      src_ip_ranges = ["0.0.0.0/0"]
    }}
  }}
}}
'''
                status, rules, findings, data = scan(src)
                self.assertEqual((status, rules), REVIEW)
                self.assertEqual([c["status"] for c in build_checks(data, findings)], ["REVIEW"])

    def test_policy_container_and_association_are_not_flagged(self):
        src = '''resource "google_compute_network_firewall_policy" "p" {
  name = "p"
}
resource "google_compute_network_firewall_policy_association" "a" {
  name              = "a"
  firewall_policy   = "p"
  attachment_target = "network"
}
resource "google_compute_firewall_policy" "h" {
  parent     = "organizations/123"
  short_name = "h"
}
'''
        status, rules, findings, data = scan(src)
        self.assertEqual((status, rules), PASS)
        self.assertEqual(build_checks(data, findings), [])


if __name__ == "__main__":
    unittest.main()
