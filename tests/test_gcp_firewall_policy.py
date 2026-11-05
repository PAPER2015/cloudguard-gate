"""PR 4 보완: firewall policy rule 3종 및 미지원 계열 감지 테스트.

hcl2 설치 없이도 실행되는 Python 구조 기반 테스트. 정식 .tf 파싱은
기존 GitHub self_test.py가 추가된 samples 4개로 별도 검증한다.
"""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from policy_gate import (  # noqa: E402
    GCP_FIREWALL_POLICY_RULE_TYPES, build_checks, file_status,
    scan_configuration, evaluate_gcp_firewall_policy_rule,
)

TYPES = sorted(GCP_FIREWALL_POLICY_RULE_TYPES)


def rule(**updates):
    body = {
        "action": "allow",
        "direction": "INGRESS",
        "disabled": False,
        "match": [{
            "src_ip_ranges": ["0.0.0.0/0"],
            "layer4_configs": [{"ip_protocol": "tcp", "ports": ["22"]}],
        }],
    }
    body.update(updates)
    return body


def document(resource_type, body=None):
    return {"resource": [{resource_type: {"example": copy.deepcopy(body or rule())}}]}


class GcpPolicyRuleTest(unittest.TestCase):
    def assert_verdict(self, expected, body):
        actual, _unknown = evaluate_gcp_firewall_policy_rule(body)
        self.assertEqual(actual, expected)

    def test_three_official_policy_types_block_and_record(self):
        for typ in TYPES:
            with self.subTest(typ=typ):
                data = document(typ)
                findings = scan_configuration(data)
                self.assertEqual(file_status(findings), "BLOCK")
                self.assertEqual([f["rule"] for f in findings],
                                 ["GCP_FIREWALL_POLICY_PUBLIC_ADMIN_PORT"])
                self.assertEqual(build_checks(data, findings)[0]["status"], "BLOCK")
                self.assertEqual(build_checks(data, findings)[0]["policy"], "CG-NET-01")

    def test_deny_is_pass(self):
        self.assert_verdict("PASS", rule(action="deny"))

    def test_goto_next_is_pass(self):
        self.assert_verdict("PASS", rule(action="goto_next"))

    def test_egress_is_pass(self):
        self.assert_verdict("PASS", rule(direction="EGRESS"))

    def test_disabled_is_pass(self):
        self.assert_verdict("PASS", rule(disabled=True))

    def test_literal_private_source_is_pass(self):
        self.assert_verdict("PASS", rule(match=[{
            "src_ip_ranges": ["10.0.0.0/8"],
            "layer4_configs": [{"ip_protocol":"tcp", "ports":["22"]}]
        }]))

    def test_https_only_is_pass(self):
        self.assert_verdict("PASS", rule(match=[{
            "src_ip_ranges": ["0.0.0.0/0"],
            "layer4_configs": [{"ip_protocol":"tcp", "ports":["443"]}]
        }]))

    def test_udp_ssh_is_pass(self):
        self.assert_verdict("PASS", rule(match=[{
            "src_ip_ranges": ["0.0.0.0/0"],
            "layer4_configs": [{"ip_protocol":"udp", "ports":["22"]}]
        }]))

    def test_ipv6_public_rdp_is_block(self):
        self.assert_verdict("BLOCK", rule(match=[{
            "src_ip_ranges": ["::/0"],
            "layer4_configs": [{"ip_protocol":"tcp", "ports":["3389"]}]
        }]))

    def test_ip_protocol_all_is_block(self):
        self.assert_verdict("BLOCK", rule(match=[{
            "src_ip_ranges": ["0.0.0.0/0"],
            "layer4_configs": [{"ip_protocol":"all"}]
        }]))

    def test_tcp_ports_omitted_is_block(self):
        self.assert_verdict("BLOCK", rule(match=[{
            "src_ip_ranges": ["0.0.0.0/0"],
            "layer4_configs": [{"ip_protocol":"tcp"}]
        }]))

    def test_tcp_range_open_is_block(self):
        self.assert_verdict("BLOCK", rule(match=[{
            "src_ip_ranges": ["0.0.0.0/0"],
            "layer4_configs": [{"ip_protocol":"tcp", "ports":["20-30"]}]
        }]))

    def test_multiple_layer4_blocks_any_open_blocks(self):
        self.assert_verdict("BLOCK", rule(match=[{
            "src_ip_ranges": ["0.0.0.0/0"],
            "layer4_configs": [
                {"ip_protocol":"tcp", "ports":["443"]},
                {"ip_protocol":"tcp", "ports":["22"]},
            ]
        }]))

    def test_missing_direction_requires_review(self):
        body=rule(); body.pop("direction")
        self.assert_verdict("REVIEW", body)

    def test_missing_match_requires_review(self):
        body=rule(); body.pop("match")
        self.assert_verdict("REVIEW", body)

    def test_opaque_match_requires_review(self):
        self.assert_verdict("REVIEW", rule(match="${var.match}"))

    def test_dynamic_match_requires_review(self):
        self.assert_verdict("REVIEW", rule(dynamic=[{"match":{"for_each":"${var.blocks}"}}]))

    def test_unknown_action_requires_review(self):
        self.assert_verdict("REVIEW", rule(action="${var.action}"))

    def test_unknown_source_requires_review(self):
        self.assert_verdict("REVIEW", rule(match=[{
            "src_ip_ranges": ["${var.source}"],
            "layer4_configs": [{"ip_protocol":"tcp", "ports":["22"]}]
        }]))

    def test_address_group_source_requires_review(self):
        self.assert_verdict("REVIEW", rule(match=[{
            "src_address_groups": ["projects/demo/locations/global/addressGroups/test"],
            "layer4_configs": [{"ip_protocol":"tcp", "ports":["22"]}]
        }]))

    def test_public_ip_plus_other_selector_requires_review(self):
        self.assert_verdict("REVIEW", rule(match=[{
            "src_ip_ranges": ["0.0.0.0/0"], "src_network_scope": "VPC_NETWORKS",
            "layer4_configs": [{"ip_protocol":"tcp", "ports":["22"]}]
        }]))

    def test_unknown_port_requires_review(self):
        self.assert_verdict("REVIEW", rule(match=[{
            "src_ip_ranges": ["0.0.0.0/0"],
            "layer4_configs": [{"ip_protocol":"tcp", "ports":["${var.port}"]}]
        }]))

    def test_irrelevant_description_variable_does_not_trigger_review(self):
        self.assert_verdict("BLOCK", rule(description="${var.description}"))

    def test_future_unknown_policy_rule_type_review_and_checks(self):
        data = document("google_compute_future_firewall_policy_rule")
        findings = scan_configuration(data)
        self.assertEqual(file_status(findings), "REVIEW")
        self.assertEqual([f["rule"] for f in findings], ["GCP_FIREWALL_POLICY_UNRESOLVED"])
        self.assertEqual(build_checks(data, findings)[0]["status"], "REVIEW")

    def test_unrelated_google_compute_resource_not_blocked(self):
        data = document("google_compute_network")
        self.assertEqual(scan_configuration(data), [])
        self.assertEqual(build_checks(data, []), [])


if __name__ == '__main__':
    unittest.main()
