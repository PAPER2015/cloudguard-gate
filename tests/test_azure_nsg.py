"""Azure NSG 관리자 포트 규칙 (CG-NET-01) 경계 상황 단위 테스트 — v3 PR 3.

실제 Terraform 문장을 python-hcl2로 읽어서 검사한다 (GitHub Actions에서는 설치되어 있음).
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


def nsg_rule(**values):
    """azurerm_network_security_rule 하나. 기본값은 '인터넷 → SSH 허용'(위험)."""
    base = {
        "direction": '"Inbound"', "access": '"Allow"', "protocol": '"Tcp"',
        "source_address_prefix": '"*"', "destination_port_range": '"22"',
    }
    base.update(values)
    lines = "\n".join(f"  {k} = {v}" for k, v in base.items() if v is not None)
    return f'resource "azurerm_network_security_rule" "r" {{\n  name = "t"\n{lines}\n}}\n'


BLOCK = ("BLOCK", ["AZURE_PUBLIC_ADMIN_PORT"])
REVIEW = ("REVIEW", ["AZURE_ADMIN_PORT_UNRESOLVED"])
PASS = ("PASS", [])


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class AzureStandaloneRuleTest(unittest.TestCase):
    def check(self, src, expected):
        status, rules, _f, _d = scan(src)
        self.assertEqual((status, rules), expected)

    # --- BLOCK ---
    def test_ssh_from_star(self):
        self.check(nsg_rule(), BLOCK)

    def test_case_insensitive_values(self):
        self.check(nsg_rule(direction='"inbound"', access='"allow"', protocol='"tcp"',
                            source_address_prefix='"INTERNET"'), BLOCK)

    def test_protocol_star_rdp(self):
        self.check(nsg_rule(protocol='"*"', destination_port_range='"3389"'), BLOCK)

    def test_port_list_contains_22(self):
        self.check(nsg_rule(destination_port_range=None, destination_port_ranges='["80", "22"]'), BLOCK)

    def test_all_ports_star(self):
        self.check(nsg_rule(destination_port_range='"*"'), BLOCK)

    def test_range_contains_3389(self):
        self.check(nsg_rule(destination_port_range='"3000-4000"'), BLOCK)

    def test_numeric_port(self):
        self.check(nsg_rule(destination_port_range="22"), BLOCK)

    def test_ipv6_any(self):
        self.check(nsg_rule(source_address_prefix='"::/0"'), BLOCK)

    def test_prefixes_list_with_public(self):
        self.check(nsg_rule(source_address_prefix=None,
                            source_address_prefixes='["10.0.0.0/8", "0.0.0.0/0"]'), BLOCK)

    def test_port_list_variable_plus_22_is_still_block(self):
        self.check(nsg_rule(destination_port_range=None,
                            destination_port_ranges='[var.extra_port, "22"]'), BLOCK)

    # --- PASS ---
    def test_office_source(self):
        self.check(nsg_rule(source_address_prefix='"203.0.113.0/24"'), PASS)

    def test_https_only(self):
        self.check(nsg_rule(destination_port_range='"443"'), PASS)

    def test_range_without_admin_ports(self):
        self.check(nsg_rule(destination_port_range='"1000-2000"'), PASS)

    def test_deny(self):
        self.check(nsg_rule(access='"Deny"', source_address_prefix="var.anything"), PASS)

    def test_outbound(self):
        self.check(nsg_rule(direction='"Outbound"'), PASS)

    def test_udp(self):
        self.check(nsg_rule(protocol='"Udp"'), PASS)

    def test_variable_source_but_https(self):
        self.check(nsg_rule(source_address_prefix="var.source", destination_port_range='"443"'), PASS)

    def test_asg_only_source(self):
        self.check(nsg_rule(source_address_prefix=None,
                            source_application_security_group_ids='["asg-id-1"]'), PASS)

    # --- REVIEW ---
    def test_variable_source_ssh(self):
        self.check(nsg_rule(source_address_prefix="var.source"), REVIEW)

    def test_variable_direction(self):
        self.check(nsg_rule(direction="var.direction"), REVIEW)

    def test_prefixes_list_with_variable(self):
        self.check(nsg_rule(source_address_prefix=None,
                            source_address_prefixes='["10.0.0.0/8", var.extra]'), REVIEW)

    def test_reversed_range(self):
        self.check(nsg_rule(destination_port_range='"30-20"'), REVIEW)

    def test_non_numeric_port(self):
        self.check(nsg_rule(destination_port_range='"ssh"'), REVIEW)

    def test_out_of_range_port(self):
        self.check(nsg_rule(destination_port_range='"70000"'), REVIEW)

    def test_missing_port(self):
        self.check(nsg_rule(destination_port_range=None), REVIEW)

    def test_review_reason_names_unknown_item(self):
        _s, _r, findings, _d = scan(nsg_rule(source_address_prefix="var.source"))
        self.assertIn("출발지", findings[0]["reason"])


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class AzureInlineRuleTest(unittest.TestCase):
    def test_one_bad_inline_rule_blocks(self):
        src = '''resource "azurerm_network_security_group" "n" {
  security_rule {
    name = "web"
    direction = "Inbound"
    access = "Allow"
    protocol = "Tcp"
    source_address_prefix = "Internet"
    destination_port_range = "443"
  }
  security_rule {
    name = "ssh-open"
    direction = "Inbound"
    access = "Allow"
    protocol = "Tcp"
    source_address_prefix = "*"
    destination_port_range = "22"
  }
}'''
        status, rules, findings, _d = scan(src)
        self.assertEqual((status, rules), BLOCK)
        self.assertEqual(len(findings), 1)
        self.assertIn("ssh-open", findings[0]["reason"])

    def test_inline_source_variable_with_https_only_is_pass(self):
        src = '''resource "azurerm_network_security_group" "n" {
  security_rule {
    name = "web"
    direction = "Inbound"
    access = "Allow"
    protocol = "Tcp"
    source_address_prefix = var.source
    destination_port_range = "443"
  }
}'''
        self.assertEqual(scan(src)[:2], PASS)

    def test_inline_outbound_variable_description_is_pass(self):
        src = '''resource "azurerm_network_security_group" "n" {
  security_rule {
    name = "outbound"
    direction = "Outbound"
    access = "Allow"
    protocol = "Tcp"
    description = var.description
    source_address_prefix = "0.0.0.0/0"
    destination_port_range = "22"
  }
}'''
        self.assertEqual(scan(src)[:2], PASS)

    def test_inline_ssh_with_source_variable_is_review_once(self):
        src = '''resource "azurerm_network_security_group" "n" {
  security_rule {
    name = "ssh"
    direction = "Inbound"
    access = "Allow"
    protocol = "Tcp"
    source_address_prefix = var.source
    destination_port_range = "22"
  }
}'''
        status, rules, findings, _ = scan(src)
        self.assertEqual((status, rules), REVIEW)
        self.assertEqual(len(findings), 1)
        self.assertIn("출발지", findings[0]["reason"])

    def test_opaque_list_expression_is_review(self):
        src = 'resource "azurerm_network_security_group" "n" {\n  security_rule = [var.rules]\n}\n'
        self.assertEqual(scan(src)[:2], REVIEW)

    def test_dynamic_block_is_review(self):
        src = '''resource "azurerm_network_security_group" "n" {
  dynamic "security_rule" {
    for_each = var.rules
    content {
      name = security_rule.value.name
    }
  }
}'''
        self.assertEqual(scan(src)[:2], REVIEW)

    def test_whole_rule_list_variable_is_review(self):
        src = 'resource "azurerm_network_security_group" "n" {\n  security_rule = var.rules\n}\n'
        self.assertEqual(scan(src)[:2], REVIEW)

    def test_nsg_without_rules_is_pass_and_recorded(self):
        src = 'resource "azurerm_network_security_group" "n" {\n  name = "empty"\n}\n'
        status, rules, findings, data = scan(src)
        self.assertEqual((status, rules), PASS)
        checks = build_checks(data, findings)
        self.assertEqual(checks, [{"resource": "azurerm_network_security_group.n", "cloud": "azure",
                                   "policy": "CG-NET-01", "status": "PASS"}])

    def test_checks_record_block_and_metadata(self):
        status, _r, findings, data = scan(nsg_rule())
        self.assertEqual(findings[0]["cloud"], "azure")
        self.assertEqual(findings[0]["policy"], "CG-NET-01")
        self.assertEqual(findings[0]["verdict"], "BLOCK")
        checks = build_checks(data, findings)
        self.assertEqual([c["status"] for c in checks], ["BLOCK"])


if __name__ == "__main__":
    unittest.main()
