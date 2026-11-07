"""Independent GPT regression checks for CloudGuard v3.2.

Place this file at the root of cloudguard-gate and run:
    python -m unittest cloudguard_v32_gpt_regression_tests -v

These tests use the parsed-dictionary interface of policy_gate.py so no
external HCL parser is required. The current v3.2 is expected to fail five
negative cases; two positive controls are expected to pass.
"""
import unittest
from pathlib import Path
from policy_gate import (
    add_cross_folder_aws_union, cidr_network, file_status, make_aws_context,
    scan_configuration,
)

GROUP = '${aws_security_group.web.id}'

def ingress(name, cidr, protocol='tcp', target=GROUP):
    return {'aws_vpc_security_group_ingress_rule': {
        name: {'security_group_id': target, 'ip_protocol': protocol,
               'from_port': 22, 'to_port': 22, 'cidr_ipv4': cidr}}}

def findings(*rules):
    return scan_configuration({'resource': list(rules)})

class IndependentV32Review(unittest.TestCase):
    # Positive controls, expected to pass already.
    def test_tcp_two_halves_block(self):
        self.assertEqual(file_status(findings(
            ingress('a', '0.0.0.0/1'), ingress('b', '128.0.0.0/1'))), 'BLOCK')

    def test_mapped_ipv4_normalization(self):
        self.assertEqual(str(cidr_network('::ffff:0:0/96')), '0.0.0.0/0')

    # Should PASS according to CG-NET-01 as documented (SSH/RDP are TCP).
    def test_udp_full_internet_is_not_ssh(self):
        self.assertEqual(file_status(findings(
            ingress('a', '0.0.0.0/0', protocol='udp'))), 'PASS')

    def test_udp_halves_do_not_open_ssh(self):
        self.assertEqual(file_status(findings(
            ingress('a', '0.0.0.0/1', protocol='udp'),
            ingress('b', '128.0.0.0/1', protocol='udp'))), 'PASS')

    def test_icmp_halves_do_not_open_ssh(self):
        self.assertEqual(file_status(findings(
            ingress('a', '0.0.0.0/1', protocol='icmp'),
            ingress('b', '128.0.0.0/1', protocol='icmp'))), 'PASS')

    def test_udp_plus_all_does_not_open_ssh_globally(self):
        self.assertEqual(file_status(findings(
            ingress('a', '0.0.0.0/1', protocol='udp'),
            ingress('b', '128.0.0.0/1', protocol='-1'))), 'PASS')

    # Full exposure is real, but private rule must not be falsely blamed.
    def test_redundant_partitions_do_not_flag_private_rule(self):
        cidrs = ['0.0.0.0/1', '128.0.0.0/1',
                 '0.0.0.0/2', '64.0.0.0/2', '128.0.0.0/2', '192.0.0.0/2',
                 '10.0.0.0/8']
        fs = findings(*(ingress(str(i), cidr) for i, cidr in enumerate(cidrs)))
        self.assertEqual(file_status(fs), 'BLOCK')
        self.assertNotIn('aws_vpc_security_group_ingress_rule.6',
                         {f['resource'] for f in fs})

    # Separate diagnostic; a redundant cross-folder REVIEW is not a new risk.
    def test_other_folder_private_rule_adds_no_cross_folder_review(self):
        a, b = Path('/module-a'), Path('/module-b')
        target = 'sg-0123'
        a_ctx = make_aws_context([{'resource': [
            ingress('a', '0.0.0.0/1', target=target),
            ingress('b', '128.0.0.0/1', target=target)]}], a)
        b_ctx = make_aws_context([{'resource': [
            ingress('c', '10.0.0.0/8', target=target)]}], b)
        contexts = {a: a_ctx, b: b_ctx}
        add_cross_folder_aws_union(contexts)
        all_a = [entry for items in contexts[a]['union'].values() for entry in items]
        self.assertFalse(any(rule == 'AWS_ADMIN_PORT_UNRESOLVED' for rule, _ in all_a))

if __name__ == '__main__':
    unittest.main()
