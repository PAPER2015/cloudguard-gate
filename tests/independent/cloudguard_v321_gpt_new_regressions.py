"""Independent CloudGuard v3.2.1 additional regression tests, no hcl2 dependency.
Copy this file to the cloudguard-gate root and run:
    python -m unittest cloudguard_v321_gpt_new_regressions -v
Expected on the submitted v3.2.1: 3 failures, 1 positive control passes.
"""
import unittest
from pathlib import Path
from policy_gate import (
    cidr_network, networks_cover_internet, file_status, make_aws_context,
    scan_configuration,
)

GROUP = '${aws_security_group.web.id}'

def ingress(name, cidr, *, sg=GROUP, protocol='tcp', from_port=22, to_port=22):
    return {'aws_vpc_security_group_ingress_rule': {name: {
        'security_group_id': sg, 'ip_protocol': protocol,
        'from_port': from_port, 'to_port': to_port, 'cidr_ipv4': cidr,
    }}}

def findings(*rules):
    return scan_configuration({'resource': list(rules)})

class IndependentV321Review(unittest.TestCase):
    def test_positive_control_two_definite_halves_are_block(self):
        fs = findings(ingress('a', '0.0.0.0/1'), ingress('b', '128.0.0.0/1'))
        self.assertEqual(file_status(fs), 'BLOCK')

    def test_definite_block_not_downgraded_by_unresolved_full(self):
        fs = findings(ingress('a', '0.0.0.0/1'),
                      ingress('b', '128.0.0.0/1'),
                      ingress('unknown_full', '0.0.0.0/0',
                              from_port='${var.min_port}',
                              to_port='${var.max_port}'))
        # A + B is a certain full-internet TCP/22 exposure, independent of C.
        self.assertEqual(file_status(fs), 'BLOCK')
        blocked = {f['resource'] for f in fs if f['verdict'] == 'BLOCK'}
        self.assertIn('aws_vpc_security_group_ingress_rule.a', blocked)
        self.assertIn('aws_vpc_security_group_ingress_rule.b', blocked)

    def test_redundant_non_private_subset_not_blindly_blocked(self):
        cidrs = ['0.0.0.0/1', '128.0.0.0/1',
                 '0.0.0.0/2', '64.0.0.0/2',
                 '128.0.0.0/2', '192.0.0.0/2',
                 '8.8.8.0/24']
        fs = findings(*(ingress(f'r{i}', c) for i, c in enumerate(cidrs)))
        self.assertEqual(file_status(fs), 'BLOCK')
        flagged = {f['resource'] for f in fs}
        # r6 is an already-covered small range; never needed to cover /0.
        self.assertNotIn('aws_vpc_security_group_ingress_rule.r6', flagged)

    def test_referenced_blocked_rules_really_cover_internet(self):
        cidrs = ['0.0.0.0/1', '128.0.0.0/1',
                 '128.0.0.0/2', '192.0.0.0/2']
        fs = findings(*(ingress(f'r{i}', c) for i, c in enumerate(cidrs)))
        self.assertEqual(file_status(fs), 'BLOCK')
        flagged = {f['resource'] for f in fs if f['verdict'] == 'BLOCK'}
        selected = [cidr_network(c) for i, c in enumerate(cidrs)
                    if f'aws_vpc_security_group_ingress_rule.r{i}' in flagged]
        # A message claiming that flagged rules in combination open the whole
        # internet must include a sufficient witness set, not merely one /1.
        self.assertTrue(networks_cover_internet(selected),
                        f'Only these ranges were blamed: {selected}')

if __name__ == '__main__':
    unittest.main()
