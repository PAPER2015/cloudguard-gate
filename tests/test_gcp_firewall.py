"""GCP 방화벽 관리자 포트 규칙 (CG-NET-01) 경계 상황 단위 테스트 — v3 PR 4.

실제 Terraform 문장을 python-hcl2로 읽어서 검사한다 (GitHub Actions에서는 설치되어 있음).
정상(PASS) · 위험(BLOCK) · 판정 불가(REVIEW)를 각각 충분히 확인하고,
PR 3의 Azure 오탐처럼 "판단과 무관한 변수" 때문에 판정이 바뀌지 않는지도 확인한다.
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


def fw(top=None, allows=('protocol = "tcp"\n    ports = ["22"]',), extra=""):
    """google_compute_firewall 하나. 기본값은 '인터넷 → TCP 22 허용'(위험).

    top: 최상위 속성 (기본 source_ranges = ["0.0.0.0/0"]). None 값은 빼고 만든다.
    allows: allow 블록 내용 목록. extra: 그 밖에 덧붙일 문장(deny, dynamic 등).
    """
    attrs = {"source_ranges": '["0.0.0.0/0"]'}
    attrs.update(top or {})
    lines = "\n".join(f"  {k} = {v}" for k, v in attrs.items() if v is not None)
    allow_text = "".join(f"\n  allow {{\n    {a}\n  }}" for a in allows)
    return (f'resource "google_compute_firewall" "f" {{\n  name = "t"\n  network = "default"\n'
            f'{lines}{allow_text}\n{extra}\n}}\n')


BLOCK = ("BLOCK", ["GCP_PUBLIC_ADMIN_PORT"])
REVIEW = ("REVIEW", ["GCP_ADMIN_PORT_UNRESOLVED"])
PASS = ("PASS", [])


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class GcpFirewallBlockTest(unittest.TestCase):
    def check(self, src, expected):
        self.assertEqual(scan(src)[:2], expected)

    def test_ssh_open_direction_omitted(self):
        self.check(fw(), BLOCK)

    def test_direction_ingress_lowercase(self):
        self.check(fw({"direction": '"ingress"'}), BLOCK)

    def test_rdp_open(self):
        self.check(fw(allows=('protocol = "tcp"\n    ports = ["3389"]',)), BLOCK)

    def test_ports_omitted_means_all_tcp(self):
        self.check(fw(allows=('protocol = "tcp"',)), BLOCK)

    def test_protocol_all(self):
        self.check(fw(allows=('protocol = "all"',)), BLOCK)

    def test_protocol_uppercase_tcp(self):
        self.check(fw(allows=('protocol = "TCP"\n    ports = ["22"]',)), BLOCK)

    def test_protocol_number_6(self):
        self.check(fw(allows=('protocol = "6"\n    ports = ["22"]',)), BLOCK)

    def test_port_range(self):
        self.check(fw(allows=('protocol = "tcp"\n    ports = ["20-30"]',)), BLOCK)

    def test_port_list(self):
        self.check(fw(allows=('protocol = "tcp"\n    ports = ["80", "443", "3389"]',)), BLOCK)

    def test_numeric_port(self):
        self.check(fw(allows=('protocol = "tcp"\n    ports = [22]',)), BLOCK)

    def test_ipv6_any(self):
        self.check(fw({"source_ranges": '["::/0"]'}), BLOCK)

    def test_public_range_among_others(self):
        self.check(fw({"source_ranges": '["10.0.0.0/8", "0.0.0.0/0"]'}), BLOCK)

    def test_public_range_with_variable_in_list(self):
        self.check(fw({"source_ranges": '["0.0.0.0/0", var.extra]'}), BLOCK)

    def test_public_range_or_source_tags(self):
        # source_ranges와 source_tags는 OR → 공개 대역이 있으면 태그가 있어도 공개
        self.check(fw({"source_tags": '["web"]'}), BLOCK)

    def test_one_of_several_allow_blocks(self):
        self.check(fw(allows=('protocol = "icmp"', 'protocol = "tcp"\n    ports = ["443"]',
                              'protocol = "tcp"\n    ports = ["22"]')), BLOCK)

    def test_port_list_variable_plus_22(self):
        self.check(fw(allows=('protocol = "tcp"\n    ports = [var.extra_port, "22"]',)), BLOCK)

    def test_disabled_false(self):
        self.check(fw({"disabled": "false"}), BLOCK)

    def test_unrelated_variables_do_not_change_block(self):
        self.check(fw({"description": "var.description", "priority": "var.priority",
                       "target_tags": "var.tags"}), BLOCK)


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class GcpFirewallPassTest(unittest.TestCase):
    def check(self, src, expected=PASS):
        self.assertEqual(scan(src)[:2], expected)

    def test_office_range(self):
        self.check(fw({"source_ranges": '["203.0.113.0/24"]'}))

    def test_https_only(self):
        self.check(fw(allows=('protocol = "tcp"\n    ports = ["443"]',)))

    def test_range_without_admin_ports(self):
        self.check(fw(allows=('protocol = "tcp"\n    ports = ["1000-2000"]',)))

    def test_udp_22_is_not_ssh(self):
        self.check(fw(allows=('protocol = "udp"\n    ports = ["22"]',)))

    def test_icmp_only(self):
        self.check(fw(allows=('protocol = "icmp"',)))

    def test_egress(self):
        self.check(fw({"direction": '"EGRESS"', "source_ranges": None,
                       "destination_ranges": '["0.0.0.0/0"]'}))

    def test_disabled_true(self):
        self.check(fw({"disabled": "true"}))

    def test_deny_only(self):
        self.check(fw(allows=(), extra='  deny {\n    protocol = "tcp"\n    ports = ["22"]\n  }'))

    def test_deny_ssh_allow_https(self):
        self.check(fw(allows=('protocol = "tcp"\n    ports = ["443"]',),
                      extra='  deny {\n    protocol = "tcp"\n    ports = ["22"]\n  }'))

    def test_source_tags_only(self):
        self.check(fw({"source_ranges": None, "source_tags": '["bastion"]'}))

    def test_source_service_accounts_only(self):
        self.check(fw({"source_ranges": None,
                       "source_service_accounts": '["ci@project.iam.gserviceaccount.com"]'}))

    def test_source_tags_variable_only(self):
        # 태그는 IP 대역이 될 수 없으므로 값이 변수여도 인터넷 전체가 아님
        self.check(fw({"source_ranges": None, "source_tags": "var.tags"}))

    def test_office_range_and_tags(self):
        self.check(fw({"source_ranges": '["203.0.113.0/24"]', "source_tags": '["web"]'}))

    def test_variable_source_but_https(self):
        self.check(fw({"source_ranges": "var.ranges"},
                      allows=('protocol = "tcp"\n    ports = ["443"]',)))

    def test_variable_port_but_office_source(self):
        self.check(fw({"source_ranges": '["203.0.113.0/24"]'},
                      allows=('protocol = "tcp"\n    ports = [var.port]',)))

    def test_unrelated_variables_do_not_cause_review(self):
        # PR 3 Azure 오탐과 같은 유형: 판단과 무관한 변수는 결과에 영향이 없어야 함
        self.check(fw({"source_ranges": '["203.0.113.0/24"]', "description": "var.description",
                       "priority": "var.priority", "target_service_accounts": "var.targets"}))

    def test_variable_disabled_but_egress(self):
        self.check(fw({"direction": '"EGRESS"', "disabled": "var.off", "source_ranges": None}))


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class GcpFirewallReviewTest(unittest.TestCase):
    def check(self, src, expected=REVIEW):
        self.assertEqual(scan(src)[:2], expected)

    def test_variable_source_ranges_ssh(self):
        self.check(fw({"source_ranges": "var.ranges"}))

    def test_source_ranges_list_with_only_variable(self):
        self.check(fw({"source_ranges": '["10.0.0.0/8", var.extra]'}))

    def test_no_source_at_all(self):
        # 출발지 미지정: provider에 따라 오류이거나 GCP 기본값 0.0.0.0/0 → 안전하다고 가정하지 않음
        self.check(fw({"source_ranges": None}))

    def test_empty_source_ranges(self):
        self.check(fw({"source_ranges": "[]"}))

    def test_variable_direction(self):
        self.check(fw({"direction": "var.direction"}))

    def test_unknown_direction_value(self):
        self.check(fw({"direction": '"SIDEWAYS"'}))

    def test_variable_disabled(self):
        self.check(fw({"disabled": "var.disabled"}))

    def test_variable_protocol(self):
        self.check(fw(allows=('protocol = var.protocol',)))

    def test_variable_ports(self):
        self.check(fw(allows=('protocol = "tcp"\n    ports = var.ports',)))

    def test_reversed_port_range(self):
        self.check(fw(allows=('protocol = "tcp"\n    ports = ["30-20"]',)))

    def test_non_numeric_port(self):
        self.check(fw(allows=('protocol = "tcp"\n    ports = ["ssh"]',)))

    def test_whole_allow_variable(self):
        src = ('resource "google_compute_firewall" "f" {\n  name = "t"\n  network = "default"\n'
               '  source_ranges = ["0.0.0.0/0"]\n  allow = var.allows\n}\n')
        self.check(src)

    def test_dynamic_allow(self):
        self.check(fw(allows=(), extra='  dynamic "allow" {\n    for_each = var.rules\n'
                                       '    content {\n      protocol = allow.value.protocol\n    }\n  }'))

    def test_dynamic_allow_with_safe_static_allow(self):
        self.check(fw(allows=('protocol = "tcp"\n    ports = ["443"]',),
                      extra='  dynamic "allow" {\n    for_each = var.rules\n'
                            '    content {\n      protocol = allow.value.protocol\n    }\n  }'))

    def test_review_reason_names_unknown_items(self):
        _s, _r, findings, _d = scan(fw({"source_ranges": "var.ranges", "disabled": "var.off"}))
        self.assertEqual(len(findings), 1)
        self.assertIn("출발지", findings[0]["reason"])
        self.assertIn("disabled", findings[0]["reason"])


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class GcpFirewallRecordTest(unittest.TestCase):
    def test_metadata_and_checks_block(self):
        _s, _r, findings, data = scan(fw())
        self.assertEqual((findings[0]["cloud"], findings[0]["policy"], findings[0]["verdict"]),
                         ("gcp", "CG-NET-01", "BLOCK"))
        self.assertEqual(build_checks(data, findings),
                         [{"resource": "google_compute_firewall.f", "cloud": "gcp",
                           "policy": "CG-NET-01", "status": "BLOCK"}])

    def test_checks_record_pass_for_safe_firewall(self):
        _s, _r, findings, data = scan(fw({"source_ranges": '["203.0.113.0/24"]'}))
        self.assertEqual([c["status"] for c in build_checks(data, findings)], ["PASS"])

    def test_one_finding_per_firewall(self):
        _s, _r, findings, _d = scan(fw(allows=('protocol = "tcp"\n    ports = ["22"]',
                                                'protocol = "tcp"\n    ports = ["3389"]')))
        self.assertEqual(len(findings), 1)

    def test_existing_gcp_rules_still_work_together(self):
        src = fw() + ('resource "google_project_iam_member" "o" {\n  role = "roles/owner"\n'
                      '  member = "user:x@example.com"\n}\n')
        self.assertEqual(scan(src)[1], ["GCP_PROJECT_OWNER", "GCP_PUBLIC_ADMIN_PORT"])


if __name__ == "__main__":
    unittest.main()
