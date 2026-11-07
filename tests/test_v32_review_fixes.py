"""v3.2 교차 검토 지적 A·B·C 회귀 테스트 — v3.2.1.

A. UDP·ICMP 오탐: AWS 만 프로토콜과 상관없이 포트 범위로 판정해서 udp 22 공개, ICMP(from_port/to_port 가
   ICMP type·code 인데 0~255 처럼 22 를 '포함'하는 값)를 BLOCK 했다. Azure·GCP 는 TCP(와 전체 프로토콜)만
   관리자 포트로 본다 (tests/test_azure_nsg.py test_udp, tests/test_gcp_firewall.py test_udp_22_is_not_ssh·test_icmp_only).
   → AWS 도 tcp(6)·전체(-1/all)만. 같은 보안그룹 합산도 같은 기준.
B. 무관한 사설 규칙 BLOCK: 합산에서 '꼭 필요한 규칙'이 하나도 없을 때(겹치는 덮개) 그룹 전체를 표시하면서
   사설 대역(10.0.0.0/8 등)만 가진 규칙까지 BLOCK 했고, 사설 규칙이 0.0.0.0/0 의 빈틈을 메우는 경우에도 BLOCK 했다.
   → (v3.2.1) 사설·내부 전용 대역만 가진 규칙은 표시하지 않는다.
   → (v3.2.2) 사설 특별 취급 대신 일반 규칙: 최소 충분 집합(덮개)에 들어가는 규칙만 표시. 이미 덮인 대역은
     사설이든 아니든 표시하지 않고, 빈틈을 실제로 메우는 규칙은 사설이어도 표시한다.
C. 중복 REVIEW(BLOCK): 한 규칙이 22·3389 두 포트, 여러 대상 그룹, 개별 판정과 합산에서 같은 규칙 ID 를
   여러 번 받았다. → 규칙 하나에 같은 규칙 ID 는 한 번만 (사유는 합쳐서 하나).
실행: python -m unittest discover -s tests -v
"""
import io
import sys
import unittest
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from policy_gate import file_status, scan_configuration  # noqa: E402

try:
    import hcl2
except ImportError:  # pragma: no cover
    hcl2 = None

SG = 'resource "aws_security_group" "web" {\n  name = "web"\n}\n'
WEB = "aws_security_group.web.id"


def vpc(name, cidr, proto="tcp", from_port=22, to_port=22, sg=WEB, family=4):
    key = "cidr_ipv4" if family == 4 else "cidr_ipv6"
    ports = "" if proto == "-1" else f"  from_port = {from_port}\n  to_port = {to_port}\n"
    return (f'resource "aws_vpc_security_group_ingress_rule" "{name}" {{\n  security_group_id = {sg}\n'
            f'  ip_protocol = "{proto}"\n{ports}  {key} = "{cidr}"\n}}\n')


def sgr(name, cidrs, proto="tcp", from_port=22, to_port=22, sg=WEB, rule_type='"ingress"'):
    items = ", ".join(c if c.startswith("var.") else f'"{c}"' for c in cidrs)
    return (f'resource "aws_security_group_rule" "{name}" {{\n  type = {rule_type}\n  security_group_id = {sg}\n'
            f'  protocol = "{proto}"\n  from_port = {from_port}\n  to_port = {to_port}\n  cidr_blocks = [{items}]\n}}\n')


def inline(proto, from_port, to_port, cidr="0.0.0.0/0"):
    return (f'resource "aws_security_group" "t" {{\n  ingress {{\n    from_port = {from_port}\n    to_port = {to_port}\n'
            f'    protocol = "{proto}"\n    cidr_blocks = ["{cidr}"]\n  }}\n}}\n')


def scan(src):
    findings = scan_configuration(hcl2.load(io.StringIO(src)))
    return findings, file_status(findings)


def per_resource(findings):
    out = {}
    for f in findings:
        out.setdefault(f["resource"], set()).add(f["verdict"])
    return {ref: max(v, key=["PASS", "REVIEW", "BLOCK"].index) for ref, v in out.items()}


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class ProtocolTest(unittest.TestCase):
    """A. 관리자 포트는 TCP 22·3389 (와 전체 프로토콜). Azure·GCP 와 같은 기준."""

    def test_single_rule_protocols(self):
        cases = [
            ("udp 22", "udp", 22, 22, "PASS"),
            ("udp 3389", "udp", 3389, 3389, "PASS"),
            ("udp 0-65535", "udp", 0, 65535, "PASS"),
            ("프로토콜 번호 17(udp) 22", "17", 22, 22, "PASS"),
            ("icmp type 0~255 (22 를 '포함'하는 숫자)", "icmp", 0, 255, "PASS"),
            ("icmp 전체 -1/-1", "icmp", -1, -1, "PASS"),
            ("icmpv6 0~255", "icmpv6", 0, 255, "PASS"),
            ("프로토콜 번호 1(icmp) 0~255", "1", 0, 255, "PASS"),
            ("프로토콜 번호 50(ESP)", "50", 0, 65535, "PASS"),
            ("tcp 22", "tcp", 22, 22, "BLOCK"),
            ("TCP 대문자 3389", "TCP", 3389, 3389, "BLOCK"),
            ("프로토콜 번호 6(tcp) 22", "6", 22, 22, "BLOCK"),
            ("전체 프로토콜 -1", "-1", 0, 0, "BLOCK"),
            ("전체 프로토콜 all", "all", 0, 0, "BLOCK"),
        ]
        for title, proto, start, end, expected in cases:
            for form, src in (("인라인", inline(proto, start, end)),
                              ("security_group_rule", sgr("r", ["0.0.0.0/0"], proto, start, end)),
                              ("vpc ingress_rule", SG + vpc("r", "0.0.0.0/0", proto, start, end))):
                with self.subTest(title, form=form):
                    self.assertEqual(scan(src)[1], expected)

    def test_union_uses_same_protocol_rule(self):
        cases = [
            ("udp 절반 2개", vpc("a", "0.0.0.0/1", "udp") + vpc("b", "128.0.0.0/1", "udp"), "PASS"),
            ("icmp 0~255 절반 2개", vpc("a", "0.0.0.0/1", "icmp", 0, 255) + vpc("b", "128.0.0.0/1", "icmp", 0, 255), "PASS"),
            ("전체 프로토콜 절반 + udp 절반", vpc("a", "0.0.0.0/1", "-1") + vpc("b", "128.0.0.0/1", "udp"), "PASS"),
            ("전체 프로토콜 절반 + tcp 절반", vpc("a", "0.0.0.0/1", "-1") + vpc("b", "128.0.0.0/1", "tcp"), "BLOCK"),
            ("tcp 절반 + 프로토콜 번호 6 절반", vpc("a", "0.0.0.0/1", "tcp") + vpc("b", "128.0.0.0/1", "6"), "BLOCK"),
        ]
        for title, rules, expected in cases:
            with self.subTest(title):
                self.assertEqual(scan(SG + rules)[1], expected)

    def test_same_intent_same_verdict_across_clouds(self):
        """udp 22 공개·icmp 전체 공개 — 세 클라우드 모두 PASS."""
        azure = ('resource "azurerm_network_security_rule" "r" {{\n  name = "t"\n  direction = "Inbound"\n'
                 '  access = "Allow"\n  protocol = "{p}"\n  destination_port_range = "{port}"\n'
                 '  source_address_prefix = "*"\n}}\n')
        gcp = ('resource "google_compute_firewall" "f" {{\n  name = "t"\n  network = "d"\n'
               '  source_ranges = ["0.0.0.0/0"]\n  allow {{\n    protocol = "{p}"\n{ports}  }}\n}}\n')
        for title, srcs in {
            "udp 22": (inline("udp", 22, 22), azure.format(p="Udp", port="22"),
                       gcp.format(p="udp", ports='    ports = ["22"]\n')),
            "icmp 전체": (inline("icmp", -1, -1), azure.format(p="Icmp", port="*"), gcp.format(p="icmp", ports="")),
        }.items():
            with self.subTest(title):
                self.assertEqual([scan(s)[1] for s in srcs], ["PASS", "PASS", "PASS"])


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class PrivateRuleFlagTest(unittest.TestCase):
    """B. 사설·내부 전용 대역만 가진 규칙은 BLOCK 표시하지 않는다."""

    def test_overlapping_covers_do_not_drag_private_rule(self):
        # x·z 는 각각 0/1 을 포함, y·x·z 어느 둘을 합쳐도 전체 → 혼자 꼭 필요한 규칙이 없는 경우
        src = (SG + sgr("x", ["0.0.0.0/1", "128.0.0.0/2"]) + vpc("y", "128.0.0.0/1")
               + sgr("z", ["0.0.0.0/1", "192.0.0.0/2"]) + vpc("p", "10.0.0.0/8"))
        findings, status = scan(src)
        self.assertEqual(status, "BLOCK")
        per = per_resource(findings)
        self.assertNotIn("aws_vpc_security_group_ingress_rule.p", per)
        self.assertEqual(set(per), {"aws_security_group_rule.x", "aws_vpc_security_group_ingress_rule.y",
                                    "aws_security_group_rule.z"})

    def test_private_rule_filling_the_gap_is_part_of_the_witness(self):
        """v3.2.2 에서 기대값을 바꿈: 0.0.0.0/0 판단에서 10.0.0.0/8 이 빈틈을 실제로 메우면 그 규칙도 원인이다.
        (v3.2.1 은 사설 대역을 특별 취급해 빼서, 표시된 규칙만으로는 전체가 되지 않았다 — GPT 재검토 B 의 '충분한 증거 집합')"""
        public_except_10 = ["0.0.0.0/5", "8.0.0.0/7", "11.0.0.0/8", "12.0.0.0/6", "16.0.0.0/4",
                            "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1"]
        src = SG + sgr("x", public_except_10) + vpc("p", "10.0.0.0/8")
        findings, status = scan(src)
        self.assertEqual(status, "BLOCK")
        self.assertEqual(per_resource(findings), {"aws_security_group_rule.x": "BLOCK",
                                                  "aws_vpc_security_group_ingress_rule.p": "BLOCK"})

    def test_other_internal_ranges(self):
        for private in ("172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16"):
            with self.subTest(private):
                src = (SG + sgr("x", ["0.0.0.0/1", "128.0.0.0/2"]) + vpc("y", "128.0.0.0/1")
                       + sgr("z", ["0.0.0.0/1", "192.0.0.0/2"]) + vpc("p", private))
                self.assertNotIn("aws_vpc_security_group_ingress_rule.p", per_resource(scan(src)[0]))

    def test_ipv6_internal_range(self):
        """IPv6 겹치는 덮개 + ULA(fd00::/8) 규칙 — 혼자 꼭 필요한 규칙이 없어 사설 제외 기준이 실제로 쓰이는 경우."""
        v6 = lambda name, cidrs: sgr(name, cidrs).replace("cidr_blocks", "ipv6_cidr_blocks")  # noqa: E731
        src = (SG + v6("x", ["::/1", "8000::/2"]) + vpc("y", "8000::/1", family=6)
               + v6("z", ["::/1", "c000::/2"]) + vpc("p", "fd00::/8", family=6))
        per = per_resource(scan(src)[0])
        self.assertNotIn("aws_vpc_security_group_ingress_rule.p", per)
        self.assertEqual(set(per), {"aws_security_group_rule.x", "aws_vpc_security_group_ingress_rule.y",
                                    "aws_security_group_rule.z"})

    def test_public_redundant_rule_still_follows_v32_rule(self):
        """사설이 아닌 중복 규칙의 표시 기준은 v3.2 와 같다 (꼭 필요한 규칙만)."""
        src = SG + vpc("a", "0.0.0.0/1") + vpc("b", "128.0.0.0/1") + vpc("c", "10.0.0.0/8")
        self.assertEqual(set(per_resource(scan(src)[0])),
                         {"aws_vpc_security_group_ingress_rule.a", "aws_vpc_security_group_ingress_rule.b"})


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class NoDuplicateFindingTest(unittest.TestCase):
    """C. 자원 하나에 같은 규칙 ID 의 판정은 한 번만."""

    def assertNoDuplicates(self, findings):
        counts = Counter((f["resource"], f["rule"]) for f in findings)
        self.assertEqual({k: v for k, v in counts.items() if v > 1}, {})

    def test_both_admin_ports_one_review(self):
        src = SG + vpc("a", "0.0.0.0/1", from_port=20, to_port=4000) + vpc("b", "128.0.0.0/1", from_port=20,
                                                                           to_port=4000, sg="var.sg")
        findings, status = scan(src)
        self.assertEqual(status, "REVIEW")
        self.assertNoDuplicates(findings)
        reason = [f["reason"] for f in findings if f["resource"].endswith(".a")][0]
        self.assertIn("22", reason)
        self.assertIn("3389", reason)

    def test_both_admin_ports_one_block(self):
        src = SG + vpc("a", "0.0.0.0/1", from_port=20, to_port=4000) + vpc("b", "128.0.0.0/1", from_port=20,
                                                                           to_port=4000)
        findings, status = scan(src)
        self.assertEqual(status, "BLOCK")
        self.assertNoDuplicates(findings)
        self.assertEqual(len(findings), 2)

    def test_several_unknown_groups_one_review(self):
        src = SG + vpc("a", "0.0.0.0/1") + vpc("b", "128.0.0.0/1", sg="var.s1") + vpc("c", "0.0.0.0/1", sg="var.s2")
        findings, status = scan(src)
        self.assertEqual(status, "REVIEW")
        self.assertNoDuplicates(findings)
        self.assertEqual(len(findings), 3)

    def test_individual_review_and_union_review_once(self):
        """출발지 일부가 변수라 이미 REVIEW 인 규칙에 합산 REVIEW 를 또 붙이지 않는다."""
        src = SG + vpc("a", "0.0.0.0/1") + sgr("u", ["128.0.0.0/1", "var.extra"], sg="var.sg")
        findings, _ = scan(src)
        self.assertNoDuplicates(findings)

    def test_union_context_skips_rule_already_public_alone(self):
        """혼자 이미 0.0.0.0/0 인 규칙이 있으면 합산 계산 자체가 그 묶음을 건너뛴다 (합산 결과에 남지 않음)."""
        from policy_gate import make_aws_context
        data = hcl2.load(io.StringIO(SG + vpc("a", "0.0.0.0/0") + vpc("b", "10.0.0.0/8") + vpc("c", "8.8.8.0/24")))
        self.assertEqual(make_aws_context([data])["union"], {})

    def test_ipv4_and_ipv6_union_one_block(self):
        src = (SG + vpc("a", "0.0.0.0/1") + vpc("b", "128.0.0.0/1")
               + sgr("c", ["0.0.0.0/1"]).replace("cidr_blocks", "ipv6_cidr_blocks").replace('"0.0.0.0/1"', '"::/1"')
               + vpc("d", "8000::/1", family=6))
        findings, status = scan(src)
        self.assertEqual(status, "BLOCK")
        self.assertNoDuplicates(findings)

    def test_block_and_review_for_same_rule_keeps_block_only(self):
        """규칙 a 가 22번에서는 확정 BLOCK, 3389번에서는 대상 불명 규칙과 합쳐 REVIEW → BLOCK 하나만."""
        src = (SG + vpc("a", "0.0.0.0/1", from_port=20, to_port=4000) + vpc("b", "128.0.0.0/1")
               + vpc("c", "128.0.0.0/1", from_port=3389, to_port=3389, sg="var.sg"))
        findings, _ = scan(src)
        verdicts = {f["resource"]: f["verdict"] for f in findings}
        self.assertEqual(verdicts["aws_vpc_security_group_ingress_rule.a"], "BLOCK")
        self.assertNoDuplicates(findings)
        self.assertEqual(sum(1 for f in findings if f["resource"].endswith(".a")), 1)


if __name__ == "__main__":
    unittest.main()
