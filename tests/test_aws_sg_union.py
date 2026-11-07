"""같은 보안그룹의 여러 인바운드 규칙을 합친 출발지 판단 — v3.2 (CG-NET-01, AWS).

AWS 보안그룹 규칙은 허용(allow)만 있고 거부가 없어서, 같은 보안그룹에 붙은 규칙들의 출발지를
합친 것이 그 보안그룹의 실제 공개 범위다. 그래서 규칙 하나하나는 인터넷 절반이라도
둘이 합쳐 인터넷 전체가 되면 위반이다. aws_vpc_security_group_ingress_rule 은 규칙 하나에
출발지를 하나만 쓸 수 있어서, 분할 공개는 여러 리소스를 합쳐야만 보인다.

오탐을 막기 위해 다음이 모두 같을 때만 합친다.
  - 대상 보안그룹: 같은 aws_security_group 리소스(인라인 규칙 / .id 참조) 또는 같은 리터럴 sg ID
  - 방향: 인바운드
  - 포트: 같은 관리자 포트(22 또는 3389)를 확실히 포함
  - 프로토콜: 같은 프로토콜 (전체 프로토콜 -1 은 모든 프로토콜과 합침)
  - IP 종류: IPv4 끼리, IPv6 끼리
  - 같은 폴더(Terraform 모듈)
대상·방향·포트·프로토콜을 확인할 수 없는 규칙이 섞여야만 전체가 되면 REVIEW.
Azure·GCP 는 거부 규칙과 우선순위가 있어 규칙끼리 합치지 않는다 (한 규칙 안의 목록만 합침).
실행: python -m unittest discover -s tests -v
"""
import io
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from policy_gate import file_status, scan_configuration, scan_paths  # noqa: E402

try:
    import hcl2
except ImportError:  # pragma: no cover
    hcl2 = None

SG = 'resource "aws_security_group" "{name}" {{\n  name = "{name}"\n{inner}}}\n'


def inline(cidr, port=22, proto="tcp", direction="ingress", key="cidr_blocks", to_port=None):
    return (f'  {direction} {{\n    from_port = {port}\n    to_port = {to_port or port}\n'
            f'    protocol = "{proto}"\n    {key} = ["{cidr}"]\n  }}\n')


def vpc_rule(name, sg, cidr, port=22, proto="tcp", family=4, to_port=None):
    key = "cidr_ipv4" if family == 4 else "cidr_ipv6"
    ports = "" if proto == "-1" else f"  from_port = {port}\n  to_port = {to_port or port}\n"
    return (f'resource "aws_vpc_security_group_ingress_rule" "{name}" {{\n  security_group_id = {sg}\n'
            f'  ip_protocol = "{proto}"\n{ports}  {key} = "{cidr}"\n}}\n')


def sg_rule(name, sg, cidr, port=22, proto="tcp", rule_type='"ingress"', to_port=None):
    return (f'resource "aws_security_group_rule" "{name}" {{\n  type = {rule_type}\n  security_group_id = {sg}\n'
            f'  protocol = "{proto}"\n  from_port = {port}\n  to_port = {to_port or port}\n'
            f'  cidr_blocks = ["{cidr}"]\n}}\n')


WEB = "aws_security_group.web.id"
DB = "aws_security_group.db.id"
EMPTY_WEB = SG.format(name="web", inner="")
EMPTY_DB = SG.format(name="db", inner="")


def scan_text(src):
    """한 파일로 검사 → {자원: 그 자원의 판정}."""
    findings = scan_configuration(hcl2.load(io.StringIO(src)))
    per = {}
    for f in findings:
        per.setdefault(f["resource"], set()).add(f["verdict"])
    return {ref: max(v, key=["PASS", "REVIEW", "BLOCK"].index) for ref, v in per.items()}, file_status(findings)


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class SameSecurityGroupTest(unittest.TestCase):
    def assertVerdicts(self, src, expected_per_resource, expected_file):
        per, status = scan_text(src)
        self.assertEqual(per, expected_per_resource)
        self.assertEqual(status, expected_file)

    # --- 합쳐서 인터넷 전체 → BLOCK ---
    def test_two_vpc_rules_halves(self):
        src = EMPTY_WEB + vpc_rule("a", WEB, "0.0.0.0/1") + vpc_rule("b", WEB, "128.0.0.0/1")
        self.assertVerdicts(src, {"aws_vpc_security_group_ingress_rule.a": "BLOCK",
                                  "aws_vpc_security_group_ingress_rule.b": "BLOCK"}, "BLOCK")

    def test_two_security_group_rules_halves(self):
        src = EMPTY_WEB + sg_rule("a", WEB, "0.0.0.0/1") + sg_rule("b", WEB, "128.0.0.0/1")
        self.assertVerdicts(src, {"aws_security_group_rule.a": "BLOCK",
                                  "aws_security_group_rule.b": "BLOCK"}, "BLOCK")

    def test_two_inline_blocks_in_one_group(self):
        src = SG.format(name="web", inner=inline("0.0.0.0/1") + inline("128.0.0.0/1"))
        self.assertVerdicts(src, {"aws_security_group.web": "BLOCK"}, "BLOCK")

    def test_inline_block_plus_separate_rule(self):
        src = SG.format(name="web", inner=inline("0.0.0.0/1")) + vpc_rule("b", WEB, "128.0.0.0/1")
        self.assertVerdicts(src, {"aws_security_group.web": "BLOCK",
                                  "aws_vpc_security_group_ingress_rule.b": "BLOCK"}, "BLOCK")

    def test_same_literal_group_id(self):
        src = vpc_rule("a", '"sg-0abc"', "0.0.0.0/1") + sg_rule("b", '"sg-0abc"', "128.0.0.0/1")
        self.assertVerdicts(src, {"aws_vpc_security_group_ingress_rule.a": "BLOCK",
                                  "aws_security_group_rule.b": "BLOCK"}, "BLOCK")

    def test_rdp_halves(self):
        src = EMPTY_WEB + vpc_rule("a", WEB, "0.0.0.0/1", port=3389) + vpc_rule("b", WEB, "128.0.0.0/1", port=3389)
        self.assertEqual(scan_text(src)[1], "BLOCK")

    def test_ipv6_halves(self):
        src = EMPTY_WEB + vpc_rule("a", WEB, "::/1", family=6) + vpc_rule("b", WEB, "8000::/1", family=6)
        self.assertEqual(scan_text(src)[1], "BLOCK")

    def test_overlapping_port_ranges_both_contain_22(self):
        src = EMPTY_WEB + vpc_rule("a", WEB, "0.0.0.0/1", port=20, to_port=30) + vpc_rule("b", WEB, "128.0.0.0/1")
        self.assertEqual(scan_text(src)[1], "BLOCK")

    def test_all_protocols_joins_tcp(self):
        src = EMPTY_WEB + vpc_rule("a", WEB, "0.0.0.0/1", proto="-1") + vpc_rule("b", WEB, "128.0.0.0/1")
        self.assertEqual(scan_text(src)[1], "BLOCK")

    def test_three_pieces(self):
        src = (EMPTY_WEB + vpc_rule("a", WEB, "0.0.0.0/2") + vpc_rule("b", WEB, "64.0.0.0/2")
               + vpc_rule("c", WEB, "128.0.0.0/1"))
        self.assertEqual(set(scan_text(src)[0].values()), {"BLOCK"})

    # --- 합치면 안 되는 경우 → PASS (오탐 방지) ---
    def test_different_groups(self):
        src = EMPTY_WEB + EMPTY_DB + vpc_rule("a", WEB, "0.0.0.0/1") + vpc_rule("b", DB, "128.0.0.0/1")
        self.assertVerdicts(src, {}, "PASS")

    def test_different_literal_ids(self):
        src = vpc_rule("a", '"sg-1"', "0.0.0.0/1") + vpc_rule("b", '"sg-2"', "128.0.0.0/1")
        self.assertVerdicts(src, {}, "PASS")

    def test_different_admin_ports(self):
        src = EMPTY_WEB + vpc_rule("a", WEB, "0.0.0.0/1", port=22) + vpc_rule("b", WEB, "128.0.0.0/1", port=3389)
        self.assertVerdicts(src, {}, "PASS")

    def test_one_half_on_non_admin_port(self):
        src = EMPTY_WEB + vpc_rule("a", WEB, "0.0.0.0/1", port=22) + vpc_rule("b", WEB, "128.0.0.0/1", port=443)
        self.assertVerdicts(src, {}, "PASS")

    def test_tcp_and_udp_are_not_joined(self):
        src = EMPTY_WEB + vpc_rule("a", WEB, "0.0.0.0/1", proto="tcp") + vpc_rule("b", WEB, "128.0.0.0/1", proto="udp")
        self.assertVerdicts(src, {}, "PASS")

    def test_ipv4_half_and_ipv6_half(self):
        src = EMPTY_WEB + vpc_rule("a", WEB, "0.0.0.0/1") + vpc_rule("b", WEB, "8000::/1", family=6)
        self.assertVerdicts(src, {}, "PASS")

    def test_egress_half_is_not_joined(self):
        src = SG.format(name="web", inner=inline("0.0.0.0/1") + inline("128.0.0.0/1", direction="egress"))
        self.assertVerdicts(src, {}, "PASS")

    def test_security_group_rule_egress_not_joined(self):
        src = EMPTY_WEB + sg_rule("a", WEB, "0.0.0.0/1") + sg_rule("b", WEB, "128.0.0.0/1", rule_type='"egress"')
        self.assertVerdicts(src, {}, "PASS")

    def test_gap_remains(self):
        src = EMPTY_WEB + vpc_rule("a", WEB, "0.0.0.0/1") + vpc_rule("b", WEB, "128.0.0.0/2")
        self.assertVerdicts(src, {}, "PASS")

    def test_literal_id_and_reference_are_not_joined(self):
        """리터럴 sg ID 와 Terraform 이 만드는 보안그룹 참조는 같은 그룹인지 알 수 없어 합치지 않음 (알려진 한계)."""
        src = EMPTY_WEB + vpc_rule("a", '"sg-0abc"', "0.0.0.0/1") + vpc_rule("b", WEB, "128.0.0.0/1")
        self.assertVerdicts(src, {}, "PASS")

    # --- 표시 범위: 꼭 필요한 규칙만 BLOCK ---
    def test_redundant_private_rule_is_not_flagged(self):
        src = (EMPTY_WEB + vpc_rule("a", WEB, "0.0.0.0/1") + vpc_rule("b", WEB, "128.0.0.0/1")
               + vpc_rule("c", WEB, "10.0.0.0/8"))
        per, status = scan_text(src)
        self.assertEqual(status, "BLOCK")
        self.assertNotIn("aws_vpc_security_group_ingress_rule.c", per)

    def test_duplicate_halves_are_all_flagged(self):
        src = (EMPTY_WEB + vpc_rule("a", WEB, "0.0.0.0/1") + vpc_rule("a2", WEB, "0.0.0.0/1")
               + vpc_rule("b", WEB, "128.0.0.0/1"))
        per, _ = scan_text(src)
        self.assertEqual(per, {f"aws_vpc_security_group_ingress_rule.{n}": "BLOCK" for n in ("a", "a2", "b")})

    def test_rule_already_public_alone_does_not_drag_others(self):
        """0.0.0.0/0 규칙이 이미 혼자 BLOCK 이면, 같은 그룹의 사설 대역 규칙까지 BLOCK 하지 않는다."""
        src = EMPTY_WEB + vpc_rule("a", WEB, "0.0.0.0/0") + vpc_rule("b", WEB, "10.0.0.0/8")
        per, _ = scan_text(src)
        self.assertEqual(per, {"aws_vpc_security_group_ingress_rule.a": "BLOCK"})
        findings = scan_configuration(hcl2.load(io.StringIO(src)))
        self.assertEqual(len(findings), 1)          # 합산 사유가 덧붙지 않고 기존 판정 하나만
        self.assertNotIn("합치면", findings[0]["reason"])

    def test_union_reason_names_the_group_and_port(self):
        src = EMPTY_WEB + vpc_rule("a", WEB, "0.0.0.0/1") + vpc_rule("b", WEB, "128.0.0.0/1")
        findings = scan_configuration(hcl2.load(io.StringIO(src)))
        reasons = [f["reason"] for f in findings if f["resource"].endswith(".a")]
        self.assertTrue(any("aws_security_group.web" in r and "22" in r for r in reasons), reasons)
        self.assertEqual({f["rule"] for f in findings}, {"AWS_PUBLIC_ADMIN_PORT"})

    # --- 확인할 수 없는 값이 섞여야만 전체 → REVIEW ---
    def test_unknown_target_completes_coverage(self):
        src = EMPTY_WEB + vpc_rule("a", WEB, "0.0.0.0/1") + vpc_rule("b", "var.sg_id", "128.0.0.0/1")
        self.assertVerdicts(src, {"aws_vpc_security_group_ingress_rule.a": "REVIEW",
                                  "aws_vpc_security_group_ingress_rule.b": "REVIEW"}, "REVIEW")

    def test_two_unknown_targets(self):
        src = vpc_rule("a", "var.sg_a", "0.0.0.0/1") + vpc_rule("b", "data.aws_security_group.x.id", "128.0.0.0/1")
        self.assertEqual(scan_text(src)[1], "REVIEW")

    def test_unknown_port_completes_coverage(self):
        src = EMPTY_WEB + vpc_rule("a", WEB, "0.0.0.0/1") + vpc_rule("b", WEB, "128.0.0.0/1", port="var.p")
        self.assertEqual(scan_text(src)[1], "REVIEW")

    def test_unknown_direction_completes_coverage(self):
        src = EMPTY_WEB + sg_rule("a", WEB, "0.0.0.0/1") + sg_rule("b", WEB, "128.0.0.0/1", rule_type="var.t")
        self.assertEqual(scan_text(src)[1], "REVIEW")

    def test_unknown_protocol_completes_coverage(self):
        src = (EMPTY_WEB + vpc_rule("a", WEB, "0.0.0.0/1")
               + 'resource "aws_vpc_security_group_ingress_rule" "b" {\n  security_group_id = aws_security_group.web.id\n'
                 '  ip_protocol = var.proto\n  from_port = 22\n  to_port = 22\n  cidr_ipv4 = "128.0.0.0/1"\n}\n')
        self.assertEqual(scan_text(src)[1], "REVIEW")

    def test_unknown_target_but_cannot_complete(self):
        src = EMPTY_WEB + vpc_rule("a", WEB, "0.0.0.0/1") + vpc_rule("b", "var.sg_id", "10.0.0.0/8")
        self.assertVerdicts(src, {}, "PASS")

    def test_unknown_target_on_other_port_is_not_review(self):
        src = EMPTY_WEB + vpc_rule("a", WEB, "0.0.0.0/1") + vpc_rule("b", "var.sg_id", "128.0.0.0/1", port=443)
        self.assertVerdicts(src, {}, "PASS")

    def test_definite_block_wins_over_unknown(self):
        src = (EMPTY_WEB + vpc_rule("a", WEB, "0.0.0.0/1") + vpc_rule("b", WEB, "128.0.0.0/1")
               + vpc_rule("c", "var.sg_id", "10.0.0.0/8"))
        per, status = scan_text(src)
        self.assertEqual(status, "BLOCK")
        self.assertNotIn("aws_vpc_security_group_ingress_rule.c", per)


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class FolderBoundaryTest(unittest.TestCase):
    """GitHub Actions 게이트와 같은 scan_paths() 경로. 같은 폴더(모듈)의 다른 파일끼리만 합친다."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def statuses(self):
        return {str(Path(r["file"]).relative_to(self.root)).replace("\\", "/"): r["status"]
                for r in scan_paths(sorted(self.root.rglob("*.tf")))}

    def test_rules_in_two_files_of_same_folder(self):
        self.write("net/sg.tf", EMPTY_WEB)
        self.write("net/a.tf", vpc_rule("a", WEB, "0.0.0.0/1"))
        self.write("net/b.tf", vpc_rule("b", WEB, "128.0.0.0/1"))
        self.assertEqual(self.statuses(), {"net/sg.tf": "PASS", "net/a.tf": "BLOCK", "net/b.tf": "BLOCK"})

    def test_same_names_in_different_folders_are_not_joined(self):
        self.write("one/main.tf", EMPTY_WEB + vpc_rule("a", WEB, "0.0.0.0/1"))
        self.write("two/main.tf", EMPTY_WEB + vpc_rule("b", WEB, "128.0.0.0/1"))
        self.assertEqual(set(self.statuses().values()), {"PASS"})

    def test_same_literal_id_in_different_folders_is_review(self):
        """다른 루트 모듈이 같은 기존 보안그룹(리터럴 sg ID)에 규칙을 나눠 다는 경우.
        같은 계정·리전인지 정적으로 알 수 없으므로 BLOCK 이 아니라 REVIEW."""
        self.write("one/main.tf", vpc_rule("a", '"sg-0abc"', "0.0.0.0/1"))
        self.write("two/main.tf", vpc_rule("b", '"sg-0abc"', "128.0.0.0/1"))
        self.assertEqual(self.statuses(), {"one/main.tf": "REVIEW", "two/main.tf": "REVIEW"})

    def test_different_literal_ids_in_different_folders(self):
        self.write("one/main.tf", vpc_rule("a", '"sg-1"', "0.0.0.0/1"))
        self.write("two/main.tf", vpc_rule("b", '"sg-2"', "128.0.0.0/1"))
        self.assertEqual(set(self.statuses().values()), {"PASS"})


if __name__ == "__main__":
    unittest.main()
