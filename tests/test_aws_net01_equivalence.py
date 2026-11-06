"""AWS CG-NET-01 표현 방식 동등성 테스트 — v3.1.

같은 보안그룹 인바운드 규칙을 Terraform으로 쓰는 4가지 방법에서 같은 판정이 나오는지 확인한다.
  1) aws_security_group 의 ingress 블록          (인라인 블록)
  2) aws_security_group 의 ingress = [{ ... }]    (인라인 속성 문법)
  3) aws_vpc_security_group_ingress_rule          (별도 규칙, 권장 방식)
  4) aws_security_group_rule (type = "ingress")   (별도 규칙, 예전 방식)  ← v3.1 이전에는 검사하지 않아 조용한 PASS

나가는 방향(egress)은 CG-NET-01(인터넷 → 관리자 포트 인바운드 공개 금지) 범위 밖이므로
어느 표현이든 PASS 여야 한다. 방향을 알 수 없으면 REVIEW.
실행: python -m unittest discover -s tests -v
"""
import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from policy_gate import (build_checks, file_status, policy_support_resources,  # noqa: E402
                         scan_configuration)

try:
    import hcl2
except ImportError:  # pragma: no cover
    hcl2 = None

V4_PUBLIC, V6_PUBLIC = "0.0.0.0/0", "::/0"
V4_SAFE, V6_SAFE = "203.0.113.0/24", "2001:db8::/32"
VAR = "var.x"


def lit(value):
    """var.x 는 그대로(표현식), 나머지는 따옴표 문자열/숫자."""
    if value == VAR or isinstance(value, int):
        return str(value)
    return f'"{value}"'


def fields(case, *, single_cidr, proto_key, ports_for_all):
    """case → [(속성 이름, HCL 값)]."""
    proto, ports, (family, cidr) = case
    out = [(proto_key, lit(proto))]
    if proto != "-1" or ports_for_all:
        start, end = ports if proto != "-1" else (0, 0)
        out += [("from_port", lit(start)), ("to_port", lit(end))]
    if single_cidr:
        out.append(("cidr_ipv4" if family == 4 else "cidr_ipv6", lit(cidr)))
    else:
        key = "cidr_blocks" if family == 4 else "ipv6_cidr_blocks"
        out.append((key, lit(cidr) if cidr == VAR else f"[{lit(cidr)}]"))
    return out


def body(pairs, indent="  "):
    return "\n".join(f"{indent}{k} = {v}" for k, v in pairs)


def inline_block(case, direction="ingress"):
    pairs = fields(case, single_cidr=False, proto_key="protocol", ports_for_all=True)
    return f'resource "aws_security_group" "t" {{\n  {direction} {{\n{body(pairs, "    ")}\n  }}\n}}\n'


def inline_attr(case, direction="ingress"):
    pairs = fields(case, single_cidr=False, proto_key="protocol", ports_for_all=True)
    return f'resource "aws_security_group" "t" {{\n  {direction} = [{{\n{body(pairs, "    ")}\n  }}]\n}}\n'


def vpc_rule(case, direction="ingress"):
    pairs = fields(case, single_cidr=True, proto_key="ip_protocol", ports_for_all=False)
    pairs.append(("security_group_id", '"sg-123"'))
    return f'resource "aws_vpc_security_group_{direction}_rule" "t" {{\n{body(pairs)}\n}}\n'


def sg_rule(case, direction="ingress"):
    pairs = [("type", lit(direction))] + fields(case, single_cidr=False, proto_key="protocol",
                                                 ports_for_all=True)
    pairs.append(("security_group_id", '"sg-123"'))
    return f'resource "aws_security_group_rule" "t" {{\n{body(pairs)}\n}}\n'


FORMS = {
    "ingress 블록": inline_block,
    "ingress = [{...}]": inline_attr,
    "aws_vpc_security_group_ingress_rule": vpc_rule,
    "aws_security_group_rule": sg_rule,
}

# (설명, (프로토콜, (시작 포트, 끝 포트), (IP 종류, 출발지)), 기대 판정)
CASES = [
    ("IPv4 공개 + SSH 22", ("tcp", (22, 22), (4, V4_PUBLIC)), "BLOCK"),
    ("IPv6 공개 + SSH 22", ("tcp", (22, 22), (6, V6_PUBLIC)), "BLOCK"),
    ("IPv4 공개 + RDP 3389", ("tcp", (3389, 3389), (4, V4_PUBLIC)), "BLOCK"),
    ("IPv6 공개 + RDP 3389", ("tcp", (3389, 3389), (6, V6_PUBLIC)), "BLOCK"),
    ("IPv4 회사 대역 + 22", ("tcp", (22, 22), (4, V4_SAFE)), "PASS"),
    ("IPv6 회사 대역 + 22", ("tcp", (22, 22), (6, V6_SAFE)), "PASS"),
    ("IPv4 공개 + 443", ("tcp", (443, 443), (4, V4_PUBLIC)), "PASS"),
    ("IPv6 공개 + 443", ("tcp", (443, 443), (6, V6_PUBLIC)), "PASS"),
    ("IPv4 공개 + 포트 범위 20-30 (22 포함)", ("tcp", (20, 30), (4, V4_PUBLIC)), "BLOCK"),
    ("IPv6 공개 + 포트 범위 3000-4000 (3389 포함)", ("tcp", (3000, 4000), (6, V6_PUBLIC)), "BLOCK"),
    ("IPv4 공개 + 전체 포트 0-65535", ("tcp", (0, 65535), (4, V4_PUBLIC)), "BLOCK"),
    ("IPv4 공개 + 23-3388 (둘 다 제외)", ("tcp", (23, 3388), (4, V4_PUBLIC)), "PASS"),
    ("IPv4 공개 + 전체 프로토콜 -1", ("-1", None, (4, V4_PUBLIC)), "BLOCK"),
    ("IPv6 공개 + 전체 프로토콜 -1", ("-1", None, (6, V6_PUBLIC)), "BLOCK"),
    ("IPv4 회사 대역 + 전체 프로토콜 -1", ("-1", None, (4, V4_SAFE)), "PASS"),
    ("IPv4 출발지 변수 + 22", ("tcp", (22, 22), (4, VAR)), "REVIEW"),
    ("IPv6 출발지 변수 + 22", ("tcp", (22, 22), (6, VAR)), "REVIEW"),
    ("출발지 변수 + 443 (관리자 포트 아님)", ("tcp", (443, 443), (4, VAR)), "PASS"),
    ("IPv4 공개 + 포트 변수", ("tcp", (VAR, VAR), (4, V4_PUBLIC)), "REVIEW"),
    ("회사 대역 + 포트 변수 (공개 아님)", ("tcp", (VAR, VAR), (4, V4_SAFE)), "PASS"),
    ("IPv4 공개 + 프로토콜 변수 + 443", (VAR, (443, 443), (4, V4_PUBLIC)), "REVIEW"),
    ("출발지 변수 + 전체 프로토콜 -1", ("-1", None, (4, VAR)), "REVIEW"),
]

RULE_OF = {"BLOCK": {"AWS_PUBLIC_ADMIN_PORT"}, "REVIEW": {"AWS_ADMIN_PORT_UNRESOLVED"}, "PASS": set()}


def scan(src):
    data = hcl2.load(io.StringIO(src))
    findings = scan_configuration(data)
    return data, findings, file_status(findings)


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class IngressEquivalenceTest(unittest.TestCase):
    def test_same_verdict_in_every_form(self):
        for title, case, expected in CASES:
            for form, render in FORMS.items():
                with self.subTest(case=title, form=form):
                    data, findings, status = scan(render(case))
                    self.assertEqual(status, expected)
                    self.assertEqual({f["rule"] for f in findings}, RULE_OF[expected])
                    self.assertTrue(all(f["policy"] == "CG-NET-01" for f in findings))

    def test_every_ingress_form_is_recorded_as_checked(self):
        """checks 에 기록되지 않으면 지원 행렬에서 'N/A(대상 없음)'로 보여 조용한 PASS 가 된다."""
        case = ("tcp", (22, 22), (4, V4_SAFE))
        for form, render in FORMS.items():
            with self.subTest(form=form):
                data, findings, _ = scan(render(case))
                checks = [c for c in build_checks(data, findings) if c["policy"] == "CG-NET-01"]
                self.assertEqual(len(checks), 1)
                self.assertEqual((checks[0]["cloud"], checks[0]["status"]), ("aws", "PASS"))

    def test_support_matrix_lists_security_group_rule(self):
        self.assertIn("aws_security_group_rule", policy_support_resources("CG-NET-01", "aws"))


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class EgressOutOfScopeTest(unittest.TestCase):
    """나가는 방향은 CG-NET-01 대상이 아니다 — 어느 표현이든 공개 22번이어도 PASS."""
    EGRESS_FORMS = {
        "egress 블록": inline_block,
        "egress = [{...}]": inline_attr,
        "aws_vpc_security_group_egress_rule": vpc_rule,
        "aws_security_group_rule (type=egress)": sg_rule,
    }

    def test_egress_is_pass_in_every_form(self):
        for title, case, _ in CASES:
            for form, render in self.EGRESS_FORMS.items():
                with self.subTest(case=title, form=form):
                    self.assertEqual(scan(render(case, "egress"))[2], "PASS")


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class DirectionAndOpaqueTest(unittest.TestCase):
    PUBLIC_22 = ("tcp", (22, 22), (4, V4_PUBLIC))
    SAFE_22 = ("tcp", (22, 22), (4, V4_SAFE))

    def rule_with_type(self, type_line, case):
        pairs = fields(case, single_cidr=False, proto_key="protocol", ports_for_all=True)
        return (f'resource "aws_security_group_rule" "t" {{\n{type_line}\n{body(pairs)}\n'
                f'  security_group_id = "sg-123"\n}}\n')

    def test_security_group_rule_direction(self):
        cases = [
            ("type 변수 + 공개 22 → 방향 불명이라 REVIEW", '  type = var.t', self.PUBLIC_22, "REVIEW"),
            ("type 변수 + 회사 대역 22 → 어느 방향이든 안전", '  type = var.t', self.SAFE_22, "PASS"),
            ("type 생략 + 공개 22 → REVIEW", "", self.PUBLIC_22, "REVIEW"),
            ("type 알 수 없는 값 + 공개 22 → REVIEW", '  type = "sideways"', self.PUBLIC_22, "REVIEW"),
            ("type = ingress (대문자) + 공개 22 → BLOCK", '  type = "INGRESS"', self.PUBLIC_22, "BLOCK"),
        ]
        for title, type_line, case, expected in cases:
            with self.subTest(title):
                self.assertEqual(scan(self.rule_with_type(type_line, case))[2], expected)

    def test_inline_rules_that_cannot_be_read_are_review(self):
        """인라인 규칙 목록 전체가 변수·for 식·dynamic 이면 내용을 볼 수 없으므로 REVIEW (조용한 PASS 금지)."""
        sg = 'resource "aws_security_group" "t" {{\n{}\n}}\n'
        cases = [
            ("ingress = var.rules", "  ingress = var.rules", "REVIEW"),
            ("ingress = [for ...]", "  ingress = [for r in var.rules : { from_port = r }]", "REVIEW"),
            ("dynamic \"ingress\"", '  dynamic "ingress" {\n    for_each = var.r\n    content {\n'
                                    '      from_port = ingress.value\n    }\n  }', "REVIEW"),
            ("ingress = [] (규칙 없음)", "  ingress = []", "PASS"),
            ("dynamic \"egress\" 만 있음 (범위 밖)", '  dynamic "egress" {\n    for_each = var.r\n'
                                                   '    content {\n      from_port = egress.value\n    }\n  }', "PASS"),
            ("egress = var.rules 만 있음 (범위 밖)", "  egress = var.rules", "PASS"),
        ]
        for title, inner, expected in cases:
            with self.subTest(title):
                data, findings, status = scan(sg.format(inner))
                self.assertEqual(status, expected)
                if expected == "REVIEW":
                    self.assertEqual({f["rule"] for f in findings}, {"AWS_ADMIN_PORT_UNRESOLVED"})

    def test_readable_block_still_blocks_next_to_dynamic(self):
        """읽을 수 있는 공개 22번 블록이 있으면 dynamic 이 함께 있어도 BLOCK 이 우선."""
        src = ('resource "aws_security_group" "t" {\n  ingress {\n    from_port = 22\n    to_port = 22\n'
               '    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n'
               '  dynamic "ingress" {\n    for_each = var.r\n    content {\n      from_port = 1\n    }\n  }\n}\n')
        self.assertEqual(scan(src)[2], "BLOCK")


if __name__ == "__main__":
    unittest.main()
