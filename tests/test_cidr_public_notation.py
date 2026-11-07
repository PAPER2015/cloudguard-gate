"""인터넷 전체 출발지의 다른 표기와 한 규칙 안의 분할 대역 — v3.2 (CG-NET-01, AWS·Azure·GCP).

v3.1 까지는 출발지 문자열이 정확히 "0.0.0.0/0" 또는 "::/0" 일 때만 인터넷 전체로 봤다.
같은 대역의 다른 표기(0::/0 등)나, 한 규칙의 목록 안에서 대역을 쪼개 전체를 덮는 경우
(["0.0.0.0/1", "128.0.0.0/1"])는 PASS 였다.

한 규칙(블록 하나·리소스 하나)의 출발지 목록은 대상·방향·프로토콜·포트가 모두 같으므로
합쳐서 판단해도 오탐이 생기지 않는다. 여러 규칙을 합치는 판단은 tests/test_aws_sg_union.py.

AWS provider 가 받아들이는 표기는 review/aws_cidr_oracle (terraform-provider-aws 의 CIDR 검증 함수를
그대로 옮긴 Go 프로그램)로 확인한 결과를 아래 PROVIDER 열에 적었다. AWS EC2 API 의 실제 수용 여부는 확인하지 않았다.
실행: python -m unittest discover -s tests -v
"""
import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from policy_gate import file_status, scan_configuration  # noqa: E402

try:
    import hcl2
except ImportError:  # pragma: no cover
    hcl2 = None


def status_rules(src):
    findings = scan_configuration(hcl2.load(io.StringIO(src)))
    return file_status(findings), sorted({f["rule"] for f in findings})


def hcl_list(items):
    return "[" + ", ".join(i if i.startswith("var.") else f'"{i}"' for i in items) + "]"


# ---- AWS: 4가지 표현 (vpc ingress_rule 은 출발지가 한 개뿐) ----

def aws_inline(v4=(), v6=(), port=22, proto="tcp"):
    lines = [f'from_port = {port}', f'to_port = {port}', f'protocol = "{proto}"']
    if v4:
        lines.append(f"cidr_blocks = {hcl_list(v4)}")
    if v6:
        lines.append(f"ipv6_cidr_blocks = {hcl_list(v6)}")
    inner = "\n    ".join(lines)
    return f'resource "aws_security_group" "t" {{\n  ingress {{\n    {inner}\n  }}\n}}\n'


def aws_inline_attr(v4=(), v6=(), port=22, proto="tcp"):
    lines = [f'from_port = {port}', f'to_port = {port}', f'protocol = "{proto}"']
    if v4:
        lines.append(f"cidr_blocks = {hcl_list(v4)}")
    if v6:
        lines.append(f"ipv6_cidr_blocks = {hcl_list(v6)}")
    inner = "\n    ".join(lines)
    return f'resource "aws_security_group" "t" {{\n  ingress = [{{\n    {inner}\n  }}]\n}}\n'


def aws_sg_rule(v4=(), v6=(), port=22, proto="tcp"):
    lines = ['type = "ingress"', f'from_port = {port}', f'to_port = {port}', f'protocol = "{proto}"',
             'security_group_id = "sg-123"']
    if v4:
        lines.append(f"cidr_blocks = {hcl_list(v4)}")
    if v6:
        lines.append(f"ipv6_cidr_blocks = {hcl_list(v6)}")
    inner = "\n  ".join(lines)
    return f'resource "aws_security_group_rule" "t" {{\n  {inner}\n}}\n'


def aws_vpc_rule(cidr, family, port=22, proto="tcp"):
    key = "cidr_ipv4" if family == 4 else "cidr_ipv6"
    return (f'resource "aws_vpc_security_group_ingress_rule" "t" {{\n  security_group_id = "sg-123"\n'
            f'  ip_protocol = "{proto}"\n  from_port = {port}\n  to_port = {port}\n  {key} = "{cidr}"\n}}\n')


AWS_BLOCK = ("BLOCK", ["AWS_PUBLIC_ADMIN_PORT"])
AWS_REVIEW = ("REVIEW", ["AWS_ADMIN_PORT_UNRESOLVED"])
PASS = ("PASS", [])

# (출발지, 넣는 칸(4=cidr_blocks/cidr_ipv4, 6=ipv6_cidr_blocks/cidr_ipv6), PROVIDER 수용, 기대 판정, 설명)
NOTATION = [
    ("0.0.0.0/0", 4, "수용", AWS_BLOCK, "기존 표기"),
    ("::/0", 6, "수용", AWS_BLOCK, "기존 표기"),
    ("0::/0", 6, "수용", AWS_BLOCK, "IPv6 다른 표기 — v3.1 PASS"),
    ("0:0::/0", 6, "수용", AWS_BLOCK, "IPv6 다른 표기"),
    ("0000::/0", 6, "수용", AWS_BLOCK, "IPv6 다른 표기"),
    ("::0/0", 6, "수용", AWS_BLOCK, "IPv6 다른 표기"),
    ("0:0:0:0:0:0:0:0/0", 6, "수용", AWS_BLOCK, "IPv6 전체 표기"),
    ("0.0.0.0/00", 4, "수용", AWS_BLOCK, "접두사 길이 00"),
    ("::ffff:0:0/96", 4, "수용", AWS_BLOCK, "IPv4-mapped IPv6 — provider 는 IPv4 0.0.0.0/0 으로 봄"),
    ("::ffff:0.0.0.0/96", 4, "수용", AWS_BLOCK, "IPv4-mapped IPv6 (점 표기)"),
    ("10.0.0.1/0", 4, "거부", AWS_BLOCK, "호스트 비트 있음 — provider 가 거부(배포 불가), 검사기는 보수적으로 공개 취급"),
    ("0.0.0.0/1", 4, "수용", PASS, "인터넷 절반 — 전체 아님"),
    ("::/1", 6, "수용", PASS, "IPv6 절반"),
    ("203.0.113.0/24", 4, "수용", PASS, "특정 대역"),
    ("2001:db8::/32", 6, "수용", PASS, "특정 대역"),
    ("::ffff:10.0.0.0/104", 4, "수용", PASS, "IPv4-mapped 10.0.0.0/8 — 전체 아님"),
    ("0.0.0.0", 4, "거부", PASS, "접두사 없음 = 주소 하나"),
]


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class AwsNotationTest(unittest.TestCase):
    def test_equivalent_notations_in_every_form(self):
        for cidr, family, _provider, expected, title in NOTATION:
            kw = {"v4": [cidr]} if family == 4 else {"v6": [cidr]}
            forms = {"인라인 블록": aws_inline(**kw), "인라인 목록": aws_inline_attr(**kw),
                     "security_group_rule": aws_sg_rule(**kw), "vpc ingress_rule": aws_vpc_rule(cidr, family)}
            for form, src in forms.items():
                with self.subTest(cidr=cidr, form=form, why=title):
                    self.assertEqual(status_rules(src), expected)

    def test_other_port_is_still_pass(self):
        for cidr, family in (("0::/0", 6), ("::ffff:0:0/96", 4)):
            kw = {"v4": [cidr]} if family == 4 else {"v6": [cidr]}
            with self.subTest(cidr):
                self.assertEqual(status_rules(aws_inline(port=443, **kw)), PASS)


# 한 규칙 안의 출발지 목록 (대상·방향·프로토콜·포트가 같음)
SPLIT = [
    (["0.0.0.0/1", "128.0.0.0/1"], (), 22, AWS_BLOCK, "IPv4 두 조각"),
    (["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/1"], (), 3389, AWS_BLOCK, "IPv4 세 조각, RDP"),
    ((), ["::/1", "8000::/1"], 22, AWS_BLOCK, "IPv6 두 조각"),
    (["0.0.0.0/1", "128.0.0.0/1", "var.extra"], (), 22, AWS_BLOCK, "변수가 섞여도 확정된 조각만으로 전체"),
    (["0.0.0.0/1", "128.0.0.0/2"], (), 22, PASS, "128.0.0.0/2 뒤쪽 빈틈"),
    (["0.0.0.0/1", "128.0.0.0/1"], (), 443, PASS, "관리자 포트 아님"),
    (["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"], (), 22, PASS, "사설 대역"),
    (["0.0.0.0/1"], ["8000::/1"], 22, PASS, "IPv4 절반 + IPv6 절반 = 어느 쪽도 전체 아님"),
    (["0.0.0.0/1", "var.extra"], (), 22, AWS_REVIEW, "나머지 절반이 변수 — 확인 불가"),
]


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class AwsSplitInOneRuleTest(unittest.TestCase):
    def test_split_ranges_in_one_rule(self):
        for v4, v6, port, expected, title in SPLIT:
            for form, render in (("인라인 블록", aws_inline), ("인라인 목록", aws_inline_attr),
                                 ("security_group_rule", aws_sg_rule)):
                with self.subTest(title, form=form):
                    self.assertEqual(status_rules(render(v4=v4, v6=v6, port=port)), expected)


# ---- Azure NSG 규칙 ----

def azure_rule(prefix=None, prefixes=None, port="22"):
    lines = ['direction = "Inbound"', 'access = "Allow"', 'protocol = "Tcp"',
             f'destination_port_range = "{port}"']
    if prefix is not None:
        lines.append(f'source_address_prefix = "{prefix}"')
    if prefixes is not None:
        lines.append(f"source_address_prefixes = {hcl_list(prefixes)}")
    inner = "\n  ".join(lines)
    return f'resource "azurerm_network_security_rule" "r" {{\n  name = "t"\n  {inner}\n}}\n'


AZ_BLOCK = ("BLOCK", ["AZURE_PUBLIC_ADMIN_PORT"])
AZ_REVIEW = ("REVIEW", ["AZURE_ADMIN_PORT_UNRESOLVED"])


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class AzureNotationTest(unittest.TestCase):
    cases = [
        ({"prefix": "0::/0"}, AZ_BLOCK, "IPv6 다른 표기"),
        ({"prefix": "0.0.0.0/00"}, AZ_BLOCK, "접두사 길이 00"),
        ({"prefixes": ["0.0.0.0/1", "128.0.0.0/1"]}, AZ_BLOCK, "한 규칙 안 두 조각"),
        ({"prefixes": ["::/1", "8000::/1"]}, AZ_BLOCK, "IPv6 두 조각"),
        ({"prefixes": ["0.0.0.0/1", "128.0.0.0/1"], "port": "443"}, PASS, "관리자 포트 아님"),
        ({"prefixes": ["0.0.0.0/1", "10.0.0.0/8"]}, PASS, "전체 아님"),
        ({"prefixes": ["VirtualNetwork", "10.0.0.0/8"]}, PASS, "서비스 태그 + 사설 대역"),
        ({"prefixes": ["0.0.0.0/1", "var.rest"]}, AZ_REVIEW, "나머지 절반이 변수"),
        ({"prefix": "Internet"}, AZ_BLOCK, "기존 서비스 태그 (그대로)"),
    ]

    def test_cases(self):
        for kwargs, expected, title in self.cases:
            with self.subTest(title):
                self.assertEqual(status_rules(azure_rule(**kwargs)), expected)


# ---- GCP 방화벽·방화벽 정책 규칙 ----

def gcp_fw(ranges, port="22"):
    return (f'resource "google_compute_firewall" "f" {{\n  name = "t"\n  network = "default"\n'
            f'  source_ranges = {hcl_list(ranges)}\n  allow {{\n    protocol = "tcp"\n    ports = ["{port}"]\n  }}\n}}\n')


def gcp_policy(ranges, port="22"):
    return f'''resource "google_compute_network_firewall_policy_rule" "r" {{
  firewall_policy = "p"
  priority        = 1000
  direction       = "INGRESS"
  action          = "allow"
  match {{
    src_ip_ranges = {hcl_list(ranges)}
    layer4_configs {{
      ip_protocol = "tcp"
      ports = ["{port}"]
    }}
  }}
}}
'''


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class GcpNotationTest(unittest.TestCase):
    FW = ("BLOCK", ["GCP_PUBLIC_ADMIN_PORT"])
    POLICY = ("BLOCK", ["GCP_FIREWALL_POLICY_PUBLIC_ADMIN_PORT"])

    def test_firewall(self):
        cases = [
            (["0::/0"], "22", self.FW), (["0.0.0.0/1", "128.0.0.0/1"], "22", self.FW),
            (["::/1", "8000::/1"], "3389", self.FW),
            (["0.0.0.0/1", "128.0.0.0/1"], "443", PASS), (["0.0.0.0/1"], "22", PASS),
            (["35.235.240.0/20"], "22", PASS),
        ]
        for ranges, port, expected in cases:
            with self.subTest(ranges=ranges, port=port):
                self.assertEqual(status_rules(gcp_fw(ranges, port)), expected)

    def test_firewall_policy_rule(self):
        cases = [
            (["0::/0"], "22", self.POLICY), (["0.0.0.0/1", "128.0.0.0/1"], "22", self.POLICY),
            (["0.0.0.0/1", "128.0.0.0/1"], "443", PASS), (["0.0.0.0/1"], "22", PASS),
        ]
        for ranges, port, expected in cases:
            with self.subTest(ranges=ranges, port=port):
                self.assertEqual(status_rules(gcp_policy(ranges, port)), expected)


if __name__ == "__main__":
    unittest.main()
