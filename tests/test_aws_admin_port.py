"""AWS 관리자 포트 규칙과 S3 버킷 연결 경계 상황 단위 테스트.

PR 2에서 따로 확인했던 경계 상황 12가지를 GitHub Actions에서 계속 확인하도록 옮긴 것 (v3 PR 3).
실행: python -m unittest discover -s tests -v
"""
import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from policy_gate import collect_s3_links, file_status, scan_configuration  # noqa: E402

try:
    import hcl2
except ImportError:  # pragma: no cover
    hcl2 = None


def status_of(src, links_from=None):
    data = hcl2.load(io.StringIO(src))
    links = collect_s3_links([data] + [hcl2.load(io.StringIO(s)) for s in (links_from or [])])
    return file_status(scan_configuration(data, links))


def sg(ingress):
    return 'resource "aws_security_group" "t" {\n  ingress {\n' + ingress + '\n  }\n}\n'


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class AwsAdminPortTest(unittest.TestCase):
    cases = [
        ("공개 + 443", 'from_port=443\nto_port=443\nprotocol="tcp"\ncidr_blocks=["0.0.0.0/0"]', "PASS"),
        ("출발지 변수 + 443", 'from_port=443\nto_port=443\nprotocol="tcp"\ncidr_blocks=var.c', "PASS"),
        ("출발지 변수 + 22", 'from_port=22\nto_port=22\nprotocol="tcp"\ncidr_blocks=var.c', "REVIEW"),
        ("공개 + protocol 변수 + 443", 'from_port=443\nto_port=443\nprotocol=var.p\ncidr_blocks=["0.0.0.0/0"]', "REVIEW"),
        ("회사IP + 포트 변수", 'from_port=var.p\nto_port=var.p\nprotocol="tcp"\ncidr_blocks=["203.0.113.0/24"]', "PASS"),
        ("IPv6 목록 [::/0, 변수] + 22", 'from_port=22\nto_port=22\nprotocol="tcp"\nipv6_cidr_blocks=["::/0", var.c]', "BLOCK"),
        ("공개 + 포트범위 20-30", 'from_port=20\nto_port=30\nprotocol="tcp"\ncidr_blocks=["0.0.0.0/0"]', "BLOCK"),
        ("공개 + protocol -1", 'from_port=0\nto_port=0\nprotocol="-1"\ncidr_blocks=["0.0.0.0/0"]', "BLOCK"),
    ]

    def test_security_group_cases(self):
        for title, ingress, expected in self.cases:
            with self.subTest(title):
                self.assertEqual(status_of(sg(ingress)), expected)

    def test_vpc_rule_all_protocols_variable_source(self):
        src = 'resource "aws_vpc_security_group_ingress_rule" "r" {\n ip_protocol="-1"\n cidr_ipv4=var.c\n}'
        self.assertEqual(status_of(src), "REVIEW")


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class S3BucketLinkTest(unittest.TestCase):
    FLAGS = ("block_public_acls=true\n block_public_policy=true\n"
             " ignore_public_acls=true\n restrict_public_buckets=true\n")

    def test_linked_by_reference(self):
        src = ('resource "aws_s3_bucket" "b" {\n bucket_prefix="x"\n}\n'
               'resource "aws_s3_bucket_public_access_block" "p" {\n bucket=aws_s3_bucket.b.id\n '
               + self.FLAGS + '}')
        self.assertEqual(status_of(src), "PASS")

    def test_block_for_other_bucket(self):
        src = ('resource "aws_s3_bucket" "b" {\n bucket="aaa"\n}\n'
               'resource "aws_s3_bucket_public_access_block" "p" {\n bucket="bbb"\n ' + self.FLAGS + '}')
        self.assertEqual(status_of(src), "REVIEW")

    def test_block_in_another_file(self):
        bucket = 'resource "aws_s3_bucket" "b" {\n bucket="shared-bkt"\n}'
        block = 'resource "aws_s3_bucket_public_access_block" "p" {\n bucket="shared-bkt"\n ' + self.FLAGS + '}'
        self.assertEqual(status_of(bucket, links_from=[block]), "PASS")


if __name__ == "__main__":
    unittest.main()
