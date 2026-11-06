"""S3 버킷 ↔ 공개 차단 설정 연결의 모듈(폴더) 격리 테스트 — v3 PR 6 (GPT 교차 검토 필수 1번).

PR 5까지는 검사한 모든 폴더의 공개 차단 설정을 하나로 모아, 다른 루트 모듈의 같은 이름 버킷을
"차단 설정 있음"으로 잘못 연결할 수 있었다 (미탐 방향). PR 6부터 같은 폴더(모듈) 안에서만 연결한다.
기준: 다른 폴더의 같은 리터럴 이름은 연결하지 않는다 (다른 루트 모듈 = 별도 배포 단위).
모듈 출력 등 불명확한 참조는 안전하다고 추측하지 않는다 (REVIEW).
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from policy_gate import scan_paths  # noqa: E402

try:
    import hcl2  # noqa: F401
except ImportError:  # pragma: no cover
    hcl2 = None

FLAGS = "".join(f"  {f} = true\n" for f in ("block_public_acls", "block_public_policy",
                                            "ignore_public_acls", "restrict_public_buckets"))


def s3_bucket(name="reports", literal="cg-reports"):
    return f'resource "aws_s3_bucket" "{name}" {{\n  bucket = "{literal}"\n}}\n'


def pab(target, name="reports"):
    return f'resource "aws_s3_bucket_public_access_block" "{name}" {{\n  bucket = {target}\n{FLAGS}}}\n'


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class S3ModuleIsolationTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def scan(self):
        results = scan_paths(sorted(self.root.rglob("*.tf")))
        return {Path(r["file"]).relative_to(self.root).as_posix(): r for r in results}

    def rules(self, result):
        return [f["rule"] for f in result["findings"]]

    def test_split_files_in_same_module_still_link(self):
        self.write("main.tf", s3_bucket())
        self.write("pab.tf", pab("aws_s3_bucket.reports.id"))
        r = self.scan()
        self.assertEqual(r["main.tf"]["status"], "PASS")

    def test_same_local_name_in_two_roots_is_not_mixed(self):
        self.write("rootA/main.tf", s3_bucket() + pab("aws_s3_bucket.reports.id"))
        self.write("rootB/main.tf", s3_bucket())
        r = self.scan()
        self.assertEqual(r["rootA/main.tf"]["status"], "PASS")
        self.assertEqual(self.rules(r["rootB/main.tf"]), ["AWS_S3_NO_PUBLIC_BLOCK"])   # PR 5: PASS (미탐)

    def test_same_literal_name_in_another_folder_is_not_linked(self):
        self.write("rootA/pab.tf", pab('"cg-reports"'))
        self.write("rootB/main.tf", s3_bucket(literal="cg-reports"))
        r = self.scan()
        self.assertEqual(self.rules(r["rootB/main.tf"]), ["AWS_S3_NO_PUBLIC_BLOCK"])   # PR 5: PASS (미탐)

    def test_literal_name_in_same_folder_still_links(self):
        self.write("main.tf", s3_bucket(literal="cg-reports"))
        self.write("pab.tf", pab('"cg-reports"'))
        self.assertEqual(self.scan()["main.tf"]["status"], "PASS")

    def test_module_output_reference_is_not_assumed(self):
        self.write("root/main.tf", 'module "s3" {\n  source = "../modules/s3"\n}\n' + pab("module.s3.bucket_id"))
        self.write("modules/s3/main.tf", s3_bucket())
        r = self.scan()
        self.assertEqual(self.rules(r["modules/s3/main.tf"]), ["AWS_S3_NO_PUBLIC_BLOCK"])

    def test_single_file_scan_unchanged(self):
        self.write("one.tf", s3_bucket() + pab("aws_s3_bucket.reports.id"))
        self.assertEqual(self.scan()["one.tf"]["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
