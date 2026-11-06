"""GCP Storage 폴더 단위 테스트 — 여러 파일·여러 루트 모듈 (v3 PR 6).

자가 점검은 파일 하나씩만 보므로, 파일이 나뉜 경우와 폴더(모듈) 경계는 이 테스트가 확인한다.
임시 폴더에 실제 .tf 파일을 만들고 scan_paths()(GitHub Actions 게이트와 같은 경로)로 검사한다.
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


def bucket(pap, name="b", literal="cg-shared"):
    return (f'resource "google_storage_bucket" "{name}" {{\n  name = "{literal}"\n  location = "US"\n'
            f'  public_access_prevention = "{pap}"\n}}\n')


def public_member(ref, name="m"):
    return (f'resource "google_storage_bucket_iam_member" "{name}" {{\n  bucket = {ref}\n'
            '  role = "roles/storage.objectViewer"\n  member = "allUsers"\n}\n')


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class GcpFolderTest(unittest.TestCase):
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

    def exposure(self, result):
        return [f.get("exposure") for f in result["findings"] if f["rule"] == "GCP_STORAGE_PUBLIC_IAM"]

    def test_split_files_in_same_module_link(self):
        self.write("main.tf", bucket("enforced"))
        self.write("iam.tf", public_member("google_storage_bucket.b.name"))
        r = self.scan()
        self.assertEqual(r["iam.tf"]["status"], "BLOCK")
        self.assertEqual(self.exposure(r["iam.tf"]), ["blocked_by_public_access_prevention"])
        self.assertEqual(r["main.tf"]["status"], "PASS")

    def test_same_local_name_in_two_roots_is_not_mixed(self):
        self.write("rootA/main.tf", bucket("enforced"))
        self.write("rootB/main.tf", bucket("inherited"))
        self.write("rootB/iam.tf", public_member("google_storage_bucket.b.name"))
        r = self.scan()
        self.assertEqual(self.exposure(r["rootB/iam.tf"]), ["public_access_possible"])

    def test_same_literal_name_in_another_folder_is_not_linked(self):
        self.write("rootA/main.tf", bucket("enforced", literal="cg-logs"))
        self.write("rootB/iam.tf", public_member('"cg-logs"'))
        r = self.scan()
        self.assertEqual(self.exposure(r["rootB/iam.tf"]), ["public_access_possible"])

    def test_policy_data_from_other_folder_is_unsupported(self):
        self.write("rootA/policy.tf", 'data "google_iam_policy" "pub" {\n  binding {\n    role = "roles/storage.objectViewer"\n'
                                      '    members = ["allUsers"]\n  }\n}\n')
        self.write("rootB/main.tf", bucket("enforced") + 'resource "google_storage_bucket_iam_policy" "p" {\n'
                   '  bucket = google_storage_bucket.b.name\n  policy_data = data.google_iam_policy.pub.policy_data\n}\n')
        r = self.scan()
        self.assertEqual([f["rule"] for f in r["rootB/main.tf"]["findings"]], ["GCP_STORAGE_UNSUPPORTED"])

    def test_policy_data_in_another_file_of_same_module(self):
        self.write("policy.tf", 'data "google_iam_policy" "pub" {\n  binding {\n    role = "roles/storage.objectViewer"\n'
                                '    members = ["allUsers"]\n  }\n}\n')
        self.write("main.tf", bucket("enforced") + 'resource "google_storage_bucket_iam_policy" "p" {\n'
                   '  bucket = google_storage_bucket.b.name\n  policy_data = data.google_iam_policy.pub.policy_data\n}\n')
        r = self.scan()
        self.assertEqual(r["main.tf"]["status"], "BLOCK")

    def test_child_module_bucket_via_output_is_not_assumed_safe(self):
        self.write("root/main.tf", 'module "storage" {\n  source = "../modules/storage"\n}\n'
                   + public_member("module.storage.bucket_name"))
        self.write("modules/storage/main.tf", bucket("enforced"))
        r = self.scan()
        self.assertEqual(self.exposure(r["root/main.tf"]), ["public_access_possible"])

    def test_error_in_one_file_does_not_hide_others(self):
        self.write("ok.tf", bucket("enforced") + public_member("google_storage_bucket.b.name"))
        self.write("broken.tf", 'resource "google_storage_bucket" "x" {\n  name = "x"\n')
        r = self.scan()
        self.assertEqual(r["broken.tf"]["status"], "ERROR")
        self.assertEqual(r["ok.tf"]["status"], "BLOCK")


if __name__ == "__main__":
    unittest.main()
