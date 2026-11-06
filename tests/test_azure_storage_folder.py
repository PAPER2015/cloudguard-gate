"""Azure Storage 폴더 단위 테스트 — 여러 파일·모듈 구조·잠금 파일 (v3 PR 5).

자가 점검은 파일 하나씩만 보므로, 파일이 나뉜 경우는 이 테스트가 확인한다.
임시 폴더에 실제 .tf 파일을 만들고 scan_paths()(GitHub Actions 게이트와 같은 경로)로 검사한다.
실행: python -m unittest discover -s tests -v
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

V4 = 'terraform {\n  required_providers {\n    azurerm = {\n      source = "hashicorp/azurerm"\n      version = "~> 4.0"\n    }\n  }\n}\n'
V5 = V4.replace("~> 4.0", "~> 5.0")
OPEN = V4.replace("~> 4.0", ">= 4.0")
def account(extra=""):
    return ('resource "azurerm_storage_account" "sa" {\n  name = "cgdemo"\n  resource_group_name = "rg"\n'
            '  location = "koreacentral"\n  account_tier = "Standard"\n  account_replication_type = "LRS"\n'
            + extra + '}\n')


def lock(version):
    return ('provider "registry.terraform.io/hashicorp/azurerm" {\n'
            f'  version     = "{version}"\n  constraints = ">= 4.0"\n  hashes = ["h1:x="]\n}}\n')


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class FolderTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def run_scan(self):
        files = sorted(self.root.rglob("*.tf"))
        return {str(Path(r["file"]).relative_to(self.root)): r for r in scan_paths(files)}

    def finding(self, results, rel, rule):
        for f in results[rel]["findings"]:
            if f["rule"] == rule:
                return f
        return None

    # --- 다른 파일에 나뉜 같은 모듈 ---
    def test_account_container_network_in_separate_files(self):
        self.write("account.tf", account("  allow_nested_items_to_be_public = true\n"))
        self.write("container.tf", 'resource "azurerm_storage_container" "c" {\n  name = "c"\n'
                                   '  storage_account_id = azurerm_storage_account.sa.id\n  container_access_type = "blob"\n}\n')
        self.write("network.tf", 'resource "azurerm_storage_account_network_rules" "n" {\n'
                                 '  storage_account_id = azurerm_storage_account.sa.id\n  default_action = "Deny"\n}\n')
        r = self.run_scan()
        self.assertEqual(self.finding(r, "container.tf", "AZURE_STORAGE_CONTAINER_PUBLIC")["exposure"],
                         "anonymous_access_configured")
        allowed = self.finding(r, "account.tf", "AZURE_STORAGE_PUBLIC_ALLOWED")
        self.assertEqual(allowed["exposure"], "anonymous_access_configured")
        self.assertIn("제한됨", allowed["reason"])
        self.assertEqual(r["network.tf"]["status"], "PASS")

    def test_version_in_another_file_of_same_module(self):
        self.write("versions.tf", V4)
        self.write("account.tf", account(""))
        r = self.run_scan()
        self.assertEqual(r["account.tf"]["status"], "BLOCK")
        self.assertIn("v4", self.finding(r, "account.tf", "AZURE_STORAGE_PUBLIC_ALLOWED")["reason"])

    def test_conflicting_constraints_in_same_folder_are_review(self):
        # 같은 폴더 = 같은 모듈 → 두 제약을 동시에 만족하는 버전이 없음 (Terraform도 설치 실패)
        self.write("a.tf", V4)
        self.write("b.tf", V5)
        self.write("account.tf", account(""))
        self.assertEqual(self.run_scan()["account.tf"]["status"], "REVIEW")

    def test_different_folders_are_not_linked(self):
        self.write("one/account.tf", account("  allow_nested_items_to_be_public = false\n"))
        self.write("two/container.tf", 'resource "azurerm_storage_container" "c" {\n  name = "c"\n'
                                       '  storage_account_id = azurerm_storage_account.sa.id\n  container_access_type = "blob"\n}\n')
        r = self.run_scan()
        self.assertEqual(self.finding(r, "two/container.tf", "AZURE_STORAGE_CONTAINER_PUBLIC")["exposure"],
                         "public_access_possible")

    # --- 잠금 파일 ---
    def test_lock_file_decides_over_open_constraint(self):
        self.write("main.tf", OPEN + account(""))
        self.write(".terraform.lock.hcl", lock("5.12.0"))
        self.assertEqual(self.run_scan()["main.tf"]["status"], "PASS")
        self.write(".terraform.lock.hcl", lock("4.52.0"))
        r = self.run_scan()
        self.assertEqual(r["main.tf"]["status"], "BLOCK")
        self.assertIn("잠금 파일 azurerm 4.52.0", self.finding(r, "main.tf", "AZURE_STORAGE_PUBLIC_ALLOWED")["reason"])

    def test_lock_file_conflicting_with_constraint_is_review(self):
        self.write("main.tf", V5 + account(""))
        self.write(".terraform.lock.hcl", lock("4.52.0"))
        self.assertEqual(self.run_scan()["main.tf"]["status"], "REVIEW")

    def test_unreadable_lock_file_is_review(self):
        self.write("main.tf", V4 + account(""))
        self.write(".terraform.lock.hcl", "provider {{{ broken")
        self.assertEqual(self.run_scan()["main.tf"]["status"], "REVIEW")

    # --- 루트·하위 모듈 ---
    def test_child_module_uses_root_lock(self):
        self.write("main.tf", 'module "storage" {\n  source = "./modules/storage"\n}\n')
        self.write(".terraform.lock.hcl", lock("4.52.0"))
        self.write("modules/storage/account.tf", account(""))
        self.assertEqual(self.run_scan()["modules/storage/account.tf"]["status"], "BLOCK")
        self.write(".terraform.lock.hcl", lock("5.3.0"))
        self.assertEqual(self.run_scan()["modules/storage/account.tf"]["status"], "PASS")

    def test_child_constraints_combine_with_root(self):
        self.write("main.tf", OPEN + 'module "storage" {\n  source = "./modules/storage"\n}\n')
        self.write("modules/storage/versions.tf", V5)
        self.write("modules/storage/account.tf", account(""))
        self.assertEqual(self.run_scan()["modules/storage/account.tf"]["status"], "PASS")

    def test_child_lock_file_is_ignored(self):
        # 잠금 파일은 루트에서만 쓰인다 → 하위 모듈 폴더의 잠금 파일로 판단하면 안 됨
        self.write("main.tf", OPEN + 'module "storage" {\n  source = "./modules/storage"\n}\n')
        self.write("modules/storage/.terraform.lock.hcl", lock("5.3.0"))
        self.write("modules/storage/account.tf", account(""))
        self.assertEqual(self.run_scan()["modules/storage/account.tf"]["status"], "REVIEW")

    def test_module_shared_by_roots_with_different_versions(self):
        self.write("prod/main.tf", V4 + 'module "storage" {\n  source = "../shared"\n}\n')
        self.write("dev/main.tf", V5 + 'module "storage" {\n  source = "../shared"\n}\n')
        self.write("shared/account.tf", account(""))
        self.assertEqual(self.run_scan()["shared/account.tf"]["status"], "REVIEW")

    def test_module_shared_by_roots_with_same_default(self):
        self.write("prod/main.tf", V4 + 'module "storage" {\n  source = "../shared"\n}\n')
        self.write("dev/main.tf", V4.replace("~> 4.0", "~> 3.117") + 'module "storage" {\n  source = "../shared"\n}\n')
        self.write("shared/account.tf", account(""))
        self.assertEqual(self.run_scan()["shared/account.tf"]["status"], "BLOCK")

    # --- ARM 템플릿 파일 ---
    def test_template_file_is_read_from_module_folder(self):
        deploy = ('resource "azurerm_resource_group_template_deployment" "t" {\n  name = "t"\n'
                  '  resource_group_name = "rg"\n  deployment_mode = "Incremental"\n'
                  '  template_content = file("${path.module}/template.json")\n}\n')
        self.write("deploy.tf", deploy)
        self.write("template.json", '{"resources": [{"type": "Microsoft.Network/virtualNetworks"}]}')
        self.assertEqual(self.run_scan()["deploy.tf"]["status"], "PASS")
        self.write("template.json", '{"resources": [{"type": "Microsoft.Storage/storageAccounts"}]}')
        self.assertEqual(self.run_scan()["deploy.tf"]["status"], "REVIEW")

    # --- 오류 처리 ---
    def test_syntax_error_file_does_not_hide_others(self):
        self.write("broken.tf", 'resource "azurerm_storage_account" "x" {\n')
        self.write("account.tf", account("  allow_nested_items_to_be_public = true\n"))
        r = self.run_scan()
        self.assertEqual(r["broken.tf"]["status"], "ERROR")
        self.assertEqual(r["account.tf"]["status"], "BLOCK")


if __name__ == "__main__":
    unittest.main()
