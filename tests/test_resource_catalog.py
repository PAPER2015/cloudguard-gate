"""GCP Storage 자원 분류표 점검 — v3 PR 6 (조용한 PASS 방지 장치 4번).

Terraform google provider 8.10.0(2026-11-03) 문서 저장소(website/docs/r/storage_*)에 있는 자원을 고정해 두고,
모두 "검사 대상(POLICY_TARGETS)" 또는 "범위 밖(GCP_STORAGE_OUT_OF_SCOPE)" 중 하나로 분류됐는지 확인한다.
provider 에 새 storage 자원이 생기면 이 목록을 갱신하면서 사람이 분류해야 한다.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from policy_gate import GCP_STORAGE_OUT_OF_SCOPE, POLICY_TARGETS  # noqa: E402

DOC_PAGES = (  # website/docs/r 의 storage_* 문서 이름 (iam 문서는 policy·binding·member 3종을 설명)
    "storage_anywhere_cache storage_batch_operations_job storage_bucket storage_bucket_access_control "
    "storage_bucket_acl storage_bucket_iam storage_bucket_object storage_control_folder_intelligence_config "
    "storage_control_organization_intelligence_config storage_control_project_feature_config "
    "storage_control_project_intelligence_config storage_default_object_access_control storage_default_object_acl "
    "storage_folder storage_ftp_server storage_ftp_user storage_hmac_key storage_insights_dataset_config "
    "storage_insights_report_config storage_managed_folder storage_managed_folder_iam storage_notification "
    "storage_object_access_control storage_object_acl storage_transfer_agent_pool storage_transfer_job"
).split()


def provider_resources():
    names = set()
    for page in DOC_PAGES:
        if page.endswith("_iam"):
            names.update(f"google_{page}_{kind}" for kind in ("policy", "binding", "member"))
        else:
            names.add(f"google_{page}")
    return names


class ResourceCatalogTest(unittest.TestCase):
    def test_every_storage_resource_is_classified(self):
        targets = POLICY_TARGETS[("CG-STO-01", "gcp")]
        unclassified = provider_resources() - targets - GCP_STORAGE_OUT_OF_SCOPE
        self.assertEqual(unclassified, set())

    def test_classification_does_not_overlap_and_has_no_typos(self):
        targets = POLICY_TARGETS[("CG-STO-01", "gcp")]
        self.assertEqual(targets & GCP_STORAGE_OUT_OF_SCOPE, set())
        self.assertEqual((targets | GCP_STORAGE_OUT_OF_SCOPE) - provider_resources(), set())


if __name__ == "__main__":
    unittest.main()
