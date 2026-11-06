"""Azure Storage 공개 위험 (CG-STO-01) 단위 테스트 — v3 PR 5.

모든 테스트는 실제 Terraform 문장을 python-hcl2 7.3.1로 읽어서 검사한다 (딕셔너리 테스트 없음).
판정표(설계 검토서 7장)의 각 행과, PR 3·4에서 겪은 오탐·미탐 유형을 확인한다.
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

EXPOSURES = {"anonymous_access_configured", "public_access_possible", "blocked_by_account_setting",
             "intentional_static_website", "undetermined"}


def tf_version(constraint):
    return ('terraform {\n  required_providers {\n    azurerm = {\n      source  = "hashicorp/azurerm"\n'
            f'      version = "{constraint}"\n    }}\n  }}\n}}\n')


def account(extra="", name="sa", literal="cgdemo"):
    return (f'resource "azurerm_storage_account" "{name}" {{\n  name = "{literal}"\n'
            f'  resource_group_name = "rg"\n  location = "koreacentral"\n  account_tier = "Standard"\n'
            f'  account_replication_type = "LRS"\n{extra}\n}}\n')


def container(access=None, ref="azurerm_storage_account.sa.id", key="storage_account_id", name="c"):
    access_line = f"  container_access_type = {access}\n" if access is not None else ""
    return f'resource "azurerm_storage_container" "{name}" {{\n  name = "{name}"\n  {key} = {ref}\n{access_line}}}\n'


def scan(src):
    data = hcl2.load(io.StringIO(src))
    findings = scan_configuration(data)
    return {"status": file_status(findings), "rules": sorted({f["rule"] for f in findings}),
            "findings": findings, "data": data}


def exposure_of(result, rule, resource=None):
    for f in result["findings"]:
        if f["rule"] == rule and (resource is None or f["resource"] == resource):
            return f.get("exposure")
    return "MISSING"


ALLOWED = "AZURE_STORAGE_PUBLIC_ALLOWED"
CONTAINER = "AZURE_STORAGE_CONTAINER_PUBLIC"
UNRESOLVED = "AZURE_STORAGE_PUBLIC_UNRESOLVED"
STATIC = "AZURE_STORAGE_STATIC_WEBSITE"
UNSUPPORTED = "AZURE_STORAGE_UNSUPPORTED"


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class AccountTest(unittest.TestCase):
    def verdict(self, src):
        r = scan(src)
        return r["status"], r["rules"]

    # --- A1 / A7: 명시적 허용 ---
    def test_explicit_true_new_name(self):
        r = scan(account("  allow_nested_items_to_be_public = true"))
        self.assertEqual((r["status"], r["rules"]), ("BLOCK", [ALLOWED]))
        self.assertEqual(exposure_of(r, ALLOWED), "public_access_possible")

    def test_explicit_true_old_name(self):
        self.assertEqual(self.verdict(account("  allow_blob_public_access = true")), ("BLOCK", [ALLOWED]))

    def test_explicit_true_as_string(self):
        self.assertEqual(self.verdict(account('  allow_nested_items_to_be_public = "true"')), ("BLOCK", [ALLOWED]))

    def test_both_names_one_true(self):
        src = account("  allow_nested_items_to_be_public = false\n  allow_blob_public_access = true")
        self.assertEqual(self.verdict(src), ("BLOCK", [ALLOWED]))

    # --- A2: 명시적 차단 (버전 정보가 없어도 PASS) ---
    def test_explicit_false_without_version(self):
        self.assertEqual(self.verdict(account("  allow_nested_items_to_be_public = false")), ("PASS", []))

    def test_explicit_false_old_name(self):
        self.assertEqual(self.verdict(account("  allow_blob_public_access = false")), ("PASS", []))

    # --- A3 / A4 / A5: 생략과 버전별 기본값 ---
    def test_omitted_v4_is_block_and_reason_names_version(self):
        r = scan(tf_version("~> 4.0") + account())
        self.assertEqual((r["status"], r["rules"]), ("BLOCK", [ALLOWED]))
        self.assertIn("기본값 true", r["findings"][0]["reason"])
        self.assertIn("v4", r["findings"][0]["reason"])

    def test_omitted_v3(self):
        self.assertEqual(self.verdict(tf_version("~> 3.117") + account()), ("BLOCK", [ALLOWED]))

    def test_omitted_v3_or_v4_range(self):
        self.assertEqual(self.verdict(tf_version(">= 3.0, < 5.0") + account()), ("BLOCK", [ALLOWED]))

    def test_omitted_single_digit_pessimistic_is_v4_only(self):
        # Terraform 실제 평가: "~> 4" 는 4.x 만 허용 (tests/test_terraform_version.py 참고)
        self.assertEqual(self.verdict(tf_version("~> 4") + account()), ("BLOCK", [ALLOWED]))

    def test_omitted_v5(self):
        self.assertEqual(self.verdict(tf_version("~> 5.0") + account()), ("PASS", []))

    def test_omitted_v2(self):
        self.assertEqual(self.verdict(tf_version("~> 2.99") + account()), ("PASS", []))

    def test_omitted_no_version_is_review(self):
        r = scan(account())
        self.assertEqual((r["status"], r["rules"]), ("REVIEW", [UNRESOLVED]))
        self.assertEqual(exposure_of(r, UNRESOLVED), "undetermined")

    def test_omitted_open_range_covering_v4_and_v5(self):
        self.assertEqual(self.verdict(tf_version(">= 4.0") + account()), ("REVIEW", [UNRESOLVED]))

    def test_omitted_v1_unknown(self):
        self.assertEqual(self.verdict(tf_version("~> 1.44") + account()), ("REVIEW", [UNRESOLVED]))

    def test_omitted_constraint_syntax_error(self):
        self.assertEqual(self.verdict(tf_version("latest") + account()), ("REVIEW", [UNRESOLVED]))

    def test_omitted_conflicting_constraints(self):
        src = tf_version("~> 4.0") + tf_version("~> 5.0") + account()
        self.assertEqual(self.verdict(src), ("REVIEW", [UNRESOLVED]))

    def test_legacy_string_requirement(self):
        src = 'terraform {\n  required_providers {\n    azurerm = "~> 4.0"\n  }\n}\n' + account()
        self.assertEqual(self.verdict(src), ("BLOCK", [ALLOWED]))

    def test_foreign_source_is_unknown(self):
        src = tf_version("~> 4.0").replace("hashicorp/azurerm", "mycorp/azurerm") + account()
        self.assertEqual(self.verdict(src), ("REVIEW", [UNRESOLVED]))

    def test_provider_alias_does_not_change_version(self):
        src = (tf_version("~> 4.0") + 'provider "azurerm" {\n  features {}\n}\n'
               'provider "azurerm" {\n  alias = "second"\n  features {}\n}\n'
               + account("  provider = azurerm.second"))
        self.assertEqual(self.verdict(src), ("BLOCK", [ALLOWED]))

    # --- A6: 값이 변수 ---
    def test_variable_value_is_review(self):
        self.assertEqual(self.verdict(account("  allow_nested_items_to_be_public = var.public")),
                         ("REVIEW", [UNRESOLVED]))

    def test_variable_value_even_with_v5(self):
        src = tf_version("~> 5.0") + account("  allow_nested_items_to_be_public = var.public")
        self.assertEqual(self.verdict(src), ("REVIEW", [UNRESOLVED]))

    # --- A8: FileStorage 예외 ---
    def test_filestorage_omitted_v4_is_pass(self):
        src = tf_version("~> 4.0") + account('  account_kind = "FileStorage"')
        self.assertEqual(self.verdict(src), ("PASS", []))

    def test_filestorage_lowercase(self):
        src = tf_version("~> 4.0") + account('  account_kind = "filestorage"')
        self.assertEqual(self.verdict(src), ("PASS", []))

    def test_filestorage_explicit_true_still_block(self):
        src = account('  account_kind = "FileStorage"\n  allow_nested_items_to_be_public = true')
        self.assertEqual(self.verdict(src), ("BLOCK", [ALLOWED]))

    def test_account_kind_variable_is_not_assumed_filestorage(self):
        src = tf_version("~> 4.0") + account("  account_kind = var.kind")
        self.assertEqual(self.verdict(src), ("BLOCK", [ALLOWED]))

    def test_storagev2_omitted_v4_still_block(self):
        src = tf_version("~> 4.0") + account('  account_kind = "StorageV2"')
        self.assertEqual(self.verdict(src), ("BLOCK", [ALLOWED]))

    # --- A9: 판정과 무관한 변수 (PR 3 오탐 유형) ---
    def test_unrelated_variables_do_not_cause_review(self):
        extra = ('  allow_nested_items_to_be_public = false\n  tags = var.tags\n'
                 '  dynamic "network_rules" {\n    for_each = var.rules\n'
                 '    content {\n      default_action = network_rules.value\n    }\n  }')
        src = account(extra).replace('location = "koreacentral"', "location = var.location")
        self.assertEqual(self.verdict(src), ("PASS", []))

    def test_unrelated_variables_do_not_hide_block(self):
        src = account("  allow_nested_items_to_be_public = true\n  tags = var.tags")
        self.assertEqual(self.verdict(src), ("BLOCK", [ALLOWED]))


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class ContainerTest(unittest.TestCase):
    def verdict(self, src):
        r = scan(src)
        return r["status"], r["rules"]

    def test_private_and_omitted_are_pass(self):
        base = account("  allow_nested_items_to_be_public = false")
        self.assertEqual(self.verdict(base + container('"private"')), ("PASS", []))
        self.assertEqual(self.verdict(base + container()), ("PASS", []))

    def test_blob_and_container_are_block(self):
        base = account("  allow_nested_items_to_be_public = false")
        for access in ('"blob"', '"container"'):
            with self.subTest(access):
                self.assertEqual(self.verdict(base + container(access)), ("BLOCK", [CONTAINER]))

    def test_variable_access_is_review_even_when_account_blocks(self):
        # GPT 교차 검토 결정: 불확실한 설정이 확정 위험(blob)보다 관대하면 안 됨 → REVIEW
        src = account("  allow_nested_items_to_be_public = false") + container("var.access")
        self.assertEqual(self.verdict(src), ("REVIEW", [UNRESOLVED]))

    def test_unknown_literal_access_is_review(self):
        src = account("  allow_nested_items_to_be_public = false") + container('"public"')
        self.assertEqual(self.verdict(src), ("REVIEW", [UNRESOLVED]))

    def test_exposure_configured_when_account_allows(self):
        r = scan(account("  allow_nested_items_to_be_public = true") + container('"blob"'))
        self.assertEqual(exposure_of(r, CONTAINER), "anonymous_access_configured")
        self.assertEqual(exposure_of(r, ALLOWED), "anonymous_access_configured")

    def test_exposure_blocked_when_account_blocks(self):
        r = scan(account("  allow_nested_items_to_be_public = false") + container('"blob"'))
        self.assertEqual(exposure_of(r, CONTAINER), "blocked_by_account_setting")

    def test_exposure_uses_version_default_of_linked_account(self):
        r = scan(tf_version("~> 5.0") + account() + container('"blob"'))
        self.assertEqual((r["status"], r["rules"]), ("BLOCK", [CONTAINER]))
        self.assertEqual(exposure_of(r, CONTAINER), "blocked_by_account_setting")

    def test_exposure_possible_when_account_unknown(self):
        r = scan(account("  allow_nested_items_to_be_public = var.p") + container('"blob"'))
        self.assertEqual(exposure_of(r, CONTAINER), "public_access_possible")

    def test_data_source_account_is_not_linked(self):
        src = ('data "azurerm_storage_account" "shared" {\n  name = "x"\n  resource_group_name = "rg"\n}\n'
               + container('"blob"', ref="data.azurerm_storage_account.shared.id"))
        r = scan(src)
        self.assertEqual((r["status"], r["rules"]), ("BLOCK", [CONTAINER]))
        self.assertEqual(exposure_of(r, CONTAINER), "public_access_possible")

    def test_variable_account_is_not_linked(self):
        r = scan(account("  allow_nested_items_to_be_public = false") + container('"blob"', ref="var.account_id"))
        self.assertEqual(exposure_of(r, CONTAINER), "public_access_possible")

    def test_link_by_name_reference_and_index(self):
        for ref, key in (("azurerm_storage_account.sa.name", "storage_account_name"),
                         ("azurerm_storage_account.sa[0].id", "storage_account_id")):
            with self.subTest(ref):
                r = scan(account("  allow_nested_items_to_be_public = false") + container('"blob"', ref=ref, key=key))
                self.assertEqual(exposure_of(r, CONTAINER), "blocked_by_account_setting")

    def test_link_by_unique_literal_name(self):
        r = scan(account("  allow_nested_items_to_be_public = false") +
                 container('"blob"', ref='"cgdemo"', key="storage_account_name"))
        self.assertEqual(exposure_of(r, CONTAINER), "blocked_by_account_setting")

    def test_duplicate_literal_name_is_not_linked(self):
        src = (account("  allow_nested_items_to_be_public = false", name="a", literal="dup") +
               account("  allow_nested_items_to_be_public = true", name="b", literal="dup") +
               container('"blob"', ref='"dup"', key="storage_account_name"))
        self.assertEqual(exposure_of(scan(src), CONTAINER, "azurerm_storage_container.c"), "public_access_possible")

    def test_arm_id_literal_links_by_name(self):
        ref = '"/subscriptions/0/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/cgdemo"'
        r = scan(account("  allow_nested_items_to_be_public = false") + container('"blob"', ref=ref))
        self.assertEqual(exposure_of(r, CONTAINER), "blocked_by_account_setting")

    def test_container_links_to_its_own_account_not_the_first_one(self):
        # 고장 주입 F-4(항상 첫 계정에 연결)를 잡기 위한 테스트: 공개 컨테이너가 "두 번째" 계정을 가리킴
        src = (account("  allow_nested_items_to_be_public = false", name="first", literal="first") +
               account("  allow_nested_items_to_be_public = true", name="second", literal="second") +
               container('"blob"', ref="azurerm_storage_account.second.id", name="z"))
        r = scan(src)
        self.assertEqual(exposure_of(r, CONTAINER, "azurerm_storage_container.z"), "anonymous_access_configured")
        self.assertIn("azurerm_storage_account.second", [f["resource"] for f in r["findings"]])
        self.assertEqual(exposure_of(r, ALLOWED, "azurerm_storage_account.second"), "anonymous_access_configured")

    def test_containers_of_different_accounts_are_not_mixed(self):
        src = (account("  allow_nested_items_to_be_public = false", name="locked", literal="locked") +
               account("  allow_nested_items_to_be_public = true", name="open", literal="open") +
               container('"blob"', ref="azurerm_storage_account.locked.id", name="x") +
               container('"private"', ref="azurerm_storage_account.open.id", name="y"))
        r = scan(src)
        self.assertEqual(exposure_of(r, CONTAINER, "azurerm_storage_container.x"), "blocked_by_account_setting")
        self.assertEqual(exposure_of(r, ALLOWED, "azurerm_storage_account.open"), "public_access_possible")
        self.assertEqual([f["resource"] for f in r["findings"]],
                         ["azurerm_storage_account.open", "azurerm_storage_container.x"])


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class StaticWebsiteAndNetworkTest(unittest.TestCase):
    def test_inline_block(self):
        r = scan(account('  allow_nested_items_to_be_public = false\n  static_website {\n    index_document = "index.html"\n  }'))
        self.assertEqual((r["status"], r["rules"]), ("REVIEW", [STATIC]))
        self.assertEqual(exposure_of(r, STATIC), "intentional_static_website")

    def test_separate_resource_even_when_account_blocks(self):
        src = (account("  allow_nested_items_to_be_public = false") +
               'resource "azurerm_storage_account_static_website" "w" {\n'
               '  storage_account_id = azurerm_storage_account.sa.id\n  index_document = "index.html"\n}\n')
        self.assertEqual(scan(src)["rules"], [STATIC])

    def test_dynamic_static_website(self):
        src = account('  allow_nested_items_to_be_public = false\n  dynamic "static_website" {\n'
                      '    for_each = var.site\n    content {\n      index_document = "index.html"\n    }\n  }')
        r = scan(src)
        self.assertEqual(r["rules"], [STATIC])
        self.assertEqual(exposure_of(r, STATIC), "undetermined")

    def test_network_restriction_does_not_clear_block(self):
        for extra in ('  network_rules {\n    default_action = "Deny"\n  }',
                      "  public_network_access_enabled = false",
                      '  public_network_access = "Disabled"'):
            with self.subTest(extra):
                r = scan(account("  allow_nested_items_to_be_public = true\n" + extra))
                self.assertEqual((r["status"], r["rules"]), ("BLOCK", [ALLOWED]))
                self.assertIn("제한됨", r["findings"][0]["reason"])

    def test_network_rules_resource_is_used_for_label_only(self):
        src = (account("  allow_nested_items_to_be_public = true") +
               'resource "azurerm_storage_account_network_rules" "n" {\n'
               '  storage_account_id = azurerm_storage_account.sa.id\n  default_action = "Deny"\n}\n')
        r = scan(src)
        self.assertEqual(r["status"], "BLOCK")
        self.assertIn("제한됨", r["findings"][0]["reason"])

    def test_public_network_does_not_cause_block(self):
        src = account("  allow_nested_items_to_be_public = false\n  public_network_access_enabled = true\n"
                      '  network_rules {\n    default_action = "Allow"\n  }')
        self.assertEqual(scan(src)["status"], "PASS")


def azapi(typ, body, kind="azapi_resource"):
    return f'resource "{kind}" "z" {{\n  type = {typ}\n  parent_id = "x"\n  body = {body}\n}}\n'


ACCT = '"Microsoft.Storage/storageAccounts@2023-05-01"'
CONT = '"Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01"'


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class AzapiAndTemplateTest(unittest.TestCase):
    def verdict(self, src):
        r = scan(src)
        return r["status"], r["rules"]

    def test_azapi_account_true_false(self):
        self.assertEqual(self.verdict(azapi(ACCT, "{\n    properties = { allowBlobPublicAccess = true }\n  }")),
                         ("BLOCK", [ALLOWED]))
        self.assertEqual(self.verdict(azapi(ACCT, "{\n    properties = { allowBlobPublicAccess = false }\n  }")),
                         ("PASS", []))

    def test_azapi_account_missing_field(self):
        body = '{\n    properties = { minimumTlsVersion = "TLS1_2" }\n  }'
        self.assertEqual(self.verdict(azapi(ACCT, body)), ("REVIEW", [UNRESOLVED]))
        self.assertEqual(self.verdict(azapi(ACCT, body, kind="azapi_update_resource")), ("PASS", []))

    def test_azapi_jsonencode_literal_is_decoded(self):
        body = "jsonencode({ properties = { allowBlobPublicAccess = true } })"
        self.assertEqual(self.verdict(azapi(ACCT, body, kind="azapi_update_resource")), ("BLOCK", [ALLOWED]))

    def test_azapi_jsonencode_with_variable_is_review(self):
        body = "jsonencode({ properties = { allowBlobPublicAccess = var.public } })"
        self.assertEqual(self.verdict(azapi(ACCT, body)), ("REVIEW", [UNRESOLVED]))

    def test_azapi_body_variable_is_review(self):
        self.assertEqual(self.verdict(azapi(ACCT, "var.body")), ("REVIEW", [UNRESOLVED]))

    def test_azapi_container_levels(self):
        for value, expected in (('"Container"', ("BLOCK", [CONTAINER])), ('"Blob"', ("BLOCK", [CONTAINER])),
                                ('"None"', ("PASS", [])), ("var.level", ("REVIEW", [UNRESOLVED]))):
            with self.subTest(value):
                body = "{\n    properties = { publicAccess = " + value + " }\n  }"
                self.assertEqual(self.verdict(azapi(CONT, body)), expected)
        self.assertEqual(self.verdict(azapi(CONT, "{\n    properties = {}\n  }")), ("PASS", []))

    def test_azapi_type_case_insensitive(self):
        src = azapi('"Microsoft.Storage/StorageAccounts@2023-05-01"', "{\n    properties = { allowBlobPublicAccess = true }\n  }")
        self.assertEqual(self.verdict(src), ("BLOCK", [ALLOWED]))

    def test_unrelated_azapi_is_ignored_and_not_recorded(self):
        src = azapi('"Microsoft.Network/virtualNetworks@2023-05-01"', "var.body")
        r = scan(src)
        self.assertEqual((r["status"], r["rules"]), ("PASS", []))
        self.assertEqual(build_checks(r["data"], r["findings"]), [])

    def test_azapi_type_variable_is_review(self):
        self.assertEqual(self.verdict(azapi("var.type", "{}")), ("REVIEW", [UNRESOLVED]))

    def test_azapi_deployment(self):
        dep = '"Microsoft.Resources/deployments@2022-09-01"'
        storage = ('{\n    properties = { mode = "Incremental", template = { resources = '
                   '[{ type = "Microsoft.Storage/storageAccounts" }] } }\n  }')
        network = ('{\n    properties = { mode = "Incremental", template = { resources = '
                   '[{ type = "Microsoft.Network/virtualNetworks" }] } }\n  }')
        self.assertEqual(self.verdict(azapi(dep, storage)), ("REVIEW", [UNSUPPORTED]))
        self.assertEqual(self.verdict(azapi(dep, network)), ("PASS", []))

    def template(self, content):
        return ('resource "azurerm_resource_group_template_deployment" "t" {\n  name = "t"\n'
                f'  resource_group_name = "rg"\n  deployment_mode = "Incremental"\n  template_content = {content}\n}}\n')

    def test_template_with_storage_is_review(self):
        content = '<<EOT\n{"resources": [{"type": "Microsoft.Storage/storageAccounts", "name": "x"}]}\nEOT'
        self.assertEqual(self.verdict(self.template(content)), ("REVIEW", [UNSUPPORTED]))

    def test_template_without_storage_is_pass(self):
        content = '<<EOT\n{"resources": [{"type": "Microsoft.Network/virtualNetworks", "name": "x"}]}\nEOT'
        r = scan(self.template(content))
        self.assertEqual((r["status"], r["rules"]), ("PASS", []))
        self.assertEqual([c["status"] for c in build_checks(r["data"], r["findings"])], ["PASS"])

    def test_template_unknown_content_is_review(self):
        for content in ('file("missing-template.json")', "var.template", "templatefile(\"t.json\", {})"):
            with self.subTest(content):
                self.assertEqual(self.verdict(self.template(content)), ("REVIEW", [UNSUPPORTED]))

    def test_template_spec_is_review(self):
        src = ('resource "azurerm_resource_group_template_deployment" "t" {\n  name = "t"\n'
               '  resource_group_name = "rg"\n  deployment_mode = "Incremental"\n'
               '  template_spec_version_id = "/subscriptions/0/x"\n}\n')
        self.assertEqual(self.verdict(src), ("REVIEW", [UNSUPPORTED]))


BLOB_SVC = '"Microsoft.Storage/storageAccounts/blobServices@2023-05-01"'
DEPLOY = '"Microsoft.Resources/deployments@2022-09-01"'
OLD_TLS = "AZURE_OLD_TLS"
TLS_UNRESOLVED = "AZURE_TLS_UNRESOLVED"


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class AzapiStaticWebsiteTest(unittest.TestCase):
    """PR 5 최종: azapi blobServices 의 properties.staticWebsite.enabled (GPT 추가 검토 1번)."""

    def site(self, inner, kind="azapi_resource"):
        body = "{\n    properties = { staticWebsite = " + inner + " }\n  }"
        return scan(azapi(BLOB_SVC, body, kind=kind))

    def test_enabled_true_is_review_for_both_kinds(self):
        for kind in ("azapi_resource", "azapi_update_resource"):
            with self.subTest(kind):
                r = self.site('{ enabled = true, indexDocument = "index.html" }', kind)
                self.assertEqual((r["status"], r["rules"]), ("REVIEW", [STATIC]))
                self.assertEqual(exposure_of(r, STATIC), "intentional_static_website")

    def test_enabled_false_is_pass(self):
        r = self.site("{ enabled = false }")
        self.assertEqual((r["status"], r["rules"]), ("PASS", []))

    def test_enabled_variable_or_missing_is_review(self):
        for inner in ("{ enabled = var.site_on }", '{ indexDocument = "index.html" }', "var.site"):
            with self.subTest(inner):
                r = self.site(inner)
                self.assertEqual((r["status"], r["rules"]), ("REVIEW", [STATIC]))
                self.assertEqual(exposure_of(r, STATIC), "undetermined")

    def test_jsonencode_literal_is_decoded(self):
        body = 'jsonencode({ properties = { staticWebsite = { enabled = true } } })'
        r = scan(azapi(BLOB_SVC, body))
        self.assertEqual((r["status"], r["rules"]), ("REVIEW", [STATIC]))
        self.assertEqual(exposure_of(r, STATIC), "intentional_static_website")

    def test_opaque_body_is_review(self):
        for body in ("var.body", "jsonencode({ properties = var.props })"):
            with self.subTest(body):
                self.assertEqual(scan(azapi(BLOB_SVC, body))["rules"], [STATIC])

    def test_unrelated_blob_service_settings_do_not_block(self):
        body = ("{\n    properties = {\n      isVersioningEnabled = true\n"
                "      deleteRetentionPolicy = { enabled = true, days = 7 }\n"
                "      cors = { corsRules = [] }\n    }\n  }")
        r = scan(azapi(BLOB_SVC, body))
        self.assertEqual((r["status"], r["rules"]), ("PASS", []))
        self.assertEqual(scan(azapi(BLOB_SVC, "{}"))["status"], "PASS")

    def test_checks_record_blob_service(self):
        for inner, status in (("{ enabled = true }", "REVIEW"), ("{ enabled = false }", "PASS")):
            with self.subTest(inner):
                r = self.site(inner)
                checks = [(c["resource"], c["cloud"], c["policy"], c["status"])
                          for c in build_checks(r["data"], r["findings"])]
                self.assertEqual(checks, [("azapi_resource.z", "azure", "CG-STO-01", status)])

    def test_containers_type_is_not_mistaken_for_blob_service(self):
        # blobServices/containers 는 기존 컨테이너 규칙 그대로
        body = '{\n    properties = { publicAccess = "None" }\n  }'
        self.assertEqual(scan(azapi(CONT, body))["status"], "PASS")


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class LinkedTemplateTest(unittest.TestCase):
    """PR 5 최종: templateLink(연결 템플릿)는 내용을 볼 수 없으므로 REVIEW (GPT 추가 검토 2번)."""

    def template(self, content):
        return ('resource "azurerm_resource_group_template_deployment" "t" {\n  name = "t"\n'
                f'  resource_group_name = "rg"\n  deployment_mode = "Incremental"\n  template_content = {content}\n}}\n')

    def test_azapi_deployment_with_template_link_uri(self):
        body = ('{\n    properties = { mode = "Incremental", '
                'templateLink = { uri = "https://example.com/storage.json" } }\n  }')
        r = scan(azapi(DEPLOY, body))
        self.assertEqual((r["status"], r["rules"]), ("REVIEW", [UNSUPPORTED]))
        self.assertIn("templateLink", r["findings"][0]["reason"])
        self.assertEqual([c["status"] for c in build_checks(r["data"], r["findings"])], ["REVIEW"])

    def test_azapi_deployment_with_relative_path_or_id(self):
        for link in ('{ relativePath = "children/storage.json" }', '{ id = "/subscriptions/0/templateSpecs/x" }',
                     "{ uri = var.template_uri }"):
            with self.subTest(link):
                body = '{\n    properties = { mode = "Incremental", templateLink = ' + link + ' }\n  }'
                self.assertEqual(scan(azapi(DEPLOY, body))["rules"], [UNSUPPORTED])

    def test_nested_deployment_inside_azurerm_template(self):
        content = ('<<EOT\n{"resources": [{"type": "Microsoft.Resources/deployments", "name": "inner",\n'
                   ' "properties": {"mode": "Incremental", "templateLink": {"uri": "https://example.com/x.json"}}}]}\nEOT')
        r = scan(self.template(content))
        self.assertEqual((r["status"], r["rules"]), ("REVIEW", [UNSUPPORTED]))
        self.assertIn("templateLink", r["findings"][0]["reason"])

    def test_nested_deployment_inside_azapi_template(self):
        body = ('{\n    properties = { mode = "Incremental", template = { resources = [{\n'
                '      type = "Microsoft.Resources/deployments", name = "inner",\n'
                '      properties = { mode = "Incremental", templateLink = { uri = "https://example.com/x.json" } }\n'
                '    }] } }\n  }')
        self.assertEqual(scan(azapi(DEPLOY, body))["rules"], [UNSUPPORTED])

    def test_jsonencode_template_link(self):
        body = 'jsonencode({ properties = { mode = "Incremental", templateLink = { uri = "https://e.com/a.json" } } })'
        self.assertEqual(scan(azapi(DEPLOY, body))["rules"], [UNSUPPORTED])

    def test_ordinary_inline_templates_still_pass(self):
        content = ('<<EOT\n{"resources": [{"type": "Microsoft.Network/virtualNetworks", "name": "x",\n'
                   ' "properties": {"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}}}]}\nEOT')
        self.assertEqual(scan(self.template(content))["status"], "PASS")
        nested = ('<<EOT\n{"resources": [{"type": "Microsoft.Resources/deployments", "name": "inner",\n'
                  ' "properties": {"mode": "Incremental", "template": {"resources": '
                  '[{"type": "Microsoft.Network/virtualNetworks"}]}}}]}\nEOT')
        self.assertEqual(scan(self.template(nested))["status"], "PASS")
        body = ('{\n    properties = { mode = "Incremental", template = { resources = '
                '[{ type = "Microsoft.Network/virtualNetworks" }] } }\n  }')
        self.assertEqual(scan(azapi(DEPLOY, body))["status"], "PASS")


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class TlsFixTest(unittest.TestCase):
    """v3 PR 5: 저장소 min_tls_version 이 TLS1_0/TLS1_1 이어도 PASS 되던 문제 수정."""

    def rules(self, extra):
        return scan(account("  allow_nested_items_to_be_public = false\n" + extra))["rules"]

    def test_storage_old_tls_now_detected(self):
        for value in ('"TLS1_0"', '"TLS1_1"', '"tls1_0"'):
            with self.subTest(value):
                self.assertEqual(self.rules(f"  min_tls_version = {value}"), ["AZURE_OLD_TLS"])

    def test_storage_modern_tls_ok(self):
        self.assertEqual(self.rules('  min_tls_version = "TLS1_2"'), [])

    def test_existing_minimum_tls_version_rule_unchanged(self):
        src = 'resource "azurerm_mssql_server" "s" {\n  name = "s"\n  minimum_tls_version = "1.0"\n}\n'
        self.assertEqual(scan(src)["rules"], ["AZURE_OLD_TLS"])
        src = 'resource "azurerm_mssql_server" "s" {\n  name = "s"\n  minimum_tls_version = "1.2"\n}\n'
        self.assertEqual(scan(src)["rules"], [])

    # --- PR 5 최종: TLS 일관성 (GPT 추가 검토 3번) ---
    # 정책: 명시적인 1.0/1.1(TLS1_0/TLS1_1) → AZURE_OLD_TLS(BLOCK),
    #       변수·표현식 → AZURE_TLS_UNRESOLVED(REVIEW), 생략·1.2 이상 → 판정 없음
    def test_storage_tls_variable_is_review(self):
        for value in ("var.tls_version", 'var.legacy ? "TLS1_0" : "TLS1_2"', "local.tls"):
            with self.subTest(value):
                self.assertEqual(self.rules(f"  min_tls_version = {value}"), [TLS_UNRESOLVED])

    def test_sql_tls_variable_is_review(self):
        src = 'resource "azurerm_mssql_server" "s" {\n  name = "s"\n  minimum_tls_version = var.tls\n}\n'
        r = scan(src)
        self.assertEqual((r["status"], r["rules"]), ("REVIEW", [TLS_UNRESOLVED]))
        self.assertEqual((r["findings"][0]["cloud"], r["findings"][0]["policy"]), ("azure", None))

    def test_tls_omitted_or_modern_is_not_flagged(self):
        self.assertEqual(self.rules(""), [])
        for value in ('"TLS1_2"', '"TLS1_3"'):
            with self.subTest(value):
                self.assertEqual(self.rules(f"  min_tls_version = {value}"), [])

    def test_azapi_storage_account_old_tls_is_block(self):
        for kind in ("azapi_resource", "azapi_update_resource"):
            for value in ('"TLS1_0"', '"TLS1_1"'):
                with self.subTest(kind=kind, value=value):
                    body = ("{\n    properties = { allowBlobPublicAccess = false, minimumTlsVersion = "
                            + value + " }\n  }")
                    r = scan(azapi(ACCT, body, kind=kind))
                    self.assertEqual((r["status"], r["rules"]), ("BLOCK", [OLD_TLS]))
                    # TLS 는 CG-STO-01 이 아니므로 저장소 checks 기록은 PASS 그대로
                    self.assertEqual([c["status"] for c in build_checks(r["data"], r["findings"])], ["PASS"])

    def test_azapi_tls_variable_is_review_and_modern_is_pass(self):
        body = "{\n    properties = { allowBlobPublicAccess = false, minimumTlsVersion = var.tls }\n  }"
        self.assertEqual(scan(azapi(ACCT, body))["rules"], [TLS_UNRESOLVED])
        body = '{\n    properties = { allowBlobPublicAccess = false, minimumTlsVersion = "TLS1_2" }\n  }'
        self.assertEqual(scan(azapi(ACCT, body))["status"], "PASS")

    def test_azapi_tls_in_jsonencode_and_early_return_paths(self):
        # jsonencode 리터럴도 풀어서 본다
        body = 'jsonencode({ properties = { allowBlobPublicAccess = false, minimumTlsVersion = "TLS1_0" } })'
        self.assertEqual(scan(azapi(ACCT, body))["rules"], [OLD_TLS])
        # update_resource 에 allowBlobPublicAccess 가 없어 저장소 검사가 일찍 끝나도 TLS 는 검사
        body = '{\n    properties = { minimumTlsVersion = "TLS1_1" }\n  }'
        self.assertEqual(scan(azapi(ACCT, body, kind="azapi_update_resource"))["rules"], [OLD_TLS])

    def test_old_tls_wins_over_variable_in_other_attribute(self):
        src = ('resource "azurerm_mssql_server" "s" {\n  name = "s"\n  minimum_tls_version = "1.0"\n'
               '  min_tls_version = var.x\n}\n')
        self.assertEqual(scan(src)["rules"], [OLD_TLS])


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class RecordTest(unittest.TestCase):
    def test_checks_record_storage_resources(self):
        src = (tf_version("~> 4.0") + account("  allow_nested_items_to_be_public = false") + container('"blob"') +
               'resource "azurerm_storage_account_static_website" "w" {\n'
               '  storage_account_id = azurerm_storage_account.sa.id\n}\n')
        r = scan(src)
        checks = {c["resource"]: (c["cloud"], c["policy"], c["status"]) for c in build_checks(r["data"], r["findings"])}
        self.assertEqual(checks, {
            "azurerm_storage_account.sa": ("azure", "CG-STO-01", "PASS"),
            "azurerm_storage_container.c": ("azure", "CG-STO-01", "BLOCK"),
            "azurerm_storage_account_static_website.w": ("azure", "CG-STO-01", "REVIEW"),
        })

    def test_exposure_only_on_azure_storage_findings(self):
        src = account('  allow_nested_items_to_be_public = true\n  min_tls_version = "TLS1_0"')
        for f in scan(src)["findings"]:
            if f["rule"].startswith("AZURE_STORAGE_"):
                self.assertIn(f["exposure"], EXPOSURES)
                self.assertEqual((f["cloud"], f["policy"]), ("azure", "CG-STO-01"))
            else:
                self.assertNotIn("exposure", f)          # 기존 결과 JSON 모양 그대로

    def test_reason_states_static_basis(self):
        r = scan(account("  allow_nested_items_to_be_public = true") + container('"blob"'))
        for f in r["findings"]:
            self.assertIn("정적 구성 기준", f["reason"])


if __name__ == "__main__":
    unittest.main()
