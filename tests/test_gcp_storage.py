"""GCP Cloud Storage 공개 위험 (CG-STO-01 → GCP) 단위 테스트 — v3 PR 6.

모든 테스트는 실제 Terraform 문장을 python-hcl2 7.3.1로 읽어서 검사한다 (딕셔너리 테스트 없음).
판정표: PR 6 설계 검토서 0-1장 "최종 확정 GCP 판정표"와 6장 19개 사례.
정책: 공개 주체(allUsers·allAuthenticatedUsers)에게 권한을 부여하는 선언 자체가 BLOCK.
      버킷 PAP 가 enforced 가 아니면 REVIEW. 버킷 연결은 exposure 에만 쓴다.
실행: python -m unittest discover -s tests -v
"""
import io
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from policy_gate import (RULES, build_checks, file_status, make_gcp_context,  # noqa: E402
                         scan_configuration)

try:
    import hcl2
except ImportError:  # pragma: no cover
    hcl2 = None

PUBLIC_IAM = "GCP_STORAGE_PUBLIC_IAM"
PUBLIC_ACL = "GCP_STORAGE_PUBLIC_ACL"
PAP = "GCP_STORAGE_PAP_NOT_ENFORCED"
UNRESOLVED = "GCP_STORAGE_PUBLIC_UNRESOLVED"
UNSUPPORTED = "GCP_STORAGE_UNSUPPORTED"
GCP_EXPOSURES = {"public_access_possible", "authenticated_users_access_possible",
                 "blocked_by_public_access_prevention", "acl_disabled_by_uniform_access", "undetermined"}


def bucket(pap='"enforced"', extra="", name="b", literal="cg-bucket"):
    pap_line = f"  public_access_prevention = {pap}\n" if pap is not None else ""
    return (f'resource "google_storage_bucket" "{name}" {{\n  name     = "{literal}"\n  location = "ASIA-NORTHEAST3"\n'
            f'{pap_line}{extra}}}\n')


def member(m, role='"roles/storage.objectViewer"', ref="google_storage_bucket.b.name", name="m",
           kind="google_storage_bucket_iam_member", extra=""):
    return (f'resource "{kind}" "{name}" {{\n  bucket = {ref}\n  role   = {role}\n  member = {m}\n{extra}}}\n')


def binding(members, role='"roles/storage.objectViewer"', ref="google_storage_bucket.b.name", name="x"):
    return (f'resource "google_storage_bucket_iam_binding" "{name}" {{\n  bucket  = {ref}\n  role    = {role}\n'
            f'  members = {members}\n}}\n')


def scan(src, module_dir=None):
    data = hcl2.load(io.StringIO(src))
    findings = scan_configuration(data, gcp_ctx=make_gcp_context([data], module_dir))
    return {"status": file_status(findings), "rules": sorted({f["rule"] for f in findings}),
            "findings": findings, "data": data}


def by_resource(result, resource):
    return [f for f in result["findings"] if f["resource"] == resource]


def exposure_of(result, rule):
    for f in result["findings"]:
        if f["rule"] == rule:
            return f.get("exposure")
    return "MISSING"


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class RuleTableTest(unittest.TestCase):
    def test_new_rules_are_gcp_storage_policy(self):
        for rule in (PUBLIC_IAM, PUBLIC_ACL, PAP, UNRESOLVED, UNSUPPORTED):
            with self.subTest(rule):
                self.assertEqual((RULES[rule]["cloud"], RULES[rule]["policy"]), ("gcp", "CG-STO-01"))
        self.assertEqual(RULES[PUBLIC_IAM]["verdict"], "BLOCK")
        self.assertEqual(RULES[PUBLIC_ACL]["verdict"], "BLOCK")
        for rule in (PAP, UNRESOLVED, UNSUPPORTED):
            self.assertEqual(RULES[rule]["verdict"], "REVIEW")


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class BucketTest(unittest.TestCase):
    """버킷 자체: PAP 만 판정에 쓴다 (판정표 1~5, 18)."""

    def test_enforced_is_pass(self):
        r = scan(bucket('"enforced"'))
        self.assertEqual((r["status"], r["rules"]), ("PASS", []))

    def test_enforced_case_insensitive(self):
        self.assertEqual(scan(bucket('"Enforced"'))["status"], "PASS")

    def test_inherited_is_review(self):
        r = scan(bucket('"inherited"'))
        self.assertEqual((r["status"], r["rules"]), ("REVIEW", [PAP]))
        self.assertEqual(exposure_of(r, PAP), "undetermined")
        self.assertIn("조직 정책", r["findings"][0]["reason"])

    def test_omitted_is_review_with_default_note(self):
        r = scan(bucket(None))
        self.assertEqual(r["rules"], [PAP])
        self.assertIn("기본값 inherited", r["findings"][0]["reason"])

    def test_legacy_unspecified_value_is_inherited(self):
        self.assertEqual(scan(bucket('"unspecified"'))["rules"], [PAP])

    def test_variable_pap_is_unresolved(self):
        for value in ("var.pap", 'var.strict ? "enforced" : "inherited"'):
            with self.subTest(value):
                r = scan(bucket(value))
                self.assertEqual((r["status"], r["rules"]), ("REVIEW", [UNRESOLVED]))

    def test_unknown_literal_pap_is_unresolved(self):
        self.assertEqual(scan(bucket('"on"'))["rules"], [UNRESOLVED])

    def test_ubla_true_alone_does_not_pass_inherited(self):
        r = scan(bucket('"inherited"', '  uniform_bucket_level_access = true\n'))
        self.assertEqual(r["rules"], [PAP])

    def test_ubla_false_is_not_itself_a_violation(self):
        self.assertEqual(scan(bucket('"enforced"', '  uniform_bucket_level_access = false\n'))["status"], "PASS")

    def test_unrelated_variables_do_not_change_verdict(self):
        extra = ('  labels = var.labels\n  storage_class = var.cls\n  force_destroy = var.fd\n'
                 '  lifecycle_rule {\n    condition {\n      age = var.age\n    }\n    action {\n      type = "Delete"\n    }\n  }\n'
                 '  versioning {\n    enabled = var.v\n  }\n')
        r = scan(bucket('"enforced"', extra))
        self.assertEqual((r["status"], r["rules"]), ("PASS", []))

    def test_website_block_grants_nothing_but_is_mentioned(self):
        site = '  website {\n    main_page_suffix = "index.html"\n    not_found_page = "404.html"\n  }\n'
        self.assertEqual(scan(bucket('"enforced"', site))["status"], "PASS")
        r = scan(bucket('"inherited"', site))
        self.assertEqual(r["rules"], [PAP])
        self.assertIn("정적 웹사이트", r["findings"][0]["reason"])


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class IamPrincipalTest(unittest.TestCase):
    """IAM 구성원 (판정표 6~9, 12)."""

    def test_all_users_with_pap_enforced_is_block_but_blocked_exposure(self):
        r = scan(bucket('"enforced"') + member('"allUsers"'))
        self.assertEqual((r["status"], r["rules"]), ("BLOCK", [PUBLIC_IAM]))
        self.assertEqual(exposure_of(r, PUBLIC_IAM), "blocked_by_public_access_prevention")
        self.assertIn("412", r["findings"][0]["reason"])

    def test_all_users_with_pap_inherited(self):
        r = scan(bucket('"inherited"') + member('"allUsers"'))
        self.assertEqual(r["status"], "BLOCK")
        self.assertEqual(r["rules"], [PAP, PUBLIC_IAM])
        self.assertEqual(exposure_of(r, PUBLIC_IAM), "public_access_possible")

    def test_all_authenticated_users_is_block_with_own_exposure(self):
        r = scan(bucket('"inherited"') + member('"allAuthenticatedUsers"'))
        self.assertIn(PUBLIC_IAM, r["rules"])
        self.assertEqual(exposure_of(r, PUBLIC_IAM), "authenticated_users_access_possible")

    def test_all_authenticated_with_pap_enforced_uses_blocked(self):
        r = scan(bucket('"enforced"') + member('"allAuthenticatedUsers"'))
        self.assertEqual(exposure_of(r, PUBLIC_IAM), "blocked_by_public_access_prevention")

    def test_public_principal_case_insensitive(self):
        self.assertEqual(scan(bucket() + member('"AllUsers"'))["rules"], [PUBLIC_IAM])

    def test_non_public_principals_pass(self):
        for m in ('"user:alice@example.com"', '"serviceAccount:ci@p.iam.gserviceaccount.com"',
                  '"group:team@example.com"', '"domain:example.com"', '"projectViewer:my-project"',
                  '"principalSet://iam.googleapis.com/locations/global/workforcePools/p/*"'):
            with self.subTest(m):
                r = scan(bucket() + member(m))
                self.assertEqual((r["status"], r["rules"]), ("PASS", []))

    def test_variable_member_is_review(self):
        for m in ("var.member", 'each.value', '"user:${var.email}"'):
            with self.subTest(m):
                r = scan(bucket() + member(m))
                self.assertEqual((r["status"], r["rules"]), ("REVIEW", [UNRESOLVED]))

    def test_unknown_member_format_is_unsupported(self):
        r = scan(bucket() + member('"everyone"'))
        self.assertEqual((r["status"], r["rules"]), ("REVIEW", [UNSUPPORTED]))

    def test_binding_list_with_public_and_variable_is_block(self):
        r = scan(bucket() + binding('["group:g@example.com", "allUsers", var.extra]'))
        self.assertEqual((r["status"], r["rules"]), ("BLOCK", [PUBLIC_IAM]))

    def test_binding_list_without_public_but_variable_is_review(self):
        r = scan(bucket() + binding('["group:g@example.com", var.extra]'))
        self.assertEqual(r["rules"], [UNRESOLVED])

    def test_binding_whole_list_variable_is_review(self):
        self.assertEqual(scan(bucket() + binding("var.members"))["rules"], [UNRESOLVED])

    def test_binding_private_list_passes(self):
        self.assertEqual(scan(bucket() + binding('["group:g@example.com", "user:a@example.com"]'))["status"], "PASS")

    def test_condition_on_public_binding_is_still_block(self):
        cond = '  condition {\n    title = "prefix"\n    expression = "resource.name.startsWith(\\"x\\")"\n  }\n'
        r = scan(bucket('"inherited"') + member('"allUsers"', extra=cond))
        self.assertIn(PUBLIC_IAM, r["rules"])
        self.assertIn("IAM 조건", by_resource(r, "google_storage_bucket_iam_member.m")[0]["reason"])

    def test_condition_on_private_binding_passes(self):
        cond = '  condition {\n    title = "t"\n    expression = "request.time < timestamp(\\"2030-01-01T00:00:00Z\\")"\n  }\n'
        self.assertEqual(scan(bucket() + member('"user:a@example.com"', extra=cond))["status"], "PASS")


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class IamRoleTest(unittest.TestCase):
    """역할: 공개 주체가 확정이면 역할과 무관하게 BLOCK (교차 검토 결정). 역할 불명이면 exposure undetermined."""

    def level(self, role, pap='"inherited"'):
        r = scan(bucket(pap) + member('"allUsers"', role))
        f = by_resource(r, "google_storage_bucket_iam_member.m")[0]
        return f["rule"], f.get("exposure"), f["reason"]

    def test_read_write_admin_roles_are_block_and_named(self):
        cases = {"roles/storage.objectViewer": "공개 읽기", "roles/storage.legacyObjectReader": "공개 읽기",
                 "roles/storage.objectCreator": "공개 쓰기", "roles/storage.objectUser": "공개 읽기·쓰기",
                 "roles/storage.objectAdmin": "공개 관리", "roles/storage.admin": "공개 관리",
                 "roles/storage.legacyBucketOwner": "공개 관리"}
        for role, text in cases.items():
            with self.subTest(role):
                rule, exposure, reason = self.level(f'"{role}"')
                self.assertEqual((rule, exposure), (PUBLIC_IAM, "public_access_possible"))
                self.assertIn(text, reason)

    def test_other_storage_role_is_block(self):
        rule, exposure, _ = self.level('"roles/storage.bucketViewer"')
        self.assertEqual((rule, exposure), (PUBLIC_IAM, "public_access_possible"))

    def test_custom_non_storage_and_variable_roles_are_block_with_undetermined_exposure(self):
        for role in ('"projects/p/roles/reader"', '"organizations/1/roles/x"', '"roles/viewer"', "var.role"):
            with self.subTest(role):
                rule, exposure, reason = self.level(role)
                self.assertEqual((rule, exposure), (PUBLIC_IAM, "undetermined"))
                self.assertIn("권한 내용 불명", reason)

    def test_unknown_role_with_pap_enforced_still_reports_blocked(self):
        rule, exposure, _ = self.level('"projects/p/roles/reader"', '"enforced"')
        self.assertEqual((rule, exposure), (PUBLIC_IAM, "blocked_by_public_access_prevention"))

    def test_private_member_with_custom_role_passes(self):
        r = scan(bucket() + member('"user:a@example.com"', '"projects/p/roles/x"'))
        self.assertEqual(r["status"], "PASS")


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class IamPolicyTest(unittest.TestCase):
    """google_storage_bucket_iam_policy 의 policy_data (판정표 8·9)."""

    def policy(self, policy_data, ref="google_storage_bucket.b.name"):
        return (f'resource "google_storage_bucket_iam_policy" "p" {{\n  bucket = {ref}\n'
                f'  policy_data = {policy_data}\n}}\n')

    def data(self, members, extra=""):
        return ('data "google_iam_policy" "pub" {\n  binding {\n    role = "roles/storage.objectViewer"\n'
                f'    members = {members}\n{extra}  }}\n}}\n')

    def test_data_source_with_public_member(self):
        r = scan(bucket('"inherited"') + self.data('["allUsers"]') + self.policy("data.google_iam_policy.pub.policy_data"))
        self.assertIn(PUBLIC_IAM, r["rules"])
        self.assertEqual(exposure_of(r, PUBLIC_IAM), "public_access_possible")

    def test_data_source_private_passes(self):
        r = scan(bucket() + self.data('["group:g@example.com"]') + self.policy("data.google_iam_policy.pub.policy_data"))
        self.assertEqual(r["status"], "PASS")

    def test_data_source_with_variable_member_is_review(self):
        r = scan(bucket() + self.data("var.members") + self.policy("data.google_iam_policy.pub.policy_data"))
        self.assertEqual(r["rules"], [UNRESOLVED])

    def test_missing_data_source_is_unsupported(self):
        r = scan(bucket() + self.policy("data.google_iam_policy.elsewhere.policy_data"))
        self.assertEqual(r["rules"], [UNSUPPORTED])

    def test_jsonencode_literal_is_parsed(self):
        pd = 'jsonencode({ bindings = [{ role = "roles/storage.objectViewer", members = ["allUsers"] }] })'
        r = scan(bucket() + self.policy(pd))
        self.assertEqual(r["rules"], [PUBLIC_IAM])
        pd_private = 'jsonencode({ bindings = [{ role = "roles/storage.objectViewer", members = ["user:a@example.com"] }] })'
        self.assertEqual(scan(bucket() + self.policy(pd_private))["status"], "PASS")

    def test_jsonencode_with_variable_is_review(self):
        pd = 'jsonencode({ bindings = [{ role = "roles/storage.objectViewer", members = var.m }] })'
        self.assertEqual(scan(bucket() + self.policy(pd))["rules"], [UNRESOLVED])

    def test_variable_policy_data_is_review(self):
        self.assertEqual(scan(bucket() + self.policy("var.policy"))["rules"], [UNRESOLVED])

    def test_heredoc_json_policy(self):
        pd = '<<EOT\n{"bindings": [{"role": "roles/storage.objectViewer", "members": ["allAuthenticatedUsers"]}]}\nEOT'
        r = scan(bucket('"inherited"') + self.policy(pd))
        self.assertEqual(exposure_of(r, PUBLIC_IAM), "authenticated_users_access_possible")

    def test_file_policy_read_from_module_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "policy.json").write_text(
                '{"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}', encoding="utf-8")
            r = scan(bucket() + self.policy('file("${path.module}/policy.json")'), module_dir=Path(tmp))
            self.assertEqual(r["rules"], [PUBLIC_IAM])
            r = scan(bucket() + self.policy('file("missing.json")'), module_dir=Path(tmp))
            self.assertEqual(r["rules"], [UNSUPPORTED])

    def test_dynamic_binding_in_data_source_is_review(self):
        data = ('data "google_iam_policy" "pub" {\n  dynamic "binding" {\n    for_each = var.b\n    content {\n'
                '      role = binding.value.role\n      members = binding.value.members\n    }\n  }\n}\n')
        r = scan(bucket() + data + self.policy("data.google_iam_policy.pub.policy_data"))
        self.assertEqual(r["rules"], [UNRESOLVED])


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class ManagedFolderTest(unittest.TestCase):
    """Managed Folder IAM (판정표 16)."""

    def folder(self, m, kind="google_storage_managed_folder_iam_member"):
        key = "member" if kind.endswith("_member") else "members"
        return (f'resource "google_storage_managed_folder" "f" {{\n  bucket = google_storage_bucket.b.name\n'
                f'  name = "public/"\n}}\n'
                f'resource "{kind}" "fi" {{\n  bucket = google_storage_bucket.b.name\n'
                f'  managed_folder = google_storage_managed_folder.f.name\n  role = "roles/storage.objectViewer"\n'
                f'  {key} = {m}\n}}\n')

    def test_public_managed_folder_member_is_block(self):
        r = scan(bucket('"inherited"', '  uniform_bucket_level_access = true\n') + self.folder('"allUsers"'))
        self.assertIn(PUBLIC_IAM, r["rules"])
        self.assertIn("managed folder", by_resource(r, "google_storage_managed_folder_iam_member.fi")[0]["reason"])

    def test_public_managed_folder_binding_is_block(self):
        r = scan(bucket() + self.folder('["allAuthenticatedUsers"]', "google_storage_managed_folder_iam_binding"))
        self.assertEqual(r["rules"], [PUBLIC_IAM])

    def test_private_managed_folder_passes_and_folder_itself_not_checked(self):
        r = scan(bucket() + self.folder('"group:team@example.com"'))
        self.assertEqual(r["status"], "PASS")
        resources = [c["resource"] for c in build_checks(r["data"], r["findings"])]
        self.assertNotIn("google_storage_managed_folder.f", resources)
        self.assertIn("google_storage_managed_folder_iam_member.fi", resources)


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class AclTest(unittest.TestCase):
    """ACL 6종 (판정표 10·11)."""

    def test_bucket_acl_predefined_public(self):
        for acl, exp in (("publicRead", "public_access_possible"), ("publicReadWrite", "public_access_possible"),
                         ("authenticatedRead", "authenticated_users_access_possible")):
            with self.subTest(acl):
                src = bucket('"inherited"') + ('resource "google_storage_bucket_acl" "a" {\n'
                                               f'  bucket = google_storage_bucket.b.name\n  predefined_acl = "{acl}"\n}}\n')
                r = scan(src)
                self.assertIn(PUBLIC_ACL, r["rules"])
                self.assertEqual(exposure_of(r, PUBLIC_ACL), exp)

    def test_bucket_acl_private_predefined_passes(self):
        for acl in ("private", "projectPrivate", "bucketOwnerRead"):
            with self.subTest(acl):
                src = bucket() + f'resource "google_storage_bucket_acl" "a" {{\n  bucket = "cg-bucket"\n  predefined_acl = "{acl}"\n}}\n'
                self.assertEqual(scan(src)["status"], "PASS")

    def test_role_entity_public_reader(self):
        src = bucket() + ('resource "google_storage_object_acl" "a" {\n  bucket = "cg-bucket"\n  object = "report.csv"\n'
                          '  role_entity = ["OWNER:user-owner@example.com", "READER:allUsers"]\n}\n')
        r = scan(src)
        self.assertEqual(r["rules"], [PUBLIC_ACL])
        self.assertIn("공개 읽기", r["findings"][0]["reason"])

    def test_role_entity_private_passes(self):
        src = bucket() + ('resource "google_storage_default_object_acl" "a" {\n  bucket = "cg-bucket"\n'
                          '  role_entity = ["OWNER:project-owners-123", "READER:group-team@example.com"]\n}\n')
        self.assertEqual(scan(src)["status"], "PASS")

    def test_role_entity_variable_item_or_list_is_review(self):
        for entries in ('["OWNER:user-a@example.com", var.extra]', "var.entries", '["READER:${var.who}"]'):
            with self.subTest(entries):
                src = bucket() + f'resource "google_storage_bucket_acl" "a" {{\n  bucket = "cg-bucket"\n  role_entity = {entries}\n}}\n'
                self.assertEqual(scan(src)["rules"], [UNRESOLVED])

    def test_predefined_variable_is_review(self):
        src = bucket() + 'resource "google_storage_bucket_acl" "a" {\n  bucket = "cg-bucket"\n  predefined_acl = var.acl\n}\n'
        self.assertEqual(scan(src)["rules"], [UNRESOLVED])

    def test_access_control_entity_resources(self):
        for kind in ("google_storage_bucket_access_control", "google_storage_object_access_control",
                     "google_storage_default_object_access_control"):
            with self.subTest(kind):
                obj = '  object = "o"\n' if kind == "google_storage_object_access_control" else ""
                src = bucket() + (f'resource "{kind}" "a" {{\n  bucket = "cg-bucket"\n{obj}  role = "READER"\n'
                                  '  entity = "allUsers"\n}\n')
                self.assertEqual(scan(src)["rules"], [PUBLIC_ACL])

    def test_access_control_public_entity_with_variable_role_is_block_undetermined(self):
        src = bucket('"inherited"') + ('resource "google_storage_bucket_access_control" "a" {\n  bucket = "cg-bucket"\n'
                                       '  role = var.role\n  entity = "allUsers"\n}\n')
        r = scan(src)
        self.assertEqual(exposure_of(r, PUBLIC_ACL), "undetermined")

    def test_access_control_variable_entity_is_review(self):
        src = bucket() + 'resource "google_storage_bucket_access_control" "a" {\n  bucket = "cg-bucket"\n  role = "READER"\n  entity = var.e\n}\n'
        self.assertEqual(scan(src)["rules"], [UNRESOLVED])

    def test_unknown_entity_is_unsupported(self):
        src = bucket() + 'resource "google_storage_bucket_access_control" "a" {\n  bucket = "cg-bucket"\n  role = "READER"\n  entity = "everyone"\n}\n'
        self.assertEqual(scan(src)["rules"], [UNSUPPORTED])

    def test_public_acl_with_ubla_true_is_block_with_disabled_exposure(self):
        src = bucket('"enforced"', '  uniform_bucket_level_access = true\n') + (
            'resource "google_storage_bucket_acl" "a" {\n  bucket = google_storage_bucket.b.name\n  predefined_acl = "publicRead"\n}\n')
        r = scan(src)
        self.assertEqual((r["status"], r["rules"]), ("BLOCK", [PUBLIC_ACL]))
        self.assertEqual(exposure_of(r, PUBLIC_ACL), "acl_disabled_by_uniform_access")
        self.assertIn("400", r["findings"][0]["reason"])

    def test_public_acl_with_pap_enforced_ubla_false(self):
        src = bucket('"enforced"') + ('resource "google_storage_bucket_acl" "a" {\n  bucket = google_storage_bucket.b.name\n'
                                      '  role_entity = ["READER:allUsers"]\n}\n')
        self.assertEqual(exposure_of(scan(src), PUBLIC_ACL), "blocked_by_public_access_prevention")


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class LinkingAndRecordTest(unittest.TestCase):
    """버킷 연결은 exposure 에만 (판정표 13~15), checks 기록, JSON 호환."""

    def test_unlinked_bucket_still_blocks(self):
        for ref in ("var.bucket", '"external-bucket"', "data.google_storage_bucket.ext.name",
                    "module.storage.bucket_name"):
            with self.subTest(ref):
                r = scan(member('"allUsers"', ref=ref))
                self.assertEqual(r["rules"], [PUBLIC_IAM])
                self.assertEqual(exposure_of(r, PUBLIC_IAM), "public_access_possible")

    def test_links_to_the_referenced_bucket_not_the_first(self):
        src = (bucket('"enforced"', name="first", literal="first-bucket")
               + bucket('"inherited"', name="second", literal="second-bucket")
               + member('"allUsers"', ref="google_storage_bucket.second.name"))
        self.assertEqual(exposure_of(scan(src), PUBLIC_IAM), "public_access_possible")

    def test_for_each_reference_links_to_definition(self):
        src = (bucket('"enforced"', '  for_each = toset(["a", "b"])\n', name="site")
               + member('"allUsers"', ref='google_storage_bucket.site["a"].name'))
        self.assertEqual(exposure_of(scan(src), PUBLIC_IAM), "blocked_by_public_access_prevention")

    def test_literal_name_links_only_when_unique(self):
        unique = bucket('"enforced"', literal="logs") + member('"allUsers"', ref='"logs"')
        self.assertEqual(exposure_of(scan(unique), PUBLIC_IAM), "blocked_by_public_access_prevention")
        dup = (bucket('"enforced"', name="a", literal="logs") + bucket('"enforced"', name="c", literal="logs")
               + member('"allUsers"', ref='"logs"'))
        self.assertEqual(exposure_of(scan(dup), PUBLIC_IAM), "public_access_possible")

    def test_linking_never_relaxes_verdict(self):
        r = scan(bucket('"enforced"') + member('"allUsers"'))
        self.assertEqual(r["status"], "BLOCK")

    def test_checks_record_every_target_resource(self):
        src = (bucket() + member('"user:a@example.com"')
               + 'resource "google_storage_bucket_acl" "a" {\n  bucket = "cg-bucket"\n  predefined_acl = "private"\n}\n'
               + 'resource "google_storage_bucket_object" "o" {\n  bucket = "cg-bucket"\n  name = "x"\n  content = "y"\n}\n'
               + 'resource "google_storage_hmac_key" "k" {\n  service_account_email = "a@p.iam.gserviceaccount.com"\n}\n')
        r = scan(src)
        checks = [(c["resource"], c["cloud"], c["policy"], c["status"]) for c in build_checks(r["data"], r["findings"])]
        self.assertEqual(checks, [
            ("google_storage_bucket.b", "gcp", "CG-STO-01", "PASS"),
            ("google_storage_bucket_iam_member.m", "gcp", "CG-STO-01", "PASS"),
            ("google_storage_bucket_acl.a", "gcp", "CG-STO-01", "PASS"),
        ])

    def test_checks_status_follows_findings(self):
        r = scan(bucket('"inherited"') + member('"allUsers"'))
        statuses = {c["resource"]: c["status"] for c in build_checks(r["data"], r["findings"])}
        self.assertEqual(statuses, {"google_storage_bucket.b": "REVIEW", "google_storage_bucket_iam_member.m": "BLOCK"})

    def test_findings_shape_and_exposure_values(self):
        r = scan(bucket('"inherited"') + member('"allUsers"') + member("var.m", name="v"))
        for f in r["findings"]:
            self.assertEqual(set(f), {"rule", "resource", "reason", "cloud", "policy", "verdict", "exposure"})
            self.assertIn(f["exposure"], GCP_EXPOSURES)
            if f["verdict"] == "REVIEW":
                self.assertIn("검토 필요", f["reason"])
        public = [f for f in r["findings"] if f["rule"] == PUBLIC_IAM][0]
        self.assertIn("실제 클라우드 접근을 확인한 것은 아님", public["reason"])

    def test_project_iam_is_out_of_scope_for_storage(self):
        src = ('resource "google_project_iam_member" "p" {\n  project = "p"\n  role = "roles/storage.objectViewer"\n'
               '  member = "allUsers"\n}\n')
        r = scan(src)
        self.assertEqual(r["rules"], [])
        self.assertEqual(build_checks(r["data"], r["findings"]), [])

    def test_existing_gcp_rules_unchanged(self):
        src = ('resource "google_project_iam_member" "p" {\n  project = "p"\n  role = "roles/owner"\n'
               '  member = "user:x@example.com"\n}\n')
        self.assertEqual(scan(src)["rules"], ["GCP_PROJECT_OWNER"])


if __name__ == "__main__":
    unittest.main()
