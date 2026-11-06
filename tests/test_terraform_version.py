"""Terraform provider 버전 제약 해석 테스트 — v3 PR 5.

정답(tests/fixtures/terraform_version_constraints.json)은 Terraform이 실제로 쓰는 라이브러리
(apparentlymart/go-versions v1.0.2, ParseRubyStyleMulti + MeetingConstraints)로 직접 계산했다.
만드는 방법: tools/terraform_version_oracle/README.md
python-hcl2 없이도 실행된다.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from policy_gate import (AZURERM_PUBLIC_DEFAULT, possible_major_versions,  # noqa: E402
                         public_default_from_majors, version_satisfies)

FIXTURE = Path(__file__).parent / "fixtures" / "terraform_version_constraints.json"


class TerraformLibraryParityTest(unittest.TestCase):
    """정답표 구성 (PR 5 최종): majors 695개 = 기존 258개 + 경계 사례 + 문법 경계 + 무작위 400개,
    members 220개 = 정확한 버전(잠금 파일)이 제약을 만족하는지. 후보 버전을 표본이 아니라
    제약에 적힌 경계값에서 만들기 때문에 4.121.0 같은 큰 숫자도 정답이 정확하다."""

    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_all_fixture_cases_match_terraform_library(self):
        expected = self.fixture["majors"]
        self.assertGreaterEqual(len(expected), 650)
        mismatches = []
        for constraint, want in expected.items():
            got = possible_major_versions([constraint])
            got = "error" if got is None else sorted(got)
            if got != want:
                mismatches.append((constraint, want, got))
        self.assertEqual(mismatches, [])

    def test_lock_version_cases_match_terraform_library(self):
        expected = self.fixture["members"]
        self.assertGreaterEqual(len(expected), 200)
        mismatches = []
        for line, want in expected.items():
            constraint, version = line.split(" @@ ")
            got = version_satisfies(version, [constraint])
            if got != want:
                mismatches.append((line, want, got))
        self.assertEqual(mismatches, [])

    def test_key_cases_explicitly(self):
        # 설계 검토서에서 잘못 예상했던 "~> 4" 포함 (실제 Terraform: 4.x 만)
        cases = {"~> 4": {4}, "~> 4.0": {4}, ">= 4.0": {4, 5, 6, 7}, "< 5.0.0": {1, 2, 3, 4},
                 "<= 5.0": {1, 2, 3, 4, 5}, "4": {4}, "> 4": {4, 5, 6, 7}, ">= 3.0, < 5.0": {3, 4}}
        for constraint, want in cases.items():
            with self.subTest(constraint):
                self.assertEqual(possible_major_versions([constraint]), want)
        for bad in ("latest", "v4.0.0", "4.x", "*", ">= 4.0 < 5.0", ">=  4.0", "~>\t4.0"):
            with self.subTest(bad):
                self.assertIsNone(possible_major_versions([bad]))

    def test_numbers_outside_old_sampling_range(self):
        # PR 5 첫 제출본은 부 버전 0~120, 수 버전 {0,1,2,5,9,10,99} 만 찍어 봐서 틀렸던 사례들
        cases = {">= 4.121.0, <= 5.0.0": {4, 5}, ">= 4.0.121, < 4.1": {4}, ">= 4.200.0": {4, 5, 6, 7},
                 "> 4.120.99, < 4.121.0": {4}, ">= 4.0.121, < 4.0.122, != 4.0.121": set(),
                 ">= 4.5.1, < 4.5.4, != 4.5.1, != 4.5.2": {4}}
        for constraint, want in cases.items():
            with self.subTest(constraint):
                self.assertEqual(possible_major_versions([constraint]), want)

    def test_partial_versions_are_zero_filled(self):
        # 라이브러리 규칙: "= 4" 는 4.0.0 하나, "<= 4" 는 4.0.0 까지 (4.x 전체가 아님)
        self.assertEqual(possible_major_versions(["= 4, >= 4.1"]), set())
        self.assertEqual(possible_major_versions(["<= 4, > 4.0.0"]), set())
        self.assertTrue(version_satisfies("4.0.0", ["= 4"]))
        self.assertFalse(version_satisfies("4.5.0", ["= 4"]))
        self.assertFalse(version_satisfies("4.5.0", ["<= 4"]))

    def test_prerelease_only_when_pinned_exactly(self):
        self.assertEqual(possible_major_versions(["= 5.0.0-beta1"]), {5})
        self.assertEqual(possible_major_versions(["= 5.0.0-beta1, ~> 5.0"]), set())
        self.assertTrue(version_satisfies("4.0.0-beta1", ["= 4.0.0-beta1"]))
        self.assertFalse(version_satisfies("4.0.0-beta1", [">= 4.0.0-beta1"]))
        self.assertFalse(version_satisfies("4.0.0-beta1", ["~> 4.0"]))

    def test_conservative_where_terraform_is_lenient(self):
        # Terraform 라이브러리는 받아들이지만 이 도구는 문법 오류(None → 저장소 판정 REVIEW)로 본다.
        # 보수적인 방향(통과시키지 않음)이라 그대로 두고 여기에 기록한다.
        for text in ("~> 4.0,", "4.0.0+abc", ">= 4.0.0-"):
            with self.subTest(text):
                self.assertIsNone(possible_major_versions([text]))

    def test_multiple_constraints_must_all_hold(self):
        self.assertEqual(possible_major_versions([">= 4.0", "< 5.0"]), {4})
        self.assertEqual(possible_major_versions(["~> 4.0", "~> 5.0"]), set())
        self.assertEqual(possible_major_versions([">= 4.121.0", "<= 5.0.0"]), {4, 5})
        self.assertEqual(possible_major_versions([]), {1, 2, 3, 4, 5, 6, 7})


class DefaultsTest(unittest.TestCase):
    def test_default_table_matches_provider_history(self):
        self.assertEqual(AZURERM_PUBLIC_DEFAULT, {1: None, 2: False, 3: True, 4: True, 5: False})

    def test_default_only_when_all_majors_agree(self):
        self.assertTrue(public_default_from_majors({3, 4}))
        self.assertFalse(public_default_from_majors({5}))
        self.assertIsNone(public_default_from_majors({4, 5}))
        self.assertIsNone(public_default_from_majors({2, 5, 6}))   # 6 = 미래 버전, 기본값 모름
        self.assertIsNone(public_default_from_majors({1}))
        self.assertIsNone(public_default_from_majors(set()))

    def test_lock_version_satisfies(self):
        self.assertTrue(version_satisfies("4.52.0", ["~> 4.0", ">= 4.10"]))
        self.assertFalse(version_satisfies("4.52.0", ["~> 5.0"]))
        self.assertTrue(version_satisfies("5.12.0", []))
        self.assertIsNone(version_satisfies("not-a-version", ["~> 4.0"]))


if __name__ == "__main__":
    unittest.main()
