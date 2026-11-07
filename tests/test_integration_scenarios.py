"""멀티클라우드 통합 시나리오 A~G — v3 PR 6 Phase B.

세 클라우드가 함께 있는 루트 모듈(scenarios/<이름>/)을 실제 CLI(policy_gate.py)로 검사해
판정·종료 코드·규칙·(클라우드, 정책)별 checks 를 scenarios/expected.json 과 비교한다.
GitHub Actions 작업 "3. 멀티클라우드 통합 검증"과 같은 판정 코드(tools/check_scenario.py)를 쓴다.
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    import hcl2  # noqa: F401
except ImportError:  # pragma: no cover
    hcl2 = None

from policy_gate import scan_paths  # noqa: E402

spec = importlib.util.spec_from_file_location("check_scenario", ROOT / "tools" / "check_scenario.py")
check_scenario = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_scenario)
EXPECTED = check_scenario.load_expected()


def summary_of(name):
    # v3.2: 실행마다 새 임시 폴더 (예전 /tmp 고정 이름은 테스트를 동시에 돌리면 서로 덮어씀)
    with tempfile.TemporaryDirectory(prefix="cg-test-") as tmp:
        out = Path(tmp) / f"{name}.json"
        subprocess.run([sys.executable, "policy_gate.py", f"scenarios/{name}", "--json", str(out)],
                       cwd=ROOT, capture_output=True, text=True)
        return subprocess.run([sys.executable, "summary.py", str(out)], cwd=ROOT, capture_output=True,
                              text=True).stdout


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class ScenarioTest(unittest.TestCase):
    def test_each_scenario_matches_expected(self):
        self.assertEqual(set(EXPECTED), {"A_all_pass", "B_aws_risk", "C_azure_risk", "D_gcp_risk",
                                         "E_all_risk", "F_review", "G_syntax_error"})
        for name in EXPECTED:
            with self.subTest(name):
                result = check_scenario.run_local(name)
                self.assertEqual(result["problems"], [])

    def test_normal_scenario_deploys_and_covers_six_cells(self):
        result = check_scenario.run_local("A_all_pass")
        self.assertEqual((result["gate_outcome"], result["deploy_outcome"], result["exit"]), ("success", "success", 0))
        self.assertEqual(set(result["cells"].values()), {"PASS"})
        self.assertEqual(len(result["cells"]), 6)

    def test_risky_scenarios_do_not_deploy(self):
        for name, code in (("B_aws_risk", 1), ("C_azure_risk", 1), ("D_gcp_risk", 1), ("E_all_risk", 1),
                           ("F_review", 1), ("G_syntax_error", 2)):
            with self.subTest(name):
                result = check_scenario.run_local(name)
                self.assertEqual((result["deploy_outcome"], result["exit"]), ("skipped", code))

    def test_combined_risk_keeps_findings_per_cloud(self):
        results = scan_paths(sorted((ROOT / "scenarios" / "E_all_risk").glob("*.tf")))
        by_file = {Path(r["file"]).name: {f["cloud"] for f in r["findings"]} for r in results}
        self.assertEqual(by_file, {"aws.tf": {"aws"}, "azure.tf": {"azure"}, "gcp.tf": {"gcp"}})

    def test_folders_are_isolated_even_when_scanned_together(self):
        together = {r["file"]: r for r in scan_paths(sorted((ROOT / "scenarios").rglob("*.tf")))}
        for name in EXPECTED:
            with self.subTest(name):
                alone = scan_paths(sorted((ROOT / "scenarios" / name).glob("*.tf")))
                for r in alone:
                    self.assertEqual(together[r["file"]], r)

    def test_summary_shows_all_three_clouds_and_gate_state(self):
        text = summary_of("E_all_risk")
        self.assertIn("정책 게이트 차단", text)
        matrix = text.split("### 정책 × 클라우드 지원 행렬")[1]
        for cloud in ("AWS", "Azure", "GCP"):
            self.assertEqual(len([l for l in matrix.splitlines() if f"| {cloud} |" in l]), 2, cloud)
        self.assertEqual(matrix.count("⛔ BLOCK"), 3)
        self.assertIn("정책 게이트 통과", summary_of("A_all_pass"))


class AggregateLogicTest(unittest.TestCase):
    """Actions 집계 작업의 판정 (GitHub 없이 확인 가능한 부분)."""

    def good_rows(self):
        return [{"scenario": n, "ok": True, "problems": []} for n in EXPECTED]

    def test_all_good(self):
        self.assertEqual(check_scenario.aggregate(self.good_rows(), "success"), (True, []))

    def test_matrix_failure_fails_even_if_rows_look_good(self):
        ok, problems = check_scenario.aggregate(self.good_rows(), "failure")
        self.assertFalse(ok)
        for needs in ("cancelled", "skipped", ""):
            self.assertFalse(check_scenario.aggregate(self.good_rows(), needs)[0])

    def test_missing_or_extra_scenario_fails(self):
        rows = self.good_rows()[1:]
        self.assertFalse(check_scenario.aggregate(rows, "success")[0])
        rows = self.good_rows() + [{"scenario": "Z_extra", "ok": True}]
        self.assertFalse(check_scenario.aggregate(rows, "success")[0])

    def test_duplicate_scenario_result_fails(self):
        # GPT 교차 검토: 정상 7개 + 같은 시나리오 결과 1개 더 → set 비교로는 잘못 통과했다
        for name in ("A_all_pass", "G_syntax_error"):
            with self.subTest(name):
                rows = self.good_rows() + [{"scenario": name, "ok": True, "problems": []}]
                ok, problems = check_scenario.aggregate(rows, "success")
                self.assertFalse(ok)
                self.assertTrue(any("결과가 2개" in p and name in p for p in problems), problems)

    def test_duplicate_replacing_a_missing_one_fails(self):
        # 개수는 7개로 맞지만 B 가 없고 A 가 두 번 → 누락과 중복 둘 다 보고
        rows = self.good_rows()
        rows = [r for r in rows if r["scenario"] != "B_aws_risk"] + [{"scenario": "A_all_pass", "ok": True}]
        self.assertEqual(len(rows), len(EXPECTED))
        ok, problems = check_scenario.aggregate(rows, "success")
        self.assertFalse(ok)
        self.assertTrue(any("B_aws_risk" in p for p in problems))
        self.assertTrue(any("A_all_pass" in p and "2개" in p for p in problems))

    def test_one_mismatch_fails(self):
        rows = self.good_rows()
        rows[3] = {"scenario": rows[3]["scenario"], "ok": False, "problems": ["x"]}
        self.assertFalse(check_scenario.aggregate(rows, "success")[0])

    def test_verify_rejects_wrong_deploy_behaviour(self):
        expected = EXPECTED["B_aws_risk"]
        seen = {k: expected[k] for k in ("status", "exit", "rules", "cells")}
        self.assertEqual(check_scenario.compare("B_aws_risk", expected, seen, "failure", "skipped"), [])
        self.assertTrue(check_scenario.compare("B_aws_risk", expected, seen, "failure", "success"))   # 위험인데 배포
        self.assertTrue(check_scenario.compare("B_aws_risk", expected, seen, "success", "success"))
        a = EXPECTED["A_all_pass"]
        seen_a = {k: a[k] for k in ("status", "exit", "rules", "cells")}
        self.assertTrue(check_scenario.compare("A_all_pass", a, seen_a, "success", "skipped"))       # 정상인데 배포 안 됨


if __name__ == "__main__":
    unittest.main()
