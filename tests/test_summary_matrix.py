"""Summary 의 정책 × 클라우드 행렬 — v3 PR 6.

PASS(검사했고 위반 없음) · N/A(지원하지만 대상 없음) · 미지원 · 확인 불가(ERROR)를 구분하는지,
하나의 BLOCK 이 전체 PASS 로 집계되지 않는지, 기존 Summary 출력이 한 글자도 바뀌지 않았는지 확인한다.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from policy_gate import (POLICY_SUPPORT, POLICY_TARGETS, build_checks, is_azure_storage_check_target,  # noqa: E402
                         policy_matrix, policy_support_resources)

try:
    import hcl2  # noqa: F401
except ImportError:  # pragma: no cover
    hcl2 = None


def check(cloud, policy, status, resource="x.y"):
    return {"resource": resource, "cloud": cloud, "policy": policy, "status": status}


def result(status="PASS", checks=(), findings=()):
    return {"file": "f.tf", "status": status, "findings": list(findings), "checks": list(checks), "error": None}


def cell(cells, policy, cloud):
    return [c for c in cells if c["policy"] == policy and c["cloud"] == cloud][0]


class MatrixTest(unittest.TestCase):
    def test_six_cells_all_supported(self):
        cells = policy_matrix([])
        self.assertEqual(len(cells), 6)
        self.assertTrue(all(c["supported"] for c in cells))
        self.assertEqual({c["result"] for c in cells}, {"N/A"})

    def test_pass_na_block_review_are_distinct(self):
        cells = policy_matrix([result("BLOCK", [check("aws", "CG-NET-01", "PASS"), check("aws", "CG-NET-01", "BLOCK"),
                                                 check("gcp", "CG-STO-01", "REVIEW"), check("azure", "CG-STO-01", "PASS")])])
        self.assertEqual(cell(cells, "CG-NET-01", "aws")["result"], "BLOCK")      # 하나의 BLOCK 이 칸 전체를 BLOCK
        self.assertEqual(cell(cells, "CG-NET-01", "aws")["counts"], {"PASS": 1, "REVIEW": 0, "BLOCK": 1})
        self.assertEqual(cell(cells, "CG-STO-01", "gcp")["result"], "REVIEW")
        self.assertEqual(cell(cells, "CG-STO-01", "azure")["result"], "PASS")
        self.assertEqual(cell(cells, "CG-NET-01", "gcp")["result"], "N/A")

    def test_error_file_turns_na_into_unknown(self):
        cells = policy_matrix([result("ERROR"), result("PASS", [check("aws", "CG-NET-01", "PASS")])])
        self.assertEqual(cell(cells, "CG-NET-01", "aws")["result"], "PASS")
        self.assertEqual(cell(cells, "CG-STO-01", "gcp")["result"], "확인 불가(ERROR)")

    def test_unsupported_cell_is_labelled(self):
        saved = POLICY_SUPPORT.pop(("CG-STO-01", "gcp"))
        try:
            self.assertEqual(cell(policy_matrix([]), "CG-STO-01", "gcp")["result"], "미지원")
        finally:
            POLICY_SUPPORT[("CG-STO-01", "gcp")] = saved

    def test_support_table_resources_match_what_build_checks_records(self):
        for (policy, cloud), targets in POLICY_TARGETS.items():
            with self.subTest((policy, cloud)):
                self.assertTrue(set(targets) <= set(policy_support_resources(policy, cloud)))
        for typ in policy_support_resources("CG-STO-01", "azure"):
            with self.subTest(typ):
                self.assertTrue(is_azure_storage_check_target(typ, {}))


class SummaryOutputTest(unittest.TestCase):
    def run_summary(self, results):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "r.json"
            path.write_text(json.dumps(results, ensure_ascii=False), encoding="utf-8")
            return subprocess.run([sys.executable, "summary.py", str(path)], cwd=ROOT, capture_output=True,
                                  text=True).stdout

    def test_existing_summary_part_is_unchanged(self):
        # 기준: PR 5 의 summary.py 로 같은 입력을 처리한 출력 (tests/fixtures/pr5_summary_expected.md)
        fixtures = ROOT / "tests" / "fixtures"
        results = json.loads((fixtures / "summary_input.json").read_text(encoding="utf-8"))
        old = (fixtures / "pr5_summary_expected.md").read_text(encoding="utf-8")
        new = self.run_summary(results)
        self.assertTrue(new.startswith(old), "기존 Summary 부분이 바뀜")
        self.assertIn("### 정책 × 클라우드 지원 행렬", new[len(old):])

    def test_matrix_rows_for_every_cloud(self):
        new = self.run_summary([result("PASS", [check("aws", "CG-STO-01", "PASS")])])
        for cloud in ("| AWS |", "| Azure |", "| GCP |"):
            self.assertEqual(new.count(cloud), 2, cloud)
        self.assertIn("클라우드 전체가 안전하다는 보증이 아님", new)

    @unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
    def test_matrix_counts_real_checks(self):
        import io
        data = hcl2.load(io.StringIO('resource "google_storage_bucket" "b" {\n  name = "x"\n'
                                     '  public_access_prevention = "enforced"\n}\n'))
        cells = policy_matrix([result("PASS", build_checks(data, []))])
        self.assertEqual((cell(cells, "CG-STO-01", "gcp")["result"], cell(cells, "CG-STO-01", "gcp")["checked"]),
                         ("PASS", 1))


if __name__ == "__main__":
    unittest.main()
