"""PR 6 회귀 검사: PR 5 최종 결과(코드 수정 전에 고정한 기준 파일)와 지금 결과를 비교한다.

기준 파일: tests/fixtures/pr5_regression_baseline.json (tools/make_regression_baseline.py 로 생성)
허용하는 차이는 두 가지뿐이다.
  1) GCP Storage 검사 기록(checks 의 cloud=gcp, policy=CG-STO-01) 추가 — 교차 검토에서 허용
  2) ALLOWED_CHANGES 에 이유와 함께 적은 항목 — S3 모듈 격리로 바뀐 폴더 통째 검사 결과
그 밖의 판정·findings·error·종료 코드가 하나라도 바뀌면 실패한다.
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    import hcl2  # noqa: F401
except ImportError:  # pragma: no cover
    hcl2 = None

from policy_gate import scan_paths  # noqa: E402

BASELINE = json.loads((ROOT / "tests" / "fixtures" / "pr5_regression_baseline.json").read_text(encoding="utf-8"))

# (검사 범위, 파일) → 바뀐 뒤의 기대 결과와 이유. 비어 있으면 "바뀐 것 없음".
ALLOWED_CHANGES = {}

# infra/ 는 사용자가 실제로 배포할 파일을 넣는 곳이라 내용이 바뀌는 것이 정상이다 (시연에서도 위험 파일을 넣음).
# 기준 파일에는 PR 5 시점의 infra/ 결과도 남겨 두지만, 단위 테스트에서는 비교하지 않는다.
# (그렇지 않으면 infra/ 에 위험 파일을 넣었을 때 "보안 검사"보다 앞의 단위 테스트 단계에서 실패해 시연 의미가 바뀐다)
USER_FOLDERS = {"infra"}


def rel(results):
    for r in results:
        r["file"] = Path(r["file"]).resolve().relative_to(ROOT).as_posix()
    return {r["file"]: r for r in results}


def split_checks(checks):
    new_gcp = [c for c in checks if c["cloud"] == "gcp" and c["policy"] == "CG-STO-01"]
    rest = [c for c in checks if not (c["cloud"] == "gcp" and c["policy"] == "CG-STO-01")]
    return rest, new_gcp


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class RegressionBaselineTest(unittest.TestCase):

    def compare(self, scope, old, new):
        key = (scope, old["file"])
        rest, added = split_checks(new["checks"])
        got = {"status": new["status"], "findings": new["findings"], "error": new["error"], "checks": rest}
        want = {"status": old["status"], "findings": old["findings"], "error": old["error"],
                "checks": old["checks"]}
        if key in ALLOWED_CHANGES:
            want.update(ALLOWED_CHANGES[key]["after"])
        self.assertEqual(got, want, f"{scope} :: {old['file']}")
        for check in added:   # 추가된 GCP 기록은 GCP Storage 자원에만
            self.assertTrue(check["resource"].startswith("google_storage_"), check)

    def test_each_sample_file_alone(self):
        for file, old in BASELINE["files"].items():
            with self.subTest(file):
                new = rel(scan_paths([ROOT / file]))[file]
                self.compare("file", old, new)

    def test_whole_folders(self):
        for folder, old_results in BASELINE["folders"].items():
            if folder in USER_FOLDERS:
                continue
            new_results = rel(scan_paths(sorted((ROOT / folder).rglob("*.tf"))))
            for old in old_results:
                with self.subTest(folder=folder, file=old["file"]):
                    self.compare(folder, old, new_results[old["file"]])

    def test_exit_codes(self):
        for folder, code in BASELINE["exit"].items():
            if folder in USER_FOLDERS:
                continue
            with self.subTest(folder):
                got = subprocess.run([sys.executable, "policy_gate.py", folder], cwd=ROOT,
                                     capture_output=True, text=True).returncode
                self.assertEqual(got, code)

    def test_allowed_changes_are_documented(self):
        for key, change in ALLOWED_CHANGES.items():
            self.assertTrue(change.get("reason"), key)


if __name__ == "__main__":
    unittest.main()
