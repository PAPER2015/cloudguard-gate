"""Terraform JSON 구성 파일(.tf.json) 차단 테스트 — v3.1.

Terraform 은 같은 폴더의 .tf 와 .tf.json 을 모두 읽어 배포한다. 검사기는 .tf 만 해석하므로,
.tf.json 이 섞여 있으면 검사하지 못한 설정이 배포될 수 있다 → 반드시 ERROR(종료 코드 2).
v3.1 이전에는 .tf 가 하나라도 있으면 .tf.json 을 조용히 무시했다.

GitHub Actions 게이트와 같은 경로(명령줄 policy_gate.py)로 실행한다.
실행: python -m unittest discover -s tests -v
"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SAFE_TF = 'resource "aws_security_group" "ok" {\n  ingress {\n    from_port = 443\n    to_port = 443\n' \
          '    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
BLOCK_TF = SAFE_TF.replace("443", "22")
RISKY_JSON = json.dumps({"resource": {"aws_security_group": {"sg": {"ingress": [{
    "from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]}}}})

try:
    import hcl2  # noqa: F401
except ImportError:  # pragma: no cover
    hcl2 = None


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class TfJsonTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def gate(self, target=None):
        out = self.root.parent / (self.root.name + "-results.json")
        proc = subprocess.run([sys.executable, str(ROOT / "policy_gate.py"), str(target or self.root),
                               "--json", str(out)], capture_output=True, text=True, cwd=ROOT)
        results = json.loads(out.read_text(encoding="utf-8")) if out.exists() else None
        if out.exists():
            out.unlink()
        return proc.returncode, proc.stdout, results

    def by_name(self, results):
        return {Path(r["file"]).name: r for r in results}

    # --- 이전부터 ERROR 였던 동작 (보존) ---
    def test_empty_folder_is_error(self):
        code, out, results = self.gate()
        self.assertEqual(code, 2)
        self.assertIn("검사할 .tf 파일이 없습니다", out)
        self.assertIsNone(results)

    def test_folder_with_only_tf_json_is_error(self):
        self.write("main.tf.json", RISKY_JSON)
        code, out, results = self.gate()
        self.assertEqual(code, 2)
        self.assertIn("검사할 .tf 파일이 없습니다", out)
        self.assertIn("main.tf.json", out)
        self.assertIsNone(results)

    def test_single_tf_json_file_argument_is_error(self):
        path = self.write("main.tf.json", RISKY_JSON)
        code, _, _ = self.gate(path)
        self.assertEqual(code, 2)

    def test_missing_path_is_error(self):
        code, out, _ = self.gate(self.root / "없는폴더")
        self.assertEqual(code, 2)
        self.assertIn("경로가 없습니다", out)

    # --- v3.1: .tf 와 섞여 있어도 반드시 ERROR ---
    def test_mixed_folder_reports_tf_json_as_error(self):
        self.write("main.tf", SAFE_TF)
        self.write("extra.tf.json", RISKY_JSON)
        code, out, results = self.gate()
        self.assertEqual(code, 2)
        files = self.by_name(results)
        self.assertEqual(set(files), {"main.tf", "extra.tf.json"})
        self.assertEqual(files["extra.tf.json"]["status"], "ERROR")
        self.assertIn(".tf.json", files["extra.tf.json"]["error"])
        self.assertEqual(files["extra.tf.json"]["findings"], [])
        self.assertEqual(files["extra.tf.json"]["checks"], [])
        self.assertEqual(files["main.tf"]["status"], "PASS")    # .tf 는 평소처럼 검사한다
        self.assertIn("[ERROR]", out)

    def test_error_wins_over_block(self):
        self.write("main.tf", BLOCK_TF)
        self.write("extra.tf.json", RISKY_JSON)
        code, _, results = self.gate()
        self.assertEqual(code, 2)
        self.assertEqual(self.by_name(results)["main.tf"]["status"], "BLOCK")

    def test_tf_json_in_subfolder_and_override_file(self):
        self.write("main.tf", SAFE_TF)
        self.write("modules/net/override.tf.json", RISKY_JSON)
        self.write("modules/net/main.tf", SAFE_TF)
        code, _, results = self.gate()
        self.assertEqual(code, 2)
        errors = [r["file"] for r in results if r["status"] == "ERROR"]
        self.assertEqual([Path(f).name for f in errors], ["override.tf.json"])

    def test_tf_json_with_parse_error_style_fields(self):
        """결과 JSON 구조는 기존 분석 오류(ERROR)와 같은 5개 필드."""
        self.write("main.tf", SAFE_TF)
        self.write("x.tf.json", "{}")
        _, _, results = self.gate()
        for r in results:
            self.assertEqual(set(r), {"file", "status", "findings", "checks", "error"})

    # --- 오탐 방지: Terraform 구성 파일이 아닌 JSON 은 그대로 ---
    def test_other_json_files_are_not_errors(self):
        self.write("main.tf", SAFE_TF)
        self.write("policy.json", '{"Version": "2012-10-17"}')
        self.write("terraform.tfvars.json", '{"x": 1}')
        self.write("notes.tf.json.bak", "{}")
        code, _, results = self.gate()
        self.assertEqual(code, 0)
        self.assertEqual([Path(r["file"]).name for r in results], ["main.tf"])

    def test_folder_without_tf_json_is_unchanged(self):
        self.write("main.tf", BLOCK_TF)
        code, _, results = self.gate()
        self.assertEqual(code, 1)
        self.assertEqual([r["status"] for r in results], ["BLOCK"])

    def test_summary_shows_tf_json_error(self):
        self.write("main.tf", SAFE_TF)
        self.write("extra.tf.json", RISKY_JSON)
        out = self.root / "r.json"
        subprocess.run([sys.executable, str(ROOT / "policy_gate.py"), str(self.root), "--json", str(out)],
                       capture_output=True, text=True, cwd=ROOT)
        proc = subprocess.run([sys.executable, str(ROOT / "summary.py"), str(out)],
                              capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("extra.tf.json", proc.stdout)
        self.assertIn("ERROR", proc.stdout)


if __name__ == "__main__":
    unittest.main()
